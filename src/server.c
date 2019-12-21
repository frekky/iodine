/*
 * Copyright (c) 2006-2015 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>,
 * 2015-2017 Frekk van Blagh <frekk@frekkworks.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/time.h>
#include <fcntl.h>
#include <time.h>
#include <zlib.h>
#include <ctype.h>
#include <errno.h>

#include "version.h"
#include "common.h"
#include "encoding.h"
#include "read.h"
#include "dns.h"
#include "server.h"
#include "base32.h"
#include "cache.h"
#include "user.h"
#include "auth.h"
#include "tun.h"
#include "fw_query.h"
#include "util.h"
#include "window.h"
#include "md5.h"
#include "hmac_md5.h"

#ifdef HAVE_SYSTEMD
# include <systemd/sd-daemon.h>
#endif

#ifdef WINDOWS32
WORD req_version = MAKEWORD(2, 2);
WSADATA wsa_data;
#else
#include <err.h>
#endif

/* special flags for write_dns */
#define WD_AUTO (1 << 5)
#define WD_OLD	(1 << 6)
#define WD_CODECTEST (1 << 7)

static int raw_decode(uint8_t *packet, size_t len, struct pkt_metadata *q, int dns_fd);
static void send_dns(int fd, struct dns_packet *q);
static struct dns_packet *write_dns(struct dns_packet *q, int userid, uint8_t *data, size_t datalen, uint8_t flags);
static void handle_full_packet(int userid, uint8_t *data, size_t len, int);
static struct dns_packet *handle_null_request(struct dns_packet *q, uint8_t *encdata, size_t encdatalen);
static void handle_a_request(int dns_fd, struct dns_packet *q, int fakeip);
static void handle_ns_request(int dns_fd, struct dns_packet *q);
static struct dns_packet *send_data_or_ping(int userid, struct dns_packet *q, int immediate);

static int
get_dns_fd(struct dnsfd *fds, struct sockaddr_storage *addr)
{
	if (addr->ss_family == AF_INET6) {
		return fds->v6fd;
	}
	return fds->v4fd;
}

static void
forward_query(int bind_fd, struct dns_packet *q, uint8_t *pkt, size_t pktlen)
{
	struct fw_query fwq;
	struct sockaddr_in *myaddr;

	/* Store sockaddr for q->id */
	memcpy(&(fwq.addr), &(q->m.from), q->m.fromlen);
	fwq.addrlen = q->m.fromlen;
	fwq.id = q->id;
	fw_query_put(&fwq);

	in_addr_t newaddr = inet_addr("127.0.0.1");
	myaddr = (struct sockaddr_in *) &(q->m.from);
	memcpy(&(myaddr->sin_addr), &newaddr, sizeof(in_addr_t));
	myaddr->sin_port = htons(server.bind_port);

	DEBUG(2, "TX: forward query");

	if (sendto(bind_fd, pkt, pktlen, 0, (struct sockaddr *) &q->m.from, q->m.fromlen) <= 0) {
		warn("forward query error");
	}
}

static struct dns_packet *
send_version_response(version_ack_t ack, uint32_t payload, int userid, struct dns_packet *q)
{
	uint8_t out[28], *p = out;
	if (ack == VERSION_ACK) {
		putdata(&p, (uint8_t *) "VACK", 4);
		putlong(&p, payload);
		putdata(&p, users[userid].server_chall, 16);
		putlong(&p, CMC(users[userid].cmc_down));
	} else if (ack == VERSION_FULL) {
		putdata(&p, (uint8_t *) "VFUL", 4);
		putlong(&p, payload);
	} else { /* (ack == VERSION_NACK): backwards compatible */
		putdata(&p, (uint8_t *) "VNAK", 4);
		putlong(&p, payload);
		putbyte(&p, 0);
	}

	return write_dns(q, -1, out, (p - out), WD_OLD);
}

static struct dns_packet *
send_ping(int userid, struct dns_packet *q, int immediate)
/* Sends a ping reply.
   immediate: 1=not from qmem (ie. fresh query), 0=query is from qmem */
{
	struct tun_user *u = &users[userid];
	struct dns_packet *ans;

	uint8_t pkt[DOWNSTREAM_PING_HDR], *p = pkt;

	/* Build downstream ping header (see doc/proto_xxxxxxxx.txt) for details */
	/* flags: PI000000 */
	*p++ = (1 << 7) | ((immediate & 1) << 6);

	putlong(&p, u->cmc_up);
	*p++ = u->incoming->length & 0xFF;
	*p++ = u->outgoing->length & 0xFF;
	*p++ = u->incoming->window_start_seq & 0xFF;
	*p++ = u->outgoing->window_start_seq & 0xFF;

	/* generate answer for query */
	ans = write_dns(q, userid, pkt, sizeof(pkt), u->downenc);
	if (u->tuntype != USER_CONN_NONE) {
		qmem_answered(u->qmem, ans);
	}
	return ans;
}

static struct dns_packet *
send_data_or_ping(int userid, struct dns_packet *q, int immediate)
/* Sends current fragment to user, or a ping if no data available.
   ping: 1=force send ping (even if data available), 0=only send if no data.
   immediate: 1=not from qmem (ie. fresh query), 0=query is from qmem */
{
	fragment *f;
	struct tun_user *u = &users[userid];

	/* check if we have data, if not, send a ping instead */
	if (window_to_send(u->outgoing, &f) == 0) {
		DEBUG(3, "user=%d no fragment to send -- replying with ping", userid);
		return send_ping(userid, q, immediate);
	}

	uint8_t pkt[DOWNSTREAM_DATA_HDR + f->len];
	uint8_t *p = pkt;

	/* build downstream data packet (see doc/proto_xxxxxxxx.txt) for details) */
	/* Set data header flags: PI000KFS */
	*p++ = ((immediate & 1) << 6) | ((f->compressed & 1) << 2) | (f->start << 1) | f->end;
	*p++ = f->seqID & 0xFF;
	putdata(&p, f->data, f->len);

	/* send an answer for the query and save it to the cache */
	struct dns_packet *ans = write_dns(q, userid, pkt, sizeof(pkt), u->downenc | DH_HMAC32);
	qmem_answered(u->qmem, ans);
	window_mark_sent(u->outgoing, f); /* we are done with the fragment now */

	return ans;
}

static void
user_process_incoming_data(int userid)
{
	uint8_t pkt[65536];
	int can_reassemble_more = 1;

	while (can_reassemble_more) {
		size_t datalen = sizeof(pkt);
		uint8_t compressed = 0;
		can_reassemble_more = window_reassemble_data(users[userid].incoming, pkt, &datalen, &compressed);
		DEBUG(4, "Incoming data for user=%d, can_reassemble=%d, datalen=%zu, compressed=%hhu, last_pkt=%ld",
				userid, can_reassemble_more, datalen, compressed, users[userid].last_pkt);

		/* Update time info */
		users[userid].last_pkt = time(NULL);

		if (datalen > 0) {
			/* Data reassembled successfully + cleared out of buffer */
			handle_full_packet(userid, pkt, datalen, compressed);
		}
	}
}

static int
user_send_data(int userid, uint8_t *indata, size_t len, int compressed)
/* Appends data to a user's outgoing queue and sends it (in raw mode only) */
{
	size_t datalen;
	int ret = 0;
	uint8_t out[65536], *data;
	struct tun_user *u = &users[userid];

	data = indata;
	datalen = len;

	/* use compressed or uncompressed packet to match user settings */
	if (u->down_compression && !compressed) {
		datalen = sizeof(out);
		compress2(out, &datalen, indata, len, 9);
		data = out;
	} else if (!u->down_compression && compressed) {
		datalen = sizeof(out);
		ret = uncompress(out, &datalen, indata, len);
		if (ret != Z_OK) {
			DEBUG(1, "FAIL: Uncompress == %d: %zu bytes to user %d!", ret, len, userid);
			return 0;
		}
	}

	compressed = u->down_compression;

	if (u->conn == CONN_DNS_NULL && data && datalen) {
		/* append new data to user's outgoing queue; sent later in qmem_max_wait */
		ret = window_add_outgoing_data(u->outgoing, data, datalen, compressed);

	} else if (data && datalen) { /* CONN_RAW_UDP */
		if (!compressed)
			DEBUG(1, "Sending in RAW mode uncompressed to user %d!", userid);
		int dns_fd = get_dns_fd(&server.dns_fds, &u->host);
		send_raw(dns_fd, data, datalen, userid, RAW_HDR_CMD_DATA,
				CMC(u->cmc_down), u->hmac_key, &u->host, u->hostlen);
		ret = 1;
	}

	return ret;
}

static void
check_pending_queries(struct timeval *maxwait)
/* checks all pending queries from all users and answers those which have timed out */
{
	for (int userid = 0; userid < created_users; userid++) {
		struct tun_user *u = &users[userid];
		if (!user_active(userid) || u->conn != CONN_RAW_UDP || u->tuntype == USER_CONN_NONE)
			continue;

		/* Check if there are any queries in the cache which have timed out. */
		/* If not, check if the user has any pending fragments and send them
		 * as replies to queries from the cache. */
		size_t num_send = window_to_send(u->outgoing, NULL);
		DEBUG(5, "user %d has %zu pending queries, %zu pending frags", userid, num_send, u->qmem->num_pending);

		while (u->qmem->num_pending != 0 || num_send != 0) {
			struct dns_packet *tosend;
			int run_again = qmem_max_wait(u->qmem, &tosend, maxwait);

			if (!run_again && num_send == 0) {
				DEBUG(7, "no more queries timed out, no more frags to send");
				if (tosend) {
					dns_packet_destroy(tosend);
				}
				break;
			} else if (!tosend) {
				DEBUG(3, "should have more queries for user %d (want to send %zu frags, num_pending=%zu)",
						userid, num_send, u->qmem->num_pending);
				break;
			}

			/* construct and send a DNS reply with the next data frag if one exists */
			struct dns_packet *ans = send_data_or_ping(userid, tosend, 0);
			send_dns(get_dns_fd(&server.dns_fds, &tosend->m.from), ans);

			DEBUG(8, "ans->refcount=%zu, tosend->refcount=%zu, maxwait=%ldms",
					ans->refcount, tosend->refcount, timeval_to_ms(maxwait));

			dns_packet_destroy(ans);
			dns_packet_destroy(tosend);
		};
	}
}

static int
tunnel_bind()
{
	uint8_t packet[64*1024];
	struct sockaddr_storage from;
	socklen_t fromlen;
	struct fw_query *query;
	unsigned short id;
	int dns_fd;
	int r;

	fromlen = sizeof(struct sockaddr);
	r = recvfrom(server.bind_fd, packet, sizeof(packet), 0,
		(struct sockaddr*)&from, &fromlen);

	if (r <= 0)
		return 0;

	id = dns_get_id(packet, r);

	DEBUG(3, "RX: Got response on query %u from DNS", (id & 0xFFFF));

	/* Get sockaddr from id */
	fw_query_get(id, &query);
	if (!query) {
		DEBUG(2, "Lost sender of id %u, dropping reply", (id & 0xFFFF));
		return 0;
	}

	DEBUG(3, "TX: client %s id %u, %d bytes",
			format_addr(&query->addr, query->addrlen), (id & 0xffff), r);

	dns_fd = get_dns_fd(&server.dns_fds, &query->addr);
	if (sendto(dns_fd, packet, r, 0, (const struct sockaddr *) &(query->addr),
		query->addrlen) <= 0) {
		warn("forward reply error");
	}

	return 0;
}

static ssize_t
tunnel_udp(int userid)
{
	ssize_t len;
	uint8_t buf[64*1024];
	char *errormsg = NULL;

	if (users[userid].tuntype != USER_CONN_UDPFORWARD) {
		DEBUG(1, "BUG! tunnel_udp: user %d UDP socket not active!", userid);
		return 0;
	}

	len = read(users[userid].remote_udp_fd, buf, sizeof(buf));

	DEBUG(5, "IN UDP: %ld bytes to user %d", len, userid);
	if (len < 0) {
		errormsg = strerror(errno);
		DEBUG(1, "Error %d on UDP forward for user %d: %s", errno, userid, errormsg);
		return -1;
	}

	user_send_data(userid, buf, (size_t) len, 0);
	return len;
}

static int
tunnel_tun()
{
	struct ip *header;
	static uint8_t in[64*1024];
	int userid;
	int read;

	if ((read = read_tun(server.tun_fd, in, sizeof(in))) <= 0)
		return 0;

	/* find target ip in packet, in is padded with 4 bytes TUN header */
	header = (struct ip*) (in + 4);
	userid = find_user_by_ip(header->ip_dst.s_addr);
	if (userid < 0) {
		DEBUG(2, "IN: rejecting %d byte pkt from tun", read);
		return 0;
	}

	DEBUG(3, "IN: %d byte pkt from tun to user %d; compression %d",
				read, userid, users[userid].down_compression);

	return user_send_data(userid, in, read, 0);
}

static void
tunnel_dns(int dns_fd)
{
	struct dns_packet *q, *ans = NULL;
	struct pkt_metadata m;
	uint8_t pkt[64*1024], encdata[64*1024];
	size_t encdatalen = sizeof(encdata), pktlen = sizeof(pkt);

	if (read_packet(dns_fd, pkt, &pktlen, &m) <= 0)
		return;

	if (raw_decode(pkt, pktlen, &m, dns_fd))
		return;

	if ((q = dns_decode(pkt, pktlen)) == NULL)
		return;

	DEBUG(3, "RX: client %s ID %5d, pktlen %zu, type %d, name '%s'", format_addr(&m.from, m.fromlen),
			q->id, pktlen, q->q[0].type, format_host(q->q[0].name, q->q[0].namelen, 0));

	memcpy(&q->m, &m, sizeof(m));
	if (dns_decode_data_query(q, server.topdomain, encdata, &encdatalen)) {
		/* inside our topdomain: is a query we can handle */

		/* Handle A-type query for ns.topdomain, possibly caused
		   by our proper response to any NS request */
		if (encdatalen == 2 && q->q[0].type == T_A && memcmp(encdata, "ns", 2) == 0) {
			handle_a_request(dns_fd, q, 0);
			dns_packet_destroy(q);
			return;
		}

		/* Handle A-type query for www.topdomain, for anyone that's
		   poking around */
		if (encdatalen == 3 && q->q[0].type == T_A && memcmp(encdata, "www", 3) == 0) {
			handle_a_request(dns_fd, q, 1);
			dns_packet_destroy(q);
			return;
		}

		switch (q->q[0].type) {
		case T_NULL:
		case T_PRIVATE:
		case T_CNAME:
		case T_A:
		case T_MX:
		case T_SRV:
		case T_TXT:
		case T_PTR:
		case T_AAAA:
		case T_A6:
		case T_DNAME:
			/* encoding is "transparent" here */
			ans = handle_null_request(q, encdata, encdatalen);
			break;
		case T_NS:
			handle_ns_request(dns_fd, q);
			break;
		default:
			break;
		}
	} else {
		/* Forward query to DNS server listening on different port on localhost */
		DEBUG(2, "Requested domain outside our topdomain.");
		if (server.bind_fd) {
			forward_query(server.bind_fd, q, pkt, pktlen);
		}
	}
	if (ans) {
		DEBUG(7, "tunnel_dns got answer ")
		send_dns(dns_fd, ans);
		dns_packet_destroy(ans);
	}
	dns_packet_destroy(q);
}

int
server_tunnel()
{
	struct timeval wait_time;
	fd_set read_fds, write_fds;

	while (server.running) {
		int maxfd;
		wait_time.tv_sec = 10;
		wait_time.tv_usec = 0;

		/* get max wait time based on pending queries */
		check_pending_queries(&wait_time);
		DEBUG(5, "server_tunnel: waiting %" L "d ms", timeval_to_ms(&wait_time));

		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		maxfd = 0;

		if (server.dns_fds.v4fd >= 0) {
			FD_SET(server.dns_fds.v4fd, &read_fds);
			maxfd = MAX(server.dns_fds.v4fd, maxfd);
		}
		if (server.dns_fds.v6fd >= 0) {
			FD_SET(server.dns_fds.v6fd, &read_fds);
			maxfd = MAX(server.dns_fds.v6fd, maxfd);
		}

		if (server.bind_fd) {
			/* wait for replies from real DNS */
			FD_SET(server.bind_fd, &read_fds);
			maxfd = MAX(server.bind_fd, maxfd);
		}

		/* Don't read from tun if all users have filled outpacket queues */
		if(!all_users_waiting_to_send()) {
			FD_SET(server.tun_fd, &read_fds);
			maxfd = MAX(server.tun_fd, maxfd);
		}

		/* add connected user TCP forward FDs to read set */
		maxfd = MAX(set_user_udp_fds(&read_fds), maxfd);

		int i = select(maxfd + 1, &read_fds, &write_fds, NULL, &wait_time);

		if(i < 0) { /* select error */
			if (server.running)
				warn("select < 0");
			return 1;
		}

		if (i == 0) { /* select timeout */
			if (server.max_idle_time) {
				/* check if idle time expired */
				time_t last_action = 0;
				for (int userid = 0; userid < created_users; userid++) {
					last_action = (users[userid].last_pkt > last_action) ? users[userid].last_pkt : last_action;
				}
				double idle_time = difftime(time(NULL), last_action);
				if (idle_time > server.max_idle_time && last_action > 0) {
					fprintf(stderr, "Server idle for %f.0 seconds, shutting down...\n", idle_time);
					server.running = 0;
				}
			}
		} else {
			if (FD_ISSET(server.tun_fd, &read_fds)) {
				tunnel_tun();
			}

			for (int userid = 0; userid < created_users; userid++) {
				if (user_active(userid) && FD_ISSET(users[userid].remote_udp_fd, &read_fds)) {
					tunnel_udp(userid);
				}
			}

			if (FD_ISSET(server.dns_fds.v4fd, &read_fds)) {
				tunnel_dns(server.dns_fds.v4fd);
			}
			if (FD_ISSET(server.dns_fds.v6fd, &read_fds)) {
				tunnel_dns(server.dns_fds.v6fd);
			}

			if (FD_ISSET(server.bind_fd, &read_fds)) {
				tunnel_bind();
			}
		}
	}

	return 0;
}

static void
handle_full_packet(int userid, uint8_t *data, size_t len, int compressed)
{
	size_t rawlen;
	uint8_t out[64*1024], *rawdata;
	struct ip *hdr;
	int touser = -1;
	int ret;

	/* Check if data needs to be uncompressed */
	if (compressed) {
		rawlen = sizeof(out);
		ret = uncompress(out, &rawlen, data, len);
		rawdata = out;
	} else {
		rawlen = len;
		rawdata = data;
		ret = Z_OK;
	}

	if (ret == Z_OK) {
		if (users[userid].remoteforward_addr_len == 0) {
			hdr = (struct ip*) (out + 4);
			touser = find_user_by_ip(hdr->ip_dst.s_addr);
			DEBUG(2, "OUT on tun: %zu bytes from user %d (touser %d)", len, userid, touser);
			if (touser == -1) {
				/* send the uncompressed packet to tun device */
				write_tun(server.tun_fd, rawdata, rawlen);
			} else {
				/* don't re-compress if possible */
				if (users[touser].down_compression && compressed) {
					user_send_data(touser, data, len, 1);
				} else {
					user_send_data(touser, rawdata, rawlen, 0);
				}
			}
		} else {
			/* Write full pkt to user's remote forward TCP stream */
			if ((ret = write(users[userid].remote_udp_fd, rawdata, rawlen)) != rawlen) {
				DEBUG(2, "Write error %d on TCP socket for user %d: %s", errno, userid, strerror(errno));
			}
		}

	} else {
		DEBUG(2, "Discarded pkt from user %d, uncompress()==%d, len=%zu, rawlen=%zu",
				userid, ret, len, rawlen);
	}
}

static void
handle_raw_login(uint8_t *packet, size_t len, struct pkt_metadata *m, int fd, int userid)
{
	struct tun_user *u = &users[userid];
	if (len < 16) {
		DEBUG(2, "Invalid raw login packet: length %zu < 16 bytes!", len);
		return;
	}

	DEBUG(1, "RX-raw: login, len %zu, from user %d", len, userid);

	/* User is authenticated using HMAC (already verified) */
	/* Update time info for user */
	u->last_pkt = time(NULL);

	/* Store remote IP number */
	memcpy(&(u->host), &(m->from), m->fromlen);
	u->hostlen = m->fromlen;

	u->conn = CONN_RAW_UDP;

	uint8_t data[16];
	get_rand_bytes(data, sizeof(data));
	send_raw(fd, data, sizeof(data), userid, RAW_HDR_CMD_LOGIN,
			CMC(u->cmc_down), u->hmac_key, &m->from, m->fromlen);

	u->authenticated_raw = 1;
}

static void
handle_raw_data(uint8_t *packet, size_t len, int userid)
{
	/* Update time info for user */
	users[userid].last_pkt = time(NULL);

	/* copy to packet buffer, update length */

	DEBUG(3, "RX-raw: full pkt raw, length %zu, from user %d", len, userid);

	handle_full_packet(userid, packet, len, 1);
}

static void
handle_raw_ping(struct pkt_metadata *m, int dns_fd, int userid)
{
	struct tun_user *u = &users[userid];
	/* Update time info for user */
	u->last_pkt = time(NULL);

	DEBUG(3, "RX-raw: ping from user %d", userid);

	/* Send ping reply */
	send_raw(dns_fd, NULL, 0, userid, RAW_HDR_CMD_PING,
			CMC(u->cmc_down), u->hmac_key, &m->from, m->fromlen);
}

static int
raw_decode(uint8_t *packet, size_t len, struct pkt_metadata *m, int dns_fd)
{
	uint8_t userid;
	uint8_t raw_cmd;
	uint8_t hmac_pkt[16], hmac[16];
	uint32_t cmc;

	/* minimum length */
	if (len < RAW_HDR_LEN) return 0;
	/* should start with header */
	if (memcmp(packet, raw_header, RAW_HDR_IDENT_LEN))
		return 0;

	raw_cmd = RAW_HDR_GET_CMD(packet);
	userid = RAW_HDR_GET_USR(packet);
	cmc = ntohl(*(uint32_t *) (packet + RAW_HDR_CMC));
	// TODO check CMC
	memset(hmac_pkt, 0, sizeof(hmac_pkt));
	memcpy(hmac_pkt, packet + RAW_HDR_HMAC, RAW_HDR_HMAC_LEN);

	DEBUG(3, "RX-raw: client %s, user %d, raw command 0x%02X, length %zu",
			  format_addr(&m->from, m->fromlen), userid, raw_cmd, len);

	if (!is_valid_user(userid)) {
		DEBUG(2, "Drop raw pkt from invalid user %d", userid);
		return 0;
	}

	struct tun_user *u = &users[userid];

	packet += RAW_HDR_LEN;
	len -= RAW_HDR_LEN;

	/* Verify HMAC */
	memset(packet + RAW_HDR_HMAC, 0, RAW_HDR_HMAC_LEN);
	hmac_md5(hmac, u->hmac_key, sizeof(u->hmac_key), packet, len);
	if (memcmp(hmac, hmac_pkt, RAW_HDR_HMAC_LEN) != 0) {
		DEBUG(3, "RX-raw: bad HMAC pkt=0x%s, actual=0x%s",
				tohexstr(hmac_pkt, RAW_HDR_HMAC_LEN, 0),
				tohexstr(hmac, RAW_HDR_HMAC_LEN, 1));
	}

	if (raw_cmd == RAW_HDR_CMD_LOGIN) {
		/* Raw login packet */
		handle_raw_login(packet, len, m, dns_fd, userid);
		return 1;
	}

	if (!users[userid].authenticated_raw) {
		DEBUG(2, "Warning: Valid HMAC on RAW UDP packet from unauthenticated user!");
		return 0;
	}

	if (raw_cmd == RAW_HDR_CMD_DATA) {
		/* Data packet */
		handle_raw_data(packet, len, userid);
	} else if (raw_cmd == RAW_HDR_CMD_PING) {
		/* Keepalive packet */
		handle_raw_ping(m, dns_fd, userid);
	} else {
		DEBUG(1, "Unhandled raw command %02X from user %d", raw_cmd, userid);
		return 0;
	}
	return 1;
}

static void
send_dns(int fd, struct dns_packet *q)
{
	uint8_t buf[64*1024];
	size_t len = sizeof(buf);
	if (!dns_encode(buf, &len, q, 0)) {
		DEBUG(1, "dns_encode failed");
		return;
	}

	DEBUG(3, "TX: client %s ID %5d, dnslen %zu, type %hu, name '%10s'",
			format_addr(&q->m.dest, q->m.destlen), q->id, len, q->q[0].type,
			format_host(q->q[0].name, q->q[0].namelen, 0));

	sendto(fd, buf, len, 0, (struct sockaddr *) &q->m.dest, q->m.destlen);
}

static struct dns_packet *
write_dns(struct dns_packet *q, int userid, uint8_t *data, size_t datalen, uint8_t flags)
/* takes query q and returns valid DNS answer after sending (NULL on error)
 * answer packet must be freed after use */
{
	uint8_t buf[64*1024], tmpbuf[64*1024];
	size_t len = 0;
	if (data == NULL) {
		datalen = 0;
		data = buf;
	}
	if ((flags & WD_AUTO) && userid >= 0) {
		flags = users[userid].downenc;
	}

	uint16_t qtype = q->q[0].type;
	if (flags & WD_OLD) {
		uint8_t codec = C_BASE32, *datap;
		len = 1;
		if (qtype == T_TXT) {
			datap = tmpbuf + 1;
			tmpbuf[0] = 't'; /* base32 for TXT only */
		} else if (qtype == T_SRV || qtype == T_MX ||
			qtype == T_CNAME || qtype == T_A ||	qtype == T_PTR ||
			qtype == T_AAAA || qtype == T_A6 || qtype == T_DNAME) {
			datap = tmpbuf + 1;
			tmpbuf[0] = 'h'; /* base32 */
		} else { /* if (qtype == T_NULL || qtype == T_PRIVATE) */
			codec = C_RAW; /* no encoding char */
			datap = tmpbuf;
			len = 0;
		}
		len += encode_data(datap, sizeof(tmpbuf) - 1, data, datalen, codec);
	} else {
		len = sizeof(tmpbuf);
		if (userid < 0) { /* invalid userid: preauthenticated response */
			downstream_encode(tmpbuf, &len, data, datalen, NULL, flags | DH_HMAC32, rand());
		} else if ((flags & WD_CODECTEST) && datalen >= 4) {
			downstream_encode(tmpbuf, &len, data, 4, users[userid].hmac_key,
					flags & 0x1f, CMC(users[userid].cmc_down));
			memcpy(tmpbuf + len, data + 4, datalen - 4);
			len += datalen - 4;
		} else {
			downstream_encode(tmpbuf, &len, data, datalen, users[userid].hmac_key,
							flags, CMC(users[userid].cmc_down));
		}
	}

	struct dns_packet *ans = dns_encode_data_answer(q, tmpbuf, len);
	if (!ans)
		DEBUG(1, "dns_encode doesn't fit, downstream_encode len=%zu", len);
	return ans;
}

#define CHECK_LEN_U(l, x, u) \
	if (l != x) { \
		DEBUG(3, "BADLEN: expected %u, got %zu", x, l); \
		return write_dns(q, u, NULL, 0, DH_ERR(BADLEN)); \
	}

#define CHECK_LEN(l, x)		CHECK_LEN_U(l, x, userid)

static struct dns_packet *
handle_dns_version(struct dns_packet *q, uint8_t *encdata, size_t encdatalen)
{
	uint8_t unpacked[512];
	uint32_t version = !PROTOCOL_VERSION, cmc;
	int userid, read;

	read = unpack_data(unpacked, sizeof(unpacked), encdata + 1, encdatalen - 1, C_BASE32);
	/* Version greeting, compare and send ack/nak */
	if (read >= 8) {
		/* Received V + 32bits version + 32bits CMC */
		version = ntohl(*(uint32_t *) unpacked);
		cmc = ntohl(*(uint32_t *) (unpacked + 4));
	} /* if invalid pkt, just send VNAK */

	if (version != PROTOCOL_VERSION) {
		DEBUG(1, "client from %s sent bad version %08X, dropping.",
				format_addr(&q->m.from, q->m.fromlen), version);
		syslog(LOG_INFO, "dropped user from %s, sent bad version %08X",
			   format_addr(&q->m.from, q->m.fromlen), version);
		return send_version_response(VERSION_NACK, PROTOCOL_VERSION, 0, q);
	}

	userid = find_available_user();
	if (userid < 0) {
		/* No space for another user */
		DEBUG(1, "dropping client from %s, server full.",
				format_addr(&q->m.from, q->m.fromlen));
		syslog(LOG_INFO, "dropped user from %s, server full",
		format_addr(&q->m.from, q->m.fromlen));
		return send_version_response(VERSION_FULL, created_users, 0, q);
	}

	struct tun_user *u = &users[userid];
	/* Store remote IP number */
	memcpy(&(u->host), &(q->m.from), q->m.fromlen);
	u->hostlen = q->m.fromlen;
	u->cmc_up = cmc;

	syslog(LOG_INFO, "Accepted version for user #%d from %s",
		userid, format_addr(&q->m.from, q->m.fromlen));

	DEBUG(1, "User %d connected with correct version from %s.",
				userid, format_addr(&q->m.from, q->m.fromlen));
	DEBUG(3, "User %d: sc=0x%s", userid, tohexstr(u->server_chall, 16, 0));

	return send_version_response(VERSION_ACK, userid, userid, q);
}

static struct dns_packet *
handle_dns_codectest(struct dns_packet *q, int userid, uint8_t *header, uint8_t *encdata, size_t encdatalen)
/* header is 20 bytes (raw) base32 decoded from encdata+2 to encdata+34 */
{
	uint8_t reply[4096], qflags, ulq, flags, ulr = 0, *p;
	uint16_t dlq, dlr;
	size_t replylen;
	/* header is CMC+HMAC+flags+ulq+dlq */
	p = header + 16;
	qflags = *p++;
	ulq = *p++;
	readshort(header, &p, &dlq);

	if (dlq > sizeof(reply) - 4) {
		return write_dns(q, userid, NULL, 0, DH_ERR(BADOPTS));
	}

	flags = qflags & 1;
	/* check if q has EDNS0 OPT additional record present: see RFC 6891 */
	for (uint8_t i = 0; i < q->arcount; i++) {
		if (q->ar[i].type == 41) {
			flags &= (1 << 1);
		}
	}

	if (qflags & 1) { /* downstream codec test */
		/* build downstream test data */
		uint8_t dataqdec[512];
		size_t declen = sizeof(dataqdec);
		declen = b32->decode(dataqdec, &declen, encdata + 34, encdatalen - 34);
		for (uint16_t i = 0; i < dlq; i++) {
			reply[4 + i] = dataqdec[i % declen];
		}
		replylen = (dlr = dlq);
	} else { /* upstream codec test */
		/* encode dns-decoded query hostname as base32 */
		replylen = sizeof(reply) - 4;
		if (encdatalen > 255)
			DEBUG(1, "upstream codec test query data >255!");
		ulr = encdatalen;
		replylen = (dlr = b32->encode(reply + 4, &replylen, encdata + 34, encdatalen - 34));
	}
	p = reply; /* make 4 bytes appended to CMC+HMAC */
	putbyte(&p, flags);
	putbyte(&p, ulr);
	putshort(&p, dlr);
	replylen += 4;

	DEBUG(4, "codectest: qflags=%hhx, rflags=%hhx, ulq=%hhu, dlq=%hu, ulr=%hhu, dlr=%hu",
			qflags, flags, ulq, dlq, ulr, dlr);

	return write_dns(q, userid, reply, replylen, WD_CODECTEST | C_BASE32);
}

static struct dns_packet *
handle_dns_ip_request(struct dns_packet *q, int userid)
{
	uint8_t reply[17];
	int length;
	reply[0] = 'I';
	if (q->m.from.ss_family == AF_INET) {
		if (server.ns_ip != INADDR_ANY) {
			/* If set, use assigned external ip (-n option) */
			memcpy(reply + 1, &server.ns_ip, sizeof(server.ns_ip));
		} else {
			/* otherwise return destination ip from packet */
			struct sockaddr_in *addr = (struct sockaddr_in *) &q->m.dest;
			memcpy(reply + 1, &addr->sin_addr, sizeof(struct in_addr));
		}
		length = 1 + sizeof(struct in_addr);
	} else {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &q->m.dest;
		memcpy(reply + 1, &addr->sin6_addr, sizeof(struct in6_addr));
		length = 1 + sizeof(struct in6_addr);
	}

	return write_dns(q, userid, reply, length, WD_AUTO);
}

static struct dns_packet *
handle_dns_set_options(struct dns_packet *q, int userid, uint8_t *data, size_t len)
{
	uint16_t dnfragsize;
	uint8_t flags[2], *p = data, out[40], *o = out, nup, ndn;
	enum user_conn_type newtuntype = USER_CONN_NONE;
	int good = 0;
	struct tun_user *u = &users[userid];

	if (len < 4 || len > 22) {
		return write_dns(q, userid, NULL, 0, DH_ERR(BADOPTS));
	}

	readdata(&p, flags, 2);
	readshort(data, &p, &dnfragsize);

	/* set user options */
	ndn = flags[0] & 7;
	nup = (flags[0] >> 3) & 7;
	if (!get_encoder(ndn) || !get_encoder(nup)) {
		DEBUG(1, "user %d requested invalid up/down codecs, up=%hhu, dn=%hhu!", userid, nup, ndn);
		return write_dns(q, userid, NULL, 0, DH_ERR(BADOPTS));
	} else {
		u->downenc = ndn;
		u->upenc = nup;
	}
	u->down_compression = (flags[0] >> 6) & 1;
	u->lazy = (flags[0] >> 7) & 1;

	u->hmaclen_down = (flags[1] >> 4) ? 4 : 12;
	u->hmaclen_up = (flags[1] >> 5) ? 4 : 12;

	DEBUG(1, "OPTS user %d: lazy %hhd, comp_down %hhd, enc_up %s, enc_dn %s, fragsize %hu",
		  userid, u->lazy, u->down_compression, get_encoder(u->upenc)->name,
		  get_encoder(u->downenc)->name, dnfragsize);

	/* start constructing "good opts" reply */
	putdata(&o, flags, 2);
	putshort(&o, dnfragsize);

	if ((flags[1] & 0x01) && len == 4) { /* client requests TUN IP */
		struct in_addr tunip;
		tunip.s_addr = u->tun_ip; /* user is already allocated IP based on userid */
		DEBUG(1, "user %d requested TUN IP, giving %s", userid, inet_ntoa(tunip));
		/* send TUN config details to client */
		putdata(&o, (uint8_t *) &server.my_ip, 4);
		putdata(&o, (uint8_t *) &u->tun_ip, 4);
		putshort(&o, server.mtu);
		putbyte(&o, server.netmask);
		good = 1;
		newtuntype = USER_CONN_TUNIP;
	} else if ((flags[1] & 0x08) && len >= 6) {
		struct sockaddr_in *addr = (struct sockaddr_in *) &u->remoteforward_addr;
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &u->remoteforward_addr;
		uint16_t port;
		readshort(data, &p, &port);
		newtuntype = USER_CONN_UDPFORWARD;
		if ((flags[1] & 0x04) && server.allow_forward_remote) {
			if ((flags[1] & 0x02) && len == 22) { /* IPv6 */
				addr6->sin6_family = AF_INET6;
				addr6->sin6_port = port;
				u->remoteforward_addr_len = sizeof(*addr6);
				readdata(&p, (uint8_t *) &addr6->sin6_addr, 16);
				good = 1;
			} else if (!(flags[1] & 0x02) && len == 10) { /* IPv4 */
				addr->sin_family = AF_INET;
				addr->sin_port = port;
				u->remoteforward_addr_len = sizeof(*addr);
				readdata(&p, (uint8_t *) &addr->sin_addr, 4);
				good = 1;
			}
			DEBUG(1, "User %d requested forward to udp://%s:%hu.", userid,
				  format_addr(&u->remoteforward_addr, u->remoteforward_addr_len),
				  port);
		} else if (!(flags[1] & 0x04) && server.allow_forward_local_port && len == 6) {
			/* forward UDP to local address with specified port */
			addr->sin_family = AF_INET;
			addr->sin_port = port;
			addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			DEBUG(1, "User %d requested forward to udp://localhost:%hu.", userid, port);
			good = 1;
		}
	} else if ((flags[1] == 0) && len == 4) {
		/* client requests no connection, clean up connection-related stuff */
		qmem_destroy(u->qmem);
		window_buffer_destroy(u->incoming);
		window_buffer_destroy(u->outgoing);
		if (u->tuntype == USER_CONN_UDPFORWARD) {
			user_close_udp(userid);
		}
		u->tuntype = USER_CONN_NONE;
		DEBUG(1, "user %d closing connection!", userid);
		return write_dns(q, userid, out, o - out, WD_AUTO);
	}

	if (good) {
		if (u->tuntype == USER_CONN_NONE) {
			/* we can now initialise qmem and send/recv buffers */
			u->qmem = qmem_init(QMEM_LEN);
			u->incoming = window_buffer_init(WINDOW_BUFFER_LENGTH, MAX_FRAGSIZE_UP, WINDOW_RECVING);
			u->outgoing = window_buffer_init(WINDOW_BUFFER_LENGTH, u->fragsize, WINDOW_SENDING);
		} else if (u->fragsize != dnfragsize) {
			/* resize only, if necessary */
			u->fragsize = dnfragsize;
			window_buffer_resize(u->outgoing, u->outgoing->length, dnfragsize);
		}

		if (newtuntype == USER_CONN_UDPFORWARD) {
			/* open UDP connection as requested, close any existing connection first */
			if (u->tuntype == USER_CONN_UDPFORWARD) {
				user_close_udp(userid);
			}
			if (!user_open_udp(userid)) {
				return write_dns(q, userid, NULL, 0, DH_ERR(BADOPTS));
			}
		}
		u->tuntype = newtuntype;
		return write_dns(q, userid, out, o - out, WD_AUTO);
	} else {
		DEBUG(2, "bad connection options from user %d, len=%zu", userid, len);
		return write_dns(q, userid, NULL, 0, DH_ERR(BADOPTS));
	}

	return write_dns(q, userid, data, len, WD_AUTO);
}

static struct dns_packet *
handle_dns_ping(struct dns_packet *q, int userid, uint8_t *unpacked, size_t read)
{
	int dn_seq, up_seq, dn_winsize, up_winsize;
	int respond, set_qtimeout, set_wtimeout;
	uint16_t qtimeout_ms, wtimeout_ms;
	uint32_t client_cmc_down;
	struct tun_user *u = &users[userid];
	struct dns_packet *cached;

	CHECK_LEN(read, 13);

	/* Unpack flags/options from ping header */
	uint8_t *p = unpacked;
	readlong(unpacked, &p, &client_cmc_down);
	up_winsize = *p++; /* following are ignored if user has not requested connection */
	dn_winsize = *p++;
	up_seq = *p++;
	dn_seq = *p++;

	/* Check if query is cached, and if the cached query contains an answer */
	if (u->qmem && qmem_is_cached(u->qmem, q, &cached)) {
		if (q->ancount) {
			return cached; /* answer from cache if cached query has answer section */
		} else {
			/* server has received the query but no cached answer exists */
			dns_packet_destroy(cached);
			return NULL;
		}
	}

	/* Query timeout and window frag timeout */
	readshort(unpacked, &p, &qtimeout_ms);
	readshort(unpacked, &p, &wtimeout_ms); /* XXX: deprecated */

	uint8_t flags = *p++;

	respond = flags & 1;
	set_qtimeout = (flags >> 1) & 1;
	set_wtimeout = (flags >> 2) & 1; /* XXX: deprecated */

	DEBUG(3, "PING pkt user %d, client CMC %u, down %d/%d, up %d/%d, %sqtime %u ms, "
		  "%swtime %u ms, respond %d (flags %02X)",
				userid, client_cmc_down, dn_seq, dn_winsize, up_seq, up_winsize,
				set_qtimeout ? "SET " : "", qtimeout_ms, set_wtimeout ? "SET " : "",
				wtimeout_ms, respond, flags);

	if (set_qtimeout && u->qmem) {
		/* update user's query timeout if timeout flag set */
		u->qmem->timeout = ms_to_timeval(qtimeout_ms);

		/* if timeout is 0, we do not enable lazy mode but it is effectively the same */
		int newlazy = !(qtimeout_ms == 0);
		if (newlazy != u->lazy)
			DEBUG(2, "User %d: not changing lazymode to %d with timeout %u",
				  userid, newlazy, qtimeout_ms);
	}

	if (u->qmem) {
		qmem_append(u->qmem, q);
	}

	if (respond || u->tuntype == USER_CONN_NONE) {
		/* if user has not requested a connection yet, we must respond immediately. */
		/* ping handshake - set windowsizes etc, respond NOW using this query
		 * NOTE: still added to qmem (for cache) even though responded to immediately */
		if (u->outgoing && u->incoming) {
			DEBUG(2, "PING HANDSHAKE set max_queries up=%d, down=%d", up_winsize, dn_winsize);
			// TODO what does dn_winsize actually mean nowadays?
			u->max_queries = up_winsize;
		}
		DEBUG(3, "sending ping in response to ping: respond=%d, u->tuntype=%d", respond, u->tuntype);
		return send_ping(userid, q, 1);
	}

	/* if respond flag not set, query waits in qmem and is used later */
	user_process_incoming_data(userid);
	return NULL;
}

static struct dns_packet *
handle_dns_data(struct dns_packet *q, int userid, uint8_t *unpacked, size_t len)
{
	fragment f;
	struct dns_packet *ans;
	struct tun_user *u = &users[userid];
	uint8_t *p = unpacked, flags;

	/* Need 2 byte header + >=1 byte data */
	if (len < UPSTREAM_DATA_HDR + 1) {
		DEBUG(3, "BADLEN: expected upstream data pkt >3 bytes, got %zu bytes", len);
		return write_dns(q, userid, NULL, 0, DH_ERR(BADLEN));
	}

	/* Check if cached */
	if (qmem_is_cached(u->qmem, q, &ans)) {
		return ans;
	} else {
		qmem_append(u->qmem, q);
	}

	/* Decode upstream data header - see docs/proto_XXXXXXXX.txt */
	flags = *p++;
	f.seqID = *p++;
	f.compressed = (flags >> 2) & 1;
	f.start = (flags >> 1) & 1;
	f.end = flags & 1;

	/* HMAC makes sure the packet isn't truncated, so this should be OK */
	f.len = len - (p - unpacked);
	f.data = p;

	DEBUG(3, "frag seq %3u, datalen %5lu, compression %1d, s%1d e%1d",
				f.seqID, f.len, f.compressed, f.start, f.end);

	window_process_incoming_fragment(u->incoming, &f);

	user_process_incoming_data(userid);
	return NULL;
}

static struct dns_packet *
handle_dns_login(struct dns_packet *q, uint8_t *unpacked,
		size_t len, int userid, uint32_t cmc)
{
	uint8_t logindata[16], cc[16], out[16];
	char fromaddr[100];

	CHECK_LEN(len, 32);

	strncpy(fromaddr, format_addr(&q->m.from, q->m.fromlen), sizeof(fromaddr) - 1);

	if (!is_valid_user(userid)) { /* TODO check if user already logged in */
		syslog(LOG_WARNING, "rejected login request from user #%d from %s",
			userid, fromaddr);
		DEBUG(1, "Rejected login request from user %d (%s): bad user", userid, fromaddr);
		return write_dns(q, userid, NULL, 0, DH_ERR(BADAUTH));
	}

	struct tun_user *u = &users[userid];
	u->last_pkt = time(NULL);
	login_calculate(logindata, server.passwordmd5, u->server_chall);
	memcpy(cc, unpacked + 16, 16);

	DEBUG(2, "RX login U%d (%s): hash=0x%s, cc=0x%s, cmc=%u",
			  userid, fromaddr, tohexstr(unpacked, 16, 0), tohexstr(cc, 16, 1), cmc);

	if (memcmp(logindata, unpacked, 16) != 0) {
		if (--u->authenticated >= 0)
			u->authenticated = -1;
		int tries = abs(u->authenticated);
		DEBUG(1, "rejected login from user %d (%s), reason: bad hash, tries: %d",
			  userid, fromaddr, tries);
		syslog(LOG_WARNING, "rejected login from user #%d from %s; incorrect attempts: %d",
			userid, fromaddr, tries);
		return write_dns(q, userid, NULL, 0, DH_ERR(BADLOGIN));
	}

	/* Store user auth OK, count number of logins */
	if (++u->authenticated > 1) {
		syslog(LOG_WARNING, "duplicate login request from user #%d from %s",
			   userid, fromaddr);
		DEBUG(1, "duplicate login request from user %d (%s)", userid, fromaddr);
	}

	/* calculate server-to-client authentication data */
	login_calculate(out, server.passwordmd5, cc);

	DEBUG(1, "User %d connected from %s, srv auth=0x%s",
			userid, fromaddr, tohexstr(logindata, 16, 0));
	syslog(LOG_NOTICE, "accepted login from user #%d", userid);

	/* get HMAC key */
	hmac_key_calculate(u->hmac_key, u->server_chall, 16, cc, 16, server.passwordmd5);

	return write_dns(q, userid, out, sizeof(out), WD_AUTO);
}

static struct dns_packet *
handle_null_request(struct dns_packet *q, uint8_t *encdata, size_t encdatalen)
/* Handles a NULL DNS request. See doc/proto_XXXXXXXX.txt for details on iodine protocol. */
{
	char cmd, userchar;
	int userid = -1;
	uint8_t hmac[16], hmac_pkt[16], enc = C_BASE32;
	size_t hmaclen = 12, headerlen = 2, pktlen, minlen;
	uint32_t cmc;

	/* Everything here needs at least 5 chars in the name:
	 * cmd, userid and more data or at least 3 bytes CMC */
	if (encdatalen < 5)
		return write_dns(q, -1, NULL, 0, DH_ERR(BADLEN));

	/* get the cmd and change to uppercase for HMAC calculation */
	cmd = encdata[0] = toupper(encdata[0]);
	DEBUG(3, "NULL request encdatalen %zu, cmd '%c'", encdatalen, cmd);

	/* Pre-login commands: backwards compatible with protocol 00000402 */
	if (cmd == 'V') { /* Version check - before userid is assigned */
		return handle_dns_version(q, encdata, encdatalen);
	} else if (cmd == 'Y') { /* Downstream codec check - unauthenticated */
		/* Note: this is for simple backwards compatibility only but required
		 * for older clients to reach the version check and fail correctly */
		/* here the content of the query is ignored, and the answer is given solely
		 * based on the query type for basic backwards compatibility
		 * this works since the client always respects the server's downstream codec */
		return write_dns(q, -1, DOWNCODECCHECK1, DOWNCODECCHECK1_LEN, WD_OLD);
	}

	/* Get userid from query (always 2nd byte in hex except for data packets) */
	if (isxdigit(cmd)) {
		/* Upstream data packet - first byte is userid in hex */
		userid = HEX2INT(cmd);
		cmd = 'd'; /* flag for data packet - not part of protocol */
	} else {
		userchar = encdata[1] = toupper(encdata[1]); /* make uppercase for HMAC */
		userid = HEX2INT(userchar);
		if (!isxdigit(userchar) || !is_valid_user(userid)) {
			/* Invalid user ID or bad DNS query */
			return write_dns(q, -1, NULL, 0, DH_ERR(BADAUTH));
		}
	}
	DEBUG(6, "got userid %d", userid);

	/* Check authentication status */
	if (cmd != 'L' && !users[userid].authenticated) {
		DEBUG(3, "replying with BADAUTH to user %d", userid);
		return write_dns(q, -1, NULL, 0, DH_ERR(BADAUTH));
	}

	if (cmd == 'd') {
		/* now we know userid exists, we can set encoder */
		enc = users[userid].upenc;
		hmaclen = users[userid].hmaclen_up;
		headerlen = 1;
		pktlen = encdatalen - 1;
		minlen = 10;
	} else if (cmd == 'U') { /* upstream codec check: nonstandard header */
		pktlen = 32;
		minlen = 20;
	} else {
		pktlen = encdatalen - headerlen; /* pktlen is length of packet to decode */
		minlen = hmaclen + 4; /* minimum raw decoded length of header */
	}
	DEBUG(7, "cmd='%c', upenc=%hhu, hmaclen=%zu, headerlen=%zu, pktlen=%zu, minlen=%zu",
			cmd, enc, hmaclen, headerlen, pktlen, minlen);

	/* Following commands have everything after cmd and userid encoded
	 *  Header consists of 4 bytes CMC + 4 or 12 bytes HMAC
	 *  unpack data with enough space for HMAC stuff as well */
	uint8_t hmacbuf[512], *p;
	const uint8_t *unpacked = hmacbuf + 4 + headerlen;
	const size_t unpacked_len = sizeof(hmacbuf) - (unpacked - hmacbuf);

	const size_t raw_len = unpack_data(unpacked, unpacked_len, encdata + headerlen, pktlen, enc);
	if (raw_len < minlen) {
		DEBUG(2, "unpack_data got decoded data length %zu < expected minimum %zu", raw_len, minlen);
		return write_dns(q, userid, NULL, 0, DH_ERR(BADLEN));
	}

	p = hmacbuf;
	putlong(&p, raw_len + headerlen); /* 4 bytes length prefix for HMAC */
	memcpy(p, encdata, headerlen), p += headerlen; /* command and userid char (header) */
	readlong(unpacked, &p, &cmc); /* CMC is first 4 bytes of unpacked data */

	/* Login request - after version check successful, do not check auth yet */
	if (cmd == 'L') {
		return handle_dns_login(q, unpacked + 4, raw_len - 4, userid, cmc);
	}

	/* backup HMAC from packet then clear it */
	memcpy(hmac_pkt, p, hmaclen);
	memset(p, 0, hmaclen), p += hmaclen;

	/* commands have data following the header (cmc + hmac) */
	const uint8_t *cmd_data = p;
	const size_t cmd_len = raw_len - (p - unpacked);

	/* now verify HMAC!
	 * Packet data and header is assembled (data is not encoded yet).
	2. HMAC field is set to 0.
	3. Data to be encoded is appended to string (ie. cmd + userid chars) at
		beginning of query name.
	4. Length (32 bits, network byte order) is prepended to the result from (3)
	5. HMAC is calculated using the output from (4) and inserted into the HMAC
		field in the data header. The data is then encoded (ie. base32 + dots)
		and the query is sent. */
	const size_t hmacbuf_len = raw_len + (unpacked - hmacbuf);
	hmac_md5(hmac, users[userid].hmac_key, 16, hmacbuf, hmacbuf_len);
	if (memcmp(hmac, hmac_pkt, hmaclen) != 0) {    /* verify signed data */
		DEBUG(2, "HMAC mismatch! pkt: 0x%s, actual: 0x%s (%zu)",
			tohexstr(hmac_pkt, hmaclen, 0),	tohexstr(hmac, hmaclen, 1), hmaclen);
		DEBUG(6, "    hmacbuf: len=%zu, %s", hmacbuf_len,
			tohexstr(hmacbuf, hmacbuf_len, 0));
		return write_dns(q, userid, NULL, 0, DH_ERR(BADAUTH));
	}

	switch (cmd) {
	case 'U':
		/* codectest command has custom 32-byte header, which includes cmc+hmac */
		return handle_dns_codectest(q, userid, unpacked, encdata, encdatalen);
	case 'I':
		/* this command doesn't actually have any data */
		return handle_dns_ip_request(q, userid);
	case 'd':
		/* we can only process data once a connection has been requested */
		if (users[userid].tuntype == USER_CONN_NONE) {
			DEBUG(2, "user %d sent data without connection", userid);
			return write_dns(q, userid, NULL, 0, DH_ERR(BADOPTS));
		}

		return handle_dns_data(q, userid, cmd_data, cmd_len);
	case 'P':
		return handle_dns_ping(q, userid, cmd_data, cmd_len);
	case 'O':
		return handle_dns_set_options(q, userid, cmd_data, cmd_len);
	default:
		DEBUG(2, "Invalid DNS query! cmd = %c, cmd_len = %zu, hostname = '%s'",
				cmd, cmd_len, format_host(q->q[0].name, q->q[0].namelen, 0));
		return write_dns(q, userid, NULL, 0, DH_ERR(BADOPTS));
	}
}

static void
handle_ns_request(int dns_fd, struct dns_packet *q)
/* Mostly identical to handle_a_request() below */
{
	uint8_t buf[64*1024];
	size_t len;

	if (server.ns_ip != INADDR_ANY) {
		/* If ns_ip set, overwrite destination addr with it.
		 * Destination addr will be sent as additional record (A, IN) */
		struct sockaddr_in *addr = (struct sockaddr_in *) &q->m.dest;
		memcpy(&addr->sin_addr, &server.ns_ip, sizeof(server.ns_ip));
	}

	len = dns_encode_ns_response(buf, sizeof(buf), q, server.topdomain);
	if (len < 1) {
		warnx("dns_encode_ns_response doesn't fit");
		return;
	}

	DEBUG(2, "TX: NS reply client %s ID %5d, type %d, name %s, %zu bytes",
			format_addr(&q->m.from, q->m.fromlen), q->id, q->q[0].type, q->q[0].name, q->q[0].namelen);
	if (sendto(dns_fd, buf, len, 0, (struct sockaddr *) &q->m.from, q->m.fromlen) <= 0) {
		warn("ns reply send error");
	}
}

static void
handle_a_request(int dns_fd, struct dns_packet *q, int fakeip)
/* Mostly identical to handle_ns_request() above */
{
	uint8_t buf[64*1024];
	size_t len;

	if (fakeip) {
		in_addr_t ip = inet_addr("127.0.0.1");
		struct sockaddr_in *addr = (struct sockaddr_in *) &q->m.dest;
		memcpy(&addr->sin_addr, &ip, sizeof(ip));

	} else if (server.ns_ip != INADDR_ANY) {
		/* If ns_ip set, overwrite destination addr with it.
		 * Destination addr will be sent as additional record (A, IN) */
		struct sockaddr_in *addr = (struct sockaddr_in *) &q->m.dest;
		memcpy(&addr->sin_addr, &server.ns_ip, sizeof(server.ns_ip));
	}

	len = dns_encode_a_response(buf, sizeof(buf), q);
	if (len < 1) {
		warnx("dns_encode_a_response doesn't fit");
		return;
	}

	DEBUG(2, "TX: A reply client %s ID %5d, type %d, name %s, %zu bytes",
			format_addr(&q->m.from, q->m.fromlen), q->id, q->q[0].type, q->q[0].name, q->q[0].namelen);
	if (sendto(dns_fd, buf, len, 0, (struct sockaddr *) &q->m.from, q->m.fromlen) <= 0) {
		warn("a reply send error");
	}
}
