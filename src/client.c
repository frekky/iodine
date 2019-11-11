/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>,
 * 2015 Frekk van Blagh <frekk@frekkworks.com>
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

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <sys/param.h>
#include <fcntl.h>
#include <zlib.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

#ifdef WINDOWS32
#include "windows.h"
#else
#include <arpa/nameser.h>
#ifdef ANDROID
#include "android_dns.h"
#endif
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif
#include <grp.h>
#include <pwd.h>
#include <netdb.h>
#endif

#include "common.h"
#include "encoding.h"
#include "base32.h"
#include "base64.h"
#include "base64u.h"
#include "base128.h"
#include "read.h"
#include "dns.h"
#include "auth.h"
#include "tun.h"
#include "version.h"
#include "window.h"
#include "util.h"
#include "client.h"
#include "hmac_md5.h"

static int parse_data(uint8_t *data, size_t len, fragment *f, int *immediate, int*);
static int handshake_waitdns(uint8_t *buf, size_t *buflen, size_t signedlen, char cmd, int timeout);
static int send_ping(int ping_response, int timeout);
static int handshake_switch_options();

void
client_set_hostname_maxlen(size_t i)
{
	if (i <= 0xFF && i != this.hostname_maxlen) {
		this.hostname_maxlen = i;
		this.maxfragsize_up = get_raw_length_from_dns(this.hostname_maxlen - 1,
				get_encoder(this.enc_up), this.topdomain) - UPSTREAM_DATA_HDR; // XXX this doesn't account for CMC or HMAC!! [as of proto 801]
		if (this.outbuf)
			window_buffer_resize(this.outbuf, this.outbuf->length, this.maxfragsize_up);
	}
}

void
client_rotate_nameserver()
{
	this.current_nameserver ++;
	if (this.current_nameserver >= this.nameserv_addrs_count)
		this.current_nameserver = 0;
}

void
immediate_mode_defaults()
{
	this.send_interval_ms = MIN(this.rtt_total_ms / this.num_immediate, 1000);
	this.max_timeout_ms = MAX(4 * this.rtt_total_ms / this.num_immediate, 5000);
	this.server_timeout_ms = 0;
}

/* Client-side query tracking for lazy mode */

/* Handy macro for printing this.stats with messages */
#define QTRACK_DEBUG(level, ...) \
		_DEBUG_PRINT(level, DEBUG_PRINT("[QTRACK (%zu/%zu), ? %zu, TO %zu, S %zu] ", this.num_pending, PENDING_QUERIES_LENGTH, \
			this.num_untracked, this.num_timeouts, this.outbuf->numitems), __VA_ARGS__)

static int
update_server_timeout(int handshake)
/* Calculate server timeout based on average RTT, send ping "handshake" to set
 * if handshake sent, return query ID */
{
	time_t rtt_ms;
	static size_t num_rtt_timeouts = 0;

	/* Get average RTT in ms */
	rtt_ms = (this.num_immediate == 0) ? 1 : this.rtt_total_ms / this.num_immediate;
	if (rtt_ms >= this.max_timeout_ms && this.num_immediate > 5) {
		num_rtt_timeouts++;
		if (num_rtt_timeouts < 3) {
			fprintf(stderr, "Target interval of %ld ms less than average round-trip of "
					"%ld ms! Try increasing interval with -I.\n", this.max_timeout_ms, rtt_ms);
		} else {
			/* bump up target timeout */
			this.max_timeout_ms = rtt_ms + 1000;
			this.server_timeout_ms = 1000;
			if (this.lazymode)
				fprintf(stderr, "Adjusting server timeout to %ld ms, target interval %ld ms. Try -I%.1f next time with this network.\n",
						this.server_timeout_ms, this.max_timeout_ms, this.max_timeout_ms / 1000.0);

			num_rtt_timeouts = 0;
		}
	} else {
		/* Set server timeout based on target interval and RTT */
		this.server_timeout_ms = this.max_timeout_ms - rtt_ms;
		if (this.server_timeout_ms <= 0) {
			this.server_timeout_ms = 0;
			fprintf(stderr, "Setting server timeout to 0 ms: if this continues try disabling lazy mode. (-L0)\n");
		}
	}

	/* update up/down window timeouts to something reasonable */
	this.downstream_timeout_ms = rtt_ms * this.downstream_delay_variance;
	// TODO: update server_timeout based on variance

	if (handshake) {
		/* Send ping handshake to set server timeout */
		return send_ping(1, 1);
	}
	return -1;
}

static void
check_pending_queries()
/* Updates pending queries list */
{
	this.num_pending = 0;
	struct timeval now, qtimeout, max_timeout;
	gettimeofday(&now, NULL);
	/* Max timeout for queries is max interval + 1 second extra */
	max_timeout = ms_to_timeval(this.max_timeout_ms + 1000);
	for (int i = 0; i < PENDING_QUERIES_LENGTH; i++) {
		if (this.pending_queries[i].time.tv_sec > 0 && this.pending_queries[i].id >= 0) {
			timeradd(&this.pending_queries[i].time, &max_timeout, &qtimeout);
			if (!timercmp(&qtimeout, &now, >)) {
				/* Query has timed out, clear timestamp but leave ID */
				this.pending_queries[i].time.tv_sec = 0;
				this.num_timeouts++;
			}
			this.num_pending++;
		}
	}
}

static void
query_sent_now(int id)
{
	int i = 0, found = 0;
	if (!this.pending_queries)
		return;

	if (id < 0 || id > 65535)
		return;

	/* Replace any empty queries first, then timed out ones if necessary */
	for (i = 0; i < PENDING_QUERIES_LENGTH; i++) {
		if (this.pending_queries[i].id < 0) {
			found = 1;
			break;
		}
	}
	if (!found) {
		for (i = 0; i < PENDING_QUERIES_LENGTH; i++) {
			if (this.pending_queries[i].time.tv_sec == 0) {
				found = 1;
				break;
			}
		}
	}
	/* if no slots found after both checks */
	if (!found) {
		QTRACK_DEBUG(1, "Buffer full! Failed to add id %d.", id);
	} else {
		/* Add query into found location */
		this.pending_queries[i].id = id;
		gettimeofday(&this.pending_queries[i].time, NULL);
		this.num_pending ++;
		QTRACK_DEBUG(4, "Adding query id %d into this.pending_queries[%d]", id, i);
		id = -1;
	}
}

static void
got_response(int id, int immediate)
/* immediate: if query was replied to immediately (see below) */
{
	struct timeval now, rtt;
	time_t rtt_ms;
	static time_t rtt_min_ms = 1;
	gettimeofday(&now, NULL);

	QTRACK_DEBUG(4, "Got answer id %d (%s)", id, immediate ? "immediate" : "lazy");

	for (int i = 0; i < PENDING_QUERIES_LENGTH; i++) {
		if (id >= 0 && this.pending_queries[i].id == id) {
			if (this.num_pending > 0)
				this.num_pending--;

			if (this.pending_queries[i].time.tv_sec == 0) {
				if (this.num_timeouts > 0) {
					/* If query has timed out but is still stored - just in case
					 * ID is kept on timeout in check_pending_queries() */
					this.num_timeouts --;
					immediate = 0;
				} else {
					/* query is empty */
					continue;
				}
			}

			if (immediate || debug >= 4) {
				timersub(&now, &this.pending_queries[i].time, &rtt);
				rtt_ms = timeval_to_ms(&rtt);
			}

			QTRACK_DEBUG(5, "    found answer id %d in pending queries[%d], %ld ms old", id, i, rtt_ms);

			if (immediate) {
				/* If this was an immediate response we can use it to get
				   more detailed connection statistics like RTT.
				   This lets us determine and adjust server lazy response time
				   during the session much more accurately. */
				this.rtt_total_ms += rtt_ms;
				this.num_immediate++;

				if (this.autodetect_server_timeout) {
					if (this.autodetect_delay_variance) {
						if (rtt_ms > 0 && (rtt_ms < rtt_min_ms || 1 == rtt_min_ms)) {
							rtt_min_ms = rtt_ms;
						}
						this.downstream_delay_variance = (double) (this.rtt_total_ms /
							this.num_immediate) / rtt_min_ms;
					}
					update_server_timeout(0);
				}
			}

			/* Remove query info from buffer to mark it as answered */
			id = -1;
			this.pending_queries[i].id = -1;
			this.pending_queries[i].time.tv_sec = 0;
			break;
		}
	}
	if (id > 0) {
		QTRACK_DEBUG(4, "    got untracked response to id %d.", id);
		this.num_untracked++;
	}
}

static int
send_query(uint8_t *encdata, size_t encdatalen)
/* Returns DNS ID of sent query */
{
	uint8_t packet[4096];
	struct dns_packet *q;
	size_t len = sizeof(packet);

	this.lastid += 7727;

	q = dns_encode_data_query(this.do_qtype, this.topdomain, encdata, encdatalen);
	if (q == NULL) {
		DEBUG(1, "send_query: dns_encode_data_query failed");
		return -1;
	}

	q->id = this.lastid;

	if (!dns_encode(packet, &len, q, this.use_edns0)) {
		warnx("dns_encode doesn't fit");
		dns_packet_destroy(q);
		return -1;
	}

	DEBUG(3, "TX: id %5d len %zu: hostname '%s'", q->id, encdatalen,
			format_host(q->q[0].name, q->q[0].namelen, 0));

	uint16_t query_id = q->id;
	dns_packet_destroy(q);

	sendto(this.dns_fd, packet, len, 0,
			(struct sockaddr*)&this.nameserv_addrs[this.current_nameserver].addr,
			this.nameserv_addrs[this.current_nameserver].len);

	client_rotate_nameserver();

	/* There are DNS relays that time out quickly but don't send anything
	   back on timeout.
	   And there are relays where, in lazy mode, our new query apparently
	   _replaces_ our previous query, and we get no answers at all in
	   lazy mode while legacy immediate-ping-pong works just fine.
	   In this case, the up/down windowsizes may need to be set to 1 for there
	   to only ever be one query pending.
	   Here we detect and fix these situations.
	   (Can't very well do this anywhere else; this is the only place
	   we'll reliably get to in such situations.)
	   Note: only start fixing up connection AFTER we have this.connected
	         and if user hasn't specified server timeout/window timeout etc. */

	this.num_sent++;
	if (this.send_query_sendcnt > 0 && this.send_query_sendcnt < 100 &&
		this.lazymode && this.connected && this.autodetect_server_timeout) {
		this.send_query_sendcnt++;

		if ((this.send_query_sendcnt > this.windowsize_down && this.send_query_recvcnt <= 0) ||
		    (this.send_query_sendcnt > 2 * this.windowsize_down && 4 * this.send_query_recvcnt < this.send_query_sendcnt)) {
			if (this.max_timeout_ms > 500) {
				this.max_timeout_ms -= 200;
				double secs = (double) this.max_timeout_ms / 1000.0;
				fprintf(stderr, "Receiving too few answers. Setting target timeout to %.1fs (-I%.1f)\n", secs, secs);

				/* restart counting */
				this.send_query_sendcnt = 0;
				this.send_query_recvcnt = 0;

			} else if (this.lazymode) {
				fprintf(stderr, "Receiving too few answers. Will try to switch lazy mode off, but that may not"
					" always work any more. Start with -L0 next time on this network.\n");
				this.lazymode = 0;
				this.server_timeout_ms = 0;
			}
			update_server_timeout(1);
		}
	}
	return query_id;
}

static void
send_raw_data(uint8_t *data, size_t datalen)
{
	send_raw(this.dns_fd, data, datalen, this.userid, RAW_HDR_CMD_DATA,
			CMC(this.cmc_up), this.hmac_key, &this.raw_serv, this.raw_serv_len);
}


static int
send_packet(char cmd, const uint8_t *rawdata, const size_t rawdatalen, const int hmaclen)
/* Base32 encodes data and sends as single DNS query
 * Returns ID of sent query */
{
	size_t len = rawdatalen + hmaclen + 4 + 2;
	uint8_t buf[512], data[len + 4], hmac[16], *p = data;

	if (rawdata && rawdatalen) {
		memcpy(data + 10 + hmaclen, rawdata, rawdatalen);
	}

	putlong(&p, (uint32_t) len);
	*p++ = toupper(cmd);
	*p++ = toupper(this.userid_char);
	putlong(&p, CMC(this.cmc_up));

	if (hmaclen > 0) {
		/* calculate HMAC as specified in doc/proto_00000801.txt
		 * section "Protocol security" */
		memset(p, 0, hmaclen);
		hmac_md5(hmac, this.hmac_key, 16, data, len + 4);
		memcpy(p, hmac, hmaclen);
	}

	/* build the un-dotted hostname: cmd+userid+base32(data) */
	buf[0] = cmd;
	buf[1] = this.userid_char;

	size_t encdatalen, buflen = sizeof(buf);
	encdatalen = b32->encode(buf + 2, &buflen, data + 6, len - 2);

	return send_query(buf, encdatalen + 2);
}

static int
send_ping(int ping_response, int set_timeout)
{
	this.num_pings++;
	if (this.conn == CONN_DNS_NULL) {
		uint8_t data[13], *p = data;
		int id;

		/* 4 bytes client downstream CMC */
		putlong(&p, this.cmc_down);

		/* Build ping header (see doc/proto_xxxxxxxx.txt) */
		if (this.outbuf && this.inbuf) {
			*p++ = this.outbuf->windowsize & 0xff;	/* Upstream window size */
			*p++ = this.inbuf->windowsize & 0xff;	/* Downstream window size */
			*p++ = this.outbuf->start_seq_id & 0xff;	/* Upstream window start */
			*p++ = this.inbuf->start_seq_id & 0xff;	/* Downstream window start */
		} else {
			putlong(&p, 0); /* prevent memory leak */
		}

		putshort(&p, this.server_timeout_ms);
		putshort(&p, this.downstream_timeout_ms);

		/* flags byte: 00000WTR */
		*p++ = (set_timeout ? (3 << 1) : 0) | (ping_response & 1);

		DEBUG(3, " SEND PING: respond %d, %s(server %ld ms, downfrag %ld ms), flags 0x%02x, wup %u, wdn %u",
				ping_response, set_timeout ? "SET " : "",
				this.server_timeout_ms, this.downstream_timeout_ms,
				data[8], this.outbuf->windowsize, this.inbuf->windowsize);

		id = send_packet('p', data, sizeof(data), 12);

		/* Log query ID as being sent now */
		query_sent_now(id);
		return id;
	} else {
		send_raw(this.dns_fd, NULL, 0, this.userid, RAW_HDR_CMD_PING,
				CMC(this.cmc_up), this.hmac_key, &this.raw_serv, this.raw_serv_len);
		return -1;
	}
}

static void
send_next_frag()
/* Sends next available fragment of data from the outgoing window buffer */
{
    uint8_t buf[MAX_FRAGSIZE_UP], flags;
	uint16_t id;
	fragment *f;
	size_t buflen, hmaclen = 4;

	/* Get next fragment to send */
	if (window_to_send(this.outbuf, &f) == 0) {
		DEBUG(4, "no fragments to send right now");
		return;
	}

	/* upstream data flags (00000CFL) */
	flags = (f->compressed << 2) | (f->start << 1) | f->end;

	/* Build upstream data header (see doc/proto_xxxxxxxx.txt) with HMAC.
	 * 	1. Packet data and header is assembled (data is not encoded yet).
		2. HMAC field is set to 0.
		3. Data to be encoded is appended to string (ie. cmd + userid chars) at
			beginning of query name.
		4. Length (32 bits, network byte order) is prepended to the result from (3)
			Length = (len of chars at start of query) + (len of raw data)
		5. HMAC is calculated using the output from (4) and inserted into the HMAC
			field in the data header. The data is then encoded (ie. base32 + dots)
			and the query is sent. */
	uint8_t hmacbuf[4 + 1 + 4 + hmaclen + 1 + 1 + f->len], hmac[16], *p;
	p = hmacbuf;
	putlong(&p, sizeof(hmacbuf) - 4);	/* data length (only used for HMAC) */
	putbyte(&p, (uint8_t) toupper(this.userid_char)); /* First byte is hex userid */
	putlong(&p, CMC(this.cmc_up));		/* 4 bytes CMC (encoding will start from here, inclusive) */
	memset(p, 0, hmaclen), p += hmaclen;	/* 4 or 12 bytes zero'ed HMAC field */
	putbyte(&p, flags);					/* one byte flags */
	putbyte(&p, f->seqID & 0xFF);		/* one byte fragment sequence ID */
	putdata(&p, f->data, f->len);		/* fragment data */
	hmac_md5(hmac, this.hmac_key, 16, hmacbuf, sizeof(hmacbuf));
	memcpy(hmacbuf + 9, hmac, hmaclen);	/* copy in HMAC */

	/* encode data prepared in hmacbuf, skipping length + userid char (5 bytes) */
	buf[0] = this.userid_char;
	buflen = sizeof(buf) - 1; /* userid char */
	size_t enclen = get_encoder(this.enc_up)->encode(buf + 1, &buflen, hmacbuf + 5, sizeof(hmacbuf) - 5);

	DEBUG(3, " SEND DATA: seq %d, len %zu, s%d e%d c%d flags %02X hmac=%s",
			f->seqID, f->len, f->start, f->end, f->compressed, flags, tohexstr(hmac, hmaclen, 0));
	DEBUG(6, "    hmacbuf: len=%zu, %s", sizeof(hmacbuf), tohexstr(hmacbuf, sizeof(hmacbuf), 0));

	id = send_query(buf, enclen + 1);
	/* Log query ID as being sent now */
	query_sent_now(id);
	window_mark_sent(this.outbuf, f);

	this.num_frags_sent++;
}

static void
write_dns_error(uint16_t rcode, int ignore_some_errors)
/* This is called from:
   1. handshake_waitdns() when already checked that reply fits to our
      latest query.
   2. tunnel_dns() when already checked that reply is for a ping or data
      packet, but possibly timed out.
   Errors should not be ignored, but too many can be annoying.
*/
{
	static size_t errorcounts[24] = {0};

	if (rcode < 24) {
		errorcounts[rcode]++;
		if (errorcounts[rcode] == 20) {
			warnx("Too many error replies, not logging any more.");
			return;
		} else if (errorcounts[rcode] > 20) {
			return;
		}
	}

	switch (rcode) {
	case NOERROR:	/* 0 */
		if (!ignore_some_errors)
			warnx("Got reply without error, but also without question and/or answer");
		break;
	case FORMERR:	/* 1 */
		warnx("Got FORMERR as reply: server does not understand our request");
		break;
	case SERVFAIL:	/* 2 */
		if (!ignore_some_errors)
			warnx("Got SERVFAIL as reply: server failed or recursion timeout");
		break;
	case NXDOMAIN:	/* 3 */
		warnx("Got NXDOMAIN as reply: domain does not exist");
		break;
	case NOTIMP:	/* 4 */
		warnx("Got NOTIMP as reply: server does not support our request");
		break;
	case REFUSED:	/* 5 */
		warnx("Got REFUSED as reply");
		break;
	default:
		warnx("Got RCODE %u as reply", rcode);
		break;
	}
}

static void
handle_data_servfail()
/* some logic to minimize SERVFAILs, usually caused by DNS servers treating lazy
 * mode queries as timed out, so this attempts to reduce server timeout so that
 * queries are responded to sooner and eventually disabling lazy mode */
{
	this.num_servfail++;

	if (!this.lazymode) {
		return;
	}

	if (this.send_query_recvcnt < 500 && this.num_servfail < 4) {
		fprintf(stderr, "Hmm, that's %" L "d SERVFAILs. Your data should still go through...\n", this.num_servfail);

	} else if (this.send_query_recvcnt < 500 && this.num_servfail >= 10 &&
		this.autodetect_server_timeout && this.max_timeout_ms >= 500 && this.num_servfail % 5 == 0) {

		this.max_timeout_ms -= 200;
		double target_timeout = (float) this.max_timeout_ms / 1000.0;
		fprintf(stderr, "Too many SERVFAILs (%" L "d), reducing timeout to"
			" %.1f secs. (use -I%.1f next time on this network)\n",
				this.num_servfail, target_timeout, target_timeout);

		/* Reset query counts this.stats */
		this.send_query_sendcnt = 0;
		this.send_query_recvcnt = 0;
		update_server_timeout(1);

	} else if (this.send_query_recvcnt < 500 && this.num_servfail >= 40 &&
		this.autodetect_server_timeout && this.max_timeout_ms < 500) {

		/* last-ditch attempt to fix SERVFAILs - disable lazy mode */
		immediate_mode_defaults();
		fprintf(stderr, "Attempting to disable lazy mode due to excessive SERVFAILs\n");
		this.lazymode = 0;
		handshake_switch_options();
	}
}

/* verify the HMAC on a raw packet */
static int
raw_validate(uint8_t **packet, size_t len, uint8_t *cmd)
{
	uint8_t hmac_pkt[16], hmac[16], userid;
	uint32_t cmc;

	/* minimum length */
	if (len < RAW_HDR_LEN) return 0;
	/* should start with header */
	if (memcmp(*packet, raw_header, RAW_HDR_IDENT_LEN))
		return 0;

	userid = RAW_HDR_GET_USR(*packet);

	*cmd = RAW_HDR_GET_CMD(*packet);
	cmc = ntohl(*(uint32_t *) (*packet + RAW_HDR_CMC));
	// TODO check CMC
	memset(hmac_pkt, 0, sizeof(hmac_pkt));
	memcpy(hmac_pkt, *packet + RAW_HDR_HMAC, RAW_HDR_HMAC_LEN);

	DEBUG(2, "RX-raw: user %d, raw command 0x%02X, length %zu", userid, *cmd, len);

	*packet += RAW_HDR_LEN;
	len -= RAW_HDR_LEN;

	/* Verify HMAC */
	memset(*packet + RAW_HDR_HMAC, 0, RAW_HDR_HMAC_LEN);
	hmac_md5(hmac, this.hmac_key, 16, *packet, len);
	if (memcmp(hmac, hmac_pkt, RAW_HDR_HMAC_LEN) != 0) {
		DEBUG(3, "RX-raw: bad HMAC pkt=0x%s, actual=0x%s (%d)",
				tohexstr(hmac_pkt, RAW_HDR_HMAC_LEN, 0),
				tohexstr(hmac_pkt, RAW_HDR_HMAC_LEN, 1), RAW_HDR_HMAC_LEN);
		return 0;
	}

	return 1;
}

static int
handshake_waitdns(uint8_t *buf, size_t *buflen, size_t signedlen, char cmd, int timeout)
/* Wait for DNS reply fitting to our latest query and returns it.
   *buflen is set to length of reply data = #bytes used in buf
   Version commands 'v' are not downstream-decoded
   signedlen = length of b32 data that is signed by HMAC (0 if full reply signed)
   Returns 1 on success
   Returns 0 on signed error code from server OR invalid downstream decoding
   Returns -1 on syscall errors.
   Returns -2 on (at least) DNS error that fits to our latest query,
   error message already printed.
   Returns -3 on timeout (given in seconds).

   Timeout is restarted when "wrong" (previous/delayed) replies are received,
   so effective timeout may be longer than specified.
*/
{
	struct pkt_metadata m;
	int r;
	fd_set fds;
	struct timeval tv;
	char qcmd;
	uint8_t pkt[64*1024], ansdata[4096];
	size_t pktlen;

	cmd = toupper(cmd);

	while (1) {
		tv.tv_sec = timeout;
		tv.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(this.dns_fd, &fds);
		r = select(this.dns_fd + 1, &fds, NULL, NULL, &tv);

		if (r < 0) {
			warn("select");
			return -1;	/* select error */
		} else if (r == 0) {
			DEBUG(1, "timeout in handshake_waitdns, cmd '%c'", cmd);
			return -3;	/* select timeout */
		}

		pktlen = sizeof(pkt);
		if (!read_packet(this.dns_fd, pkt, &pktlen, &m)) {
			return -1;	/* read error */
		}

		struct dns_packet *q;
		if ((q = dns_decode(pkt, pktlen)) == NULL) {
			DEBUG(1, "got invalid DNS packet as reply, cmd '%c'", cmd);
			return -1;	/* invalid DNS packet */
		}

		DEBUG(2, "RX: id %5d len %zu: hostname '%s'", q->id, q->q[0].namelen,
				format_host(q->q[0].name, q->q[0].namelen, 0));

		/* Non-recursive DNS servers (such as [a-m].root-servers.net)
		   return no answer, but only additional and authority records.
		   Can't explicitly test for that here, just assume that
		   NOERROR is such situation. Only trigger on the very first
		   requests (Y or V, depending if -T given).
		 */
		if (q->rcode == NOERROR && q->ancount == 0) {
			fprintf(stderr, "Got empty reply. This nameserver may not be resolving recursively, use another.\n");
			char *td = format_host(this.topdomain, HOSTLEN(this.topdomain), 0);
			fprintf(stderr, "Try \"iodine [options] %s ns.%s\" first, it might just work.\n", td, td);
			dns_packet_destroy(q);
			return -2;
		}

		size_t ansdatalen = sizeof(ansdata);
		r = dns_decode_data_answer(q, ansdata, &ansdatalen);

		qcmd = toupper(q->q[0].name[1]);
		if (r && ansdatalen && (q->id != this.lastid || qcmd != toupper(cmd))) {
			DEBUG(1, "Ignoring unfitting reply id %hu starting with '%c'", q->id, qcmd);
			dns_packet_destroy(q);
			continue;
		} else if (q->rcode != NOERROR) {
			/* If we get an immediate SERVFAIL on the handshake query
			   we're waiting for, wait a while before sending the next.
			   SERVFAIL reliably happens during fragsize autoprobe, but
			   mostly long after we've moved along to some other queries.
			   However, some DNS relays, once they throw a SERVFAIL, will
			   for several seconds apply it immediately to _any_ new query
			   for the same this.topdomain. When this happens, waiting a while
			   is the only option that works. */
			if (q->rcode == SERVFAIL)
				sleep(1);
			write_dns_error(q->rcode, 1);
			dns_packet_destroy(q);
			return -2;
		}
		/* if still here: reply matches our latest query, and we don't need the original query any more */
		dns_packet_destroy(q);

		/* version commands have old format, so treat these differently */
		if (cmd == 'V') {
			memcpy(buf, ansdata, MIN(*buflen, ansdatalen));
			*buflen = MIN(*buflen, ansdatalen);
			return 1;
		}

		if (signedlen && ansdatalen >= signedlen) {
			/* only a the base32-encoded header of (signedlen) bytes (encoded length)
			 * is signed by the HMAC, rest of data is not to be decoded. */
			size_t hdrlen = *buflen;

			r = downstream_decode(buf, &hdrlen, ansdata, signedlen, this.hmac_key);
			if (r && hdrlen + ansdatalen - signedlen <= *buflen) {
				memcpy(buf + hdrlen, ansdata + signedlen, ansdatalen - signedlen);
				*buflen = hdrlen + ansdatalen - signedlen;
				return 1;
			} else {
				return 0;
			}
		} else { /* normal downstream decode */
			return downstream_decode(buf, buflen, ansdata, ansdatalen,
					this.connected ? this.hmac_key : NULL);
		}
	}

	/* not reached */
	return -1;
}

static int
parse_data(uint8_t *data, size_t len, fragment *f, int *immediate, int *ping)
{
	uint8_t *p = data;

	if (len < DOWNSTREAM_DATA_HDR) {
		return 0;
	}

	uint8_t flags = *p++;

	/* Data/ping flags (PI000[KFS|000]) */
	*ping = (flags >> 7) & 1;
	*immediate = (flags >> 6) & 1;

	if (*ping) { /* handle downstream ping */
		uint8_t dn_start_seq, up_start_seq;
		uint16_t dn_wsize, up_wsize;
		uint32_t dn_cmc;

		if (len < DOWNSTREAM_PING_HDR) {
			return 0; /* invalid packet - continue */
		}

		/* Parse data/ping header */
		readlong(data, &p, &dn_cmc);
		up_wsize = *p++;
		dn_wsize = *p++;
		up_start_seq = *p++;
		dn_start_seq = *p++;

		// TODO do something with server CMC & windowsizes
		DEBUG(3, "RX PING CMC: %u, WS: up=%u, dn=%u; Start: up=%u, dn=%u",
				dn_cmc, up_wsize, dn_wsize, up_start_seq, dn_start_seq);
	} else { /* handle downstream data */
		f->seqID = *p++;
		f->end = flags & 1; /* flags: PI000KFS */
		f->start = (flags >> 1) & 1;
		f->compressed = (flags >> 2) & 1;
		f->len = len - (p - data);
		DEBUG(2, " RX DATA frag ID %3u, compression %d, fraglen %zu, s%d e%d\n",
				f->seqID, f->compressed, f->len, f->start, f->end);
		if (f->len > 0) {
			memcpy(f->data, p, MIN(f->len, this.inbuf->maxfraglen));
		} else {
			/* data packets must have len > 0, this is technically illegal */
			DEBUG(1, "BUG! Empty downstream data from server!! flags=%02x", flags);
			return 0;
		}
	}
	return 1;
}

static ssize_t
tunnel_stdin()
{
	size_t datalen;
	uint8_t out[64*1024];
	uint8_t in[64*1024];
	uint8_t *data;
	ssize_t readlen;

	readlen = read(STDIN_FILENO, in, sizeof(in));
	DEBUG(4, "  IN: %" L "d bytes on stdin, to be compressed: %d", readlen, this.compression_up);
	if (readlen == 0) {
		DEBUG(2, "EOF on stdin!");
		return -1;
	} else if (readlen < 0) {
		warnx("Error %d reading from stdin: %s", errno, strerror(errno));
		return -1;
	}

	if (this.conn != CONN_DNS_NULL || this.compression_up) {
		datalen = sizeof(out);
		compress2(out, &datalen, in, readlen, 9);
		data = out;
	} else {
		datalen = readlen;
		data = in;
	}

	if (this.conn == CONN_DNS_NULL) {
		/* Check if outgoing buffer can hold data */
		if (window_buffer_available(this.outbuf) < (datalen / this.outbuf->maxfraglen) + 1) {
			DEBUG(1, "  Outgoing buffer full (%zu/%zu), not adding data!",
						this.outbuf->numitems, this.outbuf->length);
			return -1;
		}

		window_add_outgoing_data(this.outbuf, data, datalen, this.compression_up);
		/* Don't send anything here to respect min. send interval */
	} else {
		send_raw_data(data, datalen);
	}

	return datalen;
}

static int
tunnel_tun()
{
	size_t datalen;
	uint8_t out[64*1024];
	uint8_t in[64*1024];
	uint8_t *data;
	ssize_t read;

	if ((read = read_tun(this.tun_fd, in, sizeof(in))) <= 0)
		return -1;

	DEBUG(2, " IN: %zu bytes on tunnel, to be compressed: %d", read, this.compression_up);

	if (this.conn != CONN_DNS_NULL || this.compression_up) {
		datalen = sizeof(out);
		compress2(out, &datalen, in, read, 9);
		data = out;
	} else {
		datalen = read;
		data = in;
	}

	if (this.conn == CONN_DNS_NULL) {
		/* Check if outgoing buffer can hold data */
		if ((this.windowsize_up == 0 && this.outbuf->numitems != 0) ||
				window_buffer_available(this.outbuf) < (read / this.outbuf->maxfraglen) + 1) {
			DEBUG(1, "  Outgoing buffer full (%zu/%zu), not adding data!",
						this.outbuf->numitems, this.outbuf->length);
			return -1;
		}

		window_add_outgoing_data(this.outbuf, data, datalen, this.compression_up);
		/* Don't send anything here to respect min. send interval */
	} else {
		send_raw_data(data, datalen);
	}

	return read;
}


#define DNS_CLEANUP got_response(q->id, 0); dns_packet_destroy(q);

static void
tunnel_dns()
{
	struct dns_packet *q;
	struct pkt_metadata m;
	size_t datalen, buflen;
	uint8_t buf[64*1024], cbuf[64*1024];
	fragment f;
	int ping, immediate;
	char cmd;

	memset(&q, 0, sizeof(q));
	memset(buf, 0, sizeof(buf));
	memset(cbuf, 0, sizeof(cbuf));

	buflen = sizeof(buf);
	if (!read_packet(this.dns_fd, buf, &buflen, &m)) {
		return;
	}

	if (this.conn == CONN_DNS_NULL) {
		if ((q = dns_decode(buf, buflen)) == NULL)
			return;

		DEBUG(2, "RX: id %5d len=%zu name='%s'", q->id, q->q[0].namelen, format_host(q->q[0].name, q->q[0].namelen, 0));
		memcpy(&q->m, &m, sizeof(m));

		datalen = sizeof(buf);
		if (!dns_decode_data_answer(q, cbuf, &datalen)) /* cbuf contains data */
			datalen = 0;
		buflen = sizeof(buf);
		if (!downstream_decode(buf, &buflen, cbuf, datalen, this.hmac_key)) {
			if ((downstream_decode_err & DDERR_IS_ANS) && (downstream_decode_err & 7) == E_BADAUTH) {
				this.num_badauth++;
				if (this.num_badauth % 5 == 1) {
					fprintf(stderr, "BADAUTH (%" L "d): Server rejected client authentication, or server "
						"kicked us due to timeout. Will exit if no downstream data is received in 60 seconds.\n", this.num_badauth);
				}
				DNS_CLEANUP;
				return;	/* nothing done */
			}
			write_dns_error(q->rcode, 0);
			if (q->rcode == SERVFAIL) { /* Maybe SERVFAIL etc */
				/* TODO: If we get an immediate SERVFAIL on the handshake query
				   we're waiting for, wait a while before sending the next.
				   SERVFAIL reliably happens during fragsize autoprobe, but
				   mostly long after we've moved along to some other queries.
				   However, some DNS relays, once they throw a SERVFAIL, will
				   for several seconds apply it immediately to _any_ new query
				   for the same this.topdomain. When this happens, waiting a while
				   is the only option that works. */
				handle_data_servfail();
			}
			DNS_CLEANUP;
			return;	/* nothing done */
		}
		cmd = tolower(q->q[0].name[1]);

		/* don't handle anything that's not data or ping */
		if (cmd != 'p' && cmd != this.userid_char) {
			DEBUG(1, "Got strange data response, cmd='%c'" + cmd);
			DNS_CLEANUP;
			return;	/* nothing done */
		}
	} else { /* CONN_RAW_UDP */
		uint8_t *data = buf, cmd;
		if (!raw_validate(&data, buflen, &cmd)) {
			return;
		}

		if (cmd == RAW_HDR_CMD_DATA || cmd == RAW_HDR_CMD_PING)
			this.lastdownstreamtime = time(NULL);

		/* should be data packet */
		if (RAW_HDR_GET_CMD(buf) != RAW_HDR_CMD_DATA)
			return;

		buflen -= RAW_HDR_LEN;
		datalen = sizeof(buf);
		if (uncompress(cbuf, &datalen, data, buflen) == Z_OK) {
			write_tun(this.tun_fd, cbuf, datalen);
		}

		return; /* all done */
	}

	this.send_query_recvcnt++;  /* unlikely we will ever overflow (size_t is large) */
	this.num_recv++;
	this.lastdownstreamtime = time(NULL); /* recent downstream packet */

	/* Decode the downstream data header and fragment-ify ready for processing */
	f.data = buf;
	if (parse_data(buf, buflen, &f, &immediate, &ping)) {
		got_response(q->id, immediate);
		dns_packet_destroy(q); /* we don't need this any more */
	} else {
		DEBUG(1, "failed to parse downstream data/ping packet!");
		DNS_CLEANUP;
		return;
	}

	if (!ping) {
		/* Downstream data traffic */
		window_process_incoming_fragment(this.inbuf, &f);
	}

	this.num_frags_recv++;

	/* Continue reassembling packets until not possible to do so.
	 * This prevents a buildup of fully available packets (with one or more fragments each)
	 * in the incoming window buffer. */

	int can_reassemble_more = 1;
	while (can_reassemble_more) {
		uint8_t compressed;
		uint8_t *data = cbuf;
		datalen = sizeof(cbuf);
		can_reassemble_more = window_reassemble_data(this.inbuf, cbuf, &datalen, &compressed);

		/* try to decompress the data if it is compressed */
		if (compressed) {
			buflen = sizeof(buf);
			int ret = uncompress(buf, &buflen, cbuf, datalen);
			if (ret != Z_OK) {
				DEBUG(1, "Uncompress failed (%d) for datalen=%zu: reassembled data corrupted or incomplete!", ret, datalen);
				continue;
			} else {
				datalen = buflen;
			}
			data = buf;
		}

		if (this.use_remote_forward) {
			if (write(STDOUT_FILENO, data, datalen) != datalen) {
				warn("write_stdout != datalen");
			}
		} else {
			write_tun(this.tun_fd, data, datalen);
		}
	}
}

int
client_tunnel()
{
	struct timeval tv, nextresend, tmp, now, now2;
	fd_set fds;
	int rv;
	int i, use_min_send;
	int sending, total, maxfd;
	time_t last_stats;
	size_t sent_since_report, recv_since_report;

	this.connected = 1;

	/* start counting now */
	rv = 0;
	this.lastdownstreamtime = time(NULL);
	last_stats = time(NULL);

	/* reset connection statistics */
	this.num_badauth = 0;
	this.num_servfail = 0;
	this.num_timeouts = 0;
	this.send_query_recvcnt = 0;
	this.send_query_sendcnt = 0;
	this.num_sent = 0;
	this.num_recv = 0;
	this.num_frags_sent = 0;
	this.num_frags_recv = 0;
	this.num_pings = 0;

	sent_since_report = 0;
	recv_since_report = 0;

	use_min_send = 0;

	while (this.running) {
		if (!use_min_send)
			tv = ms_to_timeval(this.max_timeout_ms);

		/* TODO: detect DNS servers which drop frequent requests
		 * TODO: adjust number of pending queries based on current data rate */
		if (this.conn == CONN_DNS_NULL && !use_min_send) {

			/* Send a single query per loop */
			sending = window_to_send(this.outbuf, NULL);
			total = sending;
			check_pending_queries();
			if (this.num_pending < this.windowsize_down && this.lazymode)
				total = MAX(total, this.windowsize_down - this.num_pending);
			else if (this.num_pending < 1 && !this.lazymode)
				total = MAX(total, 1);

			QTRACK_DEBUG(2, "sending=%d, total=%d, next_ack=%d, outbuf.n=%zu",
					sending, total, this.next_downstream_ack, this.outbuf->numitems);
			/* Upstream traffic - this is where all ping/data queries are sent */
			if (sending > 0 || total > 0) {

				if (sending > 0) {
					/* More to send - next fragment */
					send_next_frag();
				} else {
					/* Send ping if we didn't send anything yet */
					send_ping(0, (this.num_pings > 20 &&
							this.num_pings % 50 == 0));
				}

				sending--;
				total--;
				QTRACK_DEBUG(3, "Sent a query to fill server lazy buffer to %zu, will send another %d",
							 this.lazymode ? this.windowsize_down : 1, total);

				if (sending > 0 || (total > 0 && this.lazymode)) {
					/* If sending any data fragments, or server has too few
					 * pending queries, send another one after min. interval */
					/* TODO: enforce min send interval even if we get new data */
					tv = ms_to_timeval(this.min_send_interval_ms);
					if (this.min_send_interval_ms)
						use_min_send = 1;
					tv.tv_usec += 1;
				} else if (total > 0 && !this.lazymode) {
					/* In immediate mode, use normal interval when needing
					 * to send non-data queries to probe server. */
					tv = ms_to_timeval(this.send_interval_ms);
				}

				if (sending == 0 && !use_min_send) {
					/* check next resend time when not sending any data */
					if (timercmp(&nextresend, &tv, <))
						tv = nextresend;
				}
			}
		}

		if (this.stats) {
			if (difftime(time(NULL), last_stats) >= this.stats) {
				/* print useful statistics report */
				fprintf(stderr, "\n============ iodine connection statistics (user %1d) ============\n", this.userid);
				fprintf(stderr, " Queries   sent: %8" L "u"  ", answered: %8" L "u"  ", SERVFAILs: %4" L "u\n",
						this.num_sent, this.num_recv, this.num_servfail);
				fprintf(stderr, "  last %3d secs: %7" L "u" " (%4" L "u/s),   replies: %7" L "u" " (%4" L "u/s)\n",
						this.stats, this.num_sent - sent_since_report, (this.num_sent - sent_since_report) / this.stats,
						this.num_recv - recv_since_report, (this.num_recv - recv_since_report) / this.stats);
				fprintf(stderr, "  num auth rejected: %4" L "u,   untracked: %4" L "u,   lazy mode: %1d\n",
						this.num_badauth, this.num_untracked, this.lazymode);
				fprintf(stderr, " Min send: %5" L "d ms, Avg RTT: %5" L "d ms  Timeout server: %4" L "d ms\n",
						this.min_send_interval_ms, this.rtt_total_ms / this.num_immediate, this.server_timeout_ms);
				fprintf(stderr, " Queries immediate: %5" L "u, timed out: %4" L "u    target: %4" L "d ms\n",
						this.num_immediate, this.num_timeouts, this.max_timeout_ms);
				if (this.conn == CONN_DNS_NULL) {
					fprintf(stderr, " Out of sequence frags: %4u          down frag: %4" L "d ms\n",
							 this.inbuf->oos, this.downstream_timeout_ms);
					fprintf(stderr, " TX fragments: %8" L "u" ",   RX: %8" L "u" ",   pings: %8" L "u" "\n",
							this.num_frags_sent, this.num_frags_recv, this.num_pings);
				}
				fprintf(stderr, " Pending frags: %4" L "u\n", this.outbuf->numitems);
				/* update since-last-report this.stats */
				sent_since_report = this.num_sent;
				recv_since_report = this.num_recv;
				last_stats = time(NULL);

			}
		}

		FD_ZERO(&fds);
		maxfd = 0;
		if (this.conn != CONN_DNS_NULL || 0 == this.windowsize_up || window_buffer_available(this.outbuf) > 1) {
			/* Fill up outgoing buffer with available data if it has enough space
			 * The windowing protocol manages data retransmits, timeouts etc. */
			if (this.use_remote_forward) {
				FD_SET(STDIN_FILENO, &fds);
				maxfd = MAX(STDIN_FILENO, maxfd);
			} else {
				FD_SET(this.tun_fd, &fds);
				maxfd = MAX(this.tun_fd, maxfd);
			}
		}
		FD_SET(this.dns_fd, &fds);
		maxfd = MAX(this.dns_fd, maxfd);

		DEBUG(4, "Waiting %ld ms before sending more... (min_send %d)", timeval_to_ms(&tv), use_min_send);

		if (use_min_send) {
			gettimeofday(&now, NULL);
		}

		i = select(maxfd + 1, &fds, NULL, NULL, &tv);

		if (use_min_send && i > 0) {
			/* enforce min_send_interval if we get interrupted by new tun data */
			gettimeofday(&now2, NULL);
			timersub(&now2, &now, &tmp);
			timersub(&tv, &tmp, &now);
			tv = now;
		} else {
			use_min_send = 0;
		}

		if (difftime(time(NULL), this.lastdownstreamtime) > 60) {
 			fprintf(stderr, "No downstream data received in 60 seconds, shutting down.\n");
 			this.running = 0;
 		}

		if (this.running == 0)
			break;

		if (i < 0)
			err(1, "select < 0");

		if (i == 0) {
			/* timed out - no new packets recv'd */
		} else {
			if (!this.use_remote_forward && FD_ISSET(this.tun_fd, &fds)) {
				if (tunnel_tun() <= 0)
					continue;
				/* Returns -1 on error OR when quickly
				   dropping data in case of DNS congestion;
				   we need to _not_ do tunnel_dns() then.
				   If chunk sent, sets this.send_ping_soon=0. */
			}
			if (this.use_remote_forward && FD_ISSET(STDIN_FILENO, &fds)) {
				if (tunnel_stdin() <= 0) {
					fprintf(stderr, "error on stdin: client stopping.\n");
					this.running = 0;
					break;
				}
			}

			if (FD_ISSET(this.dns_fd, &fds)) {
				tunnel_dns();
			}
		}
		if (this.running == 0)
			break;
	}

	return rv;
}

static void
send_version(uint32_t version)
{
	uint8_t data[8], buf[512];
	size_t buflen = sizeof(buf) - 1, encbuflen;

	*(uint32_t *) data = htonl(version);
	*(uint32_t *) (data + 4) = htonl(CMC(this.cmc_up)); /* CMC */

	buf[0] = 'v';
	encbuflen = b32->encode(buf + 1, &buflen, data, sizeof(data));

	send_query(buf, encbuflen + 1);
}

static void
send_login(uint8_t *login, uint8_t *cc)
/* Send DNS login packet. See doc/proto_xxxxxxxx.txt for details
 * login and cc must point to buffers of 16 bytes login hash / client challenge */
{
	uint8_t data[32];

	DEBUG(6, "TX login: hash=0x%s, cc=0x%s, cmc=%u",
			tohexstr(login, 16, 0), tohexstr(cc, 16, 1), this.cmc_up);

	memcpy(data, login, 16);
	memcpy(data + 16, cc, 16);

	send_packet('l', data, sizeof(data), 0);
}

static void
send_codectest(uint8_t *dataq, uint8_t dqlen, uint16_t drlen, int dnchk)
/* dnchk == 1: downstream codec check; dnchk == 0: upstream */
{
	uint8_t buf[34 + dqlen], hmac[16], header[4 + 2 + 20], *p;
	p = header;
	putlong(&p, 22); /* HMAC-only length field */
	putbyte(&p, 'U');
	putbyte(&p, toupper(this.userid_char));
	putlong(&p, CMC(this.cmc_up));
	memset(p, 0, 12), p += 12; /* clear HMAC field */
	putbyte(&p, (dnchk & 1)); /* 1 byte flags */
	putbyte(&p, dqlen);
	putshort(&p, drlen);
	hmac_md5(hmac, this.hmac_key, 16, header, sizeof(header));

	DEBUG(5, "TX codectest: CMC %08x HMAC %s (12) hmacbuf %s (26)",
			this.cmc_up, tohexstr(hmac, 12, 0), tohexstr(header, 26, 1));

	memcpy(header + 10, hmac, 12); /* copy the calculated hmac into the packet buffer to send */

	size_t buflen = 32;
	if (b32->encode(buf + 2, &buflen, header + 6, 20) != 32)
		DEBUG(1, "upenctest got wrong encoded headerlen!");

	buf[0] = 'u';
	buf[1] = this.userid_char;
	/* Append codec test data without changing it */
	memcpy(buf + 34, dataq, dqlen);

	send_query(buf, sizeof(buf));
}

static void
send_ip_request()
{
	send_packet('i', NULL, 0, 12);
}

static void
send_raw_udp_login()
{
	uint8_t buf[16];
	get_rand_bytes(buf, sizeof(buf));
	send_raw(this.dns_fd, buf, sizeof(buf), this.userid, RAW_HDR_CMD_LOGIN,
			CMC(this.cmc_up), this.hmac_key, &this.raw_serv, this.raw_serv_len);
}

static void
send_server_options(uint8_t *flags)
/* sets flags[0] and flags[1] */
{
	uint8_t buf[30], *p = buf + 2;

	/* standard options flags byte: see docs/proto_xxx.txt */
	buf[0] = ((!!this.lazymode) << 7) | ((!!this.compression_down) << 6) |
			((this.enc_up & 7) << 3) | (this.enc_down & 7);
	buf[1] = (1 << 5) | (1 << 4); /* set upstream and downstream data HMAC to 32 bits */
	putshort(&p, this.maxfragsize_down);

	/* connection options */
	if (this.use_remote_forward) { /* request UDP forward */
		struct sockaddr_in *s = (struct sockaddr_in *) &this.remote_forward_addr;
		buf[1] |= 1 << 3;
		if (this.remote_forward_addr.ss_family == AF_INET) {
			/* remote address is IPv4 */
			buf[1] |= (1 << 2) | (1 << 1);
			putshort(&p, s->sin_port); /* port */
			putdata(&p, (uint8_t *) &s->sin_addr, 4); /* ipv4 addr */
		} else if (this.remote_forward_addr.ss_family == AF_INET6) {
			/* remote address is IPv6 */
			struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) &this.remote_forward_addr;
			buf[1] |= 1 << 2;
			putshort(&p, s6->sin6_port);
			putdata(&p, (uint8_t *) &s6->sin6_addr, 16);
		} else {
			/* remote address is server's local IP */
			putbyte(&p, 0x08);
			putshort(&p, s->sin_port);
		}
		DEBUG(2, "Sending UDP forward request, length %zu, ss_family %hu",
				p - buf, this.remote_forward_addr.ss_family);
	} else { /* request TUN IP */
		DEBUG(2, "Requesting TUN IP");
		buf[1] |= 1;
	}

	memcpy(flags, buf, 2); /* make a copy of resulting flags */

	send_packet('o', buf, (p - buf), 12);
}

static int
handshake_version(uint8_t *sc)
/* takes server challenge (16 bytes) as argument */
{
	uint8_t hex[] = "0123456789abcdef", in[100], raw[100], *p;
	uint32_t payload;
	size_t len;
	int ret;

	for (int i = 0; this.running && i < 5; i++) {

		send_version(PROTOCOL_VERSION);

		len = sizeof(in);
		if ((ret = handshake_waitdns(in, &len, 0, 'V', i + 1)) != 1 || len < 8) {
			fprintf(stderr, "Retrying version check...\n");
			if (ret == 0) print_downstream_err();
			continue;
		}

		/* decode version reply: assume base32 using old downstream encoding */
		if (toupper(in[0]) == 'T' || toupper(in[0]) == 'H') {
			len = unpack_data(raw, sizeof(raw), in + 1, len - 1, C_BASE32);
		} else {
			memcpy(raw, in, len);
		}

		p = raw + 4;
		readlong(in, &p, &payload);
		if (memcmp("VACK", raw, 4) == 0) {
			if (len != 28) {
				fprintf(stderr, "Bad version check reply from server, trying again...\n");
				continue;
			}
			/* Payload is new userid, and there will also be 16 bytes
			 * server challenge. */
			readdata(&p, sc, 16);
			/* Set CMC to starting value given by server. */
			readlong(in, &p, &this.cmc_down);
			this.userid = payload;
			this.userid_char = hex[this.userid & 15];

			DEBUG(2, "Login: sc=%s, cmc_up=%u, cmc_dn=%u", tohexstr(sc, 16, 0), this.cmc_up, this.cmc_down);

			fprintf(stderr, "Version ok, both using protocol v 0x%08x. You are user #%d\n",
				PROTOCOL_VERSION, this.userid);
			return 1;
		} else if (memcmp("VNAK", raw, 4) == 0) {
			/* Payload is server version */
			warnx("You use protocol v 0x%08x, server uses v 0x%08x. Giving up",
					PROTOCOL_VERSION, payload);
			return 0;
		} else if (memcmp("VFUL", raw, 4) == 0) {
			/* Payload is max number of users on server */
			warnx("Server full, all %d slots are taken. Try again later", payload);
			return 0;
		} else {
			raw[4] = 0;
			DEBUG(1, "bad version reply: '%s'", raw);
		}
	}
	warnx("couldn't connect to server (maybe other -T options will work)");
	return 0;
}

static int
handshake_login(uint8_t *sc)
{
	uint8_t in[40], clogin[16], slogin[16], cc[16];
	size_t len;
	int ret;

	/* generate client-to-server login challenge and hashes */
	get_rand_bytes(cc, sizeof(cc));
	login_calculate(clogin, this.passwordmd5, sc);
	login_calculate(slogin, this.passwordmd5, cc);

	for (int i = 0; this.running && i < 5; i++) {
		send_login(clogin, cc);

		len = sizeof(in);
		if ((ret = handshake_waitdns(in, &len, 0, 'L', i + 1)) != 1 || len != 16) {
			fprintf(stderr, "Retrying login...\n");
			if (ret == 0) print_downstream_err();
			continue;
		}

		/* confirm server identity by checking the hash */
		if (memcmp(in, slogin, 16) != 0) {
			DEBUG(1, "hash mismatch! server: 0x%s, actual: 0x%s",
					tohexstr(in, 16, 0), tohexstr(slogin, 16, 1));
			fprintf(stderr, "Server authentication failed: hash mismatch! Trying again...\n");
			continue;
		}
		/* Login is now completed, now we can generate HMAC key */
		hmac_key_calculate(this.hmac_key, sc, 16, cc, 16, this.passwordmd5);
		this.connected = 1;
		memset(sc, 0, 16);
		memset(cc, 0, 16);
		return 0;

	}
	warnx("couldn't login to server");

	return 1;
}

static int
handshake_raw_udp()
{
	struct timeval tv;
	uint8_t in[4096];
	size_t len;
	fd_set fds;
	int ret;
	int got_addr = 0;
	// TODO fix raw UDP login

	memset(&this.raw_serv, 0, sizeof(this.raw_serv));
	got_addr = 0;

	fprintf(stderr, "Testing raw UDP data to the server (skip with -r)");
	for (int i = 0; this.running && i < 3; i++) {
		send_ip_request(); /* get server IP address */
		fprintf(stderr, ".");
		fflush(stderr);
		len = sizeof(in);
		if ((ret = handshake_waitdns(in, &len, 0, 'I', i + 1)) != 1) {
			if (ret == 0) print_downstream_err();
			continue;
		} else if (len == 5 && in[0] == 4) {
			/* Received IPv4 address */
			struct sockaddr_in *raw4_serv = (struct sockaddr_in *) &this.raw_serv;
			raw4_serv->sin_family = AF_INET;
			memcpy(&raw4_serv->sin_addr, &in[1], sizeof(struct in_addr));
			raw4_serv->sin_port = htons(53);
			this.raw_serv_len = sizeof(struct sockaddr_in);
			got_addr = 1;
			break;
		} else if (len == 17 && in[0] == 16) {
			/* Received IPv6 address */
			struct sockaddr_in6 *raw6_serv = (struct sockaddr_in6 *) &this.raw_serv;
			raw6_serv->sin6_family = AF_INET6;
			memcpy(&raw6_serv->sin6_addr, &in[1], sizeof(struct in6_addr));
			raw6_serv->sin6_port = htons(53);
			this.raw_serv_len = sizeof(struct sockaddr_in6);
			got_addr = 1;
			break;
		}
		DEBUG(1, "got invalid external IP: datalen %zu, data[0]=0x%02x", len, in[0]);
	}
	fprintf(stderr, "\n");
	if (!this.running)
		return 0;

	if (!got_addr) {
		fprintf(stderr, "Failed to get raw server IP, will use DNS mode.\n");
		return 0;
	}
	fprintf(stderr, "Server is at %s, trying raw login: ", format_addr(&this.raw_serv, this.raw_serv_len));
	fflush(stderr);

	/* do login against port 53 on remote server
	 * based on the old seed. If reply received,
	 * switch to raw udp mode */
	for (int i = 0; this.running && i < 4; i++) {
		tv.tv_sec = i + 1;
		tv.tv_usec = 0;

		send_raw_udp_login();

		FD_ZERO(&fds);
		FD_SET(this.dns_fd, &fds);

		ret = select(this.dns_fd + 1, &fds, NULL, NULL, &tv);

		if(ret > 0) {
			/* recv() needed for windows, dont change to read() */
			len = recv(this.dns_fd, in, sizeof(in), 0);
			if (ret >= (16 + RAW_HDR_LEN)) {
				char hash[16];
				// login_calculate(hash, 16, this.passwordmd5, seed - 1);
				if (memcmp(in, raw_header, RAW_HDR_IDENT_LEN) == 0
					&& RAW_HDR_GET_CMD(in) == RAW_HDR_CMD_LOGIN
					&& memcmp(&in[RAW_HDR_LEN], hash, sizeof(hash)) == 0) {

					fprintf(stderr, "OK\n");
					return 1;
				}
			}
		}
		fprintf(stderr, ".");
		fflush(stderr);
	}

	fprintf(stderr, "failed\n");
	return 0;
}

static int
codectest_validate(uint8_t *test, size_t testlen, uint8_t *datar, size_t datarlen)
/* returns:
   -2: test data was truncated
   -1: case swap, no need for any further test: error printed; or Ctrl-C
   0: not identical or error or timeout: error printed
   1: identical string returned */
{
	if (datarlen != testlen) {
		/* length mismatch: definitely unreliable */
		fprintf(stderr, "Test data length mismatch (wanted %zu, got %zu), retrying...\n",
				testlen, datarlen);
		return -2;
	}

	/* quick check if case swapped, to give informative error msg */
	if (*datar == 'A' || *(datar + 1) == 'a') {
		fprintf(stderr, "data changed to %scase, keeping codec Base32\n",
				(*datar == 'A') ? "upper" : "lower");
		return -1;
	}

	for (int k = 0; k < testlen; k++) {
		if (datar[k] != test[k]) {
			/* Definitely not reliable */
			if (isprint(datar[k]) && isprint(test[k])) {
				fprintf(stderr, "data[%d] '%c' gets changed into '%c'\n",
					k, test[k], datar[k]);
			} else {
				fprintf(stderr, "data[%d] 0x%02X gets changed into 0x%02X\n",
					k, test[k], datar[k]);
			}
			return 0;
		}
	}
	return 1; /* identical string */
}

static int
handshake_codectest(uint8_t *s, size_t slen, int dn, int tries, size_t testlen)
/* NOTE: *s must start with "aA" for case-swap check.
   dn==1 for downstream check, 0 for upstream check
   testlen is length of hostname (dn==0) or reply RDATA (dn==1) to fill
   	   (iodine DNS encoding overhead subtracted from RDATA length)
   Returns same as codectest_validate
*/
{
	uint8_t in[4096], test[4096], ulr, flags;
	uint16_t drlen;
	int ret;
	size_t inlen;
	char *stream = dn ? "downstream" : "upstream";

	if (testlen < 34) {
		DEBUG(1, "tried to send codectest too short for header (%zu)", testlen);
		return -2;
	}
	testlen -= dn ? 33 : 34;

	for (size_t i = 0; i < testlen; i++) {
		test[i] = s[i % slen];
	}

	for (int i = 0; this.running && i < tries; i++) {
		if (dn) {
			uint8_t encs[256];
			size_t encslen = sizeof(encs);
			encslen = b32->encode(encs, &encslen, s, slen);
			send_codectest(encs, encslen, testlen, 1);
		} else {
			send_codectest(test, (uint8_t) testlen, 0, 0);
		}

		inlen = sizeof(in);
		if ((ret = handshake_waitdns(in, &inlen, 33, 'U', i + 1)) != 1 || inlen < 4) {
			if (i < tries - 1) {
				fprintf(stderr, "Retrying %s codec test: ", stream);
				print_downstream_err();
			}
			continue;
		}
		
		uint8_t *p = in;
		flags = *p++;
		ulr = *p++;
		readshort(in, &p, &drlen);

		DEBUG(4, "RX codectest: flags=%hhx, ulr=%hhu, drlen=%zu (%hu), testlen=%zu",
				flags, ulr, inlen - 4, drlen, testlen);

		if (dn) { /* downstream check: datar is repeated base32 decoded dataq */
			return codectest_validate(test, testlen, in + 4, inlen - 4);
		} else { /* upstream check: datar is base32 encoded dataq */
			uint8_t buf[4096];
			size_t buflen = sizeof(buf);
			buflen = b32->decode(buf, &buflen, in + 4, inlen - 4);
			return codectest_validate(test, testlen, buf, buflen);
		}
	}

	if (!this.running)
		return -1;

	/* timeout */
	return 0;
}

static uint8_t
handshake_codec_autodetect(int dn)
/* dn: 1=downstream codec test, 0=upstream
 * Returns: codec ID of detected codec */
{
	static struct upenctest {
		char *data;
		size_t datalen;
		int rating;
		int inorder;
		uint8_t codec;
	} cases[] = {
			/* Try Base128, starting very gently to not draw attention */
			{ TEST_PAT128A, sizeof(TEST_PAT128A) - 1, 0, 0, C_BASE32 },
			{ TEST_PAT128B, sizeof(TEST_PAT128B) - 1, 0, 1, C_BASE32 },
			{ TEST_PAT128C, sizeof(TEST_PAT128C) - 1, 0, 2, C_BASE32 },
			{ TEST_PAT128D, sizeof(TEST_PAT128D) - 1, 0, 3, C_BASE32 },
			{ TEST_PAT128E, sizeof(TEST_PAT128E) - 1, 9, 4, C_BASE128 },

			/* Try raw data, test all bytes */
			{ TEST_PATRAWA, sizeof(TEST_PATRAWA) - 1, 0, 5, C_BASE32 },
			{ TEST_PATRAWB, sizeof(TEST_PATRAWB) - 1, 0, 6, C_BASE32 },
			{ TEST_PATRAWC, sizeof(TEST_PATRAWC) - 1, 0, 7, C_BASE32 },
			{ TEST_PATRAWD, sizeof(TEST_PATRAWD) - 1, 10, 8, C_RAW },
			/* Try Base64 (with plus sign) */
			{ TEST_PAT64, sizeof(TEST_PAT64) - 1, 5, 0, C_BASE64 },
			/* Try Base64u (with _u_nderscore) */
			{ TEST_PAT64U, sizeof(TEST_PAT64U) - 1, 3, 0, C_BASE64U },

	};
	/* Note: must start with "aA" for case check.
	   pat64: If 0129 work, assume 3-8 are okay too.

	   RFC1035 par 2.3.1 states that [A-Z0-9-] allowed, but only
	   [A-Z] as first, and [A-Z0-9] as last char _per label_.
	   Test by having '-' as last char.
	 */
	fprintf(stderr, "Autodetecting %s codec...", dn ? "downstream" : "upstream");

	int res, highest = -10000;
	size_t highestid;
	int inorder = 0;

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		if (inorder < cases[i].inorder)
			continue;

		if ((res = handshake_codectest((uint8_t *) cases[i].data,
				cases[i].datalen, 0, 2, cases[i].datalen + 34)) < 0) {
			if (!this.running) {
				fprintf(stderr, " aborted!\n");
				return C_UNSET;
			}
			fprintf(stderr, " using Base32\n");
			return C_BASE32; /* DNS swaps case, msg already printed; or Ctrl-C */
		} else if (res == 0) { /* data was changed */
			inorder = 0;
			continue;
		}

		if (cases[i].rating > highest && inorder >= cases[i].inorder) {
			highestid = i;
			highest = cases[i].rating;
		}
		inorder++;
	}

	char *encname = get_encoder(cases[highestid].codec)->name;
	fprintf(stderr, " using %s\n", encname ? encname : "raw");
	return cases[highestid].codec;
}

static int
handshake_qtype_autodetect()
/* Returns 1: this.do_qtype set,  0: problem, program exit */
{
	/* list of available query types from good to OK */
	uint16_t qtypes[] = {
			T_NULL, T_PRIVATE, T_TXT, /* single RR has unlimited data */
			T_SRV, T_MX, /* multiple RRs supported */
			T_DNAME, T_PTR, T_CNAME, T_A, T_AAAA, T_A6 /* single RR with hostname */
	};
	size_t numqtypes = sizeof(qtypes) / 2;

	uint8_t test[100], raw[50];
	size_t testlen;
	int ret, qtypenum;
	uint16_t working = this.do_qtype;

	fprintf(stderr, "Autodetecting DNS query type (use -T to override)");
	fflush(stderr);

	/* try different qtypes from best to worst */
	for (qtypenum = 0; qtypenum < numqtypes && this.running; qtypenum++) {
		fprintf(stderr, ".");
		fflush(stderr);

		get_rand_bytes(raw, sizeof(raw)); /* generate very "soft" test, only base32 chars */
		testlen = sizeof(test);
		testlen = b32->encode(test, &testlen, raw, sizeof(raw));
		this.do_qtype = qtypes[qtypenum];
		if ((ret = handshake_codectest(test, testlen, 0, 3, 80)) == 1) {
			/* query type works */
			fprintf(stderr, " Type %s works", get_qtype_name(this.do_qtype));
			fflush(stderr);
			working = this.do_qtype;
			break;
		}
	}

	fprintf(stderr, "\n");

	if (!this.running) {
		warnx("Stopped while autodetecting DNS query type (try setting manually with -T)");
		return 0;
	}

	/* finished, found at least some kind of working query type */
	this.do_qtype = working;

	return 1; /* "using qtype" message printed in handshake function */
}

static int
handshake_edns0_check()
/* Returns:
   0: problem; or Ctrl-C
   1: this.use_edns0 set correctly
*/
{
	uint8_t test[100], raw[50];
	size_t testlen = sizeof(test);
	int ret;

	get_rand_bytes(raw, sizeof(raw)); /* generate very "soft" test, only base32 chars */
	testlen = b32->encode(test, &testlen, raw, sizeof(raw));

	this.use_edns0 = 1;
	if ((ret = handshake_codectest(test, testlen, 1, 5, 100)) == 1) {;
		fprintf(stderr, "Using EDNS0 extension\n");
		return 1;
	} else {
		this.use_edns0 = 0;
		if (!this.running)
			return 0;

		fprintf(stderr, "DNS relay does not support EDNS0 extension\n");
		return 0;
	}
}

static int
handshake_switch_options()
{
	uint8_t in[100], flags[2];
	size_t len;
	int ret;
	fprintf(stderr, "Sending connection options: %s mode, compression %s, ",
			this.lazymode ? "lazy" : "immediate", this.compression_down ? "enabled" : "disabled");
	if (this.use_remote_forward) {
		fprintf(stderr, "forwarding stdin to udp://%s:%hu...",
				format_addr(&this.remote_forward_addr, this.remote_forward_addr_len),
				((struct sockaddr_in *) &this.remote_forward_addr)->sin_port);
	} else {
		fprintf(stderr, "request IP on TUN interface...");
	}

	for (int i = 0; this.running && i < 5; i++) {
		send_server_options(flags);

		len = sizeof(in);
		uint8_t *p = in, inflags[2];
		uint16_t dnfragsize;
		if ((ret = handshake_waitdns(in, &len, 0, 'O', i + 1)) != 1) {
			DEBUG(2, "\ngot options reply, ret=%d, len=%zu, dderr=%d", ret, len, downstream_decode_err);
			if (downstream_decode_err == (E_BADOPTS | DDERR_IS_ANS)) {
				fprintf(stderr, "rejected by server!\n");
				return 0;
			} else {
				print_downstream_err();
			}
			fprintf(stderr, ".");
			continue;
		}

		readdata(&p, inflags, 2); /* check reply flags from server */
		readshort(in, &p, &dnfragsize);
		if (len < 4 || memcmp(flags, inflags, 2) != 0 || dnfragsize != this.maxfragsize_down) {
			DEBUG(1, "\ninvalid reply len=%zu, flags: 0x%s, expected 0x%s",
					len, tohexstr(inflags, 2, 1), tohexstr(flags, 2, 0));
			return 0;
		} else if (this.use_remote_forward && len == 4) {
			/* if we don't get BADOPTS, UDP forward was accepted */
			fprintf(stderr, "done, UDP forward accepted.\n");
			return 1;
		} else if (!this.use_remote_forward && len == 15) {
			/* decode TUN IP/MTU configuration */
			struct in_addr ip;
			char client[20], server[20];
			uint16_t mtu;
			uint8_t netmask;
			readdata(&p, (uint8_t *) &ip.s_addr, 4);
			strncpy(server, inet_ntoa(ip), sizeof(server) - 1);
			readdata(&p, (uint8_t *) &ip.s_addr, 4);
			strncpy(client, inet_ntoa(ip), sizeof(client) - 1);
			readshort(in, &p, &mtu);
			netmask = *p++;
			fprintf(stderr, "done.\nServer tunnel IP is %s, our IP is %s/%hhu\n",
					server, client, netmask);

			if (tun_setip(client, server, netmask) == 0 && tun_setmtu(mtu) == 0) {
				return 1;
			} else {
				errx(4, "Failed to set IP and MTU");
			}
		} else {
			/* invalid reply, try again */
			DEBUG(1, "\ninvalid options reply from server! len=%zu", len);
		}
		fprintf(stderr, ".");
	}

	if (!this.running)
		return 0;

	fprintf(stderr, "No reply from server on options switch.\n");

	return 0;
}

static int
handshake_autoprobe_fragsize()
/* probe the maximum size of data that can be iodine-DNS-encoded into a reply
 * of selected type using given downstream encoding */
{
	uint8_t test[256];
	int ret, max_fragsize = 768, proposed_fragsize = 768, range = 768;

	get_rand_bytes(test, sizeof(test));

	fprintf(stderr, "Autoprobing max downstream fragment size... (skip with -m fragsize)");
	while (this.running && range > 0 && (range >= 8 || max_fragsize < 300) && max_fragsize > 34) {
		/* stop the slow probing early when we have enough bytes anyway */
		for (int i = 0; this.running && i < 3; i++) {
			ret = handshake_codectest(test, this.maxfragsize_up, 1, 1, proposed_fragsize);

			if (ret == 1) { /* reply was valid - fragsize works */ 
				fprintf(stderr, "%d ok.. ", proposed_fragsize);
				fflush(stderr);
				max_fragsize = proposed_fragsize;
			} else if (ret == -2 || ret == -1) {
				break; /* data truncated or corrupted - not reliable */
			}

			/* bad header or other error; try again */
			fprintf(stderr, ".");
			fflush(stderr);
		}

		range >>= 1;
		if (max_fragsize == proposed_fragsize) {
			/* Try bigger */
			proposed_fragsize += range;
		} else {
			/* Try smaller */
			fprintf(stderr, "%d not ok.. ", proposed_fragsize);
			fflush(stderr);
			proposed_fragsize -= range;
		}
	}
	if (!this.running) {
		fprintf(stderr, "\nstopped while autodetecting fragment size (Try setting manually with -m)");
		return 0;
	}
	if (max_fragsize <= 34) {
		/* Tried all the way down to 34 and found no good size.
		   But we _did_ do all handshake before this, so there must
		   be some workable connection. */
		fprintf(stderr, "\nfound no usable fragment size.\n");
		fprintf(stderr, "Try setting -M to 200 or lower, or using -T or -O options.");
		return 0;
	}

	fprintf(stderr, "will use %d\n", max_fragsize);

	/* need 1200 / 16frags = 75 bytes fragsize */
	if (max_fragsize < 82) {
		fprintf(stderr, "Note: this probably won't work well.\n");
		fprintf(stderr, "Try setting -M to 200 or lower, or try other DNS types (-T option).\n");
	} else if (max_fragsize < 202 &&
	    (this.do_qtype == T_NULL || this.do_qtype == T_PRIVATE || this.do_qtype == T_TXT ||
	     this.do_qtype == T_SRV || this.do_qtype == T_MX)) {
		fprintf(stderr, "Note: this isn't very much.\n");
		fprintf(stderr, "Try setting -M to 200 or lower, or try other DNS types (-T option).\n");
	}

	return max_fragsize;
}

static void
handshake_set_timeout()
{
	uint8_t in[4096];
	int ret, id;
	size_t len;

	fprintf(stderr, "Setting window sizes to %zu frags upstream, %zu frags downstream...\n",
		this.windowsize_up, this.windowsize_down);

	fprintf(stderr, "Calculating round-trip time...");

	/* Reset RTT stats */
	this.num_immediate = 0;
	this.rtt_total_ms = 0;

	/* find the RTT by sending a few pings with immediate responses */
	for (int set = 0; this.running && set <= !!this.autodetect_server_timeout; set++) {
		/* run once to get RTT and again to set the timeout values */
		for (int i = 0; this.running && i < 5; i++) {
			id = (set && this.autodetect_server_timeout) ?
				update_server_timeout(1) : send_ping(1, 0);

			len = sizeof(in);
			if ((ret = handshake_waitdns(in, &len, 0, 'P', i + 1)) != 1) {
				/* error responses are not so useful for RTT calculation */
				fprintf(stderr, "!");
				got_response(id, 0);
				continue;
			}
			got_response(id, 1);

			if (set) {
				fprintf(stderr, "done.");
				break;
			} else {
				fprintf(stderr, ".");
			}
		}
	}
	if (!this.running)
		return;

	fprintf(stderr, "\nDetermined round-trip time of %ld ms, using server timeout of %ld ms.\n",
		this.rtt_total_ms / this.num_immediate, this.server_timeout_ms);
}

int
client_handshake()
/* returns 1 on success, 0 on error */
{
	uint8_t server_chall[16];
	int autoqtype = 0, r;

	/* qtype message printed in handshake function */
	if (this.do_qtype == T_UNSET) {
		autoqtype = 1;
		this.do_qtype = T_A; /* use A queries for login process */
	}

	fprintf(stderr, "Using DNS type %s queries%s\n", get_qtype_name(this.do_qtype),
			autoqtype ? " for login" : "");

	this.cmc_up = rand();

	if (!handshake_version(server_chall)) {
		return 0;
	}

	if ((r = handshake_login(server_chall))) {
		return r;
	}

	/* now that we are authenticated, try to find best possible settings */
	if (this.raw_mode) {
		if (handshake_raw_udp()) { /* test sending UDP packets */
			this.conn = CONN_RAW_UDP;
			this.max_timeout_ms = 10000;
			this.compression_down = 1;
			this.compression_up = 1;
			fprintf(stderr, "Sending raw UDP traffic directly to %s\n",
					format_addr(&this.raw_serv, this.raw_serv_len));
			return 0;
		}
	} else {
		fprintf(stderr, "Skipping raw mode check\n");
	}

	/* using CONN_DNS_NULL */
	if (!handshake_edns0_check()) {
		return 0;
	}

	if (!handshake_qtype_autodetect()) {
		return 0;
	}

	if (this.enc_up == C_UNSET) {
		this.enc_up = handshake_codec_autodetect(0);
		if (!this.running)
			return -1;
	}

	if (this.enc_down == C_UNSET) {
		this.enc_down = handshake_codec_autodetect(1);
		if (!this.running)
			return -1;
	}

	if (this.autodetect_frag_size) {
		this.maxfragsize_down = handshake_autoprobe_fragsize();
		if (!this.maxfragsize_down) {
			return 1;
		}
	}

	/* Set server-side options (up/down codec, compression, fraglen) and request desired connection. */
	if (!handshake_switch_options()) {
		return -1;
	}

	/* init windowing protocol */
	this.outbuf = window_buffer_init(WINDOW_BUFFER_LENGTH, (0 == this.windowsize_up ? 1 : this.windowsize_up), this.maxfragsize_up, WINDOW_SENDING);
	/* Incoming buffer max fragsize doesn't matter */
	this.inbuf = window_buffer_init(WINDOW_BUFFER_LENGTH, this.windowsize_down, MAX_FRAGSIZE_DOWN, WINDOW_RECVING);

	/* init query tracking */
	this.num_untracked = 0;
	this.num_pending = 0;
	this.pending_queries = calloc(PENDING_QUERIES_LENGTH, sizeof(struct query_tuple));
	for (int i = 0; i < PENDING_QUERIES_LENGTH; i++)
		this.pending_queries[i].id = -1;

	/* set server window/timeout parameters and calculate RTT */
	handshake_set_timeout();

	DEBUG(1, "Client handshake completed!");

	return 1;
}

