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

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef WINDOWS32
#include <winsock2.h>
#else
#include <netdb.h>
#endif

#include "common.h"
#include "encoding.h"
#include "cache.h"
#include "server.h"
#include "user.h"
#include "window.h"

struct tun_user *users;
unsigned usercount;
int created_users;

int
init_users(in_addr_t my_ip, int netbits)
{
	int i;
	int skip = 0;
	char newip[16];

	int maxusers;

	in_addr_t netmask = 0;
	struct in_addr net;
	struct in_addr ipstart;

	for (i = 0; i < netbits; i++) {
		netmask = (netmask << 1) | 1;
	}
	netmask <<= (32 - netbits);
	net.s_addr = htonl(netmask);
	ipstart.s_addr = my_ip & net.s_addr;

	maxusers = (1 << (32-netbits)) - 3; /* 3: Net addr, broadcast addr, iodined addr */
	usercount = MIN(maxusers, USERS);

	if (users) free(users);
	users = calloc(usercount, sizeof(struct tun_user));
	for (i = 0; i < usercount; i++) {
		in_addr_t ip;
		users[i].id = i;
		snprintf(newip, sizeof(newip), "0.0.0.%d", i + skip + 1);
		ip = ipstart.s_addr + inet_addr(newip);
		if (ip == my_ip && skip == 0) {
			/* This IP was taken by iodined */
			skip++;
			snprintf(newip, sizeof(newip), "0.0.0.%d", i + skip + 1);
			ip = ipstart.s_addr + inet_addr(newip);
		}
		users[i].tun_ip = ip;
		net.s_addr = ip;
	}

	return usercount;
}

void
user_reset(int userid)
{
	struct tun_user *u = &users[userid];
	/* reset all stats */
	u->hostlen = 0;
	u->active = 1;
	u->authenticated = 0;
	u->authenticated_raw = 0;
	u->use_hmac = 0;
	u->last_pkt = time(NULL);
	u->fragsize = MAX_FRAGSIZE;
	u->conn = CONN_DNS_NULL;
	u->remote_forward_connected = 0;
	u->remoteforward_addr_len = 0;
	u->remote_udp_fd = -1;
	u->remoteforward_addr.ss_family = AF_UNSPEC;
	u->fragsize = 150; /* very safe */
	u->conn = CONN_DNS_NULL;
	u->tuntype = USER_CONN_NONE;
	u->down_compression = 1;
	u->lazy = 0;
	u->cmc_down = rand();
	u->upenc = C_BASE32;
	u->downenc = C_BASE32;
	u->dns_timeout.tv_sec = 1; /* 1 second default lazymode timeout */
	u->dns_timeout.tv_usec = 0;
	get_rand_bytes(u->server_chall, sizeof(u->server_chall));
	window_buffer_destroy(u->outgoing); /* window buffers allocated later */
	window_buffer_destroy(u->incoming);
	u->outgoing = NULL;
	u->incoming = NULL;
	qmem_destroy(u->qmem);
	u->qmem = qmem_init(QMEM_LEN);
}

const char*
users_get_first_ip()
{
	struct in_addr ip;
	ip.s_addr = users[0].tun_ip;
	return strdup(inet_ntoa(ip));
}

int
find_user_by_ip(uint32_t ip)
{
	for (int i = 0; i < usercount; i++) {
		if (user_active(i) && users[i].authenticated && ip == users[i].tun_ip) {
			return i;
		}
	}
	return -1;
}

int
user_sending(int user)
{
	return users[user].outgoing->numitems > 0;
}

int
user_active(int i)
{
	return users[i].active && difftime(time(NULL), users[i].last_pkt) < 60;
}

int
all_users_waiting_to_send()
/* If this returns true, then reading from tun device is blocked.
   So only return true when all clients have insufficient space in
   outgoing buffer, so that sending back-to-back is possible
   without going through another select loop. */
{
	int numactive = 0;
	for (int i = 0; i < usercount; i++) {
		if (user_active(i) && users[i].outgoing) {
			if (users[i].outgoing->length - users[i].outgoing->numitems > 8)
				return 0;
			numactive ++;
		}
	}

	/* no users waiting if there are no users */
	if (numactive == 0)
		return 0;

	return 1;
}

int
find_available_user()
{
	for (int id = 0; id < usercount; id++) {
		/* Not used at all or not used in one minute */
		if (!user_active(id)) {
			user_reset(id);
			return id;
		}
	}
	return -1;
}

int
is_valid_user(int userid)
/* checks if userid given points to a user with valid data */
{
	if (userid < 0 || userid >= created_users ) {
		return 1;
	}
	return user_active(userid);
}

/* This will not check that user has passed login challenge */
int
check_user_ip(int userid, struct sockaddr_storage from, socklen_t fromlen)
{
	struct tun_user *u = &users[userid];

	if (from.ss_family != u->host.ss_family) {
		return 0;
	}
	/* Check IPv4 */
	if (from.ss_family == AF_INET) {
		struct sockaddr_in *expected, *received;

		expected = (struct sockaddr_in *) &u->host;
		received = (struct sockaddr_in *) &from;
		return memcmp(&expected->sin_addr, &(received->sin_addr), sizeof(struct in_addr)) == 0;
	}
	/* Check IPv6 */
	if (from.ss_family == AF_INET6) {
		struct sockaddr_in6 *expected, *received;

		expected = (struct sockaddr_in6 *) &u->host;
		received = (struct sockaddr_in6 *) &from;
		return memcmp(&expected->sin6_addr, &received->sin6_addr, sizeof(struct in6_addr)) == 0;
	}
	/* Unknown address family */
	return 0;
}

int
set_user_udp_fds(fd_set *fds, int conn_status)
/* Add UDP forward FDs to fd_set for users with given connection status; returns largest FD added */
{
	int max_fd = 0;
	for (int userid = 0; userid < created_users; userid ++) {
		if (user_active(userid) && users[userid].remoteforward_addr_len > 0
			&& users[userid].remote_forward_connected == conn_status) {
			FD_SET(users[userid].remote_udp_fd, fds);
			max_fd = MAX(max_fd, users[userid].remote_udp_fd);
		}
	}
	return max_fd;
}

