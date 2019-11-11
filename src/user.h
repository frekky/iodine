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

#ifndef __USER_H__
#define __USER_H__

#define USERS 16

enum user_conn_type {
	USER_CONN_NONE,
	USER_CONN_TUNIP,
	USER_CONN_UDPFORWARD,
};

struct tun_user {
	uint8_t server_chall[16];
	uint8_t hmac_key[16];
	struct sockaddr_storage host;
	struct sockaddr_storage remoteforward_addr;
	struct frag_buffer *incoming;
	struct frag_buffer *outgoing;
	struct qmem_buffer *qmem;
	size_t fragsize;
	socklen_t hostlen;
	socklen_t remoteforward_addr_len;
	time_t last_pkt;
	in_addr_t tun_ip;
	uint32_t cmc_up;
	uint32_t cmc_down;
	int remote_udp_fd;
	enum connection conn; /* using raw UDP or DNS packets */
	enum user_conn_type tuntype; /* type of iodine tunnel connection requested, USER_CONN_NONE if disconnected */
	int hmaclen_up; /* byte length of HMAC in upstream data packets */
	int hmaclen_down; /* byte length of HMAC in downstream data packets */
	int max_queries; /* maximum number of queries that the client will send at any one time */
	char lazy;
	char id;
	uint8_t downenc;
	uint8_t upenc;
	char down_compression;
	char active;
	char authenticated;
	char authenticated_raw;
};

extern struct tun_user *users;
extern int created_users;

int user_sending(int user);
int all_users_waiting_to_send();
int user_active(int i);
int is_valid_user(int userid);
void user_reset(int userid);
int init_users(in_addr_t, int);
const char* users_get_first_ip();
int find_user_by_ip(uint32_t);
int find_available_user();
int set_user_udp_fds(fd_set *fds);
int user_open_udp(int userid);
void user_close_udp(int userid);

#endif
