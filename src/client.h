/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
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

#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "window.h"

extern int debug;
extern int stats;

#define PENDING_QUERIES_LENGTH (MAX(this.windowsize_up, this.windowsize_down) * 4)
#define INSTANCE this

/* Upstream encoding tests */
#define TEST_PAT64		"aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ+0129-"
#define TEST_PAT64U		"aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ_0129-"
#define TEST_PAT128A	"aA-Aaahhh-Drink-mal-ein-J\344germeister-"
#define TEST_PAT128B	"aA-La-fl\373te-na\357ve-fran\347aise-est-retir\351-\340-Cr\350te"
#define TEST_PAT128C	"aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ"
#define TEST_PAT128D	"aA0123456789\274\275\276\277" \
      "\300\301\302\303\304\305\306\307\310\311\312\313\314\315\316\317"
#define TEST_PAT128E	"aA" \
      "\320\321\322\323\324\325\326\327\330\331\332\333\334\335\336\337" \
      "\340\341\342\343\344\345\346\347\350\351\352\353\354\355\356\357" \
      "\360\361\362\363\364\365\366\367\370\371\372\373\374\375"
#define TEST_PATRAWA	"aA\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" \
	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F" \
	"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F" \
	"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40"

#define TEST_PATRAWB	"aA\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F" \
		"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F" \
		"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F" \
		"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F"

#define TEST_PATRAWC	"aA\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F" \
		"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F" \
		"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF" \
		"\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"

#define TEST_PATRAWD	"aA\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF" \
		"\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF" \
		"\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF" \
		"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"

struct nameserv {
	struct sockaddr_storage addr;
	int len;
};

struct client_instance {
	uint8_t topdomain[128]; /* topdomain in DNS-encoded form */
	uint8_t passwordmd5[16];
	uint8_t hmac_key[16];
	char **nameserv_hosts;
	struct nameserv *nameserv_addrs;
	struct frag_buffer *outbuf; /* outgoing and incoming window buffers */
	struct frag_buffer *inbuf;
	struct query_tuple *pending_queries;	/* query tracking data */
	int autodetect_frag_size;
	int hostname_maxlen;	/* maximum length of generated hostnames (incl. topdomain) */
	int raw_mode;			/* enable raw UDP mode */
	int use_edns0;			/* use EDNS0 extension for longer DNS packets */
	int autodetect_server_timeout;
	int autodetect_delay_variance;
	int stats;		/* enable stats printout every # seconds */
	int running;	/* always == 1 unless shutting down */
	int connected;	/* using desired tunnel mode + ready to send data */
	int lazymode;	/* lazymode enabled */

	/* DNS nameserver info */
	size_t nameserv_hosts_len;
	size_t nameserv_addrs_count;
	int current_nameserver;
	struct sockaddr_storage raw_serv;
	socklen_t raw_serv_len;

	/* Remote UDP forwarding stuff (for -R) */
	struct sockaddr_storage remote_forward_addr;
	socklen_t remote_forward_addr_len;
	int use_remote_forward; /* 0 if no forwarding used */

	int tun_fd;		/* file descriptor of tunnel interface */
	int dns_fd;		/* file descriptor of DNS UDP socket */

#ifdef OPENBSD
	int rtable;
#endif


	uint16_t rand_seed; /* TODO remove this */

	/* Current up/downstream window data */

	size_t windowsize_up;
	size_t windowsize_down;
	size_t maxfragsize_down;
	size_t maxfragsize_up;
	int next_downstream_ack; /* Next downstream seqID to be ACK'd (-1 if none pending) */

	/* Connection statistics and tracking */
	size_t num_pending;				/* number of queries in pending_queries */
	size_t num_immediate;
	size_t num_timeouts;
	size_t num_untracked;
	size_t num_servfail;
	size_t num_badauth;
	size_t num_sent;
	size_t num_recv;
	size_t send_query_sendcnt;
	size_t send_query_recvcnt;
	size_t num_frags_sent;
	size_t num_frags_recv;
	size_t num_pings;
	uint16_t lastid;		/* id of last sent query */
	uint16_t do_qtype;		/* set query type to send */
	uint32_t cmc_up;		/* CMC of next query */
	uint32_t cmc_down;		/* highest CMC of downstream replies */
	time_t max_timeout_ms;
	time_t send_interval_ms;
	time_t min_send_interval_ms;
	time_t server_timeout_ms;	/* Server response timeout in ms and downstream window timeout */
	time_t downstream_timeout_ms;
	double downstream_delay_variance;
	time_t rtt_total_ms;	/* Cumulative Round-Trip-Time in ms */


	char userid;			/* My userid at the server */
	char userid_char;		/* used when sending (lowercase) */

	uint8_t enc_down;		/* encoder type ID to use for downstream data */
	uint8_t enc_up;			/* encoder for upstream data */
	int compression_up;		/* Upstream/downstream compression flags */
	int compression_down;
	unsigned max_retries;	/* number of times to resend fragments */
	enum connection conn;	/* connection mode (NULL/RAW) */
	time_t lastdownstreamtime;	/* timestamp of last received packet from server */
};

struct query_tuple {
	int id; /* DNS query / response ID */
	struct timeval time; /* time sent or 0 if cleared */
};

extern struct client_instance this;

void client_init();
void client_stop();

enum connection client_get_conn();
const char *client_get_raw_addr();

void client_rotate_nameserver();
void client_set_hostname_maxlen(size_t i);

int client_handshake();
int client_tunnel();

#endif
