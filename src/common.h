/*
 * Copyright (c) 2006-2015 Erik Ekman <yarrick@kryo.se>,
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

#ifndef __COMMON_H__
#define __COMMON_H__

#ifdef DARWIN
#ifndef __APPLE_USE_RFC_3542
#define __APPLE_USE_RFC_2292
#endif
#endif

/* Last byte of raw header is the command */
#define RAW_HDR_LEN			20
#define RAW_HDR_IDENT_LEN	3
#define RAW_HDR_CMD			3
#define RAW_HDR_CMC			4
#define RAW_HDR_HMAC		8
#define RAW_HDR_HMAC_LEN	12
#define RAW_HDR_CMD_LOGIN	0x10
#define RAW_HDR_CMD_DATA	0x20
#define RAW_HDR_CMD_PING	0x30

#define RAW_HDR_CMD_MASK	0xF0
#define RAW_HDR_USR_MASK	0x0F
#define RAW_HDR_GET_CMD(x)	((x)[RAW_HDR_CMD] & RAW_HDR_CMD_MASK)
#define RAW_HDR_GET_USR(x)	((x)[RAW_HDR_CMD] & RAW_HDR_USR_MASK)

#define MAX_CMC (0xFFFFFFFF)
#define CMC(cmc) (cmc = ((cmc + 1) == MAX_CMC ? 0 : (cmc + 1)))

/* convert uppercase hex char [A-F0-9] to int */
#define HEX2INT(c) 	((c >= 'A' && c <= 'F') ? (c - 'A' + 10) : (c - '0'))

extern const unsigned char raw_header[RAW_HDR_LEN];

/* DNS Downstream header flags */
#define DH_HMAC96	(0 << 4)
#define DH_HMAC32	(1 << 4)
#define DH_ERROR	(1 << 3)
#define DH_ERR(x)	(E_##x | DH_ERROR)

/* Codec type IDs and type chars (backwards compatibility) */
#define C_RAW		0x0 // 'R'
#define C_BASE64	0x1 // 'S'
#define C_BASE32	0x2	// 'T'
#define C_BASE64U	0x3 // 'U'
#define C_BASE128	0x4 // 'V'
#define C_UNSET		0x8

#define C_CHAR2NUM(c)	((toupper(c) - 'R') & 7)
#define C_NUM2CHAR(n)	((n) & 7 + 'R')

/* Error codes */
#define E_BADLEN	0x0
#define E_BADAUTH	0x1
#define E_BADOPTS	0x2
#define E_BADLOGIN	0x3

#define WINDOW_BUFFER_LENGTH	64

#ifdef WINDOWS32
#include "windows.h"
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#endif

#include "dns.h"

#define DNS_PORT 53

#if _WIN32 || _WIN64
#if _WIN64
#define BITS_64
#else
#define BITS_32
#endif
#endif

#if __GNUC__
#if __x86_64__ || __ppc64__
#define BITS_64 1
#else
#define BITS_32 1
#endif
#endif

/* Determine appropriate format specifier for long int on 32/64 bit systems */
#if BITS_64
#define FMT_LONG "l"
#else
#define FMT_LONG ""
#endif

/* For convenience and shortness */
#define L FMT_LONG

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#if defined IP_MTU_DISCOVER
  /* Linux */
# define IP_OPT_DONT_FRAG IP_MTU_DISCOVER
# define DONT_FRAG_VALUE IP_PMTUDISC_DO
#elif defined IP_DONTFRAG
  /* FreeBSD */
# define IP_OPT_DONT_FRAG IP_DONTFRAG
# define DONT_FRAG_VALUE 1
#elif defined IP_DONTFRAGMENT
  /* Winsock2 */
# define IP_OPT_DONT_FRAG IP_DONTFRAGMENT
# define DONT_FRAG_VALUE 1
#endif

#if defined IP_RECVDSTADDR
# define DSTADDR_SOCKOPT IP_RECVDSTADDR
# define dstaddr(x) ((struct in_addr *) CMSG_DATA(x))
#elif defined IP_PKTINFO
# define DSTADDR_SOCKOPT IP_PKTINFO
# define dstaddr(x) (&(((struct in_pktinfo *)(CMSG_DATA(x)))->ipi_addr))
#endif

#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

#ifndef GITREVISION
#define GITREVISION "GIT"
#endif

#define DOWNSTREAM_DATA_HDR	2
#define DOWNSTREAM_PING_HDR	9
#define UPSTREAM_DATA_HDR	2

#define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__);

#define PRINT_TIMESTAMP \
		struct timeval currenttime;\
		gettimeofday(&currenttime, NULL);\
		DEBUG_PRINT("%03ld.%03ld ", (long) currenttime.tv_sec, (long) currenttime.tv_usec / 1000); \

//#define DEBUG_BUILD

/* handy debug printing macro */
#ifdef DEBUG_BUILD
#define IF_DEBUG(level, what_do) \
		if (debug >= level) { \
			what_do; \
		}

/* print the base debug print header (timestamp, debug level, function, file:line) */
#define _DEBUG_PRINT(level, extra_header, ...) \
		IF_DEBUG(level, \
			PRINT_TIMESTAMP \
			DEBUG_PRINT("[D%d %s %s:%d] ", level, __func__, __FILE__, __LINE__) \
			extra_header \
			DEBUG_PRINT(__VA_ARGS__) \
			DEBUG_PRINT("\n") \
		)
#else
/* for non-debug builds, the compiler will optimise out any debug prints more than level 2 */
#define IF_DEBUG(level, what_do) if (level <= 2 && debug >= level) { what_do; }

/* print some basic info as well as the message */
#define _DEBUG_PRINT(level, extra_header, ...) \
		IF_DEBUG(level, \
			DEBUG_PRINT("[D%d:%s] ", level, __func__) \
			extra_header \
			DEBUG_PRINT(__VA_ARGS__) \
			DEBUG_PRINT("\n") \
		)
#endif

/* regular debug print macro */
#define DEBUG(level, ...) _DEBUG_PRINT(level, , __VA_ARGS__)


// TODO replace struct query with struct dns_packet
struct query {
	struct sockaddr_storage destination;
	struct sockaddr_storage from;
	uint8_t name[QUERY_NAME_SIZE];
	struct timeval time_recv;
	size_t len;
	socklen_t dest_len;
	socklen_t fromlen;
	int id;	/* id < 0: unusued */
	uint16_t type;
	uint16_t rcode;
};

enum connection {
	CONN_RAW_UDP = 0,
	CONN_DNS_NULL,
	CONN_MAX
};

extern int debug;		/* enable debug level */

void check_superuser(void (*usage_fn)(void));
char *tohexstr(const uint8_t *data, size_t datalen, size_t bufnum);
char *format_host(const uint8_t *host, size_t hostlen, size_t bufnum);
char *format_addr(struct sockaddr_storage *sockaddr, int sockaddr_len);
int get_addr(char *, int, int, int, struct sockaddr_storage *);
int open_dns(struct sockaddr_storage *, size_t);
int open_dns_opt(struct sockaddr_storage *sockaddr, size_t sockaddr_len, int v6only);
int open_dns_from_host(char *host, int port, int addr_family, int flags);
int read_packet(int fd, uint8_t *pkt, size_t *pktlen, struct pkt_metadata *m);
void send_raw(int fd, uint8_t *buf, size_t buflen, int user, int cmd, uint32_t cmc,
		uint8_t *hmac_key, struct sockaddr_storage *from, socklen_t fromlen);
void close_socket(int);

int open_tcp_nonblocking(struct sockaddr_storage *addr, char **error);
int check_tcp_error(int fd, char **error);

void do_chroot(char *);
void do_setcon(char *);
void do_detach();
void do_pidfile(char *);

void read_password(char*, size_t);

int check_topdomain(char *, char **);

int socket_set_blocking(int fd, int blocking);


extern double difftime(time_t, time_t);

#if defined(WINDOWS32) || defined(ANDROID)
#ifndef ANDROID
int inet_aton(const char *cp, struct in_addr *inp);
#endif

void err(int eval, const char *fmt, ...);
void warn(const char *fmt, ...);
void errx(int eval, const char *fmt, ...);
void warnx(const char *fmt, ...);
#endif

#ifndef WINDOWS32
void fd_set_close_on_exec(int fd);
#endif

void get_rand_bytes(uint8_t *buf, size_t len);

#endif
