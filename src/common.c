/* Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
 * Copyright (c) 2007 Albert Lee <trisk@acm.jhu.edu>.
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

#include <time.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>

#ifdef WINDOWS32
#include <winsock2.h>
#include <conio.h>
#else
#include <arpa/nameser.h>
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif
#include <termios.h>
#include <err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#ifdef HAVE_SETCON
# include <selinux/selinux.h>
#endif

#include "common.h"
#include "encoding.h"
#include "dns.h"
#include "read.h"
#include "hmac_md5.h"

char hex[] = "0123456789abcdef";

/* The raw header used when not using DNS protocol */
const unsigned char raw_header[RAW_HDR_LEN] = {
		0x10, 0xd1, 0x9e, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};

int debug = 0;

/* daemon(3) exists only in 4.4BSD or later, and in GNU libc */
#if !defined(ANDROID) && !defined(WINDOWS32) && !(defined(BSD) && (BSD >= 199306)) && !defined(__GLIBC__)
static int daemon(int nochdir, int noclose)
{
 	int fd, i;

 	switch (fork()) {
 		case 0:
 			break;
 		case -1:
 			return -1;
 		default:
 			_exit(0);
 	}

 	if (!nochdir) {
 		chdir("/");
 	}

 	if (setsid() < 0) {
 		return -1;
 	}

 	if (!noclose) {
 		if ((fd = open("/dev/null", O_RDWR)) >= 0) {
 			for (i = 0; i < 3; i++) {
 				dup2(fd, i);
 			}
 			if (fd > 2) {
 				close(fd);
 			}
 		}
 	}
	return 0;
}
#endif

#if defined(__BEOS__) && !defined(__HAIKU__)
int setgroups(int count, int *groups)
{
	/* errno = ENOSYS; */
	return -1;
}
#endif


void
check_superuser(void (*usage_fn)(void))
{
#ifndef WINDOWS32
	if (geteuid() != 0) {
		warnx("Run as root and you'll be happy.\n");
		usage_fn();
		/* NOTREACHED */
	}
#endif
}

#define MAX_DATA_LEN 256
char *
tohexstr(uint8_t *data, size_t datalen, size_t bufnum)
/* nicely formats binary data as ASCII hex null-terminated string */
{
	static char bufarr[(MAX_DATA_LEN * 2 + 1) * 2];
	char *buf = bufarr + bufnum * (MAX_DATA_LEN * 2 + 1);
	if (datalen > MAX_DATA_LEN || bufnum >= 2) {
		return NULL;
	}

	size_t i = 0;
	for (; i < datalen; i++) {
		buf[i * 2] = hex[(data[i] & 0xF0) >> 4];
		buf[i * 2 + 1] = hex[data[i] & 0x0F];
	}
	buf[i * 2] = 0;
	return buf;
}

char *
format_host(uint8_t *host, size_t hostlen, size_t bufnum)
/* nicely formats DNS-encoded hostname with printable chars
 * returns null-terminated string */
{
	static char bufarr[(QUERY_NAME_SIZE + 1) * 2];
	char *buf = bufarr + bufnum * (QUERY_NAME_SIZE + 1);
	if (hostlen > QUERY_NAME_SIZE || bufnum >= 2) {
		return NULL;
	}

	uint8_t *p = host;
	size_t len = readname(host, hostlen, &p, (uint8_t *)buf, QUERY_NAME_SIZE, 0, 0);

	for (size_t i = 0; i < len; i++) {
		if (!isprint(buf[i])) {
			buf[i] = INVALID_CHAR;
		}
	}
	buf[len] = 0;
	return buf;
}

char *
format_addr(struct sockaddr_storage *sockaddr, int sockaddr_len)
{
	static char dst[INET6_ADDRSTRLEN + 1];

	memset(dst, 0, sizeof(dst));
	if (sockaddr->ss_family == AF_INET && sockaddr_len >= sizeof(struct sockaddr_in)) {
		getnameinfo((struct sockaddr *)sockaddr, sockaddr_len, dst, sizeof(dst) - 1, NULL, 0, NI_NUMERICHOST);
	} else if (sockaddr->ss_family == AF_INET6 && sockaddr_len >= sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *) sockaddr;
		if (IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr)) {
			struct in_addr ia;
			/* Get mapped v4 addr from last 32bit field */
			memcpy(&ia.s_addr, &addr->sin6_addr.s6_addr[12], sizeof(ia));
			strcpy(dst, inet_ntoa(ia));
		} else {
			getnameinfo((struct sockaddr *)sockaddr, sockaddr_len, dst, sizeof(dst) - 1, NULL, 0, NI_NUMERICHOST);
		}
	} else {
		dst[0] = '?';
	}
	return dst;
}

int
get_addr(char *host, int port, int addr_family, int flags, struct sockaddr_storage *out)
{
	struct addrinfo hints, *addr;
	int res;
	char portnum[8];

	memset(portnum, 0, sizeof(portnum));
	snprintf(portnum, sizeof(portnum) - 1, "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = addr_family;
#if defined(WINDOWS32) || defined(OPENBSD)
	/* AI_ADDRCONFIG misbehaves on windows, and does not exist in OpenBSD */
	hints.ai_flags = flags;
#else
	hints.ai_flags = AI_ADDRCONFIG | flags;
#endif
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	res = getaddrinfo(host, portnum, &hints, &addr);
	if (res == 0) {
		int addrlen = addr->ai_addrlen;
		/* Grab first result */
		memcpy(out, addr->ai_addr, addr->ai_addrlen);
		freeaddrinfo(addr);
		return addrlen;
	}
	return res;
}

int
open_dns(struct sockaddr_storage *sockaddr, size_t sockaddr_len)
{
	return open_dns_opt(sockaddr, sockaddr_len, -1);
}

int
open_dns_opt(struct sockaddr_storage *sockaddr, size_t sockaddr_len, int v6only)
{
	int flag;
	int fd;

	if ((fd = socket(sockaddr->ss_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		err(1, "socket");
	}

	flag = 1;
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &flag, sizeof(flag));
#endif
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &flag, sizeof(flag));

#ifndef WINDOWS32
	fd_set_close_on_exec(fd);
#endif

	if (sockaddr->ss_family == AF_INET6 && v6only >= 0) {
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void*) &v6only, sizeof(v6only));
	}

#ifdef IP_OPT_DONT_FRAG
	/* Set dont-fragment ip header flag */
	flag = DONT_FRAG_VALUE;
	setsockopt(fd, IPPROTO_IP, IP_OPT_DONT_FRAG, (const void*) &flag, sizeof(flag));
#endif

	if(bind(fd, (struct sockaddr*) sockaddr, sockaddr_len) < 0)
		err(1, "bind");

	fprintf(stderr, "Opened IPv%d UDP socket\n", sockaddr->ss_family == AF_INET6 ? 6 : 4);

	return fd;
}

int
open_dns_from_host(char *host, int port, int addr_family, int flags)
{
	struct sockaddr_storage addr;
	int addrlen;

	addrlen = get_addr(host, port, addr_family, flags, &addr);
	if (addrlen < 0)
		return addrlen;

	return open_dns(&addr, addrlen);
}

int
read_packet(int fd, uint8_t *pkt, size_t *pktlen, struct pkt_metadata *m)
{
	int r;
	m->fromlen = sizeof(struct sockaddr_storage);

#ifndef WINDOWS32
	char control[CMSG_SPACE(sizeof (struct in6_pktinfo))];
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;

	iov.iov_base = pkt;
	iov.iov_len = *pktlen;

	msg.msg_name = (caddr_t) &m->from;
	msg.msg_namelen = m->fromlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	msg.msg_flags = 0;

	r = recvmsg(fd, &msg, 0);
#else
	r = recvfrom(fd, pkt, *pktlen, 0, (struct sockaddr*)&m->from, &m->fromlen);
#endif /* !WINDOWS32 */

	if (r > 0) {
		m->fromlen = msg.msg_namelen;
		gettimeofday(&m->time_recv, NULL);
		*pktlen = (size_t) r;

#ifndef WINDOWS32
		/* Read destination IP address */
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
			cmsg = CMSG_NXTHDR(&msg, cmsg)) {

			if (cmsg->cmsg_level == IPPROTO_IP &&
				cmsg->cmsg_type == DSTADDR_SOCKOPT) {

				struct sockaddr_in *addr = (struct sockaddr_in *) &m->dest;
				addr->sin_family = AF_INET;
				addr->sin_addr = *dstaddr(cmsg);
				m->destlen = sizeof(*addr);
				break;
			}
			if (cmsg->cmsg_level == IPPROTO_IPV6 &&
				cmsg->cmsg_type == IPV6_PKTINFO) {

				struct in6_pktinfo *pktinfo;
				struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &m->dest;
				pktinfo = (struct in6_pktinfo *) CMSG_DATA(cmsg);
				addr->sin6_family = AF_INET6;
				memcpy(&addr->sin6_addr, &pktinfo->ipi6_addr, sizeof(struct in6_addr));
				m->destlen = sizeof(*addr);
				break;
			}
		}
#endif
		return 1;
	} else if (r < 0) {
		/* Error */
		warn("read packet");
	}

	return 0;
}

void
send_raw(int fd, uint8_t *buf, size_t buflen, int user, int cmd, uint32_t cmc,
		uint8_t *hmac_key, struct sockaddr_storage *to, socklen_t tolen)
{
	uint8_t packet[buflen + RAW_HDR_LEN], hmac[16];

	/* construct raw packet for HMAC */
	memcpy(packet, raw_header, RAW_HDR_LEN);
	packet[RAW_HDR_CMD] = (cmd & 0xF0) | (user & 0x0F);
	*(uint32_t *) (packet + RAW_HDR_CMC) = htonl(cmc);

	if (buf && buflen) memcpy(packet + RAW_HDR_LEN, buf, buflen);

	/* calculate HMAC and insert into header */
	hmac_md5(hmac, hmac_key, 16, packet, sizeof(packet));
	memcpy(packet + RAW_HDR_HMAC, hmac, RAW_HDR_HMAC_LEN);

	DEBUG(3, "TX-raw: client %s (user %d), cmd %d, %" L "u bytes",
			format_addr(to, tolen), user, cmd, sizeof(packet));

	sendto(fd, packet, sizeof(packet), 0, (struct sockaddr *) to, tolen);
}


void
close_socket(int fd)
{
	if (fd <= 0)
		return;
#ifdef WINDOWS32
	closesocket(fd);
#else
	close(fd);
#endif
}

void
do_chroot(char *newroot)
{
#if !(defined(WINDOWS32) || defined(__BEOS__) || defined(__HAIKU__))
	if (chroot(newroot) != 0 || chdir("/") != 0)
		err(1, "%s", newroot);

	if (seteuid(geteuid()) != 0 || setuid(getuid()) != 0) {
		err(1, "set[e]uid()");
	}
#else
	warnx("chroot not available");
#endif
}

void
do_setcon(char *context)
{
#ifdef HAVE_SETCON
	if (-1 == setcon(context))
		err(1, "%s", context);
#else
	warnx("No SELinux support built in");
#endif
}

void
do_pidfile(char *pidfile)
{
#ifndef WINDOWS32
	FILE *file;

	if ((file = fopen(pidfile, "w")) == NULL) {
		syslog(LOG_ERR, "Cannot write pidfile to %s, exiting", pidfile);
		err(1, "do_pidfile: Can not write pidfile to %s", pidfile);
	} else {
		fprintf(file, "%d\n", (int)getpid());
		fclose(file);
	}
#else
	fprintf(stderr, "Windows version does not support pid file\n");
#endif
}

void
do_detach()
{
#ifndef WINDOWS32
	fprintf(stderr, "Detaching from terminal...\n");
	if (daemon(0, 0) != 0) {
		err(1, "Failed to detach from terminal. Try running in foreground.");
	}
	umask(0);
	alarm(0);
#else
	fprintf(stderr, "Windows version does not support detaching\n");
#endif
}

void
read_password(char *buf, size_t len)
{
	char pwd[80] = {0};
#ifndef WINDOWS32
	struct termios old;
	struct termios tp;

	tcgetattr(0, &tp);
	old = tp;

	tp.c_lflag &= (~ECHO);
	tcsetattr(0, TCSANOW, &tp);
#else
	int i;
#endif

	fprintf(stderr, "Enter password: ");
	fflush(stderr);
#ifndef WINDOWS32
	if (!fscanf(stdin, "%79[^\n]", pwd))
		err(1, "EOF while reading password!");
#else
	for (i = 0; i < sizeof(pwd); i++) {
		pwd[i] = getch();
		if (pwd[i] == '\r' || pwd[i] == '\n') {
			pwd[i] = 0;
			break;
		} else if (pwd[i] == '\b') {
			i--; 			/* Remove the \b char */
			if (i >=0) i--; 	/* If not first char, remove one more */
		}
	}
#endif
	fprintf(stderr, "\n");

#ifndef WINDOWS32
	tcsetattr(0, TCSANOW, &old);
#endif

	strncpy(buf, pwd, len);
	buf[len-1] = '\0';
}

int
check_topdomain(char *str, char **errormsg)
{
	int i;
	int dots = 0;
	int chunklen = 0;

	if (strlen(str) < 3) {
		if (errormsg) *errormsg = "Too short (< 3)";
		return 1;
	}
	if (strlen(str) >= 128) {
		if (errormsg) *errormsg = "Too long (>= 128)";
		return 1;
	}

	if (str[0] == '.') {
		if (errormsg) *errormsg = "Starts with a dot";
		return 1;
	}

	for( i = 0; i < strlen(str); i++) {
		if(str[i] == '.') {
			dots++;
			if (chunklen == 0) {
				if (errormsg) *errormsg = "Consecutive dots";
				return 1;
			}
			if (chunklen > 63) {
				if (errormsg) *errormsg = "Too long domain part (> 63)";
				return 1;
			}
			chunklen = 0;
		} else {
			chunklen++;
		}
		if( (str[i] >= 'a' && str[i] <= 'z') || (str[i] >= 'A' && str[i] <= 'Z') ||
				isdigit(str[i]) || str[i] == '-' || str[i] == '.' ) {
			continue;
		} else {
			if (errormsg) *errormsg = "Contains illegal character (allowed: [a-zA-Z0-9-.])";
			return 1;
		}
	}

	if (dots == 0) {
		if (errormsg) *errormsg = "No dots";
		return 1;
	}
	if (chunklen == 0) {
		if (errormsg) *errormsg = "Ends with a dot";
		return 1;
	}
	if (chunklen > 63) {
		if (errormsg) *errormsg = "Too long domain part (> 63)";
		return 1;
	}

	return 0;
}

int
socket_set_blocking(int fd, int blocking)
{
	/* Set non-blocking socket mode */
#ifdef WINDOWS32
	if (ioctlsocket(fd, FIONBIO, &blocking) != 0) {
		return WSAGetLastError();
	}
#else
	int flags;
	if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
	    return flags;
	}

	if (fcntl(fd, F_SETFL, !blocking ? (flags | O_NONBLOCK) : (flags & (~O_NONBLOCK))) == -1)
		return errno;

#endif
	return 0;
}

int
open_tcp_nonblocking(struct sockaddr_storage *addr, char **errormsg)
/* Open TCP connection to given address without blocking */
{
	int fd, ret;
	if ((fd = socket(addr->ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		if (errormsg)
			*errormsg = strerror(errno);
		return -1;
	}

	if ((ret = socket_set_blocking(fd, 0)) != 0) {
		if (errormsg)
			*errormsg = strerror(ret);
		return -1;
	}

	if ((ret = connect(fd, (struct sockaddr *)addr, sizeof(struct sockaddr_storage)))
		== -1 && errno != EINPROGRESS) {
		if (errormsg)
			*errormsg = strerror(errno);
		return -1;
	}

	if (errormsg)
		*errormsg = strerror(errno);

	return fd;
}

int
check_tcp_error(int fd, char **error)
/* checks connected status of given socket.
 * returns error code. 0 if connected or EINPROGRESS if connecting */
{
	int errornum = 0;
	socklen_t len = sizeof(int);

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &errornum, &len) != 0) {
		if (error)
			*error = "getsockopt failed.";
		return -1;
	}

	if (error)
		*error = strerror(errornum);

	return errornum;
}

#if defined(WINDOWS32) || defined(ANDROID)
#ifndef ANDROID
int
inet_aton(const char *cp, struct in_addr *inp)
{
 inp->s_addr = inet_addr(cp);
 return inp->s_addr != INADDR_ANY;
}
#endif

void
warn(const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	if (fmt) fprintf(stderr, fmt, list);
#ifndef ANDROID
	if (errno == 0) {
		fprintf(stderr, ": WSA error %d\n", WSAGetLastError());
	} else {
		fprintf(stderr, ": %s\n", strerror(errno));
	}
#endif
	va_end(list);
}

void
warnx(const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	if (fmt) fprintf(stderr, fmt, list);
	fprintf(stderr, "\n");
	va_end(list);
}

void
err(int eval, const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	warn(fmt, list);
	va_end(list);
	exit(eval);
}

void
errx(int eval, const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	warnx(fmt, list);
	va_end(list);
	exit(eval);
}
#endif

#ifndef WINDOWS32
/* Set FD_CLOEXEC flag on file descriptor.
 * This stops it from being inherited by system() calls.
 */
void
fd_set_close_on_exec(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFD);
	if (flags == -1)
		err(4, "Failed to get fd flags");
	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flags) == -1)
		err(4, "Failed to set fd flags");
}
#endif

void
get_rand_bytes(uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		buf[i] = (uint8_t) rand();
	}
}

