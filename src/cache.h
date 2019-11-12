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

#ifndef SRC_CACHE_H_

#define SRC_CACHE_H_

#define MAX_CACHESIZE 128

/* calculates the forwards 'distance' between start and end in a ring */
#define RING_OFFSET(start, end, len) ((end >= start) ? (end - start) : (len - start + end))

/* debug print with extra info for QMEM */
#define QMEM_DEBUG(level, buf, ...) \
	_DEBUG_PRINT(level, DEBUG_PRINT("[QMEM %zu/%zu/%zu] ", buf->num_pending, buf->length, buf->size), __VA_ARGS__)

#define QMEM_PRINT_STATS(buf, prefix) \
	QMEM_DEBUG(8, buf, prefix "start=%zu, start_pending=%zu, end=%zu, start_pending<-->end=%zu", \
		buf->start, buf->start_pending, buf->end, RING_OFFSET(buf->start_pending, buf->end, buf->size))

/* Struct used for QMEM + DNS cache */
struct qmem_buffer {
	struct dns_packet **queries;
	struct timeval timeout;	/* timeout of queries */
	size_t start_pending;	/* index of first "pending" query (ie. no response yet) */
	size_t start;		/* index of first stored/pending query */
	size_t end;			/* index of space after last stored/pending query */
	size_t length;		/* number of stored queries */
	size_t num_pending;	/* number of pending queries */
	size_t size;		/* size of buffer (number of queries that can be stored) */
};

struct qmem_buffer *qmem_init(size_t cachesize);
void qmem_destroy(struct qmem_buffer *buf);
int qmem_is_cached(struct qmem_buffer *buf, struct dns_packet *q, struct dns_packet **cached_q);
void qmem_append(struct qmem_buffer *buf, struct dns_packet *q);
void qmem_answered(struct qmem_buffer *buf, struct dns_packet *ans);
struct dns_packet *qmem_get_next(struct qmem_buffer *buf);
int qmem_max_wait(struct qmem_buffer *buf, struct dns_packet **sendq, struct timeval *maxwait);

#endif /* SRC_CACHE_H_ */
