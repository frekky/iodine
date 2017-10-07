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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

#include "common.h"
#include "util.h"
#include "cache.h"

/* Ringbuffer Query Handling (qmem) and DNS Cache:
   This is used to make the handling duplicates and query timeouts simpler
   and all handled in one place.
   Using this, lazy mode is possible with n queries (n <= windowsize)

   New queries are placed consecutively in the buffer, replacing any old
   queries (already responded to) if length == QMEM_LEN. Old queries are kept
   as a record for duplicate requests. If a dupe is found and USE_DNSCACHE is
   defined, the previous answer is sent (if it exists), otherwise an invalid
   response is sent.

   On the DNS cache:
   This cache is implemented to better handle the aggressively impatient DNS
   servers that very quickly re-send requests when we choose to not
   immediately answer them in lazy mode. This cache works much better than
   pruning(=dropping) the improper requests, since the DNS server will
   actually get an answer instead of silence.

   Because of the CMC in both ping and upstream data, unwanted cache hits
   are prevented. Due to the combination of CMC and varying sequence IDs, it
   is extremely unlikely that any duplicate answers will be incorrectly sent
   during a session (given QMEM_LEN is not very large). */

struct qmem_buffer *
qmem_init(size_t cachesize)
/* create new qmem buffer of given size for QMEM and DNS cache */
{
	struct qmem_buffer *buf = calloc(1, sizeof(struct qmem_buffer));
	if (!buf)
		return NULL;

	buf->queries = calloc(cachesize, sizeof(struct dns_packet *));
	if (!buf->queries)
		return NULL;
	buf->size = cachesize;

	return buf;
}

void
qmem_destroy(struct qmem_buffer *buf)
/* clean up */
{
	if (buf)
		free(buf);
}

void
qmem_set_timeout(struct qmem_buffer *buf, time_t timeout_ms)
{
	buf->timeout = ms_to_timeval(timeout_ms);
}

struct dns_packet *
qmem_is_cached(struct qmem_buffer *buf, struct dns_packet *q)
/* Check if a particular query is cached in qmem (may not have an answer)
 * Returns NULL if new query (ie. not cached), pointer to query if cached */
{
	struct dns_packet *pq;
	char *data = "x";
	uint8_t dataenc = C_BASE32;
	size_t len = 1;
	int dnscache = 0;

	/* Check if this is a duplicate query */
	for (size_t p = buf->start; p != buf->end; p = (p + 1) % buf->size) {
		pq = buf->queries[p];
		if (pq->id != q->id)
			continue;
		if (pq->q[0].type != q->q[0].type)
			continue;
		if (pq->q[0].namelen != q->q[0].namelen)
			continue;
		if (memcmp(pq->q[0].name, q->q[0].name, q->q[0].namelen) != 0)
			continue;

		/* Aha! A match! Note: might not have any actual answer */
		QMEM_DEBUG(2, buf, "OUT from qmem for '%s', ancount %hu",
				format_host(pq->q[0].name, pq->q[0].namelen, 0),
				pq->ancount);
		return pq;
	}
	return NULL; /* no matching query found */
}

void
qmem_append(struct qmem_buffer *buf, struct dns_packet *q)
/* Appends incoming query to the buffer. */
{
	if (buf->num_pending >= buf->size) {
		/* this means we have QMEM_LEN *pending* queries; drop oldest to make space */
		QMEM_DEBUG(2, buf, "Full of pending queries! Replacing old query %hu with new %hu.",
				   buf->queries[buf->start]->id, q->id);
	}

	if (buf->length < buf->size) {
		buf->length++;
	} else {
		/* will replace oldest query (in buf->queries[buf->start]) */
		buf->start = (buf->start + 1) % buf->size;
	}

	QMEM_DEBUG(5, buf, "add query ID %d", q->id);

	/* Copy query pointer into end of buffer */
	q->refcount++;
	buf->queries[buf->end] = q;
	buf->end = (buf->end + 1) % buf->size;
	buf->num_pending += 1;
}

void
qmem_answered(struct qmem_buffer *buf, struct dns_packet *ans)
/* Call when oldest/first/earliest query added has been answered */
{
	size_t answered;

	if (buf->num_pending == 0) {
		/* No queries pending: most likely caused by bugs somewhere else. */
		QMEM_DEBUG(1, buf, "Query answered with 0 in qmem! Fix bugs.");
		return;
	}
	answered = buf->start_pending;
	buf->start_pending = (buf->start_pending + 1) % buf->size;
	buf->num_pending -= 1;

	/* Replace pointer to query with pointer to answer */
	struct dns_packet *q = buf->queries[answered];
	dns_packet_destroy(q);
	buf->queries[answered] = ans;

	QMEM_DEBUG(3, buf, "query ID %d answered, replaced queries[%" L "u]", ans->id, answered);
}

struct dns_packet *
qmem_get_next_response(struct qmem_buffer *buf)
/* Gets oldest query to be responded to (for lazy mode) or NULL if none available
 * The query is NOT marked as "answered" since that is done later. */
{
	struct dns_packet *q;
	if (buf->length == 0 || buf->num_pending == 0)
		return NULL;
	q = buf->queries[buf->start_pending];
	QMEM_DEBUG(3, buf, "next response using cached query: ID %d", q->id);
	return q;
}

int
qmem_max_wait(struct qmem_buffer *buf, struct dns_packet **sendq, struct timeval *maxwait)
/* Calculates max interval before the next pending query times out
 * *maxwait should be the longest wait time so far
 * Returns 1: send query *sendq now & call again; maxwait unchanged
 * 0: no queries timed out yet, *maxwait = time to next query timeout,
 * *sendq is next query to timeout */
{
	struct timeval now, tmp, age;
	struct dns_packet *q = NULL;
	size_t timedout = 0;

	if (buf->num_pending == 0) {
		return 0;
	}

	gettimeofday(&now, NULL);

	q = buf->queries[buf->start_pending];
	if (sendq)
		*sendq = q;

	/* queries will always be in time order, so first in buf is oldest */
	timersub(&now, &q->m.time_recv, &age);
	if (!timercmp(&age, &buf->timeout, <)) {
		/* return query to respond to when if timed out */
		QMEM_DEBUG(3, buf, "TIMEOUT: ID %d, age=%ldms, timeout %ldms",
				q->id, timeval_to_ms(&age), timeval_to_ms(&buf->timeout));
		return 1;
	} else {
		/* calculate time until query timeout */
		timersub(&buf->timeout, &age, &tmp);
		if (timercmp(&tmp, maxwait, <))
			*maxwait = tmp;
		return 0;
	}
}