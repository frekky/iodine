/*
 * Copyright (c) 2015-2019 Frekk van Blagh <frekk@frekkworks.com>
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

/* Client-side query tracking for lazy mode
 * This differs in function from the server-side qmem cache:
 * a) We are only interested in tracking queries sent by us, and don't keep the answers
 * b) Queries can be answered at any time, in any order (ie. latency/jitter)
 * c) We will never have more than max_queries unanswered ("in flight") queries at once, except
 *    if a query seems to have timed out, then it is no longer counted as pending (although we
 *    might still get an answer for it eventually) */

// TODO: qtrack also does timing logic? (would make client.c a lot less messy)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "common.h"
#include "util.h"
#include "qtrack.h"
#include "client.h"

int
qtrack_init(struct qtrack_buffer *qtrack, size_t max_queries)
/* setup the pending query tracker */
{
	qtrack->size = max_queries * 2 + 1;
	DEBUG(5, "init qtrack: max_queries=%zu, size=%zu", max_queries, qtrack->size);

	/* init query tracking */
	qtrack->length = 0;
	qtrack->num_unanswered = 0;
	qtrack->oldest = 0;
	qtrack->queries = malloc(qtrack->size * sizeof(struct query_tuple));
	if (!qtrack->queries)
		return 0;

	/* mark all queries as empty */
	for (size_t i = 0; i < qtrack->size; i++) {
		qtrack->queries[i].id = -1;
	}
	return 1;
}

size_t
check_pending_queries(struct qtrack_buffer *qtrack, struct timeval *timeout, struct timeval *next_timeout)
/* Updates pending queries list, returns the number of pending queries
 * next_timeout is set to the duration before the oldest query will time out */
{
	size_t num_pending = 0; /* pending == unanswered */

	struct timeval now, timeout_threshold;
	gettimeofday(&now, NULL);
	/* queries sent before the threshold have timed out */
	timersub(&now, timeout, &timeout_threshold);
	QTRACK_DEBUG(4, "timeout=%ldms, qtrack: oldest=%zu", timeval_to_ms(timeout), qtrack->oldest);

	/* iterate over the ring structure (ascending order of time_sent) */
	for (size_t n = 0; n < qtrack->length; n++) {
		size_t i = QTRACK_WRAP(qtrack->oldest + n);
		struct query_tuple *q = &qtrack->queries[i];
		IF_DEBUG(6, {
			struct timeval age;
			timersub(&now, &q->time_sent, &age);
			DEBUG(6, "query pending[%zu]: id=%d, age=%ldms", i, q->id, timeval_to_ms(&age));
		});

		if (q->id < 0) /* this record is empty */
			continue;

		if (timercmp(&q->time_sent, &timeout_threshold, <)) {
			DEBUG(3, "query with id=%d has timed out", q->id);
		} else {
			/* query hasn't been answered yet */
			num_pending++;

			/* the first one we find will be the first to time out */
			if (next_timeout) {
				timersub(&timeout_threshold, &q->time_sent, next_timeout);
				next_timeout = NULL;
			}
		}
	}

	QTRACK_DEBUG(4, "got num_pending = %zu", num_pending);
	qtrack->num_unanswered = num_pending;

	return num_pending;
}

void
query_sent_now(struct qtrack_buffer *qtrack, int id)
/* record timestamp and ID of query as it is sent */
{
	size_t insert_index;
	if (qtrack->length == qtrack->size) {
		/* buffer is full: always overwrite the oldest entry, whether it has been answered yet or not
		 * Note: the record at queries[oldest] can be empty */
		QTRACK_DEBUG(4, "overwriting oldest: queries[%zu] id=%d",
				qtrack->oldest, qtrack->queries[qtrack->oldest].id);
		insert_index = qtrack->oldest;
		qtrack->oldest = (qtrack->oldest + 1) % qtrack->size;
	} else {
		/* put the new query at the ring buffer tail */
		insert_index = (qtrack->oldest + qtrack->length) % qtrack->size;
		qtrack->length++;
	}

	qtrack->num_unanswered++;

	QTRACK_DEBUG(4, "Adding query id %d into queries[%zu]", id, insert_index);

	gettimeofday(&qtrack->last_sent, NULL);
	qtrack->queries[insert_index].id = id;
	qtrack->queries[insert_index].time_sent = qtrack->last_sent;
}

void
got_response(struct qtrack_buffer *qtrack, int id, int immediate)
/* Marks a query as answered with the given id.
 * immediate: if query was replied to immediately (see below) */
{
	QTRACK_DEBUG(4, "Got answer id %d (%s)", id, immediate ? "immediate" : "lazy");
	if (id < 0) {
		return;
	}

	/* search for the query in the buffer, starting at the oldest */
	struct query_tuple *q = NULL;
	for (size_t n = 0; n < qtrack->length; n++) {
		size_t i = QTRACK_WRAP(qtrack->oldest + n);

		if (qtrack->queries[i].id == id) {
			q = &qtrack->queries[i];
			DEBUG(4, "Found match at queries[%zu]: time_sent=%lds", i, q->time_sent.tv_sec);
			break;
		}
	}

	if (q == NULL) {
		QTRACK_DEBUG(4, "    got untracked response to id %d.", id);
		this.num_untracked++;
		return;
	}

	/* Remove query info from buffer to mark it as answered */
	q->id = -1;
	qtrack->num_unanswered--;

	if (immediate && q != NULL) {
		/* If this was an immediate response we can use it to calculate statistics,
		 * including the RTT. This lets us determine and adjust server lazy response
		 * time during the session. */
		struct timeval rtt, now;
		gettimeofday(&now, NULL);
		timersub(&now, &q->time_sent, &rtt);
		time_t rtt_ms = timeval_to_ms(&rtt);
		static time_t rtt_min_ms = 1;

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
}

int
check_min_send_interval(struct timeval *_time_to_wait)
/* checks whether we can send a query now, based on min_send_interval */
{
	struct qtrack_buffer *qtrack = &this.qtrack;
	if (this.min_send_interval_ms == 0)
		return 1;

	struct timeval now, min_send, time_to_wait;
	gettimeofday(&now, NULL);
	min_send = ms_to_timeval(this.min_send_interval_ms);
	timersub(&now, &qtrack->last_sent, &time_to_wait);
	if (timercmp(&time_to_wait, &min_send, >)) {
		DEBUG(4, "min_send_interval: can't send for another %ldms", timeval_to_ms(&time_to_wait));
		if (_time_to_wait) {
			memcpy(_time_to_wait, &time_to_wait, sizeof(struct timeval));
		}

		return 0;
	}

	if (_time_to_wait) {
		memcpy(_time_to_wait, &min_send, sizeof(struct timeval));
	}
	return 1;
}

size_t
fill_server_lazy_queue(struct timeval *time_to_wait)
/* Determines how many queries we should send right now, and sends them;
 * See docs/proto_xxx.txt for information about "lazy mode" operation.
 * Returns number of queries sent,
 * time_to_wait is set to how long before we would send another query */
/* TODO: detect DNS servers which drop frequent requests
 * TODO: adjust number of pending queries based on current data rate */
{
	struct qtrack_buffer *qtrack = &this.qtrack;
	struct timeval timeout = ms_to_timeval(this.max_timeout_ms);
	struct timeval next_timeout;
	size_t num_pending = check_pending_queries(qtrack, &timeout, &next_timeout);

	if (num_pending >= this.max_queries) {
		QTRACK_DEBUG(4, "would exceed maximum (pending=%zu, max=%zu)",
				num_pending, this.max_queries);
		return 0;
	}

	if (!check_min_send_interval(time_to_wait))
		return 0;

	size_t sending_frags = window_to_send(this.outbuf, NULL);
	if (sending_frags == 0 && num_pending >= this.target_queries) {
		QTRACK_DEBUG(4, "sent enough queries already (pending=%zu)", num_pending);
		return 0;
	}

	QTRACK_DEBUG(6, "sending_frags=%zu, num_pending=%zu, target=%zu, max=%zu",
			sending_frags, num_pending, this.target_queries, this.max_queries);
	size_t num_sent = 0;
	while ((sending_frags > 0 || num_pending < this.target_queries)
			&& num_pending <= this.max_queries) {
		/* send a query each loop */
		if (sending_frags > 0) {
			send_next_frag();
			sending_frags--;
		} else {
			send_ping(0, this.num_pings % 50 == 0);
		}
		num_pending++;
		num_sent++;

		/* don't send more than one now if we have to wait some time between */
		if (this.min_send_interval_ms > 0) {
			QTRACK_DEBUG(2, "Send one query: wait %ld ms before sending another", timeval_to_ms(time_to_wait));
			return 1;
		}
	}
	QTRACK_DEBUG(2, "Sent %zu queries: num_pending=%zu, target=%zu, max=%zu",
			num_sent, num_pending, this.target_queries, this.max_queries);

	return num_sent;
}
