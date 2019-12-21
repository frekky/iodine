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

#ifndef SRC_QTRACK_H_
#define SRC_QTRACK_H_

#define PENDING_QUERIES_LENGTH (MAX(this.windowsize_up, this.windowsize_down) * 4)

/* Handy macro for printing pending query stats with messages */
#define QTRACK_DEBUG(level, ...) \
		_DEBUG_PRINT(level, DEBUG_PRINT("[QTRACK (%zu/%zu/%zu), ? %zu, TO %zu, S %zu] ", qtrack->num_unanswered, \
			qtrack->length, qtrack->size, this.num_untracked, this.num_timeouts, this.outbuf->numitems), __VA_ARGS__)

#define QTRACK_WRAP(index) ((index) % qtrack->size)

/* Keep track of queries in time order with a ring buffer
 * Note: queries can be answered in any order, there may be holes */
struct qtrack_buffer {
	size_t size;			/* total size of buffer (based on max_queries) */
	size_t length;			/* distance between head and tail of buffer */
	size_t num_unanswered;	/* number of queries which are not yet answered */
	size_t oldest;			/* index of oldest query in buffer (ring start) */
	struct timeval last_sent;	/* time when most recent query was sent */

	/* store only minimal information about each query
	 * Note: answered queries are "cleared", but the buffer is not reshuffled, so they can leave holes */
	struct query_tuple {
		int id; /* DNS query / response ID, <0 if this entry is empty */
		struct timeval time_sent; /* time at which query was sent */
	} *queries;
};

int qtrack_init(struct qtrack_buffer *qtrack, size_t max_queries);
size_t check_pending_queries(struct qtrack_buffer *qtrack, struct timeval *timeout, struct timeval *next_timeout);
void query_sent_now(struct qtrack_buffer *qtrack, int id);
void got_response(struct qtrack_buffer *qtrack, int id, int immediate);
size_t fill_server_lazy_queue(struct timeval *time_to_wait);


#endif /* SRC_QTRACK_H_ */
