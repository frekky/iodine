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

#ifndef __WINDOW_H__
#define __WINDOW_H__

/* Hard-coded sequence ID and fragment size limits
 * These should match the limitations of the protocol. */
#define MAX_SEQ_ID 256
#define MAX_FRAGSIZE_DOWN 2048
#define MAX_FRAGSIZE_UP	255
#define MAX_SEQ_AHEAD (MAX_SEQ_ID / 2)

/* Window function definitions. */
#define WINDOW_SENDING 1
#define WINDOW_RECVING 0

typedef struct fragment {
	uint8_t *data;				/* pointer to fragment data */
	size_t len;					/* Length of fragment data (0 if fragment unused) */
	unsigned seqID;				/* fragment sequence ID */

	/* flags */
	uint8_t compressed;			/* fragment contains compressed data */
	uint8_t start;				/* is start of chunk */
	uint8_t end;				/* is end of chunk */
} fragment;

struct frag_buffer {
	/* Generic ring-buffer stuff */
	fragment *frags;		/* pointer to array of fragment metadata */
	uint8_t *data;			/* pointer to actual fragment data */
	size_t length;			/* Length of buffer */
	size_t numitems;		/* number of non-empty fragments stored in buffer */
	size_t window_start;	/* Start of window (index) */
	int direction;			/* WINDOW_SENDING or WINDOW_RECVING */

	/* State variables for WINDOW_RECVING (reassembly) */
	size_t chunk_start;		/* oldest fragment slot (lowest seqID) in buffer (index) */
	unsigned maxfraglen;	/* Max outgoing fragment data size */
	unsigned start_seq_id;	/* lowest seqID that exists in buffer (at index chunk_start) */
	unsigned oos;			/* Number of out-of-sequence fragments received */

	/* State variables for WINDOW_SENDING */
	size_t last_write;		/* Last fragment appended (index) */
	unsigned cur_seq_id;	/* Next unused sequence ID */

	unsigned windowsize;	/* Max number of fragments in flight [DEPRECATED: this is handled at the DNS query/answer cache level] */
};

/* Window debugging macro */
#define WDEBUG(level, ...) _DEBUG_PRINT(level, \
		DEBUG_PRINT("[W:%s %zu/%zu]", w->direction == WINDOW_SENDING ? "SEND" : "RECV", \
			w->numitems, w->length), __VA_ARGS__);

/* Gets index of fragment o fragments after window start */
#define AFTER(w, o) ((w->window_start + o) % w->length)

/* Gets seqID of fragment o fragments after window start seqID */
#define AFTERSEQ(w, o) ((w->start_seq_id + o) % MAX_SEQ_ID)

/* Find the wrapped offset between sequence IDs start and a
 * Note: the maximum possible offset is MAX_SEQ_ID - 1 */
#define SEQ_OFFSET(start, a) ((a >= start) ? a - start : MAX_SEQ_ID - start + a)

/* Wrap index x to a value within the window buffer length */
#define WRAP(x) ((x) % w->length)

/* Wrap index x to a value within the seqID range */
#define WRAPSEQ(x) ((x) % MAX_SEQ_ID)


/* Perform wrapped iteration of statement with pos = (begin to end) wrapped at
 * max, executing statement f for every value of pos. */
#define ITER_FORWARD(begin, end, max, pos, f) { \
		if (end >= begin) \
			for (pos = begin; pos < end && pos < max; pos++) {f}\
		else {\
			for (pos = begin; pos < max; pos++) {f}\
			for (pos = 0; pos < end && pos < max; pos++) {f}\
		}\
	}

/* Window buffer creation */
struct frag_buffer *window_buffer_init(size_t length, unsigned windowsize, unsigned maxfraglen, int dir);

/* Resize buffer, clear and reset stats and data */
void window_buffer_resize(struct frag_buffer *w, size_t length, unsigned maxfraglen);

/* Destroys window buffer instance */
void window_buffer_destroy(struct frag_buffer *w);

/* Clears fragments and resets window stats */
void window_buffer_clear(struct frag_buffer *w);

/* Returns number of available fragment slots (NOT BYTES) */
size_t window_buffer_available(struct frag_buffer *w);

/* Handles fragment received from the sending side (RECV) */
ssize_t window_process_incoming_fragment(struct frag_buffer *w, fragment *f);

/* Reassembles first complete sequence of fragments into data. (RECV)
 * Returns length of data reassembled, or 0 if no data reassembled */
int window_reassemble_data(struct frag_buffer *w, uint8_t *data, size_t *maxlen, uint8_t *compression);

void window_mark_sent(struct frag_buffer *w, fragment *justsent);
size_t window_to_send(struct frag_buffer *w, fragment **nextsend);

/* Splits data into fragments and adds to the end of the window buffer for sending
 * All fragment meta-data is created here (SEND) */
int window_add_outgoing_data(struct frag_buffer *w, uint8_t *data, size_t len, uint8_t compressed);

#endif /* __WINDOW_H__ */
