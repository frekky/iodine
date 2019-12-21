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
#define MAX_SEND_FRAGS (MAX_SEQ_AHEAD / 2 - 1)

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
	size_t length;			/* Length of buffer */
	size_t numitems;		/* number of non-empty fragments stored in buffer */
	size_t window_start;	/* Start of window (index) */

	/* State variables relating to fragment metadata */
	int direction;			/* WINDOW_SENDING or WINDOW_RECVING */
	unsigned window_start_seq;	/* sequence ID of the frag slot at index window_start */
	uint8_t *data;			/* pointer to actual fragment data (allocated size is length * maxfraglen) */
	size_t maxfraglen;		/* Max outgoing fragment data size */

	/* State variables for WINDOW_SENDING */
	size_t last_write;		/* Tail: last fragment appended (index) */
	unsigned cur_seq_id;	/* Next unused sequence ID (tail + 1) */

	/* Statistics */
	unsigned oos;			/* Number of out-of-sequence fragments received */
};

/* Window debugging macro */
#define WDEBUG(level, ...) _DEBUG_PRINT(level, \
		DEBUG_PRINT("[W:%s %zu/%zu] ", w->direction == WINDOW_SENDING ? "SEND" : "RECV", \
			w->numitems, w->length), __VA_ARGS__);

/* Find the wrapped offset between sequence IDs start and a
 * Note: the maximum possible offset is MAX_SEQ_ID - 1 */
#define SEQ_OFFSET(start, a) ((a >= start) ? (a - start) : (MAX_SEQ_ID - start + a))

/* Wrap index x to a value within the window buffer length */
#define WRAP(x) ((x) % w->length)

/* Wrap index x to a value within the seqID range */
#define WRAPSEQ(x) ((x) % MAX_SEQ_ID)


/* Window buffer creation */
struct frag_buffer *window_buffer_init(size_t length, size_t maxfraglen, int dir);

/* Resize buffer, clear and reset stats and data */
void window_buffer_resize(struct frag_buffer *w, size_t length, size_t maxfraglen);

/* Destroys window buffer instance */
void window_buffer_destroy(struct frag_buffer *w);

/* Clears fragments and resets window stats */
void window_buffer_clear(struct frag_buffer *w);

/* Returns number of available fragment slots (NOT BYTES) */
size_t window_buffer_available(struct frag_buffer *w);

/* Handles fragment received from the sending side (RECV) */
int window_process_incoming_fragment(struct frag_buffer *w, fragment *f);

/* Reassembles first complete sequence of fragments into data. (RECV)
 * Returns length of data reassembled, or 0 if no data reassembled */
int window_reassemble_data(struct frag_buffer *w, uint8_t *data, size_t *maxlen, uint8_t *compression);

void window_mark_sent(struct frag_buffer *w, fragment *justsent);
size_t window_to_send(struct frag_buffer *w, fragment **nextsend);

/* Splits data into fragments and adds to the end of the window buffer for sending
 * All fragment meta-data is created here (SEND) */
int window_add_outgoing_data(struct frag_buffer *w, uint8_t *data, size_t len, uint8_t compressed);

#endif /* __WINDOW_H__ */
