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

#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#ifndef WINDOWS32
#include <err.h>
#endif
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "util.h"
#include "window.h"

struct frag_buffer *
window_buffer_init(size_t length, size_t maxfraglen, int dir)
{
	struct frag_buffer *w;
	DEBUG(2, "new buffer: length=%zu, maxfraglen=%zu, direction=%d",
			length, maxfraglen, dir);

	/* Note: window buffer DOES NOT WORK with length > MAX_SEQ_ID */
	if (length > MAX_SEQ_ID)
		errx(1, "window_buffer_init: length (%zu) is greater than compiled MAX_SEQ_ID (%d)!",
				length, MAX_SEQ_ID);

	w = calloc(1, sizeof(struct frag_buffer));
	if (!w) {
		errx(1, "Failed to allocate window buffer memory!");
	}
	if (dir != WINDOW_RECVING && dir != WINDOW_SENDING) {
		errx(1, "Invalid window direction!");
	}

	window_buffer_resize(w, length, maxfraglen);

	w->direction = dir;
	return w;
}

void
window_buffer_resize(struct frag_buffer *w, size_t length, size_t maxfraglen)
{
	WDEBUG(2, "resize from len=%zu, fraglen=%zu --> len=%zu, fraglen=%zu",
			w->length, w->maxfraglen, length, maxfraglen);

	if (w->length == length && w->maxfraglen == maxfraglen) {
		return;
	}

	if (w->numitems > 0) {
		WDEBUG(1, "Resizing window buffer with things still in it = data loss!");
	}

	w->frags = malloc(length * sizeof(fragment));
	if (!w->frags) {
		errx(1, "Failed to allocate fragment buffer!");
	}

	w->data = malloc(length * maxfraglen);
	if (!w->data) {
		errx(1, "Failed to allocate fragment data buffer! "
				"Maybe fragsize too large (%zu)?", maxfraglen);
	}

	w->length = length;
	w->maxfraglen = maxfraglen;
	window_buffer_clear(w);
}

void
window_buffer_destroy(struct frag_buffer *w)
{
	if (!w) return;
	WDEBUG(2, "deallocating buffer");
	if (w->frags) free(w->frags);
	if (w->data) free(w->data);
	free(w);
}

void
window_buffer_clear(struct frag_buffer *w)
{
	if (!w) return;
	WDEBUG(2, "clearing buffer");

	/* Mark frags as empty and (re)calculate fragment data pointers */
	for (size_t fragIndex = 0; fragIndex < w->length; fragIndex++) {
		fragment *f = &w->frags[fragIndex];
		f->data = ((w->data + (w->maxfraglen * fragIndex)));
		f->len = 0;
	}

	/* reset window parameters and statistics */
	w->numitems = 0;
	w->window_start = 0;
	w->window_start_seq = 0;
	w->last_write = 0;
	w->cur_seq_id = 0;
	w->oos = 0;
}

size_t
window_buffer_available(struct frag_buffer *w)
/* Returns number of available fragment slots (NOT BYTES) */
{
	return w->length - w->numitems;
}

static void
window_slide(struct frag_buffer *w, unsigned slide)
/* Slide window forwards by given number of frags, clearing out old frags */
{
	size_t new_start = WRAP(w->window_start + slide);
	unsigned new_start_seq = WRAPSEQ(w->window_start_seq + slide);

	WDEBUG(2, "move forwards by %u: start=%zu (seq=%u) --> start=%zu (seq=%u)",
			slide, w->window_start, w->window_start_seq, new_start, new_start_seq);

	size_t num_deleted = 0;

	if (slide >= w->length) {
		/* don't loop over the buffer more than once, take a shortcut instead */
		num_deleted = w->numitems;
		window_buffer_clear(w);
		w->window_start_seq = new_start_seq; /* remember which seqID we are using */
	} else {
		for (size_t i = 0; i < slide; i++) {
			size_t woffs = WRAP(w->window_start + i);
			fragment *f = &w->frags[woffs];
			if (f->len != 0) {
				WDEBUG(4, "    clear frags[%zu]: seqID=%u, len %zu", woffs, f->seqID, f->len);
				f->len = 0;
				num_deleted++;
			} else {
				/* you can't really "clear" a hole... */
				WDEBUG(4, "    clear hole at index %zu", woffs);
			}
		}

		/* Update window status */
		w->numitems -= num_deleted;
		w->window_start = new_start;
		w->window_start_seq = new_start_seq;
	}
	WDEBUG(3, "deleted %zu frags for slide", num_deleted);
}

int
window_process_incoming_fragment(struct frag_buffer *w, fragment *f)
/* Handles fragment received over the wire (RECV)
 * Returns 1 if fragment accepted, 0 if something went wrong
 * Slides window forward if fragment has sequence ID ahead of what fits in the buffer
 * Reassemble should start at window_start and loops through the entire buffer */
{
	if (f->len == 0 || f->seqID > MAX_SEQ_ID || !f->data) {
		WDEBUG(1, "got invalid frag! len=%zu, seqID=%u, data addr=%p", f->len, f->seqID, (void *)f->data);
		return 0;
	}

	/* Calculate where the new fragment would go in the buffer, based on its seqID */
	unsigned seq_offset = SEQ_OFFSET(w->window_start_seq, f->seqID);
	ssize_t dest = WRAP(w->window_start + seq_offset);

	if (seq_offset >= w->length) {
		/* The seqID is too far ahead, won't logically fit in the buffer;
		 * we have to slide the window to accomodate at least this new sewID */
		WDEBUG(2, "incoming frag seq=%u ahead: seq_offset=%u > %zu, window_start=%zu (seq=%u)",
				f->seqID, seq_offset, w->length, w->window_start, w->window_start_seq);

		/* note: sliding the window causes data loss, avoid it if the new fragment
		 * is likely to be very old (ie. with an unreasonably high offset) */
		if (seq_offset > MAX_SEQ_AHEAD && w->numitems > 1) {
			WDEBUG(2, "frag offset is too high (>%d), ignoring", MAX_SEQ_AHEAD);
			return 0;
		}

		window_slide(w, (seq_offset + 1) % w->length);
	}

	WDEBUG(3, "   Putting frag seq %u into frags[%zu + %u = %zu]",
		   f->seqID, w->window_start, seq_offset, dest);

	/* Check if fragment already received */
	fragment *fd = &w->frags[dest];
	if (fd->len != 0 && fd->seqID == f->seqID) {
		WDEBUG(2, "    Duplicate at frags[%zu], using existing (seq: prev=%u, new=%u)", dest, fd->seqID, f->seqID);
		return -1;
	}
	/* copy the new fragment into the buffer */
	fd->seqID = f->seqID;
	fd->len = MIN(f->len, w->maxfraglen);
	fd->compressed = f->compressed;
	fd->start = f->start;
	fd->end = f->end;
	memcpy(fd->data, f->data, fd->len);
	w->numitems++;

	return dest;
}

int
window_reassemble_data(struct frag_buffer *w, uint8_t *data, size_t *datalen, uint8_t *_compression)
/* Reassembles first complete sequence of fragments into data. (RECV)
 * *datalen should be passed with max space in *data, replaced with amount filled. return *datalen == 0 means empty/invalid frag
 * Returns 1 if should be called again for another packet, 0 otherwise */
/* Note: Continue reassembling full packets until none left in buffer;
 *      several full chunks (packets) are sometimes left in buffer unprocessed
 *      so we must not just take the oldest full chunk and ignore newer ones */
{
	/* nothing to try reassembling if w is empty */
	if (w->numitems == 0) {
		WDEBUG(2, "window buffer empty, nothing to reassemble");
		*datalen = 0;
		return 0;
	}

	size_t chunk_nfrags = 0; /* number of sequential non-empty fragments in chunk */
	size_t chunk_len = 0; /* total length of fragment data to reassemble */
	size_t chunk_start; /* index of first fragment in chunk */
	uint8_t compression; /* if the chunk data is compressed or not */
	int invalid = 0; /* if the chunk is invalid and should be ignored */
	int found_end = 0; /* if we found the end of the chunk */

	/* Scan the entire buffer for a valid consecutive "chunk" of fragments, starting
	 * after where we found the last end-of-chunk.
	 * eg. |0+S|1|2|3|4+E| (nfrags=5) or |0+S+E| (nfrags=1) or |0+S|1+E| (nfrags=2)
	 *     (where 'S' = start, 'E' = end, '|' = fragment boundary) */
	int more_to_check = 0; /* store whether the loop exited early or not */
	for (size_t n = 0; (more_to_check = n < w->length); n++) {
		size_t woffs = WRAP(w->window_start + n); /* current index in the buffer */
		unsigned curseq = WRAPSEQ(w->window_start_seq + n); /* expected fragment seqID at this index */
		fragment *f = &w->frags[woffs];
		WDEBUG(8, "  frags[%zu]: len=%zu, seqID=%u, start=%hhu, end=%hhu, comp=%hhu; curseq=%u",
				woffs, f->len, f->seqID, f->start, f->end, f->compressed, curseq);

		if (f->len == 0) { /* Empty fragment */
			if (chunk_nfrags > 0) {
				/* reset counters if they are counting anything */
				WDEBUG(4, "empty frag before end of chunk: index=%zu, chunk_nfrags=%zu, chunk_len=%zu",
						woffs, chunk_nfrags, chunk_len);
				chunk_len = chunk_nfrags = 0;
			}
			continue;
		} else if (f->seqID != curseq) {
			/* fragment has unexpected sequence ID, which means the buffer is probably corrupt */
			errx(1, "window_buffer_reassemble: unexpected sequence ID: invalid buffer state!");
		}

		if (f->start) {
			/* this fragment should be the start of a new chunk */
			if (chunk_nfrags != 0) {
				/* there is a start fragment in the middle of the chunk, discard the fragments before this point */
				WDEBUG(2, "(!) false start in chunk at frags[%zu]: seqID=%u, chunk_nfrags=%zu", woffs, f->seqID, chunk_nfrags);
				invalid = 1;
				break;
			}
			/* update chunk counters for the start of the chunk */
			chunk_len = f->len;
			chunk_nfrags = 1;
			chunk_start = woffs;
			compression = f->compressed;
			WDEBUG(3, "found start of chunk at frags[%zu]: seq=%u, comp=%hhu", woffs, f->seqID, f->compressed);
		} else if (chunk_nfrags == 0) {
			/* this fragment is not the start of a chunk but we haven't got the start fragment yet */
			WDEBUG(3, "got fragment before start at frags[%zu]: seq=%u", woffs, f->seqID);
			continue;
		} else {
			/* update chunk counters to include this fragment */
			WDEBUG(4, "    next fragment n=%zu in chunk at frags[%zu]: seq=%u, comp=%hhu",
					chunk_nfrags + 1, woffs, f->seqID, f->compressed);
			if (f->compressed != compression) {
				WDEBUG(2, "(!) compression flag mismatch at frags[%zu] => invalid chunk", woffs);
				invalid = 1;
				break;
			}
			chunk_len += f->len;
			chunk_nfrags++;
		}

		if (f->end) {
			/* this fragment is [also] the end of the chunk */
			WDEBUG(2, "end of chunk at frags[%zu]: seq=%u; nfrags=%zu, len=%zu, start=frags[%zu]",
					woffs, f->seqID, chunk_nfrags, chunk_len, chunk_start);
			found_end = 1;
			break;
		}
	}

	WDEBUG(5, "chunk search complete: nfrags=%zu, len=%zu, start=%zu, compression=%hhu, invalid=%d, more_to_check=%d, found_end=%d",
			chunk_nfrags, chunk_len, chunk_start, compression, invalid, more_to_check, found_end);

	if (chunk_nfrags == 0 || (!found_end && !invalid)) {
		WDEBUG(2, "no complete chunk found in buffer");
		*datalen = 0;
		return 0;
	}

	if (chunk_len > *datalen) {
		WDEBUG(1, "chunk len exceeds space in reassemble buffer (%zu > %zu), discarding data!", chunk_len, *datalen);
		invalid = 1; /* don't try to copy the data, just discard it */
	}

	size_t copy_offset = 0; /* length of data copied so far */
	/* now copy the fragment data and clear the old frags */
	for (size_t n = 0; n < chunk_nfrags; n++) {
		size_t woffs = WRAP(chunk_start + n);
		fragment *f = &w->frags[woffs];

		if (!invalid) {
			WDEBUG(6, "copy frags[%zu] len=%zu to offset=%zu, available=%zu",
					woffs, f->len, copy_offset, *datalen);
			memcpy(data + copy_offset, f->data, f->len);
			copy_offset += f->len;
		}

		/* clear the fragment */
		f->len = 0;
		w->numitems--;
	}

	/* update the length with the size of reassembled data */
	*datalen = copy_offset;
	*_compression = compression;

	WDEBUG(2, "Reassembled %zu bytes from %zu frags (chunk_len=%zu), comp=%hhu, invalid=%d",
			copy_offset, chunk_nfrags, chunk_len, compression, invalid);

	return more_to_check;
}

void
window_mark_sent(struct frag_buffer *w, fragment *justsent)
/* slides window forwards and clears the fragment from buffer */
{
	ssize_t fragoffs = justsent - w->frags;
	if (!justsent || fragoffs < 0 || fragoffs > w->length) {
		WDEBUG(1, "Warning: got bad fragment addr=%p, frag_offs=%zd", (void *)justsent, fragoffs);
		return;
	}
	if (w->window_start != fragoffs) {
		WDEBUG(1, "Warning: bad fragoffs=%zd != window_start=%zu", fragoffs, w->window_start);
		return;
	}

	window_slide(w, 1);
}

size_t
window_to_send(struct frag_buffer *w, fragment **nextsend)
/* Returns number of fragments that can be sent (immediately);
 * if possible, sets *nextsend to point to next fragment to send (on return >1)
 * Note: window_mark_sent() must be called with the fragment after it is sent! */
{
	if (w->numitems == 0)
		return 0;

	/* next fragment is at the start of the buffer */
	fragment *f = &w->frags[w->window_start];

	if (f->len == 0) {
		/* this is bad, probably indicates misuse of window_mark_sent() somewhere... */
		errx(1, "window_to_send: Warning: next fragment invalid! frags[%zu]: len=%zu", w->window_start, f->len);
	}

	if (nextsend)
		*nextsend = f;

	return w->numitems;
}

/* Splits data into fragments and adds to the end of the window buffer for sending
 * All fragment meta-data is created here (SEND) */
int
window_add_outgoing_data(struct frag_buffer *w, uint8_t *data, size_t len, uint8_t compressed)
{
	// Split data into thingies of <= fragsize
	size_t nfrags = ((len - 1) / w->maxfraglen) + 1;
	size_t available = window_buffer_available(w);
	if (!data || nfrags == 0 || len == 0 || nfrags > available) {
		WDEBUG(1, "window buffer too small or full! frags=%zu, available=%zu", nfrags, available);
		return -1;
	}
	compressed &= 1;
	size_t offset = 0;
	fragment *f;
	WDEBUG(2, "add_outgoing_data: chunk len %zu -> %zu frags, max fragsize %zu",
			len, nfrags, w->maxfraglen);
	for (size_t i = 0; i < nfrags; i++) {
		f = &w->frags[w->last_write];
		/* copy in new data and reset frag stats */
		f->len = MIN(len - offset, w->maxfraglen);
		f->seqID = w->cur_seq_id;
		f->compressed = compressed;
		f->start = (i == 0) ? 1 : 0;
		f->end = (i == nfrags - 1) ? 1 : 0;

		WDEBUG(3, "     frags[%zu]: len %zu, seqID %u, s %u, end %u, dOffs %zu",
				w->last_write, f->len, f->seqID, f->start, f->end, offset);

		memcpy(f->data, data + offset, f->len);
		w->last_write = WRAP(w->last_write + 1);
		w->cur_seq_id = WRAPSEQ(w->cur_seq_id + 1);
		w->numitems ++;
		offset += f->len;
	}
	return nfrags;
}
