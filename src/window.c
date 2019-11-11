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
window_buffer_init(size_t length, unsigned windowsize, unsigned maxfraglen, int dir)
{
	struct frag_buffer *w;

	/* Note: window buffer DOES NOT WORK with length > MAX_SEQ_ID */
	if (length > MAX_SEQ_ID)
		errx(1, "window_buffer_init: length (%" L "u) is greater than compiled MAX_SEQ_ID (%d)!",
				length, MAX_SEQ_ID);

	w = calloc(1, sizeof(struct frag_buffer));
	if (!w) {
		errx(1, "Failed to allocate window buffer memory!");
	}
	if (dir != WINDOW_RECVING && dir != WINDOW_SENDING) {
		errx(1, "Invalid window direction!");
	}

	window_buffer_resize(w, length, maxfraglen);

	w->windowsize = windowsize;
	w->direction = dir;
	return w;
}

void
window_buffer_resize(struct frag_buffer *w, size_t length, unsigned maxfraglen)
{
	if (w->length == length && w->maxfraglen == maxfraglen) {
		return;
	}

	if (w->numitems > 0) {
		WDEBUG("Resizing window buffer with things still in it = data loss!");
	}

	w->frags = malloc(length * sizeof(fragment));
	if (!w->frags) {
		errx(1, "Failed to allocate fragment buffer!");
	}

	w->data = malloc(length * maxfraglen);
	if (!w->data) {
		errx(1, "Failed to allocate fragment data buffer! "
				"Maybe fragsize too large (%u)?", maxfraglen);
	}

	w->length = length;
	w->maxfraglen = maxfraglen;
	window_buffer_clear(w);
}

void
window_buffer_destroy(struct frag_buffer *w)
{
	if (!w) return;
	if (w->frags) free(w->frags);
	if (w->data) free(w->data);
	free(w);
}

void
window_buffer_clear(struct frag_buffer *w)
{
	if (!w) return;
	memset(w->frags, 0, w->length * sizeof(fragment));
	memset(w->data, 0, w->length * w->maxfraglen);

	/* Fix fragment data pointers */
	for (size_t fragIndex = 0; fragIndex < w->length; fragIndex++) {
		w->frags[fragIndex].data = ((w->data + (w->maxfraglen * fragIndex)));
	}

	/* reset window parameters and statistics */
	w->numitems = 0;
	w->window_start = 0;
	w->last_write = 0;
	w->chunk_start = 0;
	w->cur_seq_id = 0;
	w->start_seq_id = 0;
	w->oos = 0;
}

size_t
window_buffer_available(struct frag_buffer *w)
/* Returns number of available fragment slots (NOT BYTES) */
{
	return w->length - w->numitems;
}

static void
window_slide(struct frag_buffer *w, unsigned slide, int delete)
/* Slide window forwards by given number of frags, clearing out old frags */
{
	WDEBUG("moving window forwards by %u; %" L "u-%" L "u (%u) to %" L "u-%" L "u (%u) len=%" L "u",
			slide, w->window_start, AFTER(w, w->windowsize), w->start_seq_id, AFTER(w, slide),
			AFTER(w, w->windowsize + slide), AFTERSEQ(w, slide), w->length);

	/* check if chunk_start has to be moved to prevent window overlapping,
	 * which results in deleting holes or frags */
	if (delete) {
		/* Clear old frags or holes */
		unsigned nfrags = 0;
		for (unsigned i = 0; i < slide; i++) {
			size_t woffs = WRAP(w->window_start + i);
			fragment *f = &w->frags[woffs];
			if (f->len != 0) {
				WDEBUG("    clear frag id %u, len %" L "u at index %" L "u",
						f->seqID, f->len, woffs);
				f->len = 0;
				nfrags ++;
			} else {
				WDEBUG("    clear hole at index %" L "u", woffs);
			}
		}

		WDEBUG("    chunk_start: %" L "u -> %" L "u", w->chunk_start, AFTER(w, slide));
		w->numitems -= nfrags;
		w->chunk_start = AFTER(w, slide);
		w->start_seq_id = AFTERSEQ(w, slide);
	}

	/* Update window status */
	w->window_start = AFTER(w, slide);
}

ssize_t
window_process_incoming_fragment(struct frag_buffer *w, fragment *f)
/* Handles fragment received from the sending side (RECV)
 * Returns index of fragment in window or <0 if dropped
 * Slides window forward if fragment received which is just above end seqID
 * XXX: Use whole buffer to receive and reassemble fragments
 * Old frags are "cleared" by being overwritten by newly received frags. (TODO)
 * Reassemble just starts at oldest slot (chunk_start) in window and continues until all frags
 * in buffer have been found. chunk_start incremented only if no holes found (tick). */
{
	/* Check if packet is in window */
	unsigned startid, offset;
	fragment *fd;
	startid = w->start_seq_id;
	offset = SEQ_OFFSET(startid, f->seqID);

	if (f->len == 0) {
		WDEBUG("got incoming frag with len 0! id=%u", f->seqID);
		return -1;
	}

	/* Place fragment into correct location in buffer, possibly overwriting
	 * an older and not-yet-reassembled fragment
	 * Note: chunk_start != window_start */
	ssize_t dest = WRAP(w->chunk_start + offset);

	if (offset > w->length - w->windowsize) {
		WDEBUG("incoming frag ahead: offs %u > %" L "u, cs %u[%" L "u], id %u[%" L "u]",
				offset, w->length - w->windowsize, w->start_seq_id, w->chunk_start,
				f->seqID, dest);
		offset -= w->length - w->windowsize;
		window_slide(w, offset, 1);
	}

	WDEBUG("   Putting frag seq %u into frags[%" L "u + %u = %" L "u]",
		   f->seqID, w->chunk_start, offset, dest);

	/* Check if fragment already received */
	fd = &w->frags[dest];
	if (fd->len != 0 && fd->seqID == f->seqID) {
		WDEBUG("    Duplicate at frags[%zu], using existing (seq: prev=%u, new=%u)", dest, fd->seqID, f->seqID);
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
window_reassemble_data(struct frag_buffer *w, uint8_t *data, size_t *len, uint8_t *compression)
/* Reassembles first complete sequence of fragments into data. (RECV)
 * *len should be passed with max space in *data, replaced with amount filled. *len == 0 means empty/invalid frag
 * Returns 1 if should be called again for another packet, 0 otherwise */
{
	size_t woffs;
	size_t maxlen = *len;
	size_t fraglen = 0;
	uint8_t *dest = data; //, *fdata_start;
	*len = 0;

	/* nothing to try reassembling if w is empty */
	if (w->numitems == 0) {
		WDEBUG("window buffer empty, nothing to reassemble");
		return 0;
	}
	if (compression) *compression = 1;

	unsigned consecutive_frags = 0, holes = 0, found_frags = 0;
	int end = 0, drop = 0; /* if packet is dropped */
	for (size_t i = 0; found_frags < w->numitems; i++) {
		woffs = WRAP(w->chunk_start + i);
		unsigned curseq = WRAPSEQ(w->start_seq_id + i);
		fragment *f = &w->frags[woffs];

		/* Note: Continue reassembling full packets until none left in buffer;
		 *      several full packets are sometimes left in buffer unprocessed
		 *      so we must not just take the oldest full packet and ignore newer ones */
		if (f->len == 0) { /* Empty fragment */
			if (holes < 2)
				WDEBUG("reassemble: hole at frag id %u [%" L "u]", curseq, woffs);
			/* reset reassembly things to start over */
			consecutive_frags = 0;
			holes++;
			continue;
		}

		found_frags++;
		if (f->seqID != curseq) {
			/* this is a serious bug. exit nastily */
			errx(1, "reassemble: frag [%" L "u] seqID mismatch: f=%u, cur=%u",
					woffs, f->seqID, curseq);
		}
		if (f->start && consecutive_frags != 0) {
			/* multiple "start" fragments in a row doesn't make sense => something is wrong */
			WDEBUG("reassemble: Warning: unexpected second start fragment, consecutives=%u, drop it", consecutive_frags);
			drop = 1;
		}

		if (consecutive_frags >= 1) {
			consecutive_frags++;
			if (f->len > maxlen) {
				WDEBUG("Data buffer too small: drop packet! Reassembled %" L "u bytes.", fraglen);
				drop = 1;
			} else if (drop == 0) {
				/* Copy next fragment to buffer if not going to drop */
				memcpy(dest, f->data, f->len);
			}
			dest += f->len;
			fraglen += f->len;
			maxlen -= f->len;

			if (compression) {
				*compression &= f->compressed & 1;
				if (f->compressed != *compression) {
					WDEBUG("Inconsistent compression flags in chunk. Will reassemble anyway!");
				}
			}

			WDEBUG("reassemble: id %u [%" L "u], len %" L "u, offs %" \
					L "u, total %" L "u, maxlen %" L "u, found %u/%" L "u, consecutive %u",
					f->seqID, woffs, f->len, dest - data, *len, maxlen, found_frags, w->numitems, consecutive_frags);

			if (f->end) {
				WDEBUG("Found end of chunk! (seqID %u, chunk len %u, datalen %" L "u)",
						f->seqID, consecutive_frags, *len);
				end = 1;
				consecutive_frags = 0;
				break;
			}
		}
	}

	if (end == 0 && drop == 0) {
		/* no end of chunk found because the window buffer has no more frags
		 * meaning they haven't been received yet. */
		return 0;
	}

	if (!drop)
		*len = fraglen;

	WDEBUG("Reassembled %" L "ub from %u frags; comp=%u; holes=%u; drop=%d",
			*len, consecutive_frags, *compression, holes, drop);
	/* Clear all used fragments, going backwards from last processed */
	size_t p = woffs;
	for (int n = 0; n < consecutive_frags; n++) {
		w->frags[p].len = 0;
		p = (p <= 0) ? w->length - 1 : p - 1;
	}

	w->numitems -= consecutive_frags;
	return found_frags >= consecutive_frags;
}

void
window_mark_sent(struct frag_buffer *w, fragment *justsent)
/* slides window forwards and clears the fragment from buffer */
{
	ssize_t fragoffs = justsent - w->frags;
	if (!justsent || fragoffs < 0 || fragoffs > w->length) {
		WDEBUG("Warning: window_mark_sent got bad fragment addr=%p, frag_offs=%zd", (void *)justsent, fragoffs);
		return;
	}
	if (w->window_start != fragoffs) {
		WDEBUG("Warning: bad fragoffs=%zd != window_start=%zu", fragoffs, w->window_start);
		return;
	}

	window_slide(w, 1, 1);
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
		WDEBUG("add_outgoing_data failed: buffer too small! frags=%zu, available=%zu", nfrags, available);
		return -1;
	}
	compressed &= 1;
	size_t offset = 0;
	fragment *f;
	WDEBUG("add_outgoing_data: chunk len %zu -> %zu frags, max fragsize %u",
			len, nfrags, w->maxfraglen);
	for (size_t i = 0; i < nfrags; i++) {
		f = &w->frags[w->last_write];
		/* copy in new data and reset frag stats */
		f->len = MIN(len - offset, w->maxfraglen);
		f->seqID = w->cur_seq_id;
		f->compressed = compressed;
		f->start = (i == 0) ? 1 : 0;
		f->end = (i == nfrags - 1) ? 1 : 0;

		WDEBUG("     frags[%zu]: len %zu, seqID %u, s %u, end %u, dOffs %zu",
				w->last_write, f->len, f->seqID, f->start, f->end, offset);

		memcpy(f->data, data + offset, f->len);
		w->last_write = WRAP(w->last_write + 1);
		w->cur_seq_id = WRAPSEQ(w->cur_seq_id + 1);
		w->numitems ++;
		offset += f->len;
	}
	return nfrags;
}
