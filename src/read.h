/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
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

#ifndef _READ_H_
#define _READ_H_

#define DOT_CHAR		'.'
#define INVALID_CHAR	'^'

size_t readname(const uint8_t *, size_t, const uint8_t **, uint8_t *, size_t, int, int);
size_t readshort(const uint8_t *, const uint8_t **, uint16_t *);
size_t readlong(const uint8_t *, const uint8_t **, uint32_t *);
size_t readdata(const uint8_t **, uint8_t *, size_t);
size_t readtxtbin(const uint8_t *, const uint8_t **, size_t, uint8_t *, size_t);

size_t putname(uint8_t **, size_t, const uint8_t *, size_t, int);
size_t putbyte(uint8_t **, uint8_t);
size_t putshort(uint8_t **, uint16_t);
size_t putlong(uint8_t **, uint32_t);
size_t putdata(uint8_t **, const uint8_t *, size_t);
size_t puttxtbin(uint8_t **, size_t, const uint8_t *, size_t);

#endif
