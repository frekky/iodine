/*
 * Copyright (C) 2009 J.A.Bezemer@opensourcepartners.nl,
 *               2018 Frekk van Blagh
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

/*
 * This makes an encoder definition for "raw" data = base256
 * raw	76543210
 * enc	76543210
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

#include "encoding.h"
#include "base256.h"

#define BLKSIZE_RAW 1
#define BLKSIZE_ENC 1

static size_t base256_encode(uint8_t *, size_t *, const uint8_t *, size_t);
static size_t base256_decode(uint8_t *, size_t *, const uint8_t *, size_t);
static size_t base256_blksize_raw();
static size_t base256_blksize_enc();
static size_t base256_encoded_length(size_t inputlen);
static size_t base256_raw_length(size_t inputlen);

struct encoder base256_encoder =
{
	"raw",
	base256_encode,
	base256_decode,
	base256_blksize_raw,
	base256_blksize_enc,
	base256_encoded_length,
	base256_raw_length
};

struct encoder *b256 = &base256_encoder;

struct encoder
*get_base256_encoder()
{
	return &base256_encoder;
}

static size_t
base256_blksize_raw()
{
	return BLKSIZE_RAW;
}

static size_t
base256_blksize_enc()
{
	return BLKSIZE_ENC;
}

static size_t
base256_encoded_length(size_t inputlen)
{
	return inputlen;
}

static size_t
base256_raw_length(size_t inputlen)
{
	return inputlen;
}

static size_t
base256_encode(uint8_t *ubuf, size_t *buflen, const uint8_t *udata, size_t size)
/* Fills *buf with max. *buflen characters, encoding size bytes of *data.
 *
 * return value    : #bytes filled in buf
 * sets *buflen to : #bytes encoded from data */
{
	*buflen = MIN(*buflen, size);
	memcpy(ubuf, udata, *buflen);
	return *buflen;
}

static size_t
base256_decode(uint8_t *buf, size_t *buflen, const uint8_t *data, size_t len)
/* Fills *buf with max. *buflen bytes, decoded from slen chars in *str.
 *
 * return value    : #bytes filled in buf */
{
	memcpy(buf, data, MIN(*buflen, len));
	return MIN(*buflen, len);
}
