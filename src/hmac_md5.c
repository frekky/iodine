/*
 * Copyright (c) 2017 Frekk van Blagh <frekk@frekkworks.com>
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "md5.h"
#include "hmac_md5.h"

void
hmac_md5(uint8_t *dest, uint8_t *key, size_t keylen, uint8_t *data, size_t datalen)
/* Calculates HMAC-MD5 according to RFC 2104 */
{
	md5_state_t s;
	uint8_t inner[MD5_HASHSIZE];
	uint8_t buf[MD5_BLOCKSIZE];

	memset(buf, 0, MD5_BLOCKSIZE);

	if (keylen > MD5_BLOCKSIZE) {
		/* hash key if it exceeds blocksize */
		md5_init(&s);
		md5_append(&s, key, keylen);
		md5_finish(&s, buf);
	} else {
		memcpy(buf, key, keylen);
	}

	/* prepare inner digest */
	for (int i = 0; i < MD5_BLOCKSIZE; i++) {
		buf[i] ^= IPAD;
	}

	md5_init(&s);
	md5_append(&s, buf, MD5_BLOCKSIZE);
	md5_append(&s, data, datalen);
	md5_finish(&s, inner);

	for (int i = 0; i < MD5_BLOCKSIZE; i++) {
		buf[i] ^= IPAD ^ OPAD;
	}

	md5_init(&s);
	md5_append(&s, buf, MD5_BLOCKSIZE);
	md5_append(&s, inner, MD5_HASHSIZE);
	md5_finish(&s, dest);
}

