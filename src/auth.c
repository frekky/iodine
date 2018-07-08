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

#include <string.h>
#include <sys/types.h>

#ifdef WINDOWS32
#include "windows.h"
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "md5.h"
#include "hmac_md5.h"

void
bitwise_xor(uint8_t *data, size_t datalen, uint8_t *key, size_t keylen)
{
	size_t d = 0, k = 0;
	while (d < datalen && k < keylen) {
		data[d] ^= key[k];
		d++;
		k = (k + 1 > keylen) ? 0 : k + 1;
	}
}

/* Calculates login hash based on description in docs/proto_00000801.txt,
 * section "Login process". Requires 16-byte server/client challenge and
 * password. All bufs must be >=16 bytes. */
void
login_calculate(uint8_t *buf, uint8_t *passmd5,	uint8_t *chall)
{
	unsigned char temp[16];
	md5_state_t ctx;

	memcpy(temp, passmd5, 16);

	bitwise_xor(temp, 16, chall, 16);

	md5_init(&ctx);
	md5_append(&ctx, temp, 16);
	md5_finish(&ctx, (unsigned char *) buf);

}


/* 	1. Calculate MD5(plaintext password)
	2. Calculate MD5(server challenge)
	3. Calculate MD5(client challenge)
	4. Append result from (2) to result from (1)
	5. Append result from (3) to result from (4) and pad with 0x2C to 64 bytes
	6. Bitwise XOR result from (5) with 0xB5
	7. Calculate the MD5 hash of the result from (6), this is the key for the HMAC.
	*/
void
hmac_key_calculate(uint8_t *out,
		uint8_t *sc, size_t scl,
		uint8_t *cc, size_t ccl, uint8_t *passmd5)
{
	md5_state_t h;
	uint8_t buf[64];
	memset(buf, 0x2C, sizeof(buf));

	memcpy(buf, passmd5, 16);

	md5_init(&h);
	md5_append(&h, sc, scl);
	md5_finish(&h, buf + 16);

	md5_init(&h);
	md5_append(&h, cc, ccl);
	md5_finish(&h, buf + 32);

	uint8_t k = 0xB5;
	bitwise_xor(buf, 64, &k, 1);

	md5_init(&h);
	md5_append(&h, buf, 64);
	md5_finish(&h, out);
}

