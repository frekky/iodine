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

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <arpa/nameser.h>
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif

#include "common.h"
#include "dns.h"
#include "read.h"
#include "encoding.h"
#include "base32.h"
#include "test.h"

static void dump_packet(uint8_t *, size_t);

static uint8_t query_packet[] =
	"\x05\x39\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x2D\x41\x6A\x62\x63"
	"\x75\x79\x74\x63\x70\x65\x62\x30\x67\x71\x30\x6C\x74\x65\x62\x75\x78"
	"\x67\x69\x64\x75\x6E\x62\x73\x73\x61\x33\x64\x66\x6F\x6E\x30\x63\x61"
	"\x7A\x64\x62\x6F\x72\x71\x71\x04\x6B\x72\x79\x6F\x02\x73\x65\x00\x00"
	"\x0A\x00\x01\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00";

static uint8_t answer_packet[] =
	"\x05\x39\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x05\x73\x69\x6C\x6C"
	"\x79\x04\x68\x6F\x73\x74\x02\x6F\x66\x06\x69\x6F\x64\x69\x6E\x65\x04"
	"\x63\x6F\x64\x65\x04\x6B\x72\x79\x6F\x02\x73\x65\x00\x00\x0A\x00\x01"
	"\xC0\x0C\x00\x0A\x00\x01\x00\x00\x00\x00\x00\x23\x74\x68\x69\x73\x20"
	"\x69\x73\x20\x74\x68\x65\x20\x6D\x65\x73\x73\x61\x67\x65\x20\x74\x6F"
	"\x20\x62\x65\x20\x64\x65\x6C\x69\x76\x65\x72\x65\x64";

static uint8_t answer_packet_high_trans_id[] =
	"\x85\x39\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x05\x73\x69\x6C\x6C"
	"\x79\x04\x68\x6F\x73\x74\x02\x6F\x66\x06\x69\x6F\x64\x69\x6E\x65\x04"
	"\x63\x6F\x64\x65\x04\x6B\x72\x79\x6F\x02\x73\x65\x00\x00\x0A\x00\x01"
	"\xC0\x0C\x00\x0A\x00\x01\x00\x00\x00\x00\x00\x23\x74\x68\x69\x73\x20"
	"\x69\x73\x20\x74\x68\x65\x20\x6D\x65\x73\x73\x61\x67\x65\x20\x74\x6F"
	"\x20\x62\x65\x20\x64\x65\x6C\x69\x76\x65\x72\x65\x64";
static uint8_t msgData[] = "this is the message to be delivered";
static uint8_t topdomain[] = "\x04kryo\x02se\x00";

static uint8_t innerData[] = "HELLO this is the test data";

START_TEST(test_encode_query)
{
	uint8_t buf[512], resolv[512];
	struct dns_packet *q;
	struct encoder *enc;
	size_t len, enclen;
	int ret;

	enclen = sizeof(resolv);
	memset(&buf, 0, sizeof(buf));
	memset(&resolv, 0, sizeof(resolv));
	memset(&q, 0, sizeof(struct query));
	enc = get_base32_encoder();

	len = enc->encode(resolv, &enclen, innerData, sizeof(innerData) - 1);

	q = dns_encode_data_query(T_NULL, topdomain, resolv, len);
	len = sizeof(buf);
	ret = dns_encode(buf, &len, q, 1);
	fail_if(len != sizeof(query_packet) - 1); /* Skip extra null character */

	if (memcmp(query_packet, buf, len) != 0 || len != sizeof(query_packet) - 1) {
		printf("\n");
		dump_packet(query_packet, sizeof(query_packet) - 1);
		dump_packet(buf, ret);
		fail("Did not compile expected packet; pktlen=%u, expected=%u", len, sizeof(query_packet) - 1);
	}
}
END_TEST

START_TEST(test_decode_query)
{
	uint8_t buf[512];
	struct dns_packet *q;
	struct encoder *enc;
	size_t len;

	memset(&buf, 0, sizeof(buf));
	len = sizeof(query_packet) - 1;
	enc = get_base32_encoder();

	fail_if((q = dns_decode(query_packet, len)) == NULL);
	fail_if(q->qr != QR_QUERY);
	len = sizeof(buf);
	fail_unless(dns_decode_data_query(q, topdomain, buf, &len), "decode failed!");

	fail_unless(memcmp(buf, innerData, sizeof(innerData) - 1) == 0, "Did not extract expected host");
	fail_unless(len == sizeof(innerData) - 1, "Bad host length: %zu, expected %u", len, sizeof(innerData) - 1);
}
END_TEST

START_TEST(test_encode_response)
{
	uint8_t buf[512], *p;
	uint8_t host[] = "silly.host.of.iodine.code.kryo.se";
	struct dns_packet *q, *ans;
	size_t len;
	int ret;

	fail_if((q = dns_packet_create(1, 1, 0, 0)) == NULL);
	q->id = 1337;
	q->q[0].type = T_NULL;
	p = q->q[0].name;
	putname(&p, 255, host, sizeof(host) - 1, 0);

	fail_if((ans = dns_encode_data_answer(q, msgData, sizeof(msgData) - 1)) == NULL);

	len = sizeof(buf);
	ret = dns_encode(buf, &len, q, 0);

	fail_unless(memcmp(answer_packet, buf, sizeof(answer_packet) - 1) == 0, "Did not compile expected packet");
	fail_unless(len == sizeof(buf), "Bad packet length: %d, expected %d", len, sizeof(buf));
}
END_TEST

START_TEST(test_decode_response)
{
	uint8_t buf[512];
	struct dns_packet *q;
	size_t len;

	fail_if((q = dns_decode(answer_packet, sizeof(answer_packet) - 1)) == NULL);

	len = sizeof(buf);
	fail_unless(dns_decode_data_answer(q, buf, &len));

	fail_unless(len == sizeof(msgData) - 1, "Bad data length: %zu, expected %u", len, sizeof(msgData) - 1);
	fail_unless(memcmp(msgData, buf, sizeof(msgData) - 1) == 0, "Did not extract expected data");
	fail_unless(q->id == 0x0539);
}
END_TEST

START_TEST(test_decode_response_with_high_trans_id)
{
	uint8_t buf[512];
	struct dns_packet *q;
	size_t len;

	memset(&buf, 0, sizeof(buf));

	fail_if((q = dns_decode(answer_packet_high_trans_id, sizeof(answer_packet_high_trans_id) - 1)) == NULL);

	len = sizeof(buf);
	fail_unless(dns_decode_data_answer(q, buf, &len));

	fail_unless(len == sizeof(msgData) - 1, "Bad data length: %zu, expected %u", len, sizeof(msgData) - 1);
	fail_unless(memcmp(msgData, buf, sizeof(msgData) - 1) == 0, "Did not extract expected data");
	fail_unless(q->id == 0x8539, "q.id was %08X instead of %08X!", q->id, 0x8539);
}
END_TEST

START_TEST(test_get_id_short_packet)
{
	uint8_t buf[5];
	size_t len;
	unsigned short id;

	len = sizeof(buf);
	memset(&buf, 5, sizeof(buf));

	id = dns_get_id(buf, len);
	fail_unless(id == 0);
}
END_TEST

START_TEST(test_get_id_low)
{
	unsigned short id;

	id = dns_get_id(answer_packet, sizeof(answer_packet));
	fail_unless(id == 1337);
}
END_TEST

START_TEST(test_get_id_high)
{
	unsigned short id;

	id = dns_get_id(answer_packet_high_trans_id, sizeof(answer_packet_high_trans_id));
	fail_unless(id == 0x8539);
}
END_TEST

static void
dump_packet(uint8_t *buf, size_t len)
{
	int pos;

	for (pos = 0; pos < len; pos++) {
		printf(" %02X", buf[pos]);
	}
	printf("\n");
	for (pos = 0; pos < len; pos++) {
		if (isalnum(buf[pos])) {
			printf(" %c ", buf[pos]);
		} else {
			printf(" * ");
		}
	}
	printf("\n");
}

TCase *
test_dns_create_tests()
{
	TCase *tc;

	tc = tcase_create("Dns");
	tcase_add_test(tc, test_encode_query);
	tcase_add_test(tc, test_decode_query);
	tcase_add_test(tc, test_encode_response);
	tcase_add_test(tc, test_decode_response);
	tcase_add_test(tc, test_decode_response_with_high_trans_id);
	tcase_add_test(tc, test_get_id_short_packet);
	tcase_add_test(tc, test_get_id_low);
	tcase_add_test(tc, test_get_id_high);

	return tc;
}
