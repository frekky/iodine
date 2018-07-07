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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <arpa/nameser.h>
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>

#include "common.h"
#include "encoding.h"
#include "dns.h"
#include "read.h"
#include "test.h"

START_TEST(test_read_putshort)
{
	unsigned short k;
	unsigned short l;
	uint8_t *p;
	size_t i;

	for (i = 0; i < 65536; i++) {
		p = (uint8_t *) &k;
		putshort(&p, i);
		fail_unless(ntohs(k) == i,
				"Bad value on putshort for %d: %d != %d",
					i, ntohs(k), i);

		p = (uint8_t *) &k;
		readshort(NULL, &p, &l);
		fail_unless(l == i,
				"Bad value on readshort for %d: %d != %d",
					i, l, i);
	}
}
END_TEST

START_TEST(test_read_putlong)
{
	uint32_t k, l, i, j;
	uint8_t* p;

	for (i = 0; i < 32; i++) {
		p = (uint8_t *)&k;
		j = 0xf << i;

		putlong(&p, j);

		fail_unless(ntohl(k) == j,
				"Bad value on putlong for %d: %d != %d", i, ntohl(j), j);

		p = (uint8_t *)&k;
		readlong(NULL, &p, &l);

		fail_unless(l == j,
				"Bad value on readlong for %d: %d != %d", i, l, j);
	}
}
END_TEST

START_TEST(test_read_name_empty_loop)
{
	uint8_t emptyloop[] = {
		'A', 'A', 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01 };
	uint8_t buf[1024];
	uint8_t *data;
	size_t rv;

	memset(buf, 0, sizeof(buf));
	data = emptyloop + sizeof(HEADER);
	buf[1023] = 'A';
	rv = readname(emptyloop, sizeof(emptyloop), &data, buf, 1023, 0, 0);
	fail_unless(rv == 0);
	fail_unless(buf[1023] == 'A');
}
END_TEST

START_TEST(test_read_name_inf_loop)
{
	uint8_t infloop[] = {
		'A', 'A', 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 'A', 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01 };
	uint8_t buf[1024];
	uint8_t *data;
	size_t rv;

	memset(buf, 0, sizeof(buf));
	data = infloop + sizeof(HEADER);
	buf[4] = '\a';
	rv = readname(infloop, sizeof(infloop), &data, buf, 4, 0, 0);
	fail_unless(data - infloop <= sizeof(infloop) && rv == 4);
	fail_unless(buf[4] == '\a');
}
END_TEST

START_TEST(test_read_name_longname)
{
	uint8_t longname[] =
		"AA\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x00\x00\x01\x00\x01";
	uint8_t buf[1024];
	uint8_t *data;
	size_t rv;

	memset(buf, 0, sizeof(buf));
	data = longname + sizeof(HEADER);
	buf[256] = '\a';
	rv = readname(longname, sizeof(longname), &data, buf, 256, 0, 0);
	fail_unless(data - longname <= sizeof(longname) && rv == 256);
	fail_unless(buf[256] == '\a');
}
END_TEST

START_TEST(test_read_name_invalid)
{
	uint8_t invalid[] =
		"AA\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3Finvalidquerysincethisistoooshort"; // 32 instead of 63
	uint8_t buf[1024];
	uint8_t *data, *b;
	size_t rv;
	size_t len = sizeof(invalid) - 64;


	/* This test uses malloc to cause segfault if readname accesses outside buffer */
	// resulting hostname can be max. 64*2+32=160 bytes
	memset(buf, 0, sizeof(buf));
	b = malloc(sizeof(invalid));
	if (b) {
		memcpy(b, invalid, sizeof(invalid));
		data = b + sizeof(HEADER);
		buf[160] = '\a';
		rv = readname(b, sizeof(invalid), &data, buf, 256, 0, 0);

		fail_unless(rv == 160);
		fail_unless(buf[160] == '\a');
		fail_unless((data - b) <= sizeof(invalid));
		free(b);
	} else {
		fail("couldn't allocate memory");
	}
}
END_TEST

START_TEST(test_read_name_onejump)
{
	uint8_t onejump[] =
		"AA\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
		"\x02hh\xc0\x15\x00\x01\x00\x01\x05zBCDE\x00";
	uint8_t buf[1024];
	uint8_t *data;
	size_t rv;

	memset(buf, 0, sizeof(buf));
	data = onejump + sizeof(HEADER);
	rv = readname(onejump, sizeof(onejump), &data, buf, 256, 0, 0);
	fail_unless(rv == 8);
}
END_TEST

START_TEST(test_read_name_badjump_start)
{
	uint8_t badjump[] = {
		'A', 'A', 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xfe, 0xcc, 0x00, 0x01, 0x00, 0x01 };
	uint8_t *jumper;
	uint8_t buf[1024];
	uint8_t *data;
	size_t rv;

	/* This test uses malloc to cause segfault if jump is executed */
	memset(buf, 0, sizeof(buf));
	jumper = malloc(sizeof(badjump));
	if (jumper) {
		memcpy(jumper, badjump, sizeof(badjump));
		data = jumper + sizeof(HEADER);
		rv = readname(jumper, sizeof(badjump), &data, buf, 256, 0, 0);

		fail_unless(rv == 0);
		fail_unless(buf[0] == 0);
	}
	free(jumper);
}
END_TEST

START_TEST(test_read_name_badjump_second)
{
	uint8_t badjump2[] = {
		'A', 'A', 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 'B', 'A', 0xfe, 0xcc, 0x00, 0x01, 0x00, 0x01 };
	uint8_t *jumper;
	uint8_t buf[1024];
	uint8_t *data;
	size_t rv;

	/* This test uses malloc to cause segfault if jump is executed */
	memset(buf, 0, sizeof(buf));
	jumper = malloc(sizeof(badjump2));
	if (jumper) {
		memcpy(jumper, badjump2, sizeof(badjump2));
		data = jumper + sizeof(HEADER);
		rv = readname(jumper, sizeof(badjump2), &data, buf, 256, 0, 0);

		fail_unless(rv == 3);
		fail_unless(memcmp("BA.", buf, 3) == 0, "incorrect result from readname");
	}
	free(jumper);
}
END_TEST

START_TEST(test_putname)
{
	uint8_t out[] = "\x06" "BADGER\x06" "BADGER\x04" "KRYO\x02" "SE\x00";
	uint8_t buf[256];
	uint8_t domain[] = "BADGER.BADGER.KRYO.SE";
	uint8_t *b;
	size_t ret;

	memset(buf, 0, 256);
	b = buf;
	ret = putname(&b, 256, domain, sizeof(domain) - 1, 0);
	/*for (int i = 0; i < ret; i++){
		fprintf(stderr, "%02x", buf[i]);
	}
	fprintf(stderr, " len=%d\n", ret);
	for (int i = 0; i < sizeof(out); i++){
		fprintf(stderr, "%02x", out[i]);
	}
	fprintf(stderr, " len=%d\n", sizeof(out));*/
	fail_unless(ret == sizeof(domain) + 1, "len(domain)+1==%u != %u", sizeof(domain) + 1, ret);
	fail_unless(memcmp(out, buf, MIN(ret, sizeof(out))) == 0, "Happy flow failed");
}
END_TEST

START_TEST(test_putname_nodot)
{
	uint8_t buf[256];
	uint8_t nodot[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
	uint8_t *b;
	size_t ret;

	memset(buf, 0, 256);
	b = buf;
	ret = putname(&b, 256, nodot, sizeof(nodot), 0);

	fail_unless(ret == 0);
	fail_unless(b == buf);
}
END_TEST

START_TEST(test_putname_toolong)
{
	uint8_t buf[256];
	uint8_t toolong[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ.";
	uint8_t *b;
	size_t ret;

	memset(buf, 0, 256);
	b = buf;
	ret = putname(&b, 256, toolong, sizeof(toolong), 0);

	fail_unless(ret == 0);
	fail_unless(b == buf);
}
END_TEST


TCase *
test_read_create_tests()
{
	TCase *tc;

	tc = tcase_create("Read");
	tcase_set_timeout(tc, 60);
	tcase_add_test(tc, test_read_putshort);
	tcase_add_test(tc, test_read_putlong);
	tcase_add_test(tc, test_read_name_empty_loop);
	tcase_add_test(tc, test_read_name_inf_loop);
	tcase_add_test(tc, test_read_name_longname);
	tcase_add_test(tc, test_read_name_invalid);
	tcase_add_test(tc, test_read_name_onejump);
	tcase_add_test(tc, test_read_name_badjump_start);
	tcase_add_test(tc, test_read_name_badjump_second);
	tcase_add_test(tc, test_putname);
	tcase_add_test(tc, test_putname_nodot);
	tcase_add_test(tc, test_putname_toolong);

	return tc;
}
