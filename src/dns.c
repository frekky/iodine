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

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#ifdef WINDOWS32
#include "windows.h"
#else
#include <arpa/nameser.h>
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#ifdef ANDROID
#include "android_dns.h"
#endif
#endif

#include "dns.h"
#include "encoding.h"
#include "read.h"

void
dns_packet_destroy(struct dns_packet *p)
{
	if (!p)
		return;
	if (p->refcount > 1) {
		p->refcount--;
	}
	free(p->q);
	free(p->an);
	free(p);
}

struct dns_packet *
dns_packet_create(uint16_t qdcount, uint16_t ancount, uint16_t nscount, uint16_t arcount)
{
	struct dns_packet *p;
	p = calloc(1, sizeof(struct dns_packet));
	if (!p) return NULL;
	p->refcount = 1;
	p->qdcount = qdcount;
	p->ancount = ancount;
	if (qdcount) {
		p->q = calloc(qdcount, sizeof(struct dns_question));
		if (!p->q) {
			dns_packet_destroy(p);
			return NULL;
		}
	}
	if (ancount) {
		p->an = calloc(ancount, sizeof(struct dns_rr));
		if (!p->an) {
			dns_packet_destroy(p);
			return NULL;
		}
	}
	if (nscount) {
		p->ns = calloc(nscount, sizeof(struct dns_rr));
		if (!p->ns) {
			dns_packet_destroy(p);
			return NULL;
		}
	}
	if (arcount) {
		p->ar = calloc(arcount, sizeof(struct dns_rr));
		if (!p->ar) {
			dns_packet_destroy(p);
			return NULL;
		}
	}
	return p;
}

uint16_t
get_qtype_from_name(char *qtype)
{
	if (!strcasecmp(qtype, "NULL"))
		return T_NULL;
	else if (!strcasecmp(qtype, "PRIVATE"))
		return T_PRIVATE;
	else if (!strcasecmp(qtype, "CNAME"))
		return T_CNAME;
	else if (!strcasecmp(qtype, "A"))
		return T_A;
	else if (!strcasecmp(qtype, "MX"))
		return T_MX;
	else if (!strcasecmp(qtype, "SRV"))
		return T_SRV;
	else if (!strcasecmp(qtype, "TXT"))
		return T_TXT;
	else if (!strcasecmp(qtype, "PTR"))
		return T_PTR;
	else if (!strcasecmp(qtype, "AAAA"))
		return T_AAAA;
	else if (!strcasecmp(qtype, "A6"))
		return T_A6;
	else if (!strcasecmp(qtype, "DNAME"))
		return T_DNAME;
	return T_UNSET;
}

char *
get_qtype_name(uint16_t qtype)
{
	char *c = "UNDEFINED";

	if (qtype == T_NULL)
		c = "NULL";
	else if (qtype == T_PRIVATE)
		c = "PRIVATE";
	else if (qtype == T_CNAME)
		c = "CNAME";
	else if (qtype == T_A)
		c = "A";
	else if (qtype == T_MX)
		c = "MX";
	else if (qtype == T_SRV)
		c = "SRV";
	else if (qtype == T_TXT)
		c = "TXT";
	else if (qtype == T_PTR)
		c = "PTR";
	else if (qtype == T_AAAA)
		c = "AAAA";
	else if (qtype == T_A6)
		c = "A6";
	else if (qtype == T_DNAME)
		c = "DNAME";
	return c;
}

#define CHECKLEN(x)	if (sizeof(qs->name) < (x) + p-qs->name) { \
						dns_packet_destroy(q); \
						return NULL; \
					}

struct dns_packet *
dns_encode_data_query(uint16_t qtype, uint8_t *td, uint8_t *data, size_t datalen)
/* encode (possibly binary) data as DNS labels and fill dns_packet structure
 * topdomain must be DNS-encoded (len-prefixed labels, uncompressed) */
{
	struct dns_packet *q = dns_packet_create(1, 0, 0, 0);
	if (!q)
		return NULL;

	struct dns_question *qs = &q->q[0];
	qs->type = qtype;
	q->id = rand() & 0xFFFF;
	q->qr = QR_QUERY;
	q->rcode = NOERROR;

	uint8_t *p = qs->name;
	CHECKLEN(DNS_HOSTLEN(datalen) + HOSTLEN(td) - 1);
	size_t hostlen = putname(&p, sizeof(qs->name), data, datalen, 1) - 1;

	/* overwrite root label with topdomain */
	p--;
	hostlen += putdata(&p, td, HOSTLEN(td));
	qs->namelen = hostlen;
	return q;
}
#undef CHECKLEN

#define CHECKLEN(x, ann)	if (sizeof(q->an[ann].rdata) < (x) + (p-q->an[ann].rdata)) { \
								dns_packet_destroy(q); \
								return NULL; \
							}

struct dns_packet *
dns_encode_data_answer(struct dns_packet *qu, uint8_t *data, size_t datalen)
/* encodes (possibly binary) data into new struct dns_packet using whichever
 * RR types are applicable to the question type
 * returns 0 on failure, 1 on success */
{
	if (qu->qdcount == 0 || qu->qr != QR_QUERY) {
		/* we need a question */
		return NULL;
	}

	struct dns_packet *q;

	/* determine anstype + number of RRs to be encoded */
	uint16_t ancount = 1;
	uint16_t type = qu->q[0].type;
	uint16_t anstype = type;
	if (type == T_A || type == T_AAAA) {
		anstype = T_CNAME;
	} else if (type == T_MX) {
		ancount = datalen / (DNS_MAX_HOST_DATA - 2) + 1;
	} else if (type == T_SRV) {
		ancount = datalen / (DNS_MAX_HOST_DATA - 6) + 1;
	}

	if ((q = dns_packet_create(1, ancount, 0, 0)) == NULL) {
		return NULL;
	}

	q->id = qu->id;
	q->qr = QR_ANSWER;

	memcpy(&q->q[0], &qu->q[0], sizeof(struct dns_question));

	uint8_t *p = q->an[0].rdata;
	q->an[0].type = anstype;
	q->an[0].qnum = 0;
	if (anstype == T_CNAME || anstype == T_DNAME ||
		anstype == T_PTR || anstype == T_A6) {
		if (DNS_NUM_LABELS(datalen) + 1 + datalen > QUERY_RDATA_SIZE) {
			warnx("cannot encode more than QUERY_RDATA_SIZE (%d)", QUERY_RDATA_SIZE);
			dns_packet_destroy(q);
			return NULL;
		}
		/* produce simple rdata with single hostname */
		if (anstype == T_A6) {
			CHECKLEN(1, 0);
			/* A6 prefix len = 128 (no address suffix); see RFC 2874 */
			putbyte(&p, 128);
		}
		size_t header = p - q->an[0].rdata;
		q->an[0].rdlength = header + putname(&p, QUERY_RDATA_SIZE - header, data, datalen, 1);
	} else if (anstype == T_MX || anstype == T_SRV) {
		size_t rdhostlen = datalen / q->ancount + 1;
		uint8_t *d = data;
		for (uint16_t ann = 0; ann < q->ancount; ann++) {
			q->an[ann].type = anstype;
			q->an[ann].qnum = 0;
			p = q->an[ann].rdata;
			/* preference (both MX & SRV); used for reassembly */
			CHECKLEN(2, ann);
			putshort(&p, 10 * (ann + 1));
			if (anstype == T_SRV) {
				CHECKLEN(4, ann);
				/* SRV has header 2 fields in RDATA; see RFC 2782 */
				putshort(&p, 10); /* 16 bits weight */
				putshort(&p, 5060); /* 16 bits port (5060 = SIP) */
			}
			CHECKLEN(DNS_HOSTLEN(rdhostlen), ann);
			size_t header = p - q->an[ann].rdata;
			q->an[ann].rdlength = header + putname(&p, QUERY_RDATA_SIZE - header, data, datalen, 1);
		}
	} else if (anstype == T_TXT) {
		CHECKLEN(DNS_TXTRDLEN(datalen), 0);
		q->an[0].rdlength = puttxtbin(&p, QUERY_RDATA_SIZE, data, datalen);
	} else { /* NULL or PRIVATE */
		CHECKLEN(datalen, 0);
		memcpy(q->an[0].rdata, data, datalen);
		q->an[0].rdlength = datalen;
	}

	/* copy question source address to answer dest addr */
	q->m.destlen = qu->m.fromlen;
	memcpy(&q->m.dest, &qu->m.from, qu->m.fromlen);
	return q;
}
#undef CHECKLEN

#define CHECKLEN(x) if (buflen < (x) + (unsigned)(p-buf))  return 0

static size_t
dns_encode_rr(uint8_t *buf, uint8_t **dst, size_t buflen, struct dns_rr *a, uint16_t hostlabel)
{
	uint8_t *p = *dst;

	CHECKLEN(10);
	/* name pertaining to RR is given as pointer */
	putshort(&p, hostlabel);
	/* 16 bits TYPE */
	putshort(&p, a->type);
	putshort(&p, C_IN); /* 16 bits CLASS */
	putlong(&p, 0);	/* 32 bits TTL */
	putshort(&p, a->rdlength); /* 16 bits RDLENGTH */

	/* append actual data to query */
	CHECKLEN(a->rdlength);
	putdata(&p, a->rdata, a->rdlength);
	*dst = p;
	return p - buf;
}
#undef CHECKLEN

#define CHECKLEN(x) if (*buflen < (x) + (unsigned)(p-buf))  return 0

int
dns_encode(uint8_t *buf, size_t *buflen, struct dns_packet *q, int edns0)
{
	HEADER *header;
	uint16_t ancount;
	uint8_t *p;
	size_t len;

	if (*buflen < sizeof(HEADER))
		return 0;

	memset(buf, 0, *buflen);

	header = (HEADER*)buf;

	header->id = htons(q->id);
	header->qr = (q->qr == QR_ANSWER);
	header->opcode = 0;
	header->aa = (q->qr == QR_ANSWER);
	header->tc = 0;
	header->rd = (q->qr == QR_QUERY);
	header->ra = 0;
	header->qdcount = htons(q->qdcount);
	header->ancount = htons(q->ancount);
	header->nscount = htons(q->nscount);
	header->arcount = htons(q->arcount);

	p = buf + sizeof(HEADER);

	/* Question section(s); must contain valid DNS names (len-prefixed labels) */
	uint16_t qlabel[q->qdcount];
	struct dns_question *qs;
	for (uint16_t qd = 0; qd < q->qdcount; qd++) {
		qs = &q->q[qd];
		CHECKLEN(qs->namelen + 4);
		qlabel[qd] = ((p - buf) & 0x3fff) | 0xc000;
		putdata(&p, qs->name, qs->namelen);
		putshort(&p, qs->type);
		putshort(&p, C_IN);
	}

	switch (q->qr) {
	case QR_ANSWER:

		/* Answer section */
		for (uint16_t i = 0; i < q->ancount; i++) {
			dns_encode_rr(buf, &p, *buflen, &q->an[i], qlabel[q->an[i].qnum]);
		}

		/* Authority/NS section */
		for (uint16_t i = 0; i < q->nscount; i++) {
			dns_encode_rr(buf, &p, *buflen, &q->ns[i], qlabel[q->ns[i].qnum]);
		}

		/* Additional section */
		for (uint16_t i = 0; i < q->arcount; i++) {
			dns_encode_rr(buf, &p, *buflen, &q->ar[i], qlabel[q->ar[i].qnum]);
		}

		break;
	case QR_QUERY:
		/* Note that iodined also uses this for forward queries */

		/* EDNS0 to advertise maximum response length
		   (even CNAME/A/MX, 255+255+header would be >512) */
		if (edns0) {
			header->arcount = htons(1);
			CHECKLEN(11);
			putbyte(&p, 0x00);    /* Root */
			putshort(&p, 0x0029); /* OPT */
			putshort(&p, 0x1000); /* Payload size: 4096 */
			putshort(&p, 0x0000); /* Higher bits/edns version */
			putshort(&p, 0x8000); /* Z */
			putshort(&p, 0x0000); /* Data length */
		}

		break;
	}

	len = p - buf;

	*buflen = len;
	return 1;
}
#undef CHECKLEN

#define CHECKLEN(x) if (buflen < (x) + (unsigned)(p-buf))  return 0

size_t
dns_encode_ns_response(uint8_t *buf, size_t buflen, struct dns_packet *q, uint8_t *topdomain)
/* Only used when iodined gets an NS type query */
/* Mostly same as dns_encode_a_response() below */
{
	HEADER *header;
	size_t len, domain_len;
	uint16_t name, topname, nsname;
	uint8_t *ipp, *p;

	if (buflen < sizeof(HEADER) || q->qr != QR_QUERY || q->qdcount < 1)
		return 0;

	memset(buf, 0, buflen);

	// TODO not null-terminated strings
	domain_len = q->q[0].namelen - HOSTLEN(topdomain);
	uint8_t *qtd = q->q[0].name + domain_len;
	if (domain_len <= 1)
		return 0;
	if (memcmp(qtd, topdomain,  domain_len) != 0) {
		DEBUG(2, "ns query outside topdomain: %s", format_host(q->q[0].name, q->q[0].namelen, 0));
		return 0;
	}

	header = (HEADER*)buf;

	header->id = htons(q->id);
	header->qr = 1;
	header->opcode = 0;
	header->aa = 1;
	header->tc = 0;
	header->rd = 0;
	header->ra = 0;

	p = buf + sizeof(HEADER);

	header->qdcount = htons(1);
	header->ancount = htons(1);
	header->arcount = htons(1);

	/* pointer to start of name */
	name = 0xc000 | ((p - buf) & 0x3fff);

	/* pointer to start of topdomain; instead of dots at the end
	   we have length-bytes in front, so total length is the same */
	topname = 0xc000 | ((p - buf + domain_len) & 0x3fff);

	/* Query section */
	CHECKLEN(q->q[0].namelen);
	putdata(&p, q->q[0].name, q->q[0].namelen);	/* Name */
	CHECKLEN(4);
	putshort(&p, q->q[0].type);	/* Type */
	putshort(&p, C_IN);			/* Class */

	/* Answer section */
	CHECKLEN(12);
	putshort(&p, name);			/* Name */
	putshort(&p, q->q[0].type);			/* Type */
	putshort(&p, C_IN);			/* Class */
	putlong(&p, 3600);			/* TTL */
	putshort(&p, 5);			/* Data length */

	/* pointer to ns.topdomain */
	nsname = 0xc000 | ((p - buf) & 0x3fff);
	CHECKLEN(5);
	putbyte(&p, 2);
	putbyte(&p, 'n');
	putbyte(&p, 's');
	putshort(&p, topname);			/* Name Server */

	/* Additional data (A-record of NS server) */
	CHECKLEN(12);
	putshort(&p, nsname);			/* Name Server */
	putshort(&p, T_A);			/* Type */
	putshort(&p, C_IN);			/* Class */
	putlong(&p, 3600);			/* TTL */
	putshort(&p, 4);			/* Data length */

	/* ugly hack to output IP address */
	ipp = (uint8_t *) &q->m.dest;
	CHECKLEN(4);
	putbyte(&p, *(ipp++));
	putbyte(&p, *(ipp++));
	putbyte(&p, *(ipp++));
	putbyte(&p, *ipp);

	len = p - buf;
	return len;
}

size_t
dns_encode_a_response(uint8_t *buf, size_t buflen, struct dns_packet *q)
/* Only used when iodined gets an A type query for ns.topdomain or www.topdomain */
/* Mostly same as dns_encode_ns_response() above */
{
	HEADER *header;
	size_t len;
	uint16_t name;
	uint8_t *ipp;
	uint8_t *p;

	if (buflen < sizeof(HEADER) || q->qr != QR_QUERY || q->qdcount < 1)
		return 0;

	memset(buf, 0, buflen);

	header = (HEADER*)buf;

	header->id = htons(q->id);
	header->qr = 1;
	header->opcode = 0;
	header->aa = 1;
	header->tc = 0;
	header->rd = 0;
	header->ra = 0;

	p = buf + sizeof(HEADER);

	header->qdcount = htons(1);
	header->ancount = htons(1);

	/* pointer to start of name */
	name = 0xc000 | ((p - buf) & 0x3fff);

	/* Query section */
	putname(&p, buflen - (p - buf), q->q[0].name, q->q[0].namelen, 0);	/* Name */
	CHECKLEN(4);
	putshort(&p, q->q[0].type);			/* Type */
	putshort(&p, C_IN);			/* Class */

	/* Answer section */
	CHECKLEN(12);
	putshort(&p, name);			/* Name */
	putshort(&p, q->q[0].type);			/* Type */
	putshort(&p, C_IN);			/* Class */
	putlong(&p, 3600);			/* TTL */
	putshort(&p, 4);			/* Data length */

	/* ugly hack to output IP address */
	ipp = (uint8_t *) &q->m.dest;
	CHECKLEN(4);
	putbyte(&p, *(ipp++));
	putbyte(&p, *(ipp++));
	putbyte(&p, *(ipp++));
	putbyte(&p, *ipp);

	len = p - buf;
	return len;
}
#undef CHECKLEN

unsigned short
dns_get_id(uint8_t *packet, size_t packetlen)
{
	HEADER *header;
	header = (HEADER*)packet;

	if (packetlen < sizeof(HEADER))
		return 0;

	return ntohs(header->id);
}

#define CHECKLEN(x) if (packetlen < (x) + (unsigned)(p-packet))  return 0

static size_t
dns_decode_rr(uint8_t *packet, uint8_t **dst, size_t packetlen, struct dns_rr *a)
{
	uint8_t name[256], *p = *dst;
	uint16_t class;
	uint32_t ttl;

	/* name of corresponding question */
	readname(packet, packetlen, &p, name, sizeof(name), 1, 1);
	CHECKLEN(10);
	readshort(packet, &p, &a->type); /* answer type */
	readshort(packet, &p, &class); /* answer class */
	readlong(packet, &p, &ttl); /* answer TTL (seconds) */
	readshort(packet, &p, &a->rdlength); /* length of RDATA */
	CHECKLEN(a->rdlength);
	readdata(&p, a->rdata, a->rdlength); /* RDATA */

	*dst = p;
	return (p - *dst);
}

struct dns_packet *
dns_decode(uint8_t *packet, size_t packetlen)
{
	uint8_t name[QUERY_NAME_SIZE], *p;
	uint16_t class;
	uint32_t ttl;
	struct dns_packet *q;
	HEADER *header = (HEADER *) packet;

	/* Reject short packets */
	if (packetlen < sizeof(HEADER)) {
		return NULL;
	} else if (!header->qdcount) {
		/* we need a question */
		return NULL;
	}

	q = dns_packet_create(ntohs(header->qdcount), ntohs(header->ancount),
			ntohs(header->nscount), ntohs(header->arcount));
	if (!q) {
		warnx("error allocating memory for dns_packet!");
		return NULL;
	}

	q->id = ntohs(header->id);
	q->qr = header->qr == 0 ? QR_QUERY : QR_ANSWER;
	q->rcode = header->rcode;

	p = packet + sizeof(HEADER);


	/* Read question section */
	for (uint16_t qn = 0; qn < q->qdcount; qn++) {
		struct dns_question *qs = &q->q[qn];
		qs->namelen = readname(packet, packetlen, &p, qs->name, sizeof(qs->name), 0, 1);
		CHECKLEN(4);
		readshort(packet, &p, &qs->type);
		readshort(packet, &p, &class);
		if (class != C_IN) {
			return NULL;
		}
	}

	if (q->qr == QR_ANSWER) {
		/* Answer section RRs */
		for (uint16_t i = 0; i < q->ancount; i++) {
			dns_decode_rr(packet, &p, packetlen, &q->an[i]);
		}

		/* Authority/NS section */
		for (uint16_t i = 0; i < q->nscount; i++) {
			dns_decode_rr(packet, &p, packetlen, &q->ns[i]);
		}

		/* Additional section */
		for (uint16_t i = 0; i < q->arcount; i++) {
			dns_decode_rr(packet, &p, packetlen, &q->ar[i]);
		}
	}

	return q;
}
#undef CHECKLEN

#define CHECKLEN(x) if (a->rdlength < (x) + (p-a->rdata))  return 0

int
dns_decode_data_answer(struct dns_packet *q, uint8_t *out, size_t *outlen)
{

	if (q->qdcount < 1 || q->ancount < 1) {
		/* must have a question! */
		return 0;
	}

	struct dns_rr *a = &q->an[0];
	size_t len;
	uint16_t type = a->type;
	uint8_t *p = a->rdata;
	if (type == T_CNAME || type == T_PTR || type == T_A6 || type == T_DNAME) {
		if (q->ancount > 1) {
			warnx("dns_decode_data_answer: too many answer RRs for type!");
		}
		/* Assume that first answer is what we wanted */
		if (type == T_A6) {
			uint8_t prefix;
			CHECKLEN(1);
			readdata(&p, &prefix, 1);
			if (prefix != 128) {
				return 0;
			}
		}

		CHECKLEN(1);
		/* rest of RR is DNS-encoded hostname */
		len = readname(a->rdata, a->rdlength, &p, out, *outlen, 1, 0);
	} else if (type == T_MX || type == T_SRV) {
		/* Only exact 10-multiples are accepted, however answers may not be in
		 * order since DNS servers can mess around a bit */
		uint8_t *rdatastart;
		uint16_t pref, lastpref = 0;
		size_t offset = 0;

		for (uint16_t j = 0; j < q->ancount; j++) {
			for (uint16_t i = 0; i < q->ancount; i++) {
				a = &q->an[i];
				p = a->rdata;
				CHECKLEN(2);
				readshort(a->rdata, &p, &pref);

				if (a->type == T_SRV) {
					/* skip weight, port */
					CHECKLEN(4);
					p += 4;
				} else if (a->type != T_MX) {
					/* wrong type; expect only MX answers */
					return 0;
				}

				if (pref == lastpref + 10) {
					/* append query data to out */
					CHECKLEN(1);
					len = readname(a->rdata, a->rdlength, &p, out + offset, *outlen - offset, 1, 0);
					offset += len;
					lastpref += 10;
				}
			}
			if (lastpref >= q->ancount * 10) {
				/* decoded all MX/SRV RRs: done */
				break;
			}
		}
	} else if (type == T_TXT) {
		/* Assume that first answer is what we wanted */
		len = readtxtbin(a->rdata, &p, a->rdlength, out, *outlen);
	} else if (type == T_NULL || type == T_PRIVATE) {
		len = a->rdlength;
		if (*outlen < len) {
			return 0;
		}
		memcpy(out, a->rdata, len);
	} else { /* unknown type? */
		warnx("dns_decode_data_answer: unknown answer type %u", type);
		return 0;
	}

	*outlen = len;
	return 1;
}
#undef CHECKLEN

int
dns_decode_data_query(struct dns_packet *q, uint8_t *td, uint8_t *out, size_t *outlen)
{
	if (q->qdcount != 1) {
		/* wrong number of questions */
		return 0;
	}
	
	struct dns_question *qs = &q->q[0];
	/* check topdomain */
	uint8_t *qtd = qs->name + qs->namelen - HOSTLEN(td);
	if (memcmp(qtd, td, HOSTLEN(td)) != 0) {
		DEBUG(1, "invalid topdomain: %s; expected %s",
				format_host(qtd, HOSTLEN(td), 0),
				format_host(td, HOSTLEN(td), 1));
		return 0;
	}

	uint8_t *p = qs->name;
	/* read everything up to but not including topdomain as data */
	size_t len = readname(qs->name, qs->namelen - HOSTLEN(td), &p, out, *outlen, 1, 0);
	*outlen = len;
	return 1;
}
#undef CHECKLEN
