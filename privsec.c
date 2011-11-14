/*
 * Private sections parser
 * Copyright (C) 2010-2011 Unix Solutions Ltd.
 *
 * Released under MIT license.
 * See LICENSE-MIT.txt for license terms.
 */
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tsfuncs.h"

struct ts_privsec *ts_privsec_alloc() {
	struct ts_privsec *privsec = calloc(1, sizeof(struct ts_privsec));
	privsec->section_header	= ts_section_data_alloc();
	return privsec;
}

void ts_privsec_clear(struct ts_privsec *privsec) {
	if (!privsec)
		return;
	// save
	struct ts_section_header *section_header = privsec->section_header;
	// clear
	ts_section_data_clear(section_header);
	memset(privsec, 0, sizeof(struct ts_privsec));
	// restore
	privsec->section_header = section_header;
}

void ts_privsec_free(struct ts_privsec **pprivsec) {
	struct ts_privsec *privsec = *pprivsec;
	if (privsec) {
		ts_section_data_free(&privsec->section_header);
		FREE(*pprivsec);
	}
}

void ts_privsec_copy(struct ts_privsec *src, struct ts_privsec *dst) {
	if (!src || !dst)
		return;
	dst->ts_header = src->ts_header;
	dst->initialized = src->initialized;
	ts_section_data_copy(src->section_header, dst->section_header);
}

struct ts_privsec *ts_privsec_push_packet(struct ts_privsec *privsec, uint8_t *ts_packet) {
	struct ts_header ts_header;
	memset(&ts_header, 0, sizeof(struct ts_header));

	if (ts_packet_header_parse(ts_packet, &ts_header)) {
		// Received PUSI packet before table END, clear the table to start gathering new one
		if (ts_header.pusi && privsec->ts_header.pusi)
			ts_privsec_clear(privsec);
		if (!privsec->ts_header.pusi)
			privsec->ts_header = ts_header;
	}

	if (ts_header.pusi) {
		struct ts_section_header section_header;
		memset(&section_header, 0, sizeof(struct ts_section_header));

		uint8_t *section_data = ts_section_header_parse(ts_packet, &privsec->ts_header, &section_header);
		if (!section_data) {
			memset(&privsec->ts_header, 0, sizeof(struct ts_header));
			goto OUT;
		}

		// Set correct section_header
		ts_section_header_parse(ts_packet, &privsec->ts_header, privsec->section_header);
	}

	if (!privsec->initialized) {
		ts_section_add_packet(privsec->section_header, &ts_header, ts_packet);
		if (privsec->section_header->initialized) {
			privsec->initialized = 1;
		}
	}

OUT:
	return privsec;
}

int ts_privsec_is_same(struct ts_privsec *p1, struct ts_privsec *p2) {
	if (p1 == p2) return 1; // Same
	if ((!p1 && p2) || (p1 && !p2)) return 0; // Not same (one is NULL)
	if (p1->section_header->section_length != p1->section_header->section_length) return 0; // Not same
	return memcmp(p1->section_header->section_data, p2->section_header->section_data, p1->section_header->section_length) == 0;
}

void ts_privsec_dump(struct ts_privsec *privsec) {
	struct ts_section_header *sec = privsec->section_header;
	ts_section_dump(sec);
	char *data = ts_hex_dump(sec->data, sec->data_len, 16);
	ts_LOGf("  * Section data:\n%s\n", data);
	FREE(data);
}
