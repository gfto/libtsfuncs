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

void ts_privsec_free(struct ts_privsec **pprivsec) {
	struct ts_privsec *privsec = *pprivsec;
	if (privsec) {
		ts_section_data_free(&privsec->section_header);
		FREE(*pprivsec);
	}
}

struct ts_privsec *ts_privsec_push_packet(struct ts_privsec *privsec, uint8_t *ts_packet) {
	struct ts_header ts_header;
	memset(&ts_header, 0, sizeof(struct ts_header));

	if (ts_packet_header_parse(ts_packet, &ts_header)) {
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

void ts_privsec_dump(struct ts_privsec *privsec) {
	struct ts_section_header *sec = privsec->section_header;
	ts_section_dump(sec);
	char *data = ts_hex_dump(sec->data, sec->data_len, 16);
	ts_LOGf("  * Section data:\n%s\n", data);
	FREE(data);
}
