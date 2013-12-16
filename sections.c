/*
 * PSI Section functions
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
#include <ctype.h>

#include "tsfuncs.h"

#define have_left(X) \
	do { if (data + (X) > data_end) return NULL; } while(0)

void ts_section_header_set_private_vars(struct ts_section_header *ts_section_header) {
	if (ts_section_header->section_syntax_indicator) {
		ts_section_header->data     = ts_section_header->section_data   + 3 + 5;	// Skip header and extended header
		ts_section_header->data_len = ts_section_header->section_length - 9;		// 5 for extended header, 4 for crc at the end
	} else {
		ts_section_header->data     = ts_section_header->section_data + 3; // Skip header
		ts_section_header->data_len = ts_section_header->section_length;
	}
	ts_section_header->section_data_len = ts_section_header->section_length + 3;	// 3 for section header
}

uint8_t *ts_section_header_parse(uint8_t *ts_packet, struct ts_header *ts_header, struct ts_section_header *ts_section_header) {
	uint8_t *data = ts_packet + ts_header->payload_offset;
	uint8_t *data_end = ts_packet + TS_PACKET_SIZE;

	have_left(ts_section_header->pointer_field + 1);
	ts_section_header->pointer_field = data[0];
	data += ts_section_header->pointer_field + 1;

	have_left(3);
	ts_section_header->table_id                 = data[0];
	ts_section_header->section_syntax_indicator = data[1] >> 7;				// x1111111
	ts_section_header->private_indicator        = (data[1] &~ 0xBF) >> 6;	// 1x111111
	ts_section_header->reserved1                = (data[1] &~ 0xCF) >> 4;	// 11xx1111
	ts_section_header->section_length           = ((data[1] &~ 0xF0) << 8) | data[2]; // 1111xxxx xxxxxxxx
	data += 3;

	if (ts_section_header->section_length == 0)
		return NULL;

	// Stuffing table, ignore.
	if (ts_section_header->table_id == 0x72)
		return NULL;

	if (ts_section_header->section_syntax_indicator) {
		have_left(5);
		ts_section_header->ts_id_number             = (data[0] << 8) | data[1]; // xxxxxxx xxxxxxx
		ts_section_header->reserved2                =  data[2] >> 6;			// xx111111
		ts_section_header->version_number           = (data[2] &~ 0xC1) >> 1;	// 11xxxxx1
		ts_section_header->current_next_indicator   = data[2] &~ 0xFE;			// 1111111x
		ts_section_header->section_number           = data[3];
		ts_section_header->last_section_number      = data[4];
		data += 5;
	}

	ts_section_header_set_private_vars(ts_section_header);

	return data;
}

#undef have_left

void ts_section_header_generate(uint8_t *ts_packet, struct ts_section_header *ts_section_header, uint8_t start) {
	ts_packet[start + 0] = ts_section_header->table_id;

	ts_packet[start + 1]  = ts_section_header->section_syntax_indicator << 7;		// x1111111
	ts_packet[start + 1] |= ts_section_header->private_indicator        << 6;		// 1x111111
	ts_packet[start + 1] |= ts_section_header->reserved1                << 4;		// 11xx1111
	ts_packet[start + 1] |= ts_section_header->section_length           >> 8;		// 1111xxxx xxxxxxxx
	ts_packet[start + 2]  = ts_section_header->section_length           &~ 0xff00;	// 1111xxxx xxxxxxxx

	if (ts_section_header->section_syntax_indicator) { // Extended table syntax
		ts_packet[start + 3]  = ts_section_header->ts_id_number             >> 8;		// xxxxxxxx xxxxxxxx
		ts_packet[start + 4]  = ts_section_header->ts_id_number             &~ 0xff00;

		ts_packet[start + 5]  = ts_section_header->reserved2                 << 6;		// xx111111
		ts_packet[start + 5] |= ts_section_header->version_number            << 1;		// 11xxxxx1
		ts_packet[start + 5] |= ts_section_header->current_next_indicator;				// 1111111x

		ts_packet[start + 6] = ts_section_header->section_number;
		ts_packet[start + 7] = ts_section_header->last_section_number;
	}
}

int ts_section_is_same(struct ts_section_header *s1, struct ts_section_header *s2) {
//	ts_LOGf("s1->table_id=%d s2->table_id=%d\n", s1->table_id, s2->table_id);
	if (s1->table_id != s2->table_id)
		return 0;

//	ts_LOGf("s1->version_number=%d s2->version_number=%d\n", s1->version_number, s2->version_number);
	if (s1->version_number != s2->version_number)
		return 0;

//	ts_LOGf("s1->section_number=%d s2->section_number=%d\n", s1->section_number, s2->section_number);
	if (s1->section_number != s2->section_number)
		return 0;

//	ts_LOGf("s1->section_length=%d s2->section_length=%d\n", s1->section_number, s2->section_number);
	if (s1->section_length != s2->section_length)
		return 0;

	return memcmp(s1->section_data, s2->section_data, s1->section_length) == 0;
}

#define IN(x, a, b) \
	(x >= a && x <= b)

void ts_section_header_dump(struct ts_section_header *t) {
	ts_LOGf("%s", "  * Section header\n");
	if (t->pointer_field)
	ts_LOGf("    - Pointer field      : %d\n", t->pointer_field);
	ts_LOGf("    - Table id           : %03x (%d) %s\n", t->table_id, t->table_id,
		t->table_id == 0x00         ? "program_association_section" :
		t->table_id == 0x01         ? "conditional_access_section" :
		t->table_id == 0x02         ? "program_map_section" :
		t->table_id == 0x03         ? "transport_stream_description_section" :
		IN(t->table_id, 0x04, 0x3f) ? "reserved" :
		t->table_id == 0x40         ? "network_information_section - actual_network" :
		t->table_id == 0x41         ? "network_information_section - other_network" :
		t->table_id == 0x42         ? "service_description_section - actual_transport_stream" :
		t->table_id == 0x83         ? "lcn_description_section - other" :
		IN(t->table_id, 0x43, 0x45) ? "reserved for future use" :
		t->table_id == 0x46         ? "service_description_section - other_transport_stream" :
		IN(t->table_id, 0x47, 0x49) ? "reserved for future use" :
		t->table_id == 0x4a         ? "bouquet_association_section" :
		IN(t->table_id, 0x4b, 0x4d) ? "reserved for future use" :
		t->table_id == 0x4e         ? "event_information_section - actual_transport_stream, present/following" :
		t->table_id == 0x4f         ? "event_information_section - other_transport_stream, present/following" :
		IN(t->table_id, 0x50, 0x5f) ? "event_information_section - actual_transport_stream, schedule" :
		IN(t->table_id, 0x60, 0x6f) ? "event_information_section - other_transport_stream, schedule" :
		t->table_id == 0x70         ? "time_date_section" :
		t->table_id == 0x71         ? "running_status_section" :
		t->table_id == 0x72         ? "stuffing_section" :
		t->table_id == 0x73         ? "time_offset_section" :
		t->table_id == 0x74         ? "application information section (TS 102 812 [15])" :
		t->table_id == 0x75         ? "container section (TS 102 323 [13])" :
		t->table_id == 0x76         ? "related content section (TS 102 323 [13])" :
		t->table_id == 0x77         ? "content identifier section (TS 102 323 [13])" :
		t->table_id == 0x78         ? "MPE-FEC section (EN 301 192 [4])" :
		t->table_id == 0x79         ? "resolution notification section (TS 102 323 [13])" :
		IN(t->table_id, 0x79, 0x7d) ? "reserved for future use" :
		t->table_id == 0x7e         ? "discontinuity_information_section" :
		t->table_id == 0x7f         ? "section_information_section" :
		IN(t->table_id, 0x80, 0xfe) ? "user defined" :
		t->table_id == 0xff         ? "reserved" : "Impossible!"
	);
	ts_LOGf("    - Section length     : %03x (%d) [num_packets:%d]\n",
		t->section_length, t->section_length, t->num_packets);
	if (!t->section_syntax_indicator) {
		ts_LOGf("    - Private section syntax\n");
	} else {
		ts_LOGf("    - TS ID / Program No : %04x (%d)\n", t->ts_id_number, t->ts_id_number);
		ts_LOGf("    - Version number %d, current next %d, section number %d, last section number %d\n",
				t->version_number,
				t->current_next_indicator,
				t->section_number,
				t->last_section_number);
	}
	if (t->CRC && t->CRC != 0xffffffff)
		ts_LOGf("    - CRC                : 0x%08x\n", t->CRC);
}

void ts_section_dump(struct ts_section_header *sec) {
	int i;

	ts_LOGf("%s table\n",
		sec->table_id == 0x00         ? "PAT" :
		sec->table_id == 0x01         ? "CAT" :
		sec->table_id == 0x02         ? "PMT" :
		sec->table_id == 0x03         ? "TSDT" :
		IN(sec->table_id, 0x40, 0x41) ? "NIT" :
		sec->table_id == 0x42         ? "SDT" :
		sec->table_id == 0x46         ? "SDT" :
		sec->table_id == 0x4a         ? "BAT" :
		IN(sec->table_id, 0x4e, 0x6f) ? "EIT" :
		sec->table_id == 0x70         ? "TDT" :
		sec->table_id == 0x71         ? "RST" :
		sec->table_id == 0x72         ? "STUFFING" :
		sec->table_id == 0x73         ? "TOT" :
		sec->table_id == 0x7e         ? "DIS" :
		sec->table_id == 0x7f         ? "SIS" :
		IN(sec->table_id, 0x80, 0xfe) ? "USER_DEFINED" :
		sec->table_id == 0xff         ? "RESERVED" : "UNKNOWN"
	);

	for (i=0;i<sec->num_packets;i++) {
		struct ts_header tshdr;
		ts_packet_header_parse(sec->packet_data + (i * TS_PACKET_SIZE), &tshdr);
		ts_packet_header_dump(&tshdr);
	}
	ts_section_header_dump(sec);
}

#undef IN
