#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "tsfuncs.h"

uint8_t *ts_section_header_parse(uint8_t *ts_packet, struct ts_header *ts_header, struct ts_section_header *ts_section_header) {
	if (ts_header->payload_offset + 8 > TS_PACKET_SIZE) {
		ts_packet_header_dump(ts_header);
		ts_LOGf("!!! Section start outside of TS packet %d!\n", ts_header->payload_offset + 8);
		return NULL;
	}

	uint8_t *data = ts_packet + ts_header->payload_offset;

	ts_section_header->pointer_field = data[0];
	data += ts_section_header->pointer_field + 1;

	ts_section_header->table_id                 = data[0];

	ts_section_header->section_syntax_indicator = data[1] >> 7;				// x1111111
	ts_section_header->private_indicator        = (data[1] &~ 0xBF) >> 6;	// 1x111111
	ts_section_header->reserved1                = (data[1] &~ 0xCF) >> 4;	// 11xx1111
	ts_section_header->section_length           = ((data[1] &~ 0xF0) << 8) | data[2]; // 1111xxxx xxxxxxxx

	if (ts_section_header->section_length == 0)
		return NULL;

	// Stuffing table, ignore.
	if (ts_section_header->table_id == 0x72)
		return NULL;

	ts_section_header->ts_id_number             = (data[3] << 8) | data[4]; // xxxxxxx xxxxxxx

	ts_section_header->reserved2                = data[5] >> 6;				// xx111111
	ts_section_header->version_number           = (data[5] &~ 0xC1) >> 1;	// 11xxxxx1
	ts_section_header->current_next_indicator   = data[5] &~ 0xFE;			// 1111111x

	ts_section_header->section_number           = data[6];
	ts_section_header->last_section_number      = data[7];

	if (!ts_section_header->section_syntax_indicator) {
		ts_LOGf("!!! Table 0x%02x have no section_syntax_indicator set!\n",
			ts_section_header->table_id);
		ts_packet_header_dump(ts_header);
		ts_section_header_dump(ts_section_header);
		return NULL;
	}

	ts_section_header->data_size = ts_section_header->section_length + 3;
	ts_section_header->packet_section_len = ts_section_header->data_size - 8 - 4;	// -8 for the section header, -4 for the CRC at the end

	return data + 8;
}

void ts_section_header_generate(uint8_t *ts_packet, struct ts_section_header *ts_section_header, uint8_t start) {
	ts_packet[start + 0] = ts_section_header->table_id;

	ts_packet[start + 1]  = ts_section_header->section_syntax_indicator << 7;		// x1111111
	ts_packet[start + 1] |= ts_section_header->private_indicator        << 6;		// 1x111111
	ts_packet[start + 1] |= ts_section_header->reserved1                << 4;		// 11xx1111
	ts_packet[start + 1] |= ts_section_header->section_length           >> 8;		// 1111xxxx xxxxxxxx
	ts_packet[start + 2]  = ts_section_header->section_length           &~ 0xff00;	// 1111xxxx xxxxxxxx

	ts_packet[start + 3]  = ts_section_header->ts_id_number             >> 8;		// xxxxxxxx xxxxxxxx
	ts_packet[start + 4]  = ts_section_header->ts_id_number             &~ 0xff00;

	ts_packet[start + 5]  = ts_section_header->reserved2                 << 6;		// xx111111
	ts_packet[start + 5] |= ts_section_header->version_number            << 1;		// 11xxxxx1
	ts_packet[start + 5] |= ts_section_header->current_next_indicator;				// 1111111x

	ts_packet[start + 6] = ts_section_header->section_number;
	ts_packet[start + 7] = ts_section_header->last_section_number;
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
	ts_LOGf("    - Section length     : %03x (%d)\n", t->section_length, t->section_length);
	ts_LOGf("    - TS ID / Program No : %04x (%d)\n", t->ts_id_number, t->ts_id_number);
	ts_LOGf("    - Version number %d, current next %d, section number %d, last section number %d\n",
			t->version_number,
			t->current_next_indicator,
			t->section_number,
			t->last_section_number);
	ts_LOGf("    - Private vars       : data_size:%d packet_section_len:%d num_packets:%d section_pos:%d\n",
			t->data_size,
			t->packet_section_len,
			t->num_packets,
			t->section_pos);
}

#undef IN
