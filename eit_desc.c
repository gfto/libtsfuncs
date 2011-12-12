/*
 * EIT descriptor generator
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

#include "tsfuncs.h"

static void ts_eit_regenerate_packet_data(struct ts_eit *eit) {
	uint8_t *ts_packets;
	int num_packets;
	ts_eit_generate(eit, &ts_packets, &num_packets);
	memcpy(eit->section_header->packet_data, ts_packets, num_packets * TS_PACKET_SIZE);
	eit->section_header->num_packets = num_packets;
	free(ts_packets);
}

struct ts_eit *ts_eit_init(struct ts_eit *eit, uint16_t service_id, uint16_t transport_stream_id, uint16_t org_network_id, uint8_t table_id, uint8_t sec_number, uint8_t last_sec_number) {
	eit->ts_header.pid            = 0x12;
	eit->ts_header.pusi           = 1;
	eit->ts_header.payload_field  = 1;
	eit->ts_header.payload_offset = 4;

	eit->section_header->table_id                 = table_id;
	eit->section_header->version_number           = 1;
	eit->section_header->current_next_indicator   = 1;
	eit->section_header->section_syntax_indicator = 1;
	eit->section_header->private_indicator        = 1;
	eit->section_header->section_length           = 9 + 6;		// Empty section, +6 (16+16+8+8 bits) for EIT table data
	eit->section_header->ts_id_number             = service_id;
	eit->section_header->reserved1                = 3;
	eit->section_header->reserved2                = 3;

	eit->section_header->section_number           = sec_number;
	eit->section_header->last_section_number      = last_sec_number;

	eit->transport_stream_id         = transport_stream_id;		// 16 bits
	eit->original_network_id         = org_network_id;			// 16 bits
	eit->segment_last_section_number = 0;						// 8 bits
	eit->last_table_id               = table_id;				// 8 bits

	eit->streams_num = 0;

	eit->initialized = 1;

	ts_eit_regenerate_packet_data(eit);

	return eit;
}

struct ts_eit *ts_eit_alloc_init(uint16_t service_id, uint16_t transport_stream_id, uint16_t org_network_id, uint8_t table_id, uint8_t sec_number, uint8_t last_sec_number) {
	struct ts_eit *eit = ts_eit_alloc();
	if (!eit)
		return NULL;

	return ts_eit_init(eit, service_id, transport_stream_id, org_network_id, table_id, sec_number, last_sec_number);
}

struct ts_eit *ts_eit_alloc_init_pf(uint16_t service_id, uint16_t transport_stream_id, uint16_t org_network_id, uint8_t sec_number, uint8_t last_sec_number) {
	return ts_eit_alloc_init(service_id, transport_stream_id, org_network_id, 0x4e, sec_number, last_sec_number);
}

struct ts_eit *ts_eit_alloc_init_schedule(uint16_t service_id, uint16_t transport_stream_id, uint16_t org_network_id, uint8_t sec_number, uint8_t last_sec_number) {
	return ts_eit_alloc_init(service_id, transport_stream_id, org_network_id, 0x50, sec_number, last_sec_number);
}


static int ts_eit_add_stream(struct ts_eit *eit, uint16_t event_id, uint8_t running, time_t start_time, int duration_sec, uint8_t *desc, uint16_t desc_size) {
	if (eit->streams_num == eit->streams_max - 1 || desc_size == 0) {
		FREE(desc);
		return 0;
	}

	uint16_t start_mjd;
	uint32_t start_bcd;
	uint32_t dur_bcd = ts_time_encode_bcd(duration_sec);
	ts_time_encode_mjd(&start_mjd, &start_bcd, &start_time, NULL);

	int stream_len = 12 + desc_size;
	if (stream_len + eit->section_header->section_length > 4093) {
		ts_LOGf("EIT no space left, max 4093, current %d will become %d!\n",
			eit->section_header->section_length,
			stream_len + eit->section_header->section_length);
		free(desc);
		return 0;
	}

	eit->section_header->section_length += stream_len;

	struct ts_eit_stream *sinfo = calloc(1, sizeof(struct ts_eit_stream));
	sinfo->event_id            = event_id;		// 2 bytes (16 bits)
	sinfo->start_time_mjd      = start_mjd;		// 5 bytes (40 bits)
	sinfo->start_time_bcd      = start_bcd;		//
	sinfo->duration_bcd        = dur_bcd;		// 3 bytes (24 bits)

	sinfo->running_status      = running;		// 2 bytes (3 bits), 1 == not running, 4 == running
	sinfo->free_CA_mode        = 0;				//         (1 bit) , 0 == not scrambled
	sinfo->descriptor_size     = desc_size;		//         (12 bits)

	sinfo->descriptor_data     = desc;			// desc_size bytes

	eit->streams[eit->streams_num] = sinfo;
	eit->streams_num++;

	ts_eit_regenerate_packet_data(eit);

	return 1;
}

int ts_eit_add_short_event_descriptor(struct ts_eit *eit, uint16_t event_id, uint8_t running, time_t start_time, int duration_sec, char *event_name, char *event_short_descr) {
	char *txt;
	uint8_t event_len = event_name ? strlen(event_name) : 0;
	uint8_t descr_len = event_short_descr ? strlen(event_short_descr) : 0;

	int desc_size = 2 + 3; // 2 bytes tag header, 3 bytes ISO lang code
	desc_size += 1 + event_len;
	desc_size += 1 + descr_len;
	if (desc_size > 255) {
		ts_LOGf("EIT short event descriptor size > 255 is not supported (%d)!\n", desc_size);
		return 0;
	}
	if (event_len == 0) {
		ts_LOGf("EIT event_len == 0!\n");
		return 0;
	}
	uint8_t *desc = calloc(1, desc_size);

	int dpos = 0;
	desc[dpos +  0] = 0x4d;							// Short_event_descriptor
	desc[dpos +  1] = desc_size - 2;					// -2 Because of two byte header
	desc[dpos +  2] = 'b';
	desc[dpos +  3] = 'u';
	desc[dpos +  4] = 'l';
	desc[dpos +  5] = event_len;
	dpos += 6;
	txt = event_name;
	while (txt[0]) {
		desc[dpos++] = txt[0];
		txt++;
	}
	desc[dpos++   ] = descr_len;
	if (descr_len) {
		txt = event_short_descr;
		while (txt[0]) {
			desc[dpos++] = txt[0];
			txt++;
		}
	}

	return ts_eit_add_stream(eit, event_id, running ? 4 : 1, start_time, duration_sec, desc, dpos);
}


int ts_eit_add_extended_event_descriptor(struct ts_eit *eit, uint16_t event_id, uint8_t running, time_t start_time, int duration_sec, char *text) {
	if (!text)
		return 0;
	char *txt;
	int desc_size = 2 + 3 + 1 + 1;	// 2 bytes tag header
									// 3 bytes ISO lang code
									// 1 byte, desc_number, last_desc_number (4 bits + 4 bits)
									// 1 byte length of items (0 because items are unsupported)
	int text_len = strlen(text);
	desc_size += 1 + text_len;
	if (desc_size > 257) {
		ts_LOGf("EIT extended event descriptor size > 255 is not supported (%d)!\n", desc_size);
		return 0;
	}
	if (text_len == 0) {
		ts_LOGf("EIT text_len == 0!\n");
		return 0;
	}
	uint8_t *desc = calloc(1, desc_size);

	int dpos = 0;
	desc[dpos +  0] = 0x4e;			 // Extended_event_descriptor
	desc[dpos +  1] = desc_size - 2; // -2 Because of two byte header
	desc[dpos +  2] = (0 << 4) | (0 &~ 0xf0);	 // descriptor_number, last_descriptor_number;
	desc[dpos +  3] = 'b';
	desc[dpos +  4] = 'u';
	desc[dpos +  5] = 'l';
	desc[dpos +  6] = 0;						 // Length of items (items are not supported)
	desc[dpos +  7] = text_len;
	dpos += 8;
	txt = text;
	while (txt[0]) {
		desc[dpos++] = txt[0];
		txt++;
	}

	return ts_eit_add_stream(eit, event_id, running ? 4 : 1, start_time, duration_sec, desc, dpos);
}
