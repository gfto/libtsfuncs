/*
 * SDT descriptors generator
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

static void ts_sdt_regenerate_packet_data(struct ts_sdt *sdt) {
	uint8_t *ts_packets;
	int num_packets;
	ts_sdt_generate(sdt, &ts_packets, &num_packets);
	memcpy(sdt->section_header->packet_data, ts_packets, num_packets * TS_PACKET_SIZE);
	sdt->section_header->num_packets = num_packets;
	free(ts_packets);
}

struct ts_sdt *ts_sdt_init(struct ts_sdt *sdt, uint16_t org_network_id, uint16_t transport_stream_id) {
	sdt->ts_header.pid            = 0x11;
	sdt->ts_header.pusi           = 1;
	sdt->ts_header.payload_field  = 1;
	sdt->ts_header.payload_offset = 4;

	sdt->section_header->table_id                 = 0x42;
	sdt->section_header->version_number           = 1;
	sdt->section_header->current_next_indicator   = 1;
	sdt->section_header->section_syntax_indicator = 1;
	sdt->section_header->private_indicator        = 1;
	sdt->section_header->section_length           = 9 + 3; // Empty section (9) + 3 (16+8) for SDT table data
	sdt->section_header->ts_id_number             = transport_stream_id;
	sdt->section_header->reserved1                = 3;
	sdt->section_header->reserved2                = 3;

	sdt->original_network_id = org_network_id;	// 16 bits
	sdt->reserved            = 0xff;			// 8 bits

	sdt->streams_num = 0;

	sdt->initialized = 1;

	ts_sdt_regenerate_packet_data(sdt);

	return sdt;
}

struct ts_sdt *ts_sdt_alloc_init(uint16_t org_network_id, uint16_t transport_stream_id) {
	struct ts_sdt *sdt = ts_sdt_alloc();
	if (!sdt)
		return NULL;
	return ts_sdt_init(sdt, org_network_id, transport_stream_id);
}

static int ts_sdt_add_stream(struct ts_sdt *sdt, uint16_t service_id, uint8_t *desc, uint8_t desc_size) {
	if (sdt->streams_num == sdt->streams_max - 1 || desc_size == 0) {
		FREE(desc);
		return 0;
	}

	int stream_len = 2 + 1 + 2 + desc_size;
	if (stream_len + sdt->section_header->section_length > 4093) {
		ts_LOGf("SDT no space left, max 4093, current %d will become %d!\n",
			sdt->section_header->section_length,
			stream_len + sdt->section_header->section_length);
		free(desc);
		return 0;
	}

	sdt->section_header->section_length += stream_len;

	struct ts_sdt_stream *sinfo = calloc(1, sizeof(struct ts_sdt_stream));
	sinfo->service_id                 = service_id;	// 16 bits (2 bytes)
	sinfo->reserved1                  = 63;			// 6 bits are up
	sinfo->EIT_schedule_flag          = 0;			// 1 bit
	sinfo->EIT_present_following_flag = 1;			// 1 bit (1 byte) We have EIT
	sinfo->running_status             = 4;			// 3 bits
	sinfo->free_CA_mode               = 0;			// 1 bit (0 == not scrambled)

	sinfo->descriptor_size            = desc_size;	// 12 bits (2 bytes)
	sinfo->descriptor_data            = desc;		// desc_size bytes

	sdt->streams[sdt->streams_num] = sinfo;
	sdt->streams_num++;

	ts_sdt_regenerate_packet_data(sdt);

	return 1;
}

int ts_sdt_add_service_descriptor(struct ts_sdt *sdt, uint16_t service_id, uint8_t video, char *provider_name, char *service_name) {
	char *name;
	if (!service_name && !provider_name)
		return 0;
	int desc_size = 2 + 1; // 2 tag, size; 1 service_type
	desc_size += 1 + (provider_name ? strlen(provider_name) : 0);
	desc_size += 1 + (service_name  ? strlen(service_name)  : 0);
	if (desc_size > 257) {
		ts_LOGf("SDT service_descriptor size > 255 is not supported (%d)!\n", desc_size);
		return 0;
	}

	int dpos = 0;
	uint8_t *desc = calloc(1, desc_size);
	desc[dpos + 0] = 0x48;					// Service descriptor
	desc[dpos + 1] = desc_size - 2;			// -2 Because of two byte header
	desc[dpos + 2] = video ? 0x01 : 0x02;	// DVB Table 75: Service type coding: 0x01 - digital tv, 0x02 - digital radio
	desc[dpos + 3] = (provider_name ? strlen(provider_name) : 0);
	dpos += 4;
	if (!provider_name || strlen(provider_name) == 0) {
		dpos++;
	} else {
		name = provider_name;
		while (name[0]) {
			desc[dpos++] = name[0];
			name++;
		}
	}
	if (!service_name || strlen(service_name) == 0) {
		dpos++;
	} else {
		desc[dpos++] = (service_name  ? strlen(service_name)  : 0);
		name = service_name;
		while (name[0]) {
			desc[dpos++] = name[0];
			name++;
		}
	}

	return ts_sdt_add_stream(sdt, service_id, desc, desc_size);
}
