/*
 * Section data functions
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


uint8_t *ts_section_data_alloc_section() {
	uint8_t *data = malloc(4096);
	memset(data, 0x30, 4096);
	return data;
}

uint8_t *ts_section_data_alloc_packet() {
	uint8_t *data = malloc(5120);
	memset(data, 0x31, 5120);
	return data;
}

struct ts_section_header *ts_section_data_alloc() {
	struct ts_section_header *section_data = calloc(1, sizeof(struct ts_section_header));
	section_data->section_data = ts_section_data_alloc_section();
	section_data->packet_data  = ts_section_data_alloc_packet();
	return section_data;
}

void ts_section_data_clear(struct ts_section_header *sec) {
	if (!sec)
		return;
	// save
	uint8_t *section_data = sec->section_data;
	uint8_t *packet_data = sec->packet_data;
	// clear
	memset(section_data, 0x30, 4096);
	memset(packet_data , 0x31, 5120);
	memset(sec, 0, sizeof(struct ts_section_header));
	// restore
	sec->section_data = section_data;
	sec->packet_data  = packet_data;
}

void ts_section_data_free(struct ts_section_header **psection_data) {
	struct ts_section_header *section_data = *psection_data;
	if (section_data) {
		FREE(section_data->section_data);
		FREE(section_data->packet_data);
		FREE(*psection_data);
	}
}

void ts_section_data_copy(struct ts_section_header *src, struct ts_section_header *dst) {
	if (!src || !dst)
		return;
	uint8_t *section_data = dst->section_data;
	uint8_t *packet_data = dst->packet_data;

	memcpy(section_data, src->section_data, 4096);
	memcpy(packet_data , src->packet_data, 5120);
	*dst = *src;

	dst->section_data = section_data;
	dst->packet_data  = packet_data;

	ts_section_header_set_private_vars(dst);
}

// Fill CRC of the section data after secdata_size bytes
uint32_t ts_section_data_calculate_crc(uint8_t *section_data, int secdata_size) {
	uint32_t check_crc = ts_crc32(section_data, secdata_size);
	section_data[secdata_size + 0] = ((check_crc &~ 0x00ffffff) >> 24);
	section_data[secdata_size + 1] = ((check_crc &~ 0xff00ffff) >> 16);
	section_data[secdata_size + 2] = ((check_crc &~ 0xffff00ff) >>  8);
	section_data[secdata_size + 3] =  (check_crc &~ 0xffffff00);
	return check_crc;
}

#define min(a,b) ((a < b) ? a : b)

// Returns alllocated and build ts packets in *packets "ts_header"
// Returns number of packets in *num_packets
void ts_section_data_gen_ts_packets(struct ts_header *ts_header, uint8_t *section_data, int section_data_sz, uint8_t pointer_field, uint8_t **packets, int *num_packets) {
	struct ts_header tshdr = *ts_header;
	*packets = ts_section_data_alloc_packet();
	int np = 1; // Minimum 1 TS packet
	int section_sz = section_data_sz; // Add 4 bytes CRC!
	int sect = section_sz - (TS_PACKET_SIZE - 5);
	while (sect > 0) {
		sect -= TS_PACKET_SIZE - 4;
		np++;
	}
	int i, sect_pos = 0, sect_dataleft = section_sz;
	*num_packets = np;
	int dataofs;
	for (i=0;i<np;i++) {
		uint8_t *curpacket = *packets + (i * TS_PACKET_SIZE);	// Start of the current packet

		dataofs = 4; // Start after the TS header
		if (i == 0) { // First packet have pointer field
			if (ts_header->adapt_len)
				dataofs += ts_header->adapt_len + 1; // +1 for flags
			dataofs += pointer_field + 1;
		} else { // For the following packets after the first correct flags
			tshdr.pusi = 0;
			tshdr.continuity++;
		}
		ts_packet_header_generate(curpacket, &tshdr);				// Do the header
		if (i == 0) { // Set pointer field in the first packet
			if (ts_header->adapt_len) {
				curpacket[4] = ts_header->adapt_len;
				curpacket[5] = 0;	// Adaptation field flags, all off
				curpacket[5 + ts_header->adapt_len] = pointer_field;
			} else { // No adaptation field, just set pointer field
				curpacket[4] = pointer_field;
			}
		}

		uint8_t maxdatasize = TS_PACKET_SIZE - dataofs;		// How much data can this packet carry
		int copied = min(maxdatasize, sect_dataleft);
		memcpy(curpacket + dataofs, section_data + sect_pos, copied);	// Fill the data
		sect_pos      += maxdatasize;
		sect_dataleft -= maxdatasize;
		if (sect_dataleft < 0)
			break;
	}
}

void ts_section_add_packet(struct ts_section_header *sec, struct ts_header *ts_header, uint8_t *ts_packet) {
	uint8_t payload_offset = ts_header->payload_offset;
	if (!sec->section_length)
		return;

	if (ts_header->pusi) {
		payload_offset += sec->pointer_field + 1; // Pointer field
	}

	int to_copy = min(TS_PACKET_SIZE - payload_offset, sec->section_data_len - sec->section_pos);
	if (to_copy <= 0)
		return;

	if (sec->section_pos + to_copy >= 4092) {
		to_copy = sec->section_data_len - sec->section_pos;
	}

	memcpy(sec->section_data + sec->section_pos, ts_packet + payload_offset, to_copy);
	memcpy(sec->packet_data + (sec->num_packets * TS_PACKET_SIZE), ts_packet, TS_PACKET_SIZE);
	sec->section_pos += to_copy;
	sec->num_packets++;
	sec->initialized = (sec->section_pos+1) > sec->section_data_len;

	if (sec->initialized) {
		// CRC is after sec->data[sec->data_len]
		sec->CRC = (sec->CRC << 8) | sec->data[sec->data_len + 3];
		sec->CRC = (sec->CRC << 8) | sec->data[sec->data_len + 2];
		sec->CRC = (sec->CRC << 8) | sec->data[sec->data_len + 1];
		sec->CRC = (sec->CRC << 8) | sec->data[sec->data_len + 0];
	}
}
