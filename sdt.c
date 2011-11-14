/*
 * SDT table parser and generator
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

struct ts_sdt *ts_sdt_alloc() {
	struct ts_sdt *sdt = calloc(1, sizeof(struct ts_sdt));
	sdt->section_header	= ts_section_data_alloc();
	sdt->streams_max	= 128;
	sdt->streams		= calloc(sdt->streams_max, sizeof(void *));
	return sdt;
}

static void ts_sdt_streams_data_free(struct ts_sdt *sdt) {
	int i;
	for (i=0;i<sdt->streams_num;i++) {
		if (sdt->streams[i]) {
			FREE(sdt->streams[i]->descriptor_data);
			FREE(sdt->streams[i]);
		}
	}
}

void ts_sdt_clear(struct ts_sdt *sdt) {
	if (!sdt)
		return;
	// save
	struct ts_section_header *section_header = sdt->section_header;
	struct ts_sdt_stream **streams = sdt->streams;
	int streams_max = sdt->streams_max;
	// free
	ts_sdt_streams_data_free(sdt);
	// clear
	ts_section_data_clear(section_header);
	memset(sdt, 0, sizeof(struct ts_sdt));
	// restore
	sdt->section_header = section_header;
	sdt->streams = streams;
	sdt->streams_max = streams_max;
}

void ts_sdt_free(struct ts_sdt **psdt) {
	struct ts_sdt *sdt = *psdt;
	if (sdt) {
		ts_section_data_free(&sdt->section_header);
		ts_sdt_streams_data_free(sdt);
		FREE(sdt->streams);
		FREE(*psdt);
	}
}

struct ts_sdt *ts_sdt_push_packet(struct ts_sdt *sdt, uint8_t *ts_packet) {
	struct ts_header ts_header;
	memset(&ts_header, 0, sizeof(struct ts_header));

	if (ts_packet_header_parse(ts_packet, &ts_header)) {
		// SDT should be with PID 0x11
		if (ts_header.pid != 0x11)
			goto OUT;
		// Received PUSI packet before table END, clear the table to start gathering new one
		if (ts_header.pusi && sdt->ts_header.pusi)
			ts_sdt_clear(sdt);
		if (!sdt->ts_header.pusi)
			sdt->ts_header = ts_header;
	}

	if (ts_header.pusi) {
		struct ts_section_header section_header;
		memset(&section_header, 0, sizeof(struct ts_section_header));

		uint8_t *section_data = ts_section_header_parse(ts_packet, &sdt->ts_header, &section_header);
		if (!section_data) {
			memset(&sdt->ts_header, 0, sizeof(struct ts_header));
			goto OUT;
		}
		// table_id should be 0x42 (service_description_section - actual_transport_stream)
		if (section_header.table_id != 0x42) {
			memset(&sdt->ts_header, 0, sizeof(struct ts_header));
			goto OUT;
		}

		// Set correct section_header
		ts_section_header_parse(ts_packet, &sdt->ts_header, sdt->section_header);
	}

	if (!sdt->initialized) {
		ts_section_add_packet(sdt->section_header, &ts_header, ts_packet);
		if (sdt->section_header->initialized) {
			if (!ts_sdt_parse(sdt))
				goto ERROR;
		}
	}

OUT:
	return sdt;

ERROR:
	ts_sdt_clear(sdt);
	return sdt;
}

int ts_sdt_parse(struct ts_sdt *sdt) {
	uint8_t *section_data = sdt->section_header->data;
	int section_len = sdt->section_header->data_len;

	// 3 bytes
	sdt->original_network_id = (section_data[0] << 8) | section_data[1];
	sdt->reserved            = section_data[2];

	section_data = section_data + 3;
	section_len  = section_len -3;

	while (section_len > 0) {
		if (sdt->streams_num == sdt->streams_max) {
			ts_LOGf("SDT contains too many streams (>%d), not all are initialized!\n", sdt->streams_max);
			break;
		}

		struct ts_sdt_stream *sinfo = calloc(1, sizeof(struct ts_sdt_stream));

		sinfo->service_id = (section_data[0] << 8) | section_data[1];

		sinfo->reserved1                  =  (section_data[2] &~ 0x03) >> 2;	// xxxxxx11
		sinfo->EIT_schedule_flag          =  (section_data[2] &~ 0xFD) >> 1;	// 111111x1
		sinfo->EIT_present_following_flag =  (section_data[2] &~ 0xFE);		// 1111111x

		sinfo->running_status  = section_data[3] >> 5;						// 111xxxxx
		sinfo->free_CA_mode    = (section_data[3] &~ 0xE0) >> 4;				// xxx1xxxx
		sinfo->descriptor_size = ((section_data[3] &~ 0xF0) << 8) | section_data[4];	// 1111xxxx xxxxxxxx

		sinfo->descriptor_data      = NULL;
		if (sinfo->descriptor_size > 0) {
			sinfo->descriptor_data = malloc(sinfo->descriptor_size);
			memcpy(sinfo->descriptor_data, &section_data[5], sinfo->descriptor_size);
		}
		sdt->streams[sdt->streams_num] = sinfo;
		sdt->streams_num++;

		section_data += 5 + sinfo->descriptor_size;
		section_len  -= 5 + sinfo->descriptor_size;
	}

	if (!ts_crc32_section_check(sdt->section_header, "SDT"))
		return 0;

	sdt->initialized = 1;
	return 1;
}

void ts_sdt_generate(struct ts_sdt *sdt, uint8_t **ts_packets, int *num_packets) {
	uint8_t *secdata = ts_section_data_alloc_section();
	ts_section_header_generate(secdata, sdt->section_header, 0);
	int curpos = 8; // Compensate for the section header, frist data byte is at offset 8

	secdata[curpos + 0] = sdt->original_network_id >> 8;	// 1111xxxx xxxxxxxx
	secdata[curpos + 1] = sdt->original_network_id &~ 0xff00;
	secdata[curpos + 2] = sdt->reserved;
	curpos += 3; // For the fields above

	int i;
	for(i=0;i<sdt->streams_num;i++) {
		struct ts_sdt_stream *stream = sdt->streams[i];

		secdata[curpos + 0]  = stream->service_id >> 8;			// xxxxxxxx xxxxxxxx
		secdata[curpos + 1]  = stream->service_id &~ 0xff00;

		secdata[curpos + 2]  = stream->reserved1 << 2;				// xxxxxx11
		secdata[curpos + 2] |= stream->EIT_schedule_flag << 1;		// 111111x1
		secdata[curpos + 2] |= stream->EIT_present_following_flag;	// 1111111x

		secdata[curpos + 3]  = stream->running_status << 5;		// 111xxxxx
		secdata[curpos + 3] |= stream->free_CA_mode   << 4;		// xxx1xxxx
		secdata[curpos + 3] |= stream->descriptor_size >> 8;		// 1111xxxx xxxxxxxx
		secdata[curpos + 4]  = stream->descriptor_size &~ 0xff00;
		curpos += 5; // Compensate for the above

		if (stream->descriptor_size > 0) {
			memcpy(secdata + curpos, stream->descriptor_data, stream->descriptor_size);
			curpos += stream->descriptor_size;
		}
	}
    sdt->section_header->CRC = ts_section_data_calculate_crc(secdata, curpos);
    curpos += 4; // CRC

    ts_section_data_gen_ts_packets(&sdt->ts_header, secdata, curpos, sdt->section_header->pointer_field, ts_packets, num_packets);

    FREE(secdata);
}

struct ts_sdt *ts_sdt_copy(struct ts_sdt *sdt) {
	struct ts_sdt *newsdt = ts_sdt_alloc();
	int i;
	for (i=0;i<sdt->section_header->num_packets; i++) {
		newsdt = ts_sdt_push_packet(newsdt, sdt->section_header->packet_data + (i * TS_PACKET_SIZE));
	}
	if (newsdt->initialized) {
		return newsdt;
	} else {
		ts_LOGf("Error copying sdt!\n");
		ts_sdt_free(&newsdt);
		return NULL;
	}
}

void ts_sdt_check_generator(struct ts_sdt *sdt) {
	struct ts_sdt *sdt1 = ts_sdt_alloc();
	int i;
	for (i=0;i<sdt->section_header->num_packets;i++) {
		sdt1 = ts_sdt_push_packet(sdt1, sdt->section_header->packet_data + (i * TS_PACKET_SIZE));
	}
	ts_compare_data("SDT (tspacket->struct)",
		sdt1->section_header->packet_data,
		sdt->section_header->packet_data,
		sdt->section_header->num_packets * TS_PACKET_SIZE);
	ts_sdt_free(&sdt1);

	uint8_t *ts_packets;
	int num_packets;
	ts_sdt_generate(sdt, &ts_packets, &num_packets);
	if (num_packets != sdt->section_header->num_packets) {
		ts_LOGf("ERROR: num_packets:%d != sec->num_packets:%d\n", num_packets, sdt->section_header->num_packets);
	}
	ts_compare_data("SDT (struct->tspacket)", sdt->section_header->packet_data, ts_packets, num_packets * TS_PACKET_SIZE);
	free(ts_packets);
}

void ts_sdt_dump(struct ts_sdt *sdt) {
	struct ts_section_header *sec = sdt->section_header;
	int i;

	ts_section_dump(sec);

	ts_LOGf("  * SDT data\n");
	ts_LOGf("    * PID         : %04x (%d)\n", sdt->ts_header.pid, sdt->ts_header.pid);
	ts_LOGf("    * org_net_id  : %04x (%d)\n", sdt->original_network_id, sdt->original_network_id);
	ts_LOGf("    * reserved    : %d\n", sdt->reserved);
	ts_LOGf("    * num_streams : %d\n", sdt->streams_num);

	for(i=0;i<sdt->streams_num;i++) {
		struct ts_sdt_stream *stream = sdt->streams[i];
		ts_LOGf("    * [%02d/%02d] Service_id: %04x (%d) Res1: %d EIT_schedule: %d EIT_present: %d Running_status: %d free_CA_mode: %d /es_info_size: %d/\n",
			i+1, sdt->streams_num,
			stream->service_id, stream->service_id,
			stream->reserved1,
			stream->EIT_schedule_flag,
			stream->EIT_present_following_flag,
			stream->running_status,
			stream->free_CA_mode,
			stream->descriptor_size);
		if (stream->descriptor_data) {
			ts_descriptor_dump(stream->descriptor_data, stream->descriptor_size);
		}
	}

	ts_sdt_check_generator(sdt);
}

int ts_sdt_is_same(struct ts_sdt *sdt1, struct ts_sdt *sdt2) {
	if (sdt1 == sdt2) return 1; // Same
	if ((!sdt1 && sdt2) || (sdt1 && !sdt2)) return 0; // Not same (one is NULL)
	return ts_section_is_same(sdt1->section_header, sdt2->section_header);
}
