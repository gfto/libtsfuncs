/*
 * EIT table parser and generator
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

struct ts_eit *ts_eit_alloc() {
	struct ts_eit *eit = calloc(1, sizeof(struct ts_eit));
	eit->section_header = ts_section_data_alloc();
	eit->streams_max = 128;
	eit->streams = calloc(eit->streams_max, sizeof(void *));
	return eit;
}

static void ts_eit_streams_data_free(struct ts_eit *eit) {
	int i;
	for (i=0;i<eit->streams_num;i++) {
		if (eit->streams[i]) {
			FREE(eit->streams[i]->descriptor_data);
			FREE(eit->streams[i]);
		}
	}
}

void ts_eit_clear(struct ts_eit *eit) {
	if (!eit)
		return;
	// save
	struct ts_section_header *section_header = eit->section_header;
	struct ts_eit_stream **streams = eit->streams;
	int streams_max = eit->streams_max;
	// free
	ts_eit_streams_data_free(eit);
	// clear
	ts_section_data_clear(section_header);
	memset(eit, 0, sizeof(struct ts_eit));
	// restore
	eit->section_header = section_header;
	eit->streams = streams;
	eit->streams_max = streams_max;
}

void ts_eit_free(struct ts_eit **peit) {
	struct ts_eit *eit = *peit;
	if (eit) {
		ts_section_data_free(&eit->section_header);
		ts_eit_streams_data_free(eit);
		FREE(eit->streams);
		FREE(*peit);
	}
}

struct ts_eit *ts_eit_push_packet(struct ts_eit *eit, uint8_t *ts_packet) {
	struct ts_header ts_header;
	memset(&ts_header, 0, sizeof(struct ts_header));

	if (ts_packet_header_parse(ts_packet, &ts_header)) {
		// EIT should be with PID 0x12
		if (ts_header.pid != 0x12)
			goto OUT;
		// Received PUSI packet before table END, clear the table to start gathering new one
		if (ts_header.pusi && eit->ts_header.pusi)
			ts_eit_clear(eit);
		if (!eit->ts_header.pusi)
			eit->ts_header = ts_header;
	}

	if (ts_header.pusi) {
		struct ts_section_header section_header;
		memset(&section_header, 0, sizeof(struct ts_section_header));

		uint8_t *section_data = ts_section_header_parse(ts_packet, &eit->ts_header, &section_header);
		if (!section_data) {
			memset(&eit->ts_header, 0, sizeof(struct ts_header));
			goto OUT;
		}
		// table_id should be 0x4e (event_information_section - actual_transport_stream, present/following)
		// table_id 0x50 - 0x5f    (event_information_section - actual_transport_stream, schedule)
		if (section_header.table_id != 0x4e && (section_header.table_id < 0x50 && section_header.table_id > 0x5f)) {
			memset(&eit->ts_header, 0, sizeof(struct ts_header));
			goto OUT;
		}

		// Set correct section_header
		ts_section_header_parse(ts_packet, &eit->ts_header, eit->section_header);
	}

	if (!eit->initialized) {
		ts_section_add_packet(eit->section_header, &ts_header, ts_packet);
		if (eit->section_header->initialized) {
			if (!ts_eit_parse(eit))
				goto ERROR;
		}
	}

OUT:
	return eit;

ERROR:
	ts_eit_clear(eit);
	return eit;
}


int ts_eit_parse(struct ts_eit *eit) {
	uint8_t *section_data = eit->section_header->data;
	int section_len = eit->section_header->data_len;

	/* Table data (6 bytes) */
	eit->transport_stream_id			= (section_data[0] << 8) | section_data[1];	// 11111111 11111111
	eit->original_network_id			= (section_data[2] << 8) | section_data[3];	// 11111111 11111111
	eit->segment_last_section_number	= section_data[4];
	eit->last_table_id					= section_data[5];

	uint8_t *stream_data = section_data + 6;		// +5 is to compensate for the above
	int stream_len       = section_len - 6 - 4;		// -4 for the CRC at the end

	while (stream_len > 0) {
		if (eit->streams_num == eit->streams_max) {
			ts_LOGf("!!! Too many streams in EIT, max %d\n", eit->streams_max);
			break;
		}

		struct ts_eit_stream *sinfo = calloc(1, sizeof(struct ts_eit_stream));

		sinfo->event_id			 = (stream_data[0] << 8) | stream_data[1];
		sinfo->start_time_mjd	 = (stream_data[2] << 8) | stream_data[3];

		sinfo->start_time_bcd	 = stream_data[4] << 16;
		sinfo->start_time_bcd	|= stream_data[5] << 8;
		sinfo->start_time_bcd	|= stream_data[6];

		sinfo->duration_bcd		 = stream_data[7] << 16;
		sinfo->duration_bcd		|= stream_data[8] << 8;
		sinfo->duration_bcd		|= stream_data[9];

		sinfo->running_status	 = stream_data[10] >> 5;								// 111xxxxx
		sinfo->free_CA_mode		 = (stream_data[10] &~ 0xE0) >> 4;						// xxx1xxxx
		sinfo->descriptor_size	 = ((stream_data[10] &~ 0xF0) << 8) | stream_data[11];	// 1111xxxx xxxxxxxx

		stream_data += 12; // Compensate for the the above vars
		stream_len  -= 12 + sinfo->descriptor_size;

		sinfo->descriptor_data = NULL;
		if (sinfo->descriptor_size > 0) {
			sinfo->descriptor_data = malloc(sinfo->descriptor_size);
			memcpy(sinfo->descriptor_data, stream_data, sinfo->descriptor_size);
		}
		eit->streams[eit->streams_num] = sinfo;
		eit->streams_num++;

		stream_data += sinfo->descriptor_size;
	}

	if (!ts_crc32_section_check(eit->section_header, "EIT"))
		return 0;

	eit->initialized = 1;
	return 1;
}

void ts_eit_generate(struct ts_eit *eit, uint8_t **ts_packets, int *num_packets) {
	uint8_t *secdata = ts_section_data_alloc_section();
	ts_section_header_generate(secdata, eit->section_header, 0);
	int curpos = 8; // Compensate for the section header, frist data byte is at offset 8


	secdata[curpos + 0] = eit->transport_stream_id >> 8;			// xxxxxxxx xxxxxxxx
	secdata[curpos + 1] = eit->transport_stream_id &~ 0xff00;

	secdata[curpos + 2] = eit->original_network_id >> 8;			// xxxxxxxx xxxxxxxx
	secdata[curpos + 3] = eit->original_network_id &~ 0xff00;

	secdata[curpos + 4] = eit->segment_last_section_number;
	secdata[curpos + 5] = eit->last_table_id;
	curpos += 6; // For the fields above

	int i;
	for(i=0;i<eit->streams_num;i++) {
		struct ts_eit_stream *stream = eit->streams[i];
		secdata[curpos + 0]  = stream->event_id >> 8;			// xxxxxxxx xxxxxxxx
		secdata[curpos + 1]  = stream->event_id &~ 0xff00;

		secdata[curpos + 2]  = stream->start_time_mjd >> 8;		// xxxxxxxx xxxxxxxx
		secdata[curpos + 3]  = stream->start_time_mjd &~ 0xff00;

		secdata[curpos + 4]  = stream->start_time_bcd >> 16;
		secdata[curpos + 5]  =(stream->start_time_bcd >> 8) &~ 0xff00;
		secdata[curpos + 6]  = stream->start_time_bcd &~ 0xffff00;

		secdata[curpos + 7]  = stream->duration_bcd >> 16;
		secdata[curpos + 8]  =(stream->duration_bcd >> 8) &~ 0xff00;
		secdata[curpos + 9]  = stream->duration_bcd &~ 0xffff00;

		secdata[curpos +10]  = stream->running_status << 5;		// 111xxxxx
		secdata[curpos +10] |= stream->free_CA_mode   << 4;		// xxx1xxxx
		secdata[curpos +10] |= stream->descriptor_size >> 8;		// 1111xxxx xxxxxxxx
		secdata[curpos +11]  = stream->descriptor_size &~ 0xff00;
		curpos += 12; // Compensate for the above

		if (stream->descriptor_size > 0) {
			memcpy(secdata + curpos, stream->descriptor_data, stream->descriptor_size);
			curpos += stream->descriptor_size;
		}
	}
	eit->section_header->CRC = ts_section_data_calculate_crc(secdata, curpos);
	curpos += 4; // CRC

	ts_section_data_gen_ts_packets(&eit->ts_header, secdata, curpos, eit->section_header->pointer_field, ts_packets, num_packets);

	FREE(secdata);
}

void ts_eit_check_generator(struct ts_eit *eit) {
	struct ts_eit *eit1 = ts_eit_alloc();
	int i;
	for (i=0;i<eit->section_header->num_packets;i++) {
		eit1 = ts_eit_push_packet(eit1, eit->section_header->packet_data + (i * TS_PACKET_SIZE));
	}
	ts_compare_data("EIT (tspacket->struct)",
		eit1->section_header->packet_data,
		eit->section_header->packet_data,
		eit->section_header->num_packets * TS_PACKET_SIZE);
	ts_eit_free(&eit1);

	uint8_t *ts_packets;
	int num_packets;
	ts_eit_generate(eit, &ts_packets, &num_packets);
	if (num_packets != eit->section_header->num_packets) {
		ts_LOGf("ERROR: num_packets:%d != sec->num_packets:%d\n", num_packets, eit->section_header->num_packets);
	}
	ts_compare_data("EIT (struct->tspacket)", eit->section_header->packet_data, ts_packets, num_packets * TS_PACKET_SIZE);
	free(ts_packets);
}

void ts_eit_regenerate_packets(struct ts_eit *eit) {
	uint8_t *ts_packets;
	int num_packets;
	ts_eit_generate(eit, &ts_packets, &num_packets);
	FREE(eit->section_header->packet_data);
	eit->section_header->packet_data = ts_packets;
	eit->section_header->num_packets = num_packets;
}

struct ts_eit *ts_eit_copy(struct ts_eit *eit) {
	struct ts_eit *neweit = ts_eit_alloc();
	int i;
	for (i=0;i<eit->section_header->num_packets; i++) {
		neweit = ts_eit_push_packet(neweit, eit->section_header->packet_data + (i * TS_PACKET_SIZE));
	}
	if (neweit->initialized) {
		return neweit;
	} else {
		ts_LOGf("Error copying EIT!\n");
		ts_eit_free(&neweit);
		return NULL;
	}
}

void ts_eit_dump(struct ts_eit *eit) {
	struct ts_section_header *sect = eit->section_header;
	int i;

	ts_section_dump(sect);

	ts_LOGf("  * EIT data\n");
	ts_LOGf("    * PID             : 0x%04x (%d)\n", eit->ts_header.pid, eit->ts_header.pid);
	ts_LOGf("    * ts_stream_id    : 0x%04x (%d)\n", eit->transport_stream_id, eit->transport_stream_id);
	ts_LOGf("    * org_network_id  : 0x%04x (%d)\n", eit->original_network_id, eit->original_network_id);
	ts_LOGf("    * seg_last_sec_num: %d\n", eit->segment_last_section_number);
	ts_LOGf("    * last_table_id   : 0x%02x (%d)\n", eit->last_table_id, eit->last_table_id);
	ts_LOGf("    * num_streams     : %d\n", eit->streams_num);

	for(i=0;i<eit->streams_num;i++) {
		struct ts_eit_stream *stream = eit->streams[i];
		int hour, min, sec;
		struct tm tm;
		ts_time_decode_mjd(stream->start_time_mjd, stream->start_time_bcd, &tm);
		ts_time_decode_bcd(stream->duration_bcd, NULL, &hour, &min, &sec);
		ts_LOGf("    * Event_id [%02d/%02d]\n", i+1, eit->streams_num);
		ts_LOGf("      - Event_id  : 0x%04x (%d)\n", stream->event_id, stream->event_id);
		ts_LOGf("      - Start_time: %04d-%02d-%02d %02d:%02d:%02d (0x%04x%06x) ts: %ld\n",
			tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
			stream->start_time_mjd,
			stream->start_time_bcd, timegm(&tm));
		ts_LOGf("      - Duration  : %02d:%02d:%02d (0x%06x)\n",
			hour, min, sec,
			stream->duration_bcd);
		ts_LOGf("      - Running_status: %d free_CA_mode: %d /desc_size: %d/\n",
			stream->running_status,
			stream->free_CA_mode,
			stream->descriptor_size);

		if (stream->descriptor_data) {
			ts_descriptor_dump(stream->descriptor_data, stream->descriptor_size);
		}
	}

	ts_eit_check_generator(eit);
}

int ts_eit_is_same(struct ts_eit *eit1, struct ts_eit *eit2) {
	if (eit1 == eit2) return 1; // Same
	if ((!eit1 && eit2) || (eit1 && !eit2)) return 0; // Not same (one is NULL)
	return ts_section_is_same(eit1->section_header, eit2->section_header);
}
