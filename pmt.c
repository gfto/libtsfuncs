/*
 * PMT table parser and generator
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

struct ts_pmt *ts_pmt_alloc() {
	struct ts_pmt *pmt = calloc(1, sizeof(struct ts_pmt));
	pmt->section_header	= ts_section_data_alloc();
	pmt->streams_max	= 128;
	pmt->streams		= calloc(pmt->streams_max, sizeof(void *));
	return pmt;
}

static void ts_pmt_streams_data_free(struct ts_pmt *pmt) {
	int i;
	for (i=0;i<pmt->streams_num;i++) {
		if (pmt->streams[i]) {
			FREE(pmt->streams[i]->ES_info);
			FREE(pmt->streams[i]);
		}
	}
}

void ts_pmt_clear(struct ts_pmt *pmt) {
	if (!pmt)
		return;
	// save
	struct ts_section_header *section_header = pmt->section_header;
	struct ts_pmt_stream **streams = pmt->streams;
	int streams_max = pmt->streams_max;
	// free
	FREE(pmt->program_info);
	ts_pmt_streams_data_free(pmt);
	// clear
	ts_section_data_clear(section_header);
	memset(pmt, 0, sizeof(struct ts_pmt));
	// restore
	pmt->section_header = section_header;
	pmt->streams = streams;
	pmt->streams_max = streams_max;
}


void ts_pmt_free(struct ts_pmt **ppmt) {
	struct ts_pmt *pmt = *ppmt;
	if (pmt) {
		ts_section_data_free(&pmt->section_header);
		ts_pmt_streams_data_free(pmt);
		FREE(pmt->program_info);
		FREE(pmt->streams);
		FREE(*ppmt);
	}
}

struct ts_pmt *ts_pmt_push_packet(struct ts_pmt *pmt, uint8_t *ts_packet) {
	struct ts_header ts_header;
	memset(&ts_header, 0, sizeof(struct ts_header));

	if (ts_packet_header_parse(ts_packet, &ts_header)) {
		// Received PUSI packet before table END, clear the table to start gathering new one
		if (ts_header.pusi && pmt->ts_header.pusi)
			ts_pmt_clear(pmt);
		if (!pmt->ts_header.pusi)
			pmt->ts_header = ts_header;
	}

	if (ts_header.pusi) {
		struct ts_section_header section_header;
		memset(&section_header, 0, sizeof(struct ts_section_header));

		uint8_t *section_data = ts_section_header_parse(ts_packet, &pmt->ts_header, &section_header);
		if (!section_data) {
			memset(&pmt->ts_header, 0, sizeof(struct ts_header));
			goto OUT;
		}
		// table_id should be 0x02 (program_map_section)
		if (section_header.table_id != 0x02) {
			memset(&pmt->ts_header, 0, sizeof(struct ts_header));
			goto OUT;
		}

		// Set correct section_header
		ts_section_header_parse(ts_packet, &pmt->ts_header, pmt->section_header);
	}

	if (!pmt->initialized) {
		ts_section_add_packet(pmt->section_header, &ts_header, ts_packet);
		if (pmt->section_header->initialized) {
			if (!ts_pmt_parse(pmt))
				goto ERROR;
		}
	}

OUT:
	return pmt;

ERROR:
	ts_pmt_clear(pmt);
	return pmt;
}

int ts_pmt_parse(struct ts_pmt *pmt) {
	uint8_t *section_data = pmt->section_header->data;
	int section_len = pmt->section_header->data_len;

	pmt->reserved1         =  (section_data[0] &~ 0x1F) >> 5;						// xxx11111
	pmt->PCR_pid           = ((section_data[0] &~ 0xE0) << 8) | section_data[1];	// 111xxxxx xxxxxxxx

	pmt->reserved2         =  (section_data[2] &~ 0x0F) >> 4;						// xxxx1111
	pmt->program_info_size = ((section_data[2] &~ 0xF0) << 8) | section_data[3];	// 1111xxxx xxxxxxxx

	/* Handle streams */
	uint8_t *stream_data = section_data + 4 + pmt->program_info_size;	// +4 is to compensate for reserved1,PCR,reserved2,program_info_size
	int stream_len       = section_len - pmt->program_info_size - 4;		// -4 for the CRC at the end

	pmt->program_info = NULL;
	if (pmt->program_info_size) {
		pmt->program_info = malloc(pmt->program_info_size);
		if (pmt->program_info) {
			memcpy(pmt->program_info, stream_data - pmt->program_info_size, pmt->program_info_size);
		}
	}

	while (stream_len > 0) {
		if (pmt->streams_num == pmt->streams_max) {
			ts_LOGf("PMT contains too many streams (>%d), not all are initialized!\n", pmt->streams_max);
			break;
		}

		struct ts_pmt_stream *sinfo = calloc(1, sizeof(struct ts_pmt_stream));

		sinfo->stream_type  = stream_data[0];

		sinfo->reserved1    =  (stream_data[1] &~ 0x1F) >> 5;					// xxx11111
		sinfo->pid          = ((stream_data[1] &~ 0xE0) << 8) | stream_data[2];	// 111xxxxx xxxxxxxx

		sinfo->reserved2    =  (stream_data[3] &~ 0x0F) >> 4;					// xxxx1111
		sinfo->ES_info_size = ((stream_data[3] &~ 0xF0) << 8) | stream_data[4];	// 1111xxxx xxxxxxxx

		sinfo->ES_info      = NULL;
		if (sinfo->ES_info_size > 0) {
			sinfo->ES_info = malloc(sinfo->ES_info_size);
			memcpy(sinfo->ES_info, &stream_data[5], sinfo->ES_info_size);
		}
		pmt->streams[pmt->streams_num] = sinfo;
		pmt->streams_num++;

		stream_data += 5 + sinfo->ES_info_size;
		stream_len  -= 5 + sinfo->ES_info_size;
	}

	if (!ts_crc32_section_check(pmt->section_header, "PMT"))
		return 0;

	pmt->initialized = 1;
	return 1;
}

void ts_pmt_generate(struct ts_pmt *pmt, uint8_t **ts_packets, int *num_packets) {
	uint8_t *secdata = ts_section_data_alloc_section();
	ts_section_header_generate(secdata, pmt->section_header, 0);
	int curpos = 8; // Compensate for the section header, frist data byte is at offset 8

	secdata[curpos + 0]  = pmt->reserved1 << 5;			// xxx11111
	secdata[curpos + 0] |= pmt->PCR_pid >> 8;			// 111xxxxx xxxxxxxx
	secdata[curpos + 1]  = pmt->PCR_pid &~ 0xff00;

	secdata[curpos + 2]  = pmt->reserved2 << 4;			// xxxx1111
	secdata[curpos + 2] |= pmt->program_info_size >> 8;	// 1111xxxx xxxxxxxx
	secdata[curpos + 3]  = pmt->program_info_size &~ 0xff00;
	curpos += 4; // For thje fields above

	if (pmt->program_info_size) {
		memcpy(secdata + curpos, pmt->program_info, pmt->program_info_size);
		curpos += pmt->program_info_size;
	}

	int i;
	for(i=0;i<pmt->streams_num;i++) {
		struct ts_pmt_stream *stream = pmt->streams[i];
		secdata[curpos + 0] = stream->stream_type;

		secdata[curpos + 1]  = stream->reserved1 << 5;		// xxx11111
		secdata[curpos + 1] |= stream->pid >> 8;			// 111xxxxx xxxxxxxx
		secdata[curpos + 2]  = stream->pid &~ 0xff00;

		secdata[curpos + 3]  = stream->reserved2 << 4;		// xxxx1111
		secdata[curpos + 3] |= stream->ES_info_size >> 8;	// 1111xxxx xxxxxxxx
		secdata[curpos + 4]  = stream->ES_info_size &~ 0xff00;
		curpos += 5; // Compensate for the above

		if (stream->ES_info_size > 0) {
			memcpy(secdata + curpos, stream->ES_info, stream->ES_info_size);
			curpos += stream->ES_info_size;
		}
	}
    pmt->section_header->CRC = ts_section_data_calculate_crc(secdata, curpos);
    curpos += 4; // CRC

    ts_section_data_gen_ts_packets(&pmt->ts_header, secdata, curpos, pmt->section_header->pointer_field, ts_packets, num_packets);

    FREE(secdata);
}

void ts_pmt_regenerate_packets(struct ts_pmt *pmt) {
	uint8_t *ts_packets;
	int num_packets;
	ts_pmt_generate(pmt, &ts_packets, &num_packets);
	FREE(pmt->section_header->packet_data);
	pmt->section_header->packet_data = ts_packets;
	pmt->section_header->num_packets = num_packets;
}

struct ts_pmt *ts_pmt_copy(struct ts_pmt *pmt) {
	struct ts_pmt *newpmt = ts_pmt_alloc();
	int i;
	for (i=0;i<pmt->section_header->num_packets; i++) {
		newpmt = ts_pmt_push_packet(newpmt, pmt->section_header->packet_data + (i * TS_PACKET_SIZE));
	}
	if (newpmt->initialized) {
		return newpmt;
	} else {
		ts_LOGf("Error copying PMT!\n");
		ts_pmt_free(&newpmt);
		return NULL;
	}
}

void ts_pmt_check_generator(struct ts_pmt *pmt) {
	struct ts_pmt *pmt1 = ts_pmt_copy(pmt);
	if (pmt1) {
		ts_compare_data("PMT (tspacket->struct)",
			pmt1->section_header->packet_data,
			pmt->section_header->packet_data,
			pmt->section_header->num_packets * TS_PACKET_SIZE);
		ts_pmt_free(&pmt1);
	}

	uint8_t *ts_packets;
	int num_packets;
	ts_pmt_generate(pmt, &ts_packets, &num_packets);
	if (num_packets != pmt->section_header->num_packets) {
		ts_LOGf("ERROR: num_packets:%d != sec->num_packets:%d\n", num_packets, pmt->section_header->num_packets);
	}
	ts_compare_data("PMT (struct->tspacket)", pmt->section_header->packet_data, ts_packets, num_packets * TS_PACKET_SIZE);
	free(ts_packets);
}

void ts_pmt_dump(struct ts_pmt *pmt) {
	struct ts_section_header *sec = pmt->section_header;
	int i;

	ts_section_dump(sec);

	ts_LOGf("  * PMT data\n");
	ts_LOGf("    * PID         : %04x (%d)\n", pmt->ts_header.pid, pmt->ts_header.pid);
	ts_LOGf("    * reserved1   : %d\n", pmt->reserved1);
	ts_LOGf("    * PCR PID     : %04x (%d)\n", pmt->PCR_pid, pmt->PCR_pid);
	ts_LOGf("    * reserved2   : %d\n", pmt->reserved2);
	ts_LOGf("    * program_len : %d\n", pmt->program_info_size);
	ts_LOGf("    * num_streams : %d\n", pmt->streams_num);

	if (pmt->program_info_size > 0) {
		ts_LOGf("  * Program info:\n");
		ts_LOGf("      * program info size: %d\n", pmt->program_info_size);
		ts_descriptor_dump(pmt->program_info, pmt->program_info_size);
	}

	for(i=0;i<pmt->streams_num;i++) {
		struct ts_pmt_stream *stream = pmt->streams[i];
		ts_LOGf("    * [%02d/%02d] PID %04x (%d) -> Stream type: 0x%02x (%d) /es_info_size: %d/ %s\n",
			i+1, pmt->streams_num,
			stream->pid, stream->pid,
			stream->stream_type, stream->stream_type,
			stream->ES_info_size,
			h222_stream_type_desc(stream->stream_type)
		);
		if (stream->ES_info) {
			ts_descriptor_dump(stream->ES_info, stream->ES_info_size);
		}
	}

	ts_pmt_check_generator(pmt);
}

int ts_pmt_is_same(struct ts_pmt *pmt1, struct ts_pmt *pmt2) {
	if (pmt1 == pmt2) return 1; // Same
	if ((!pmt1 && pmt2) || (pmt1 && !pmt2)) return 0; // Not same (one is NULL)
	return ts_section_is_same(pmt1->section_header, pmt2->section_header);
}
