/*
 * NIT table parser and generator
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

struct ts_nit *ts_nit_alloc() {
	struct ts_nit *nit = calloc(1, sizeof(struct ts_nit));
	nit->section_header = ts_section_data_alloc();
	nit->streams_max = 128;
	nit->streams = calloc(nit->streams_max, sizeof(void *));
	return nit;
}

static void ts_nit_streams_data_free(struct ts_nit *nit) {
	int i;
	for (i=0;i<nit->streams_num;i++) {
		if (nit->streams[i]) {
			FREE(nit->streams[i]->descriptor_data);
			FREE(nit->streams[i]);
		}
	}
}

void ts_nit_clear(struct ts_nit *nit) {
	if (!nit)
		return;
	// save
	struct ts_section_header *section_header = nit->section_header;
	struct ts_nit_stream **streams = nit->streams;
	int streams_max = nit->streams_max;
	// free
	FREE(nit->network_info);
	ts_nit_streams_data_free(nit);
	// clear
	ts_section_data_clear(section_header);
	memset(nit, 0, sizeof(struct ts_nit));
	// restore
	nit->section_header = section_header;
	nit->streams = streams;
	nit->streams_max = streams_max;
}

void ts_nit_free(struct ts_nit **pnit) {
	struct ts_nit *nit = *pnit;
	if (nit) {
		ts_section_data_free(&nit->section_header);
		FREE(nit->network_info);
		ts_nit_streams_data_free(nit);
		FREE(nit->streams);
		FREE(*pnit);
	}
}

struct ts_nit *ts_nit_push_packet(struct ts_nit *nit, uint8_t *ts_packet) {
	struct ts_header ts_header;
	memset(&ts_header, 0, sizeof(struct ts_header));

	if (ts_packet_header_parse(ts_packet, &ts_header)) {
		// NIT should be with PID 0x10
		if (ts_header.pid != 0x10)
			goto OUT;
		// Received PUSI packet before table END, clear the table to start gathering new one
		if (ts_header.pusi && nit->ts_header.pusi)
			ts_nit_clear(nit);
		if (!nit->ts_header.pusi)
			nit->ts_header = ts_header;
	}

	if (ts_header.pusi) {
		struct ts_section_header section_header;
		memset(&section_header, 0, sizeof(struct ts_section_header));

		uint8_t *section_data = ts_section_header_parse(ts_packet, &nit->ts_header, &section_header);
		if (!section_data)
			goto OUT;
		// table_id should be 0x40 (network_information_section - actual_network)
		if (section_header.table_id != 0x40) {
			memset(&nit->ts_header, 0, sizeof(struct ts_header));
			goto OUT;
		}

		// Set correct section_header
		ts_section_header_parse(ts_packet, &nit->ts_header, nit->section_header);
	}

	if (!nit->initialized) {
		ts_section_add_packet(nit->section_header, &ts_header, ts_packet);
		if (nit->section_header->initialized) {
			if (!ts_nit_parse(nit))
				goto ERROR;
		}
	}

OUT:
	return nit;

ERROR:
	ts_nit_clear(nit);
	return nit;
}


int ts_nit_parse(struct ts_nit *nit) {
	uint8_t *section_data = nit->section_header->data;
	int section_len = nit->section_header->data_len;

	/* Table data (2 bytes) */
	nit->reserved1         =  (section_data[0] &~ 0x0F) >> 4;						// xxxx1111
	nit->network_info_size = ((section_data[0] &~ 0xF0) << 8) | section_data[1];	// 1111xxxx xxxxxxxx

	/* Handle streams */
	uint8_t *stream_data = section_data + 2 + nit->network_info_size;	// +2 is to compensate for reserved1 and network_info_size
	int stream_len       = section_len - nit->network_info_size - 4;	// -4 for the CRC at the end

	nit->network_info = NULL;
	if (nit->network_info_size) {
		nit->network_info = malloc(nit->network_info_size);
		if (nit->network_info) {
			memcpy(nit->network_info, stream_data - nit->network_info_size, nit->network_info_size);
		}
	}

	// Before the table there are two more fields
	nit->reserved2    =  (stream_data[0] &~ 0x0F) >> 4;						// xxxx1111
	nit->ts_loop_size = ((stream_data[0] &~ 0xF0) << 8) | stream_data[1];	// 1111xxxx xxxxxxxx

	stream_data += 2;
	stream_len   = nit->ts_loop_size;

	while (stream_len > 0) {
		if (nit->streams_num == nit->streams_max) {
			ts_LOGf("!!! Too many streams in NIT, max %d\n", nit->streams_max);
			break;
		}

		struct ts_nit_stream *sinfo = calloc(1, sizeof(struct ts_nit_stream));

		sinfo->transport_stream_id = (stream_data[0] << 8) | stream_data[1];
		sinfo->original_network_id = (stream_data[2] << 8) | stream_data[3];

		sinfo->reserved1           =  (stream_data[4] &~ 0x0F) >> 4;					// xxxx1111
		sinfo->descriptor_size     = ((stream_data[4] &~ 0xF0) << 8) | stream_data[5];	// 1111xxxx xxxxxxxx

		sinfo->descriptor_data      = NULL;
		if (sinfo->descriptor_size > 0) {
			sinfo->descriptor_data = malloc(sinfo->descriptor_size);
			memcpy(sinfo->descriptor_data, &stream_data[6], sinfo->descriptor_size);
		}
		nit->streams[nit->streams_num] = sinfo;
		nit->streams_num++;

		stream_data += 6 + sinfo->descriptor_size;
		stream_len  -= 6 + sinfo->descriptor_size;
	}

	if (!ts_crc32_section_check(nit->section_header, "NIT"))
		return 0;

	nit->initialized = 1;
	return 1;
}

void ts_nit_generate(struct ts_nit *nit, uint8_t **ts_packets, int *num_packets) {
	uint8_t *secdata = ts_section_data_alloc_section();
	ts_section_header_generate(secdata, nit->section_header, 0);
	int curpos = 8; // Compensate for the section header, frist data byte is at offset 8

	secdata[curpos + 0]  = nit->reserved1 << 4;			// xxxx1111
	secdata[curpos + 0] |= nit->network_info_size >> 8;	// 1111xxxx xxxxxxxx
	secdata[curpos + 1]  = nit->network_info_size &~ 0xff00;
	curpos += 2; // For the fields above

	if (nit->network_info_size) {
		memcpy(secdata + curpos, nit->network_info, nit->network_info_size);
		curpos += nit->network_info_size;
	}

	// Before the table there are two more fields
	secdata[curpos + 0]  = nit->reserved2 << 4;			// xxxx1111
	secdata[curpos + 0] |= nit->ts_loop_size >> 8;		// 1111xxxx xxxxxxxx
	secdata[curpos + 1]  = nit->ts_loop_size &~ 0xff00;
	curpos += 2; // For the fields above

	int i;
	for(i=0;i<nit->streams_num;i++) {
		struct ts_nit_stream *stream = nit->streams[i];

		secdata[curpos + 0]  = stream->transport_stream_id >> 8;			// xxxxxxxx xxxxxxxx
		secdata[curpos + 1]  = stream->transport_stream_id &~ 0xff00;

		secdata[curpos + 2]  = stream->original_network_id >> 8;			// xxxxxxxx xxxxxxxx
		secdata[curpos + 3]  = stream->original_network_id &~ 0xff00;

		secdata[curpos + 4]  = stream->reserved1 << 4;						// xxxx1111
		secdata[curpos + 4] |= stream->descriptor_size >> 8;				// 1111xxxx xxxxxxxx

		secdata[curpos + 5]  = stream->descriptor_size &~ 0xff00;

		curpos += 6; // Compensate for the above

		if (stream->descriptor_size > 0) {
			memcpy(secdata + curpos, stream->descriptor_data, stream->descriptor_size);
			curpos += stream->descriptor_size;
		}
	}
	nit->section_header->CRC = ts_section_data_calculate_crc(secdata, curpos);
	curpos += 4; // CRC

	ts_section_data_gen_ts_packets(&nit->ts_header, secdata, curpos, nit->section_header->pointer_field, ts_packets, num_packets);

	FREE(secdata);
}

struct ts_nit *ts_nit_copy(struct ts_nit *nit) {
	struct ts_nit *newnit = ts_nit_alloc();
	int i;
	for (i=0;i<nit->section_header->num_packets; i++) {
		newnit = ts_nit_push_packet(newnit, nit->section_header->packet_data + (i * TS_PACKET_SIZE));
	}
	if (newnit->initialized) {
		return newnit;
	} else {
		ts_LOGf("Error copying nit!\n");
		ts_nit_free(&newnit);
		return NULL;
	}
}

void ts_nit_check_generator(struct ts_nit *nit) {
	struct ts_nit *nit1 = ts_nit_alloc();
	int i;
	for (i=0;i<nit->section_header->num_packets;i++) {
		nit1 = ts_nit_push_packet(nit1, nit->section_header->packet_data + (i * TS_PACKET_SIZE));
	}
	ts_compare_data("NIT (tspacket->struct)",
		nit1->section_header->packet_data,
		nit->section_header->packet_data,
		nit->section_header->num_packets * TS_PACKET_SIZE);
	ts_nit_free(&nit1);

	uint8_t *ts_packets;
	int num_packets;
	ts_nit_generate(nit, &ts_packets, &num_packets);
	if (num_packets != nit->section_header->num_packets) {
		ts_LOGf("ERROR: num_packets:%d != sec->num_packets:%d\n", num_packets, nit->section_header->num_packets);
	}
	ts_compare_data("NIT (struct->tspacket)", nit->section_header->packet_data, ts_packets, num_packets * TS_PACKET_SIZE);
	free(ts_packets);
}

void ts_nit_dump(struct ts_nit *nit) {
	struct ts_section_header *sec = nit->section_header;
	int i;

	ts_section_dump(sec);

	ts_LOGf("  * NIT data\n");
	ts_LOGf("    * PID         : 0x%04x (%d)\n", nit->ts_header.pid, nit->ts_header.pid);
	ts_LOGf("    * reserved1   : 0x%02x\n", nit->reserved1);
	ts_LOGf("    * network_len : 0x%02x (%d)\n", nit->network_info_size, nit->network_info_size);
	ts_LOGf("    * reserved2   : 0x%02x\n", nit->reserved1);
	ts_LOGf("    * ts_loop_len : %d\n", nit->ts_loop_size);
	ts_LOGf("    * num_streams : %d\n", nit->streams_num);

	if (nit->network_info_size > 0) {
		ts_LOGf("  * Network info:\n");
		ts_LOGf("      * network info size: %d\n", nit->network_info_size);
		ts_descriptor_dump(nit->network_info, nit->network_info_size);
	}

	for(i=0;i<nit->streams_num;i++) {
		struct ts_nit_stream *stream = nit->streams[i];
		ts_LOGf("    - [%02d/%02d] | TS_id: 0x%04x (%d) ORG_net_id: 0x%04x (%d) Reserved: 0x%0x Desc_size: %d\n",
			i+1, nit->streams_num,
			stream->transport_stream_id, stream->transport_stream_id,
			stream->original_network_id, stream->original_network_id,
			stream->reserved1,
			stream->descriptor_size);
		if (stream->descriptor_data) {
			ts_descriptor_dump(stream->descriptor_data, stream->descriptor_size);
		}
	}

	ts_nit_check_generator(nit);
}

int ts_nit_is_same(struct ts_nit *nit1, struct ts_nit *nit2) {
	if (nit1 == nit2) return 1; // Same
	if ((!nit1 && nit2) || (nit1 && !nit2)) return 0; // Not same (one is NULL)
	return ts_section_is_same(nit1->section_header, nit2->section_header);
}
