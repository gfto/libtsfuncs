/*
 * PAT descriptor generator
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

static void ts_pat_regenerate_packet_data(struct ts_pat *pat) {
	uint8_t *ts_packets;
	int num_packets;
	ts_pat_generate(pat, &ts_packets, &num_packets);
	memcpy(pat->section_header->packet_data, ts_packets, num_packets * TS_PACKET_SIZE);
	pat->section_header->num_packets = num_packets;
	free(ts_packets);
}

struct ts_pat *ts_pat_init(struct ts_pat *pat, uint16_t transport_stream_id) {
	pat->ts_header.pid            = 0x00;
	pat->ts_header.pusi           = 1;
	pat->ts_header.payload_field  = 1;
	pat->ts_header.payload_offset = 4;

	pat->section_header->table_id                 = 0x00;
	pat->section_header->version_number           = 1;
	pat->section_header->current_next_indicator   = 1;
	pat->section_header->section_syntax_indicator = 1;
	pat->section_header->private_indicator        = 0;
	pat->section_header->section_length           = 9; // Empty section (9)
	pat->section_header->reserved1                = 3;
	pat->section_header->reserved2                = 3;

	pat->section_header->ts_id_number             = transport_stream_id;

	pat->programs_num = 0;

	pat->initialized = 1;

	ts_pat_regenerate_packet_data(pat);

	return pat;
}

struct ts_pat *ts_pat_alloc_init(uint16_t transport_stream_id) {
	struct ts_pat *pat = ts_pat_alloc();
	if (!pat)
		return NULL;
	return ts_pat_init(pat, transport_stream_id);
}

int ts_pat_add_program(struct ts_pat *pat, uint16_t program, uint16_t pat_pid) {
	int i;
	if (pat->programs_max == pat->programs_num)
		return 0;

	for (i=0;i<pat->programs_num;i++) {
		struct ts_pat_program *prg = pat->programs[i];
		if (program == prg->program) {
			ts_LOGf("!!! Program 0x%04x (%d) already exists in PAT!\n", program, program);
			return 0;
		}
	}

	pat->section_header->version_number++;
	pat->section_header->section_length += 4;

	struct ts_pat_program *pinfo = calloc(1, sizeof(struct ts_pat_program));
	pinfo->program  = program;
	pinfo->reserved = 7; // All three bits are up
	pinfo->pid      = pat_pid;

	pat->programs[pat->programs_num] = pinfo;
	pat->programs_num++;

	ts_pat_regenerate_packet_data(pat);

	return 1;
}

int ts_pat_del_program(struct ts_pat *pat, uint16_t program) {
	int i, ok=1, del_pos=0;

	if (!pat->programs_num)
		return 0;

	for (i=0;i<pat->programs_num;i++) {
		struct ts_pat_program *prg = pat->programs[i];
		if (program == prg->program) {
			ts_LOGf("!!! Found program 0x%04x (%d) for deleting.\n", program, program);
			del_pos = i;
			ok = 1;
			break;
		}
	}

	if (!ok)
		return 0;

	for (i=0;i<pat->programs_num;i++) {
		if (i < del_pos)
			continue;
		if (i == del_pos) {
			FREE(pat->programs[i]);
		}
		if (i >= del_pos && i+1 < pat->programs_num) {
			struct ts_pat_program *next = pat->programs[i+1];
			pat->programs[i] = next;
		}
	}

	pat->section_header->version_number++;
	pat->section_header->section_length -= 4;
	pat->programs_num--;

	ts_pat_regenerate_packet_data(pat);

	return 1;
}
