/*
 * PAT table parser and generator
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

struct ts_pat *ts_pat_alloc() {
	struct ts_pat *pat = calloc(1, sizeof(struct ts_pat));
	pat->section_header	= ts_section_data_alloc();
	pat->programs_max	= 128;
	pat->programs		= calloc(pat->programs_max, sizeof(void *));
	return pat;
}

static void ts_pat_programs_data_free(struct ts_pat *pat) {
	int i;
	for (i=0;i<pat->programs_num;i++) {
		if (pat->programs[i]) {
			FREE(pat->programs[i]);
		}
	}
}

void ts_pat_clear(struct ts_pat *pat) {
	if (!pat)
		return;
	// save
	struct ts_section_header *section_header = pat->section_header;
	struct ts_pat_program **programs = pat->programs;
	int programs_max = pat->programs_max;
	// free
	ts_pat_programs_data_free(pat);
	// clear
	ts_section_data_clear(section_header);
	memset(pat, 0, sizeof(struct ts_pat));
	// restore
	pat->section_header = section_header;
	pat->programs = programs;
	pat->programs_max = programs_max;
}

void ts_pat_free(struct ts_pat **ppat) {
	struct ts_pat *pat = *ppat;
	if (pat) {
		ts_section_data_free(&pat->section_header);
		ts_pat_programs_data_free(pat);
		FREE(pat->programs);
		FREE(*ppat);
	}
}

struct ts_pat *ts_pat_push_packet(struct ts_pat *pat, uint8_t *ts_packet) {
	struct ts_header ts_header;
	memset(&ts_header, 0, sizeof(struct ts_header));

	if (ts_packet_header_parse(ts_packet, &ts_header)) {
		// PAT should be with PID 0x00
		if (ts_header.pid != 0x00)
			goto OUT;
		// Received PUSI packet before table END, clear the table to start gathering new one
		if (ts_header.pusi && pat->ts_header.pusi)
			ts_pat_clear(pat);
		if (!pat->ts_header.pusi)
			pat->ts_header = ts_header;
	}

	if (ts_header.pusi) {
		struct ts_section_header section_header;
		memset(&section_header, 0, sizeof(struct ts_section_header));

		uint8_t *section_data = ts_section_header_parse(ts_packet, &pat->ts_header, &section_header);
		if (!section_data) {
			memset(&pat->ts_header, 0, sizeof(struct ts_header));
			goto OUT;
		}
		// table_id should be 0x00 (program_association_section)
		if (section_header.table_id != 0x00) {
			memset(&pat->ts_header, 0, sizeof(struct ts_header));
			goto OUT;
		}

		// Set correct section_header
		ts_section_header_parse(ts_packet, &pat->ts_header, pat->section_header);
	}

	if (!pat->initialized) {
		ts_section_add_packet(pat->section_header, &ts_header, ts_packet);
		if (pat->section_header->initialized) {
			if (!ts_pat_parse(pat))
				goto ERROR;
		}
	}

OUT:
	return pat;

ERROR:
	ts_pat_clear(pat);
	return pat;
}

int ts_pat_parse(struct ts_pat *pat) {
	uint8_t *section_data = pat->section_header->data;
	int section_len = pat->section_header->data_len;

	while (section_len > 0) {
		if (pat->programs_num == pat->programs_max) {
			ts_LOGf("PAT contains too many programs (>%d), not all are initialized!\n", pat->programs_max);
			break;
		}
		struct ts_pat_program *pinfo = calloc(1, sizeof(struct ts_pat_program));

		pinfo->program  = (section_data[0] << 8) | section_data[1];				// xxxxxxxx xxxxxxxx
		pinfo->reserved = (section_data[2] &~ 0x1F) >> 5;						// xxx11111
		pinfo->pid      = ((section_data[2] &~ 0xE0) << 8) | section_data[3];	// 111xxxxx xxxxxxxx

		pat->programs[pat->programs_num] = pinfo;
		pat->programs_num++;

		section_data += 4;
		section_len  -= 4;
	}

	if (!ts_crc32_section_check(pat->section_header, "PAT"))
		return 0;

	pat->initialized = 1;
	return 1;
}

void ts_pat_generate(struct ts_pat *pat, uint8_t **ts_packets, int *num_packets) {
	uint8_t *secdata = ts_section_data_alloc_section();
	ts_section_header_generate(secdata, pat->section_header, 0);
	int curpos = 8; // Compensate for the section header, frist data byte is at offset 8

	int i;
	for (i=0;i<pat->programs_num;i++) {
		struct ts_pat_program *prg = pat->programs[i];
		secdata[curpos + 0] = prg->program >> 8;
		secdata[curpos + 1] = prg->program &~ 0xff00;

		secdata[curpos + 2]  = prg->reserved << 5;
		secdata[curpos + 2] |= prg->pid >> 8;
		secdata[curpos + 3]  = prg->pid &~ 0xff00;
		curpos += 4; // Compensate for the above
	}
	pat->section_header->CRC = ts_section_data_calculate_crc(secdata, curpos);
	curpos += 4; // CRC

	ts_section_data_gen_ts_packets(&pat->ts_header, secdata, curpos, pat->section_header->pointer_field, ts_packets, num_packets);

	FREE(secdata);
}

void ts_pat_regenerate_packets(struct ts_pat *pat) {
	uint8_t *ts_packets;
	int num_packets;
	ts_pat_generate(pat, &ts_packets, &num_packets);
	FREE(pat->section_header->packet_data);
	pat->section_header->packet_data = ts_packets;
	pat->section_header->num_packets = num_packets;
}

struct ts_pat *ts_pat_copy(struct ts_pat *pat) {
	struct ts_pat *newpat = ts_pat_alloc();
	int i;
	for (i=0;i<pat->section_header->num_packets; i++) {
		newpat = ts_pat_push_packet(newpat, pat->section_header->packet_data + (i * TS_PACKET_SIZE));
	}
	if (newpat->initialized) {
		return newpat;
	} else {
		ts_LOGf("Error copying PAT!\n");
		ts_pat_free(&newpat);
		return NULL;
	}
}

void ts_pat_check_generator(struct ts_pat *pat) {
	struct ts_pat *pat1 = ts_pat_copy(pat);
	if (pat1) {
		ts_compare_data("PAT (tspacket->struct)",
			pat1->section_header->packet_data,
			pat->section_header->packet_data,
			pat->section_header->num_packets * TS_PACKET_SIZE);
		ts_pat_free(&pat1);
	}

	uint8_t *ts_packets;
	int num_packets;
	ts_pat_generate(pat, &ts_packets, &num_packets);
	if (num_packets != pat->section_header->num_packets) {
		ts_LOGf("ERROR: num_packets:%d != sec->num_packets:%d\n", num_packets, pat->section_header->num_packets);
	}
	ts_compare_data("PAT (struct->tspacket)", pat->section_header->packet_data, ts_packets, num_packets * TS_PACKET_SIZE);
	free(ts_packets);
}

void ts_pat_dump(struct ts_pat *pat) {
	struct ts_section_header *sec = pat->section_header;
	int i;

	ts_section_dump(sec);

	ts_LOGf("  * PAT data\n");
	ts_LOGf("    * num_programs: %d\n", pat->programs_num);
	for (i=0;i<pat->programs_num;i++) {
		struct ts_pat_program *prg = pat->programs[i];
		ts_LOGf("      * [%02d/%02d]: Program No 0x%04x (%5d) -> PID %04x (%d) /res: 0x%02x/\n",
			i+1, pat->programs_num,
			prg->program, prg->program,
			prg->pid, prg->pid,
			prg->reserved);
		// Program number 0 is Network ID, not program id
		if (prg->program == 0) {
			ts_LOGf("      - NIT PID %04x (%d)\n", prg->pid, prg->pid);
		}
	}

	ts_pat_check_generator(pat);
}

int ts_pat_is_same(struct ts_pat *pat1, struct ts_pat *pat2) {
	if (pat1 == pat2) return 1; // Same
	if ((!pat1 && pat2) || (pat1 && !pat2)) return 0; // Not same (one is NULL)
	return ts_section_is_same(pat1->section_header, pat2->section_header);
}
