/*
 * TDT/TOT table parser and generator
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
#include <time.h>

#include "tsfuncs.h"

struct ts_tdt *ts_tdt_alloc() {
	struct ts_tdt *tdt = calloc(1, sizeof(struct ts_tdt));
	tdt->section_header	= ts_section_data_alloc();
	return tdt;
}

void ts_tdt_clear(struct ts_tdt *tdt) {
	if (!tdt)
		return;
	// save
	struct ts_section_header *section_header = tdt->section_header;
	// free
	FREE(tdt->descriptors);
	// clear
	ts_section_data_clear(section_header);
	memset(tdt, 0, sizeof(struct ts_tdt));
	// restore
	tdt->section_header = section_header;
}

void ts_tdt_free(struct ts_tdt **ptdt) {
	struct ts_tdt *tdt = *ptdt;
	if (tdt) {
		ts_section_data_free(&tdt->section_header);
		FREE(tdt->descriptors);
		FREE(*ptdt);
	}
}

struct ts_tdt *ts_tdt_push_packet(struct ts_tdt *tdt, uint8_t *ts_packet) {
	struct ts_header ts_header;
	memset(&ts_header, 0, sizeof(struct ts_header));

	if (ts_packet_header_parse(ts_packet, &ts_header)) {
		// TDT/TOT should be with PID 0x11
		if (ts_header.pid != 0x14)
			goto OUT;
		// Received PUSI packet before table END, clear the table to start gathering new one
		if (ts_header.pusi && tdt->ts_header.pusi)
			ts_tdt_clear(tdt);
		if (!tdt->ts_header.pusi)
			tdt->ts_header = ts_header;
	}

	if (ts_header.pusi) {
		struct ts_section_header section_header;
		memset(&section_header, 0, sizeof(struct ts_section_header));

		uint8_t *section_data = ts_section_header_parse(ts_packet, &tdt->ts_header, &section_header);
		if (!section_data) {
			memset(&tdt->ts_header, 0, sizeof(struct ts_header));
			goto OUT;
		}
		//    table_id should be 0x70 (time_date_section)
		// or table_id should be 0x73 (time_offset_section)
		if (section_header.table_id != 0x70 && section_header.table_id != 0x73) {
			memset(&tdt->ts_header, 0, sizeof(struct ts_header));
			goto OUT;
		}

		// Set correct section_header
		ts_section_header_parse(ts_packet, &tdt->ts_header, tdt->section_header);
	}

	if (!tdt->initialized) {
		ts_section_add_packet(tdt->section_header, &ts_header, ts_packet);
		if (tdt->section_header->initialized) {
			if (!ts_tdt_parse(tdt))
				goto ERROR;
		}
	}

OUT:
	return tdt;

ERROR:
	ts_tdt_clear(tdt);
	return tdt;
}

int ts_tdt_parse(struct ts_tdt *tdt) {
	struct ts_section_header *sec = tdt->section_header;
	uint8_t *data = sec->data;

	tdt->mjd = (data[0] << 8) | data[1];
	tdt->bcd = ((data[2] << 16) | (data[3] << 8)) | data[4];
	data += 5;

	tdt->utc = ts_time_decode_mjd(tdt->mjd, tdt->bcd, &tdt->tm);

	if (sec->table_id == 0x73) { // TOT
		tdt->reserved_3        = data[0] >> 4;		// xxxx1111
		tdt->descriptors_size  = data[0] &~ 0xf0;	// 1111xxxx
		tdt->descriptors_size |= data[1];			// xxxxxxxx
		data += 2;
		if (tdt->descriptors_size) {
			tdt->descriptors = malloc(tdt->descriptors_size);
			memcpy(tdt->descriptors, data, tdt->descriptors_size);
		}
		if (!ts_crc32_section_check(tdt->section_header, "TOT"))
			return 0;
	}

	tdt->initialized = 1;
	return 1;
}

void ts_tdt_generate(struct ts_tdt *tdt, uint8_t **ts_packets, int *num_packets) {
	uint8_t *secdata = ts_section_data_alloc_section();
	ts_section_header_generate(secdata, tdt->section_header, 0);
	int curpos = 3; // Compensate for the section header, first data byte is at offset 3

	secdata[curpos + 0]  = (tdt->mjd &~ 0x00ff) >> 8;
	secdata[curpos + 1]  = (tdt->mjd &~ 0xff00);

	secdata[curpos + 2]  = (tdt->bcd >> 16);
	secdata[curpos + 3]  = (tdt->bcd >> 8) &~ 0xff00;
	secdata[curpos + 4]  = (tdt->bcd << 16) >> 16;
	curpos += 5; // For the fields above

	if (tdt->section_header->table_id == 0x73) { // TOT
		secdata[curpos + 0]  = tdt->reserved_3 << 4;
		secdata[curpos + 0] |= tdt->descriptors_size >> 8;
		secdata[curpos + 1]  = tdt->descriptors_size &~ 0xf00;
		curpos += 2;

		if (tdt->descriptors_size > 0) {
			memcpy(secdata + curpos, tdt->descriptors, tdt->descriptors_size);
			curpos += tdt->descriptors_size;
		}

		tdt->section_header->CRC = ts_section_data_calculate_crc(secdata, curpos);
	    curpos += 4; // CRC
	}

    ts_section_data_gen_ts_packets(&tdt->ts_header, secdata, curpos, tdt->section_header->pointer_field, ts_packets, num_packets);

    FREE(secdata);
}

struct ts_tdt *ts_tdt_copy(struct ts_tdt *tdt) {
	struct ts_tdt *newtdt = ts_tdt_alloc();
	int i;
	for (i=0;i<tdt->section_header->num_packets; i++) {
		newtdt = ts_tdt_push_packet(newtdt, tdt->section_header->packet_data + (i * TS_PACKET_SIZE));
	}
	if (newtdt->initialized) {
		return newtdt;
	} else {
		ts_LOGf("Error copying tdt!\n");
		ts_tdt_free(&newtdt);
		return NULL;
	}
}

void ts_tdt_check_generator(struct ts_tdt *tdt) {
	struct ts_tdt *tdt1 = ts_tdt_alloc();
	int i;

	char *prefix1 = "TDT (tspacket->struct)";
	char *prefix2 = "TDT (struct->tspacket)";
	if (tdt->section_header->table_id == 0x73) {
		prefix1[1] = 'O';
		prefix2[1] = 'O';
	}

	for (i=0;i<tdt->section_header->num_packets;i++) {
		tdt1 = ts_tdt_push_packet(tdt1, tdt->section_header->packet_data + (i * TS_PACKET_SIZE));
	}

	ts_compare_data(prefix1, // "TDT (tspacket->struct)",
		tdt1->section_header->packet_data,
		tdt->section_header->packet_data,
		tdt->section_header->num_packets * TS_PACKET_SIZE);
	ts_tdt_free(&tdt1);

	uint8_t *ts_packets;
	int num_packets;
	ts_tdt_generate(tdt, &ts_packets, &num_packets);
	if (num_packets != tdt->section_header->num_packets) {
		ts_LOGf("ERROR: num_packets:%d != sec->num_packets:%d\n", num_packets, tdt->section_header->num_packets);
	}
	ts_compare_data(prefix2 /* "TDT (struct->tspacket)" */, tdt->section_header->packet_data, ts_packets, num_packets * TS_PACKET_SIZE);

	free(ts_packets);
}

void ts_tdt_dump(struct ts_tdt *tdt) {
	struct ts_section_header *sec = tdt->section_header;
	struct tm tm;
	time_t ts;
	uint16_t mjd_check;
	uint32_t bcd_check;

	ts_section_dump(sec);

	ts = ts_time_decode_mjd(tdt->mjd, tdt->bcd, &tm);
	ts_time_encode_mjd(&mjd_check, &bcd_check, &ts, &tm);

	ts_LOGf("  * %s data\n", sec->table_id == 0x70 ? "TDT" : "TOT");
	ts_LOGf("    - MJD                : 0x%04x   (%04d-%02d-%02d) unixts: %ld check:0x%04x\n",
		tdt->mjd,
		tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
		ts, mjd_check);
	ts_LOGf("    - BCD                : 0x%06x (%02d:%02d:%02d) check:0x%06x\n",
		tdt->bcd,
		tm.tm_hour, tm.tm_min, tm.tm_sec,
		bcd_check);
	ts_LOGf("    - UTC Time           : %lu (%04d-%02d-%02d %02d:%02d:%02d)\n" , tdt->utc,
		tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec);
	if (sec->table_id == 0x73 && tdt->descriptors_size) { // TOT
		ts_descriptor_dump(tdt->descriptors, tdt->descriptors_size);
	}

	ts_tdt_check_generator(tdt);
}

int ts_tdt_is_same(struct ts_tdt *tdt1, struct ts_tdt *tdt2) {
	if (tdt1 == tdt2) return 1; // Same
	if ((!tdt1 && tdt2) || (tdt1 && !tdt2)) return 0; // Not same (one is NULL)
	return ts_section_is_same(tdt1->section_header, tdt2->section_header);
}
