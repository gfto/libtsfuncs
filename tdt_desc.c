/*
 * TDT/TOT descriptors generator
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

static void ts_tdt_regenerate_packet_data(struct ts_tdt *tdt) {
	uint8_t *ts_packets;
	int num_packets;
	ts_tdt_generate(tdt, &ts_packets, &num_packets);
	memcpy(tdt->section_header->packet_data, ts_packets, num_packets * TS_PACKET_SIZE);
	tdt->section_header->num_packets = num_packets;
	free(ts_packets);
}

static struct ts_tdt *ts_tdt_init_empty(struct ts_tdt *tdt, time_t ts, int tot) {
	tdt->ts_header.pid            = 0x14;
	tdt->ts_header.pusi           = 1;
	tdt->ts_header.payload_field  = 1;
	tdt->ts_header.payload_offset = 4;

	tdt->section_header->table_id                 = 0x70;
	tdt->section_header->section_syntax_indicator = 0;
	tdt->section_header->private_indicator        = 1;
	tdt->section_header->reserved1                = 3;
	tdt->section_header->section_length           = 5; // 5 bytes UTC_time

	ts_time_encode_mjd(&tdt->mjd, &tdt->bcd, &ts, NULL);
	tdt->utc = ts_time_decode_mjd(tdt->mjd, tdt->bcd, &tdt->tm);

	if (tot) {
		tdt->section_header->table_id             = 0x73;
		tdt->section_header->section_length       = 5 + 2 + 4;	// 5 bytes UTC_time, 2 bytes reserved & descripts_size, 4 bytes CRC
		tdt->reserved_3           = 0xf;
		tdt->descriptors_size     = 0;
	}

	tdt->initialized = 1;
	ts_tdt_regenerate_packet_data(tdt);

	return tdt;
}

struct ts_tdt *ts_tdt_init(struct ts_tdt *tdt, time_t ts) {
	return ts_tdt_init_empty(tdt, ts, 0);
}

struct ts_tdt *ts_tot_init(struct ts_tdt *tot, time_t ts) {
	return ts_tdt_init_empty(tot, ts, 1);
}

struct ts_tdt *ts_tdt_alloc_init(time_t ts) {
	return ts_tdt_init_empty(ts_tdt_alloc(), ts, 0);
}

struct ts_tdt *ts_tot_alloc_init(time_t ts) {
	return ts_tdt_init_empty(ts_tdt_alloc(), ts, 1);
}

void ts_tdt_set_time(struct ts_tdt *tdt, time_t now) {
	ts_time_encode_mjd(&tdt->mjd, &tdt->bcd, &now, NULL);
	tdt->utc = ts_time_decode_mjd(tdt->mjd, tdt->bcd, &tdt->tm);
	ts_tdt_regenerate_packet_data(tdt);
}

void ts_tot_set_localtime_offset(struct ts_tdt *tdt, time_t now, time_t change_time, uint8_t polarity, uint16_t ofs, uint16_t ofs_next) {
	if (tdt->section_header->table_id != 0x73)
		return;

	ts_time_encode_mjd(&tdt->mjd, &tdt->bcd, &now, NULL);
	tdt->utc = ts_time_decode_mjd(tdt->mjd, tdt->bcd, &tdt->tm);

	uint16_t mjd = 0;
	uint32_t bcd = 0;
	ts_time_encode_mjd(&mjd, &bcd, &change_time, NULL);

	uint8_t *lto; // Local time offset
	if (tdt->descriptors_size == 0) {
		tdt->descriptors_size = 15;
		tdt->descriptors = calloc(1, tdt->descriptors_size);
		tdt->section_header->section_length += tdt->descriptors_size;
	}
	lto = tdt->descriptors;
	lto[0     ]  = 0x58;		// Descriptor tag
	lto[1     ]  = 13;			// 13 octets
	lto[2 +  0]  = 'B';			// Country code
	lto[2 +  1]  = 'U';
	lto[2 +  2]  = 'L';
	lto[2 +  3]  = 0;			// 111111xx (Country region,   6 bit)
	lto[2 +  3] |= bit_2;		// xxxxxx1x (Reserved,         1 bit) !!!!
	lto[2 +  3] |= polarity;	// xxxxxxx1 (Polarity,         1 bit, 0 +utc, 1 -utc) !!!!

	lto[2 +  4]  = ofs >> 8;	// (LocalTime offset  16 bits, bcd)
	lto[2 +  5]  = ofs &~ 0xff00;

	lto[2 +  6]  = mjd >> 8;	// Time of change (40 bcd)
	lto[2 +  7]  = mjd &~ 0xff00;
	lto[2 +  8]  = bcd >> 16;
	lto[2 +  9]  = bcd >> 8;
	lto[2 + 10]  = bcd &~ 0xffff00;

	lto[2 + 11]  = ofs_next >> 8; // Next time offset (16 bits, bcd)
	lto[2 + 12]  = ofs_next &~ 0xff00;

	ts_tdt_regenerate_packet_data(tdt);
}

// Calculate change time for European summer time, see:
// http://en.wikipedia.org/wiki/European_Summer_Time
static time_t euro_dst_start(int year) {
	struct tm tm;
	int dst_start_date;
	memset(&tm, 0, sizeof(struct tm));
	tm.tm_year = year - 1900;
	tm.tm_mon  = 2; // March
	tm.tm_mday = (31 - (5 * year / 4 + 4) % 7); // Sunday DST_START March   at 01:00 GMT
	tm.tm_hour = 1;
	dst_start_date = timegm(&tm);
	//ts_LOGf("year: %d ts: %d dst_start: %s", year, dst_start_date, asctime(&tm));
	return dst_start_date;
}

static time_t euro_dst_end(int year) {
	struct tm tm;
	int dst_end_date;
	memset(&tm, 0, sizeof(struct tm));
	tm.tm_year = year - 1900;
	tm.tm_mon  = 9; // October
	tm.tm_mday = (31 - (5 * year / 4 + 1) % 7); // Sunday DST_END   October at 01:00 GMT
	tm.tm_hour = 1;
	dst_end_date = timegm(&tm);
	//ts_LOGf("year: %d ts: %d dst_end: %s", year, dst_end_date, asctime(&tm));
	return dst_end_date;
}

void ts_tot_set_localtime_offset_sofia(struct ts_tdt *tdt, time_t now) {
	uint8_t  polarity = 0;	// 0 == UTC + offset, 1 == UTC - offset
	time_t   change_time;	// When the next DST change will be
	uint16_t current_offset;
	uint16_t next_offset;
	struct tm tm;

	gmtime_r(&now, &tm);
	//ts_LOGf("nowts: %d now: %s", now, asctime(&tm));
	int curyear  = tm.tm_year + 1900;
	int dst_start_date = euro_dst_start(curyear);
	int dst_end_date   = euro_dst_end(curyear);
	if (now < dst_start_date) {
		current_offset = 0x0200; // We are in winter time now
		next_offset    = 0x0300; // Next is the summer
		change_time    = dst_start_date;
	} else {
		if (now >= dst_start_date && now < dst_end_date) {
			current_offset = 0x0300; // We are in summer time time
			next_offset    = 0x0200; // Next time it should be winter
			change_time    = dst_end_date;
		} else {
			current_offset = 0x0200; // We are in winter time
			next_offset    = 0x0300; // Next time it should be summer
			change_time    = euro_dst_start(curyear + 1);
		}
	}
	//ts_LOGf("curofs: %04x next_ofs: %04x change_time:%d\n", current_offset, next_offset, change_time);
	ts_tot_set_localtime_offset(tdt, now, change_time, polarity, current_offset, next_offset);
}
