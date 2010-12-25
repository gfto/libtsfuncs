#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tsfuncs.h"

struct ts_tdt *ts_tdt_alloc() {
	struct ts_tdt *tdt = calloc(1, sizeof(struct ts_tdt));
	tdt->packet_data = malloc(TS_PACKET_SIZE);
	memset(tdt->packet_data, 0x32, TS_PACKET_SIZE);
	return tdt;
}

void ts_tdt_free(struct ts_tdt **ptdt) {
	struct ts_tdt *tdt = *ptdt;
	if (tdt) {
		FREE(tdt->packet_data);
		FREE(tdt->descriptors);
		FREE(*ptdt);
	}
}

static void ts_tdt_init_empty(struct ts_tdt *tdt, time_t ts, int tot) {
	tdt->ts_header.pid            = 0x14;
	tdt->ts_header.pusi           = 1;
	tdt->ts_header.payload_field  = 1;
	tdt->ts_header.payload_offset = 4;
	tdt->ts_header.continuity     = 7;

	tdt->table_id                 = 0x70;
	tdt->section_syntax_indicator = 0;
	tdt->reserved_1               = 1;
	tdt->reserved_2               = 3;
	tdt->section_length           = 5;

	ts_time_encode_mjd(&tdt->mjd, &tdt->bcd, &ts, NULL);
	tdt->utc = ts_time_decode_mjd(tdt->mjd, tdt->bcd, &tdt->tm);

	if (tot) {
		tdt->table_id            = 0x73;
		tdt->reserved_3          = 0xf;
		tdt->descriptors_size    = 0;
		tdt->CRC                 = 0;
		tdt->section_length     += 2 + 4;	// 2 bytes reserved+descripts_size
	}

	ts_tdt_generate(tdt, tdt->packet_data);

	tdt->initialized = 1;
}

struct ts_tdt *ts_tdt_alloc_init(time_t ts) {
	struct ts_tdt *tdt = ts_tdt_alloc();
	ts_tdt_init_empty(tdt, ts, 0);
	return tdt;
}

struct ts_tdt *ts_tot_alloc_init(time_t ts) {
	struct ts_tdt *tdt = ts_tdt_alloc();
	ts_tdt_init_empty(tdt, ts, 1);
	return tdt;
}

static void ts_tdt_check_generator(struct ts_tdt *tdt) {
	struct ts_tdt *tdt1 = ts_tdt_alloc();
	ts_tdt_parse(tdt1, tdt->packet_data);
	ts_compare_data("TDT/TOT (packet->data)", tdt1->packet_data, tdt->packet_data, TS_PACKET_SIZE);
	ts_tdt_free(&tdt1);

	uint8_t *tmp = malloc(TS_PACKET_SIZE);
	ts_tdt_generate(tdt, tmp);
	ts_compare_data("TDT/TOT (data->packet)", tdt->packet_data, tmp, TS_PACKET_SIZE);
	free(tmp);
}

int ts_tdt_parse(struct ts_tdt *tdt, uint8_t *ts_packet) {
	uint8_t *data = ts_packet_header_parse(ts_packet, &tdt->ts_header);

	if (!data)
		return 0;

	if (tdt->ts_header.pid != 0x14) // TOT/TDT
		return 0;

	tdt->pointer_field = data[0];
	data += tdt->pointer_field + 1;

	if ((data + 8) - ts_packet > TS_PACKET_SIZE) {
		ts_LOGf("!!! Section start outside of TS packet!\n");
		return 0;
	}

	if (data[0] != 0x70 && data[0] != 0x73) { // TDT or TOT
		ts_LOGf("Invalid TDT/TOT Table_ID 0x%02x\n", data[0]);
		return 0;
	}

	tdt->table_id                 = data[0];
	tdt->section_syntax_indicator = data[1] >> 7;			// x1111111
	tdt->reserved_1               = (data[1] &~ 0xBF) >> 6;	// 1x111111
	tdt->reserved_2               = (data[1] &~ 0xCF) >> 4;	// 11xx1111
	tdt->section_length           = ((data[1] &~ 0xF0) << 8) | data[2]; // 1111xxxx xxxxxxxx
	if (tdt->section_length > TS_MAX_PAYLOAD_SIZE - 8) {
		ts_LOGf("TDT/TOT section length is too big: %d (max: %d)\n", tdt->section_length, TS_MAX_PAYLOAD_SIZE - 8);
		return 0;
	}

	tdt->mjd       = (data[3] << 8) | data[4];
	tdt->bcd       = ((data[5] << 16) | (data[6] << 8)) | data[7];

	if (tdt->table_id == 0x73) { // TOT
		tdt->reserved_3        = data[8] >> 4;		// xxxx1111
		tdt->descriptors_size  = data[8] &~ 0xf0;	// 1111xxxx
		tdt->descriptors_size |= data[9];			// xxxxxxxx
		if (tdt->descriptors_size > TS_MAX_PAYLOAD_SIZE - 10) {
			ts_LOGf("TDT/TOT descriptors_size is too big: %d (max: %d)\n", tdt->descriptors_size, TS_MAX_PAYLOAD_SIZE - 10);
			return 0;
		}
		if (tdt->descriptors_size) {
			tdt->descriptors = malloc(tdt->descriptors_size);
			memcpy(tdt->descriptors, &data[10], tdt->descriptors_size);
		}
		tdt->CRC = (tdt->CRC << 8) | data[10 + tdt->descriptors_size + 3];
		tdt->CRC = (tdt->CRC << 8) | data[10 + tdt->descriptors_size + 2];
		tdt->CRC = (tdt->CRC << 8) | data[10 + tdt->descriptors_size + 1];
		tdt->CRC = (tdt->CRC << 8) | data[10 + tdt->descriptors_size + 0];
	}

	tdt->utc = ts_time_decode_mjd(tdt->mjd, tdt->bcd, &tdt->tm);

	memcpy(tdt->packet_data, ts_packet, TS_PACKET_SIZE);

	tdt->initialized = 1;

	return 1;
}

void ts_tdt_generate(struct ts_tdt *tdt, uint8_t *ts_packet) {
	ts_packet_header_generate(ts_packet, &tdt->ts_header);

	uint8_t start = 4;
	ts_packet[start + 0]  = tdt->pointer_field;
	start += tdt->pointer_field + 1;

	ts_packet[start + 0]  = tdt->table_id;
	ts_packet[start + 1]  = tdt->section_syntax_indicator << 7;		// x1111111
	ts_packet[start + 1] |= tdt->reserved_1               << 6;		// 1x111111
	ts_packet[start + 1] |= tdt->reserved_2               << 4;		// 11xx1111
	ts_packet[start + 1] |= tdt->section_length           >> 8;		// 1111xxxx xxxxxxxx
	ts_packet[start + 2]  = tdt->section_length           &~ 0xff00;	// 1111xxxx xxxxxxxx

	ts_packet[start + 3]  = (tdt->mjd &~ 0x00ff) >> 8;
	ts_packet[start + 4]  = (tdt->mjd &~ 0xff00);

	ts_packet[start + 5]  = (tdt->bcd >> 16);
	ts_packet[start + 6]  = (tdt->bcd >> 8) &~ 0xff00;
	ts_packet[start + 7]  = (tdt->bcd << 16) >> 16;

	if (tdt->table_id == 0x73) { // TOT
		ts_packet[start + 8]  = tdt->reserved_3 << 4;
		ts_packet[start + 8] |= tdt->descriptors_size >> 8;
		ts_packet[start + 9]  = tdt->descriptors_size &~ 0xf00;
		if (tdt->descriptors_size) {
			memcpy(&ts_packet[start + 10], tdt->descriptors, tdt->descriptors_size);
		}
		tdt->CRC = ts_section_data_calculate_crc(ts_packet + start, 10 + tdt->descriptors_size);
	}
}

void ts_tdt_dump(struct ts_tdt *tdt) {
	struct tm tm;
	time_t ts;
	uint16_t mjd_check;
	uint32_t bcd_check;
	char *prefix = tdt->table_id == 0x70 ? "TDT" : "TOT"; // TDT table_id == 0x70, TOT table_id == 0x73

	ts = ts_time_decode_mjd(tdt->mjd, tdt->bcd, &tm);
	ts_time_encode_mjd(&mjd_check, &bcd_check, &ts, &tm);

	ts_LOGf("%s packet dump\n", prefix);
	ts_packet_header_dump(&tdt->ts_header);
	ts_LOGf("    - Table id           : %03x (%d) %s\n", tdt->table_id, tdt->table_id, prefix);
	ts_LOGf("    - Section length     : %03x (%d)\n", tdt->section_length, tdt->section_length);
	ts_LOGf("  * %s data\n", prefix);
	ts_LOGf("    - MJD                : 0x%04x   (%04d-%02d-%02d) unixts: %ld check:0x%04x\n",
		tdt->mjd,
		tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
		ts, mjd_check);
	ts_LOGf("    - BCD                : 0x%06x (%02d:%02d:%02d) check:0x%06x\n",
		tdt->bcd,
		tm.tm_hour, tm.tm_min, tm.tm_sec,
		bcd_check);
	ts_LOGf("    - UTC Time           : %lu\n" , tdt->utc);
	if (tdt->table_id == 0x73) { // TOT
		if (tdt->descriptors) {
			ts_descriptor_dump(tdt->descriptors, tdt->descriptors_size);
		}
		ts_LOGf("  * CRC 0x%04x\n", tdt->CRC);
	}

	ts_tdt_check_generator(tdt);
}

void ts_tdt_set_time(struct ts_tdt *tdt, time_t now) {
	tdt->ts_header.continuity++;
	ts_time_encode_mjd(&tdt->mjd, &tdt->bcd, &now, NULL);
	tdt->utc = ts_time_decode_mjd(tdt->mjd, tdt->bcd, &tdt->tm);
	ts_tdt_generate(tdt, tdt->packet_data);
}

void ts_tot_set_localtime_offset(struct ts_tdt *tdt, time_t now, time_t change_time, uint8_t polarity, uint16_t ofs, uint16_t ofs_next) {
	if (tdt->table_id != 0x73)
		return;
	tdt->ts_header.continuity++;

	ts_time_encode_mjd(&tdt->mjd, &tdt->bcd, &now, NULL);
	tdt->utc = ts_time_decode_mjd(tdt->mjd, tdt->bcd, &tdt->tm);

	uint16_t mjd = 0;
	uint32_t bcd = 0;
	ts_time_encode_mjd(&mjd, &bcd, &change_time, NULL);

	uint8_t *lto; // Local time offset
	if (tdt->descriptors_size == 0) {
		tdt->descriptors_size = 15;
		tdt->descriptors = calloc(1, tdt->descriptors_size);
		tdt->section_length += tdt->descriptors_size;
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

	ts_tdt_generate(tdt, tdt->packet_data);
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

void ts_tot_set_localtime_offset_sofia(struct ts_tdt *tdt) {
	time_t   now = time(NULL);
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
	ts_tot_set_localtime_offset(tdt, time(NULL), change_time, polarity, current_offset, next_offset);
}

int parse_tdt(uint8_t *ts_packet, int dump) {
	struct ts_tdt *tdt = ts_tdt_alloc();
	int ret = ts_tdt_parse(tdt, ts_packet);
	if (ret && dump)
		ts_tdt_dump(tdt);
	ts_tdt_free(&tdt);
	return ret;
}
