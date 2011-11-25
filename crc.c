/*
 * CRC functions for mpeg PSI tables
 * Copyright (C) 2010-2011 Unix Solutions Ltd.
 *
 * Released under MIT license.
 * See LICENSE-MIT.txt for license terms.
 */
#include <netdb.h>

#include "tsfuncs.h"

#define CRC32_POLY 0x04C11DB7L

static int crc_table_initialized = 0;
static uint32_t crc32_table[256];

void ts_crc32_init(void) {
	int i, j;
	uint32_t crc;
	if (crc_table_initialized)
		return;
	crc_table_initialized = 1;
	for (i=0; i<256; i++) {
		crc = i << 24;
		for (j=0; j<8; j++) {
			if (crc & 0x80000000L)
				crc = (crc << 1) ^ CRC32_POLY;
			else
				crc = (crc << 1);
		}
		crc32_table[i] = crc;
	}
	crc_table_initialized = 1;
}

uint32_t ts_crc32(uint8_t *data, int data_size) {
	int i, j;
	uint32_t crc = 0xffffffff;
	if (!crc_table_initialized) {
		ts_crc32_init();
	}
	for (j=0; j<data_size; j++) {
		i = ((crc >> 24) ^ *data++) & 0xff;
		crc = (crc << 8) ^ crc32_table[i];
	}
	return crc;
}

u_int32_t ts_crc32_section(struct ts_section_header *section_header) {
	return ts_crc32(section_header->section_data, section_header->section_data_len);
}

int ts_crc32_section_check(struct ts_section_header *section_header, char *table) {
	uint32_t check_crc = ts_crc32(section_header->section_data, section_header->section_data_len);

	if (check_crc != 0) {
		ts_LOGf("!!! Wrong %s table CRC! It should be 0 but it is 0x%08x (CRC in data is 0x%08x)\n",
			table,
			check_crc,
			section_header->CRC);
		return 0;
	}
	return 1;
}
