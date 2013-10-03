/*
 * CAT table parser and generator
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

struct ts_cat *ts_cat_alloc() {
	struct ts_cat *cat = calloc(1, sizeof(struct ts_cat));
	cat->section_header	= ts_section_data_alloc();
	return cat;
}

void ts_cat_clear(struct ts_cat *cat) {
	if (!cat)
		return;
	// save
	struct ts_section_header *section_header = cat->section_header;
	// free
	FREE(cat->program_info);
	// clear
	ts_section_data_clear(section_header);
	memset(cat, 0, sizeof(struct ts_cat));
	// restore
	cat->section_header = section_header;
}

void ts_cat_free(struct ts_cat **pcat) {
	struct ts_cat *cat = *pcat;
	if (cat) {
		ts_section_data_free(&cat->section_header);
		FREE(cat->program_info);
		FREE(*pcat);
	}
}

struct ts_cat *ts_cat_push_packet(struct ts_cat *cat, uint8_t *ts_packet) {
	struct ts_header ts_header;
	memset(&ts_header, 0, sizeof(struct ts_header));

	if (ts_packet_header_parse(ts_packet, &ts_header)) {
		// Received PUSI packet before table END, clear the table to start gathering new one
		if (ts_header.pusi && cat->ts_header.pusi)
			ts_cat_clear(cat);
		if (!cat->ts_header.pusi)
			cat->ts_header = ts_header;
	}

	if (ts_header.pusi) {
		struct ts_section_header section_header;
		memset(&section_header, 0, sizeof(struct ts_section_header));

		uint8_t *section_data = ts_section_header_parse(ts_packet, &cat->ts_header, &section_header);
		if (!section_data) {
			memset(&cat->ts_header, 0, sizeof(struct ts_header));
			goto OUT;
		}
		// table_id should be 0x01 (ca_map_section)
		if (section_header.table_id != 0x01) {
			memset(&cat->ts_header, 0, sizeof(struct ts_header));
			goto OUT;
		}

		// Set correct section_header
		ts_section_header_parse(ts_packet, &cat->ts_header, cat->section_header);
	}

	if (!cat->initialized) {
		ts_section_add_packet(cat->section_header, &ts_header, ts_packet);
		if (cat->section_header->initialized) {
			if (!ts_cat_parse(cat))
				goto ERROR;
		}
	}

OUT:
	return cat;

ERROR:
	ts_cat_clear(cat);
	return cat;
}

int ts_cat_parse(struct ts_cat *cat) {
	uint8_t *section_data = cat->section_header->data;
	int section_len = cat->section_header->data_len;

	if (section_len > 4096)
		return 0;
	/* Handle streams */
	uint8_t *stream_data = section_data;
	cat->program_info_size = section_len;
	cat->program_info = malloc(cat->program_info_size);
	if (!cat->program_info)
		return 0;
	memcpy(cat->program_info, stream_data, cat->program_info_size);
	stream_data += cat->program_info_size;

	if (!ts_crc32_section_check(cat->section_header, "CAT"))
		return 0;

	cat->initialized = 1;
	return 1;
}

void ts_cat_generate(struct ts_cat *cat, uint8_t **ts_packets, int *num_packets) {
	uint8_t *secdata = ts_section_data_alloc_section();
	ts_section_header_generate(secdata, cat->section_header, 0);
	int curpos = 8; // Compensate for the section header, frist data byte is at offset 8

	memcpy(secdata + curpos, cat->program_info, cat->program_info_size);
	curpos += cat->program_info_size;

	cat->section_header->CRC = ts_section_data_calculate_crc(secdata, curpos);
    curpos += 4; // CRC

    ts_section_data_gen_ts_packets(&cat->ts_header, secdata, curpos, cat->section_header->pointer_field, ts_packets, num_packets);

    FREE(secdata);
}

void ts_cat_regenerate_packets(struct ts_cat *cat) {
	uint8_t *ts_packets;
	int num_packets;
	ts_cat_generate(cat, &ts_packets, &num_packets);
	FREE(cat->section_header->packet_data);
	cat->section_header->packet_data = ts_packets;
	cat->section_header->num_packets = num_packets;
}

struct ts_cat *ts_cat_copy(struct ts_cat *cat) {
	struct ts_cat *newcat = ts_cat_alloc();
	int i;
	for (i=0;i<cat->section_header->num_packets; i++) {
		newcat = ts_cat_push_packet(newcat, cat->section_header->packet_data + (i * TS_PACKET_SIZE));
	}
	if (newcat->initialized) {
		return newcat;
	} else {
		ts_LOGf("Error copying cat!\n");
		ts_cat_free(&newcat);
		return NULL;
	}
}

void ts_cat_check_generator(struct ts_cat *cat) {
	struct ts_cat *cat1 = ts_cat_copy(cat);
	if (cat1) {
		ts_compare_data("CAT (tspacket->struct)",
			cat1->section_header->packet_data,
			cat->section_header->packet_data,
			cat->section_header->num_packets * TS_PACKET_SIZE);
		ts_cat_free(&cat1);
	}

	uint8_t *ts_packets;
	int num_packets;
	ts_cat_generate(cat, &ts_packets, &num_packets);
	if (num_packets != cat->section_header->num_packets) {
		ts_LOGf("ERROR: num_packets:%d != sec->num_packets:%d\n", num_packets, cat->section_header->num_packets);
	}
	ts_compare_data("CAT (struct->tspacket)", cat->section_header->packet_data, ts_packets, num_packets * TS_PACKET_SIZE);
	free(ts_packets);
}

void ts_cat_dump(struct ts_cat *cat) {
	struct ts_section_header *sec = cat->section_header;

	ts_section_dump(sec);

	if (cat->program_info_size > 0) {
		ts_LOGf("  * Descriptor dump:\n");
		ts_descriptor_dump(cat->program_info, cat->program_info_size);
	}

	ts_cat_check_generator(cat);
}

int ts_cat_is_same(struct ts_cat *cat1, struct ts_cat *cat2) {
	if (cat1 == cat2) return 1; // Same
	if ((!cat1 && cat2) || (cat1 && !cat2)) return 0; // Not same (one is NULL)
	return ts_section_is_same(cat1->section_header, cat2->section_header);
}

enum CA_system ts_get_CA_sys(uint16_t CA_id) {
	if (CA_id >= 0x0100 && CA_id <= 0x01FF) return CA_SECA;
	if (CA_id >= 0x0500 && CA_id <= 0x05FF) return CA_VIACCESS;
	if (CA_id >= 0x0600 && CA_id <= 0x06FF) return CA_IRDETO;
	if (CA_id >= 0x0900 && CA_id <= 0x09FF) return CA_VIDEOGUARD;
	if (CA_id >= 0x0B00 && CA_id <= 0x0BFF) return CA_CONAX;
	if (CA_id >= 0x0D00 && CA_id <= 0x0DFF) return CA_CRYPTOWORKS;
	if (CA_id >= 0x1800 && CA_id <= 0x18FF) return CA_NAGRA;
	switch (CA_id) {
		case 0x4ABF: return CA_DGCRYPT;

		case 0x4AE0: return CA_DRECRYPT;
		case 0x4AE1: return CA_DRECRYPT;

		case 0x5581: return CA_BULCRYPT;
		case 0x4AEE: return CA_BULCRYPT;

		case 0x5501: return CA_GRIFFIN;
		case 0x5504: return CA_GRIFFIN;
		case 0x5506: return CA_GRIFFIN;
		case 0x5508: return CA_GRIFFIN;
		case 0x5509: return CA_GRIFFIN;
		case 0x550E: return CA_GRIFFIN;
		case 0x5511: return CA_GRIFFIN;
	}
	return CA_UNKNOWN;
}

char * ts_get_CA_sys_txt(enum CA_system CA_sys) {
	switch (CA_sys) {
		case CA_SECA:			return "SECA";
		case CA_VIACCESS:		return "VIACCESS";
		case CA_IRDETO:			return "IRDETO";
		case CA_VIDEOGUARD:		return "VIDEOGUARD";
		case CA_CONAX:			return "CONAX";
		case CA_CRYPTOWORKS:	return "CRYPTOWORKS";
		case CA_NAGRA:			return "NAGRA";
		case CA_DRECRYPT:		return "DRE-CRYPT";
		case CA_BULCRYPT:		return "BULCRYPT";
		case CA_GRIFFIN:		return "GRIFFIN";
		case CA_DGCRYPT:		return "DGCRYPT";
		case CA_UNKNOWN:		return "UNKNOWN";
	}
	return "UNKNOWN";
}

static int find_CA_descriptor(uint8_t *data, int data_len, enum CA_system req_CA_type, uint16_t *CA_id, uint16_t *CA_pid) {
	while (data_len >= 2) {
		uint8_t tag         = data[0];
		uint8_t this_length = data[1];
		data     += 2;
		data_len -= 2;
		if (tag == 9 && this_length >= 4) {
			uint16_t CA_ID = (data[0] << 8) | data[1];
			uint16_t CA_PID = ((data[2] & 0x1F) << 8) | data[3];
			if (ts_get_CA_sys(CA_ID) == req_CA_type) {
				*CA_id = CA_ID;
				*CA_pid = CA_PID;
				return 1;
			}
		}
		data_len -= this_length;
		data += this_length;
	}
	return 0;
}

int ts_get_emm_info(struct ts_cat *cat, enum CA_system req_CA_type, uint16_t *CA_id, uint16_t *CA_pid) {
	return find_CA_descriptor(cat->program_info, cat->program_info_size, req_CA_type, CA_id, CA_pid);
}

int ts_get_ecm_info(struct ts_pmt *pmt, enum CA_system req_CA_type, uint16_t *CA_id, uint16_t *CA_pid) {
	int i, result = find_CA_descriptor(pmt->program_info, pmt->program_info_size, req_CA_type, CA_id, CA_pid);
	if (!result) {
		for(i=0;i<pmt->streams_num;i++) {
			struct ts_pmt_stream *stream = pmt->streams[i];
			if (stream->ES_info) {
				result = find_CA_descriptor(stream->ES_info, stream->ES_info_size, req_CA_type, CA_id, CA_pid);
				if (result)
					break;
			}
		}
	}

	return result;
}

static int find_CA_descriptor_by_caid(uint8_t *data, int data_len, uint16_t caid, uint16_t *CA_pid) {
	while (data_len >= 2) {
		uint8_t tag         = data[0];
		uint8_t this_length = data[1];
		data     += 2;
		data_len -= 2;
		if (tag == 9 && this_length >= 4) {
			uint16_t CA_ID = (data[0] << 8) | data[1];
			uint16_t CA_PID = ((data[2] & 0x1F) << 8) | data[3];
			if (CA_ID == caid) {
				*CA_pid = CA_PID;
				return 1;
			}
		}
		data_len -= this_length;
		data += this_length;
	}
	return 0;
}

int ts_get_emm_info_by_caid(struct ts_cat *cat, uint16_t caid, uint16_t *ca_pid) {
	return find_CA_descriptor_by_caid(cat->program_info, cat->program_info_size, caid, ca_pid);
}

int ts_get_ecm_info_by_caid(struct ts_pmt *pmt, uint16_t caid, uint16_t *ca_pid) {
	int i, result = find_CA_descriptor_by_caid(pmt->program_info, pmt->program_info_size, caid, ca_pid);
	if (!result) {
		for(i=0;i<pmt->streams_num;i++) {
			struct ts_pmt_stream *stream = pmt->streams[i];
			if (stream->ES_info) {
				result = find_CA_descriptor_by_caid(stream->ES_info, stream->ES_info_size, caid, ca_pid);
				if (result)
					break;
			}
		}
	}

	return result;
}


static int find_CA_descriptor_by_pid(uint8_t *data, int data_len, uint16_t *caid, uint16_t pid) {
	while (data_len >= 2) {
		uint8_t tag         = data[0];
		uint8_t this_length = data[1];
		data     += 2;
		data_len -= 2;
		if (tag == 9 && this_length >= 4) {
			uint16_t CA_ID = (data[0] << 8) | data[1];
			uint16_t CA_PID = ((data[2] & 0x1F) << 8) | data[3];
			if (CA_PID == pid) {
				*caid = CA_ID;
				return 1;
			}
		}
		data_len -= this_length;
		data += this_length;
	}
	return 0;
}

int ts_get_emm_info_by_pid(struct ts_cat *cat, uint16_t *caid, uint16_t ca_pid) {
	return find_CA_descriptor_by_pid(cat->program_info, cat->program_info_size, caid, ca_pid);
}

int ts_get_ecm_info_by_pid(struct ts_pmt *pmt, uint16_t *caid, uint16_t ca_pid) {
	int i, result = find_CA_descriptor_by_pid(pmt->program_info, pmt->program_info_size, caid, ca_pid);
	if (!result) {
		for(i=0;i<pmt->streams_num;i++) {
			struct ts_pmt_stream *stream = pmt->streams[i];
			if (stream->ES_info) {
				result = find_CA_descriptor_by_pid(stream->ES_info, stream->ES_info_size, caid, ca_pid);
				if (result)
					break;
			}
		}
	}

	return result;
}
