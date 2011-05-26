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

void ts_cat_free(struct ts_cat **pcat) {
	struct ts_cat *cat = *pcat;
	if (cat) {
		ts_section_data_free(&cat->section_header);
		FREE(cat->program_info);
		FREE(*pcat);
	}
}

static struct ts_cat *ts_cat_reset(struct ts_cat *cat) {
	struct ts_cat *newcat = ts_cat_alloc();
	ts_cat_free(&cat);
	return newcat;
}

struct ts_cat *ts_cat_push_packet(struct ts_cat *cat, uint8_t *ts_packet) {
	struct ts_header ts_header;
	memset(&ts_header, 0, sizeof(struct ts_header));

	if (ts_packet_header_parse(ts_packet, &ts_header)) {
		if (!cat->ts_header.pusi)
			cat->ts_header = ts_header;
	}

	if (ts_header.pusi) {
		struct ts_section_header section_header;
		memset(&section_header, 0, sizeof(struct ts_section_header));

		uint8_t *section_data = ts_section_header_parse(ts_packet, &cat->ts_header, &section_header);
		if (!section_data || !section_header.section_syntax_indicator) {
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
		if (cat->section_header->section_syntax_indicator) {
			ts_section_add_packet(cat->section_header, &ts_header, ts_packet);
			if (cat->section_header->initialized) {
				if (!ts_cat_parse(cat))
					goto ERROR;
			}
		}
	}

OUT:
	return cat;

ERROR:
	return ts_cat_reset(cat);
}

int ts_cat_parse(struct ts_cat *cat) {
	uint8_t *section_data = cat->section_header->section_data + 8; // + 8 to compensate for section table header
	int section_len = cat->section_header->packet_section_len;

	/* Handle streams */
	uint8_t *stream_data = section_data;
	cat->program_info_size = section_len;
	cat->program_info = malloc(cat->program_info_size);
	memcpy(cat->program_info, stream_data, cat->program_info_size);
//	ts_print_bytes("DEBUG", cat->program_info, cat->program_info_size);
	stream_data += cat->program_info_size;

	cat->CRC = (cat->CRC << 8) | stream_data[3];
	cat->CRC = (cat->CRC << 8) | stream_data[2];
	cat->CRC = (cat->CRC << 8) | stream_data[1];
	cat->CRC = (cat->CRC << 8) | stream_data[0];

	u_int32_t check_crc = ts_crc32(cat->section_header->section_data, cat->section_header->data_size);
	if (check_crc != 0) {
		ts_LOGf("!!! Wrong cat CRC! It should be 0 but it is %08x (CRC in data is 0x%08x)\n", check_crc, cat->CRC);
		return 0;
	}

	cat->initialized = 1;
	return 1;
}

void ts_cat_generate(struct ts_cat *cat, uint8_t **ts_packets, int *num_packets) {
	uint8_t *secdata = ts_section_data_alloc_section();
	ts_section_header_generate(secdata, cat->section_header, 0);
	int curpos = 8; // Compensate for the section header, frist data byte is at offset 8

	memcpy(secdata + curpos, cat->program_info, cat->program_info_size);
	curpos += cat->program_info_size;

    cat->CRC = ts_section_data_calculate_crc(secdata, curpos);
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
	int i;
	ts_LOGf("CAT table\n");
    for(i=0;i<cat->section_header->num_packets;i++) {
        struct ts_header tshdr;
        ts_packet_header_parse(cat->section_header->packet_data + (i * TS_PACKET_SIZE), &tshdr);
        ts_packet_header_dump(&tshdr);
    }
    ts_section_header_dump(cat->section_header);

	if (cat->program_info_size > 0) {
		ts_LOGf(" * Descriptor dump:\n");
		ts_descriptor_dump(cat->program_info, cat->program_info_size);
	}
	ts_LOGf("  * CRC 0x%04x\n", cat->CRC);

	ts_cat_check_generator(cat);
}

int ts_cat_is_same(struct ts_cat *cat1, struct ts_cat *cat2) {
	if (cat1->CRC == cat2->CRC) // Same
		return 1;

	// If some version is not current, just claim the structures are the same
	if (!cat1->section_header->current_next_indicator || cat2->section_header->version_number)
		return 1;

	if (cat1->section_header->version_number != cat2->section_header->version_number) // Different
		return 0;

	return 1; // Same
}
