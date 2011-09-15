/*
 * Misc functions
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
#include <ctype.h>

#include "tsfuncs.h"

int dec2bcd(int dec) {
	return ((dec/10) << 4) + dec % 10;
}

int bcd2dec(int bcd) {
	return ((bcd>>4) * 10) + bcd % 16;
}

void ts_hex_dump_buf(char *buf, int bufsz, uint8_t *d, int size, int col) {
	int i;
	if (bufsz < size * 6)
		return;
	memset(buf, 0, bufsz);
	for (i=0;i<size;i++) {
		if (col && (i % col == col - 1))
			sprintf(buf+(i*3), "%02x\n", d[i]);
		else
			sprintf(buf+(i*3), "%02x ", d[i]);
	}
}

char *ts_hex_dump(uint8_t *d, int size, int col) {
	char *buf = malloc(size * 6);
	if (!buf)
		return NULL;
	ts_hex_dump_buf(buf, size * 6, d, size, col);
	return buf;
}

void ts_print_bytes(char *prefix, uint8_t *d, int size) {
	char *buf = ts_hex_dump(d, size, 0);
	ts_LOGf("%s -> %s\n", prefix, buf);
	free(buf);
}

void ts_compare_data(char *prefix, uint8_t *a, uint8_t *b, int size) {
	if (!a) {
		ts_LOGf("%s: !a\n", prefix);
		return;
	}
	if (!b) {
		ts_LOGf("%s: !b\n", prefix);
		return;
	}
	if (memcmp(a, b, size) == 0) {
		ts_LOGf("   **** %s generator is correct ****\n", prefix);
	} else {
		int i;
		for (i=0;i<size;i++) {
			ts_LOGf("%03d - %02x %02x | %s\n", i, a[i], b[i], a[i] == b[i] ? "ok" : "err");
		}
	}
}

char *init_dvb_string(uint8_t encoding, char *text) {
	if (!text)
		return NULL;
	int len = strlen(text);
	if (!len)
		return NULL;
	char *dvbtext = calloc(1, len + 2);
	memcpy(dvbtext + 1, text, len);
	dvbtext[0] = encoding; // See EN 300 469 table A.3
	return dvbtext;
}

char *init_dvb_string_utf8(char *text) {
	return init_dvb_string(0x10, text);
}

char *init_dvb_string_iso_8859_5(char *text) {
	return init_dvb_string(0x01, text);
}

int ts_is_psi_pid(uint16_t pid, struct ts_pat *pat) {
	// Skip PAT && reserved, SDT, EIT, RST, TDT/TOT. They are PSI packets
	if (pid < 0x10 || pid == 0x11 || pid == 0x12 || pid == 0x13 || pid == 0x14)
		return 1;

	int i;
	for (i=0;i<pat->programs_num;i++) {
		struct ts_pat_program *prg = pat->programs[i];
		if (prg->pid == pid) // PMT's are PSI
			return 1;
	}
	return 0;
}

int ts_is_stream_type_video(uint8_t stream_type) {
	return	stream_type == STREAM_TYPE_MPEG1_VIDEO ||
			stream_type == STREAM_TYPE_MPEG2_VIDEO ||
			stream_type == STREAM_TYPE_AVC_VIDEO   ||
			stream_type == STREAM_TYPE_AVS_VIDEO   ||
			stream_type == STREAM_TYPE_MPEG4_PART2_VIDEO;
}

// This is not enough! Must look at stream descriptors to be sure!!!
int ts_is_stream_type_ac3(uint8_t stream_type) {
	return	stream_type == STREAM_TYPE_DOLBY_DVB_AUDIO ||
			stream_type == STREAM_TYPE_DOLBY_ATSC_AUDIO;
}

int ts_is_stream_type_audio(uint8_t stream_type) {
	return	stream_type == STREAM_TYPE_MPEG1_AUDIO ||
			stream_type == STREAM_TYPE_MPEG2_AUDIO ||
			stream_type == STREAM_TYPE_ADTS_AUDIO  ||
			ts_is_stream_type_ac3(stream_type);
}

// ISO/IEC 13818-1 : 2000 (E) | Table 2-29 - Stream type assignments, Page 66 (48)
char *h222_stream_type_desc(uint8_t stream_type) {
	if (stream_type == 0 || (stream_type > 0x1c && stream_type < 0x7e))
		return "Reserved";
	switch (stream_type) {
		case 0x01: return "11172-2 video (MPEG-1)";
		case 0x02: return "H.262/13818-2 video (MPEG-2) or 11172-2 constrained video";
		case 0x03: return "11172-3 audio (MPEG-1)";
		case 0x04: return "13818-3 audio (MPEG-2)";
		case 0x05: return "H.222.0/13818-1  private sections";
		case 0x06: return "H.222.0/13818-1 PES private data";
		case 0x07: return "13522 MHEG";
		case 0x08: return "H.222.0/13818-1 Annex A - DSM CC";
		case 0x09: return "H.222.1";
		case 0x0A: return "13818-6 type A";
		case 0x0B: return "13818-6 type B";
		case 0x0C: return "13818-6 type C";
		case 0x0D: return "13818-6 type D";
		case 0x0E: return "H.222.0/13818-1 auxiliary";
		case 0x0F: return "13818-7 Audio with ADTS transport syntax";
		case 0x10: return "14496-2 Visual (MPEG-4 part 2 video)";
		case 0x11: return "14496-3 Audio with LATM transport syntax (14496-3/AMD 1)";
		case 0x12: return "14496-1 SL-packetized or FlexMux stream in PES packets";
		case 0x13: return "14496-1 SL-packetized or FlexMux stream in 14496 sections";
		case 0x14: return "ISO/IEC 13818-6 Synchronized Download Protocol";
		case 0x15: return "Metadata in PES packets";
		case 0x16: return "Metadata in metadata_sections";
		case 0x17: return "Metadata in 13818-6 Data Carousel";
		case 0x18: return "Metadata in 13818-6 Object Carousel";
		case 0x19: return "Metadata in 13818-6 Synchronized Download Protocol";
		case 0x1A: return "13818-11 MPEG-2 IPMP stream";
		case 0x1B: return "H.264/14496-10 video (MPEG-4/AVC)";
		case 0x42: return "AVS Video";
		case 0x7F: return "IPMP stream";
		default  : return "Unknown";
	}
}

// System start codes, ISO 13818-1, Table 2-18
// The function allocates memory which should be freed by the caller
char *h222_stream_id_desc(uint8_t stream_id) {
	uint8_t stream_number;
	char *text = NULL;
	switch (stream_id) {
		case 0xbc: return strdup("Program stream map"); break;
		case 0xbd: return strdup("Private stream 1"); break;
		case 0xbe: return strdup("Padding stream"); break;
		case 0xbf: return strdup("Private stream 2"); break;
		case 0xf0: return strdup("ECM stream"); break;
		case 0xf1: return strdup("EMM stream"); break;
		case 0xf2: return strdup("DSMCC stream"); break;
		case 0xf3: return strdup("13522 stream"); break;
		case 0xf4: return strdup("H.222 A stream"); break;
		case 0xf5: return strdup("H.222 B stream"); break;
		case 0xf6: return strdup("H.222 C stream"); break;
		case 0xf7: return strdup("H.222 D stream"); break;
		case 0xf8: return strdup("H.222 E stream"); break;
		case 0xf9: return strdup("Ancillary stream"); break;
		case 0xff: return strdup("Program stream directory"); break;
	}
	if (stream_id >= 0xc0 && stream_id <= 0xdf) {
		stream_number = stream_id & 0x1f;
		asprintf(&text, "Audio stream %d", stream_number);
	} else if (stream_id >= 0xe0 && stream_id <= 0xef) {
		stream_number = stream_id & 0x0f;
		asprintf(&text, "Video stream %d", stream_number);
	} else if (stream_id >= 0xfc && stream_id <= 0xfe) {
		asprintf(&text, "Reserved data stream");
	} else {
		asprintf(&text, "Unrecognised stream id 0x%02x", stream_id);
	}
	return text;
}

void pidmap_clear(pidmap_t *pm) {
	memset(pm, 0, sizeof(pidmap_t));
}

void pidmap_set(pidmap_t *pm, uint16_t pid) {
	if (pid < sizeof(pidmap_t))
		(*pm)[pid] = 1;
}

void pidmap_set_val(pidmap_t *pm, uint16_t pid, uint8_t val) {
	if (pid < sizeof(pidmap_t))
		(*pm)[pid] = val;
}

int pidmap_get(pidmap_t *pm, uint16_t pid) {
	if (pid < sizeof(pidmap_t))
		return (*pm)[pid];
	return 0;
}
