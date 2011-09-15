/*
 * PES elementary stream functions
 * Copyright (C) 2010-2011 Unix Solutions Ltd.
 *
 * Released under MIT license.
 * See LICENSE-MIT.txt for license terms.
 */
#include <netdb.h>
#include <string.h>

#include "tsfuncs.h"

int ts_pes_es_mpeg_audio_header_parse(struct mpeg_audio_header *mpghdr, uint8_t *data, int datasz) {
	if (datasz < 4)
		return 0;

	uint8_t d1 = data[0];
	uint8_t d2 = data[1];
	uint8_t d3 = data[2];
	uint8_t d4 = data[3];

	mpghdr->syncword		= (int)d1 << 4 | (d2 >> 4);			// 12 bits
	mpghdr->ID				= bit_on(d2, bit_4);				// 1 bit
	mpghdr->layer			= (d2 &~ 0xf9) >> 1;				// 2 bits
	mpghdr->protection_bit	= bit_on(d2, bit_1);				// 1 bit

	mpghdr->bitrate_index	= d3 >> 4;							// 4 bits
	mpghdr->sampl_freq		= (d3 &~ 0xf3) >> 2;				// 2 bits
	mpghdr->padding_bit		= bit_on(d3, bit_2);				// 1 bit
	mpghdr->private_bit		= bit_on(d3, bit_1);				// 1 bit

	mpghdr->mode			= d4 >> 6;							// 2 bits
	mpghdr->mode_extension	= (d4 &~ 0xcf) >> 4;				// 2 bits
	mpghdr->copyright		= bit_on(d4, bit_4);				// 1 bit
	mpghdr->org_home		= bit_on(d4, bit_3);				// 1 bit
	mpghdr->emphasis		= d4 &~ 0xfc;						// 2 bits

	if (mpghdr->syncword != 0xfff) {
		ts_LOGf("!!! Error parsing mpeg audio header! Syncword should be 0xfff but it is 0x%03x!\n", mpghdr->syncword);
		return 0;
	} else {
		mpghdr->initialized = 1;
		return 1;
	}
}

void ts_pes_es_mpeg_audio_header_dump(struct mpeg_audio_header *mpghdr) {
	if (!mpghdr->initialized)
		return;
	// See ISO-11172-3 for more info
	ts_LOGf("  - ES analyze audio frame\n");
	ts_LOGf("    - Syncword      : %x\n", mpghdr->syncword);
	if (mpghdr->syncword != 0xfff) {
		ts_LOGf("!!! ERROR: MPEG audo Syncword should be 0xfff!\n");
		return;
	}
	ts_LOGf("    - ID            : %d (%s)\n", mpghdr->ID, mpghdr->ID ? "MPEG Audio" : "Other");
	ts_LOGf("    - layer         : %d (%s)\n", mpghdr->layer,
		mpghdr->layer == 0 ? "reserved" :
		mpghdr->layer == 1 ? "Layer III" :
		mpghdr->layer == 2 ? "Layer II" :
		mpghdr->layer == 3 ? "Layer I" : "reserved"
	);
	ts_LOGf("    - protection_bit: %x\n", mpghdr->protection_bit);
	int br = 0;
	if (mpghdr->layer > 0 && mpghdr->layer < 4) {
		int bitrate_index_table[4][16] = {
			[3] = { 0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, -1},	// Layer 1
			[2] = { 0, 32, 48, 56,  64,  80,  96, 112, 128, 160, 192, 224, 256, 320, 384, -1},	// Layer 2
			[1] = { 0, 32, 40, 48,  56,  64,  80,  96, 112, 128, 160, 192, 224, 256, 320, -1}	// Layer 3
		};
		br = bitrate_index_table[mpghdr->layer][mpghdr->bitrate_index];
	}
	ts_LOGf("    - bitrate_index : %d (%d kBit/s)\n", mpghdr->bitrate_index, br);
	ts_LOGf("    - sampl_freq    : %d (%s)\n", mpghdr->sampl_freq,
		mpghdr->sampl_freq == 0 ? "44.1 kHz" :
		mpghdr->sampl_freq == 1 ? "48 kHz" :
		mpghdr->sampl_freq == 2 ? "32 kHz" : "reserved"
	);
	ts_LOGf("    - padding_bit   : %d\n", mpghdr->padding_bit);
	ts_LOGf("    - private_bit   : %d\n", mpghdr->private_bit);
	ts_LOGf("    - mode          : %d (%s)\n", mpghdr->mode,
		mpghdr->mode == 0 ? "stereo" :
		mpghdr->mode == 1 ? "join_stereo" :
		mpghdr->mode == 2 ? "dual_channel" : "single_channel"
	);
	ts_LOGf("    - mode_extension: %x\n", mpghdr->mode_extension);
	ts_LOGf("    - copyright     : %x\n", mpghdr->copyright);
	ts_LOGf("    - org_home      : %x\n", mpghdr->org_home);
	ts_LOGf("    - emphasis      : %d (%s)\n", mpghdr->emphasis,
		mpghdr->emphasis == 0 ? "none" :
		mpghdr->emphasis == 1 ? "50/15 microseconds" :
		mpghdr->emphasis == 2 ? "reserved" : "CCITT J.17"
	);
}

void ts_pes_es_parse(struct ts_pes *pes) {
	if (!pes->es_data)
		return;

	// Parse MPEG audio packet header
	if ((pes->is_audio_mpeg1 || pes->is_audio_mpeg2) && pes->es_data_size > 4) {
		struct mpeg_audio_header mpghdr;
		memset(&mpghdr, 0, sizeof(struct mpeg_audio_header));
		ts_pes_es_mpeg_audio_header_parse(&mpghdr, pes->es_data, pes->es_data_size);
		if (mpghdr.initialized) {
			pes->mpeg_audio_header = mpghdr;
			if (mpghdr.ID) {
				switch (mpghdr.layer) {
					case 3: pes->is_audio_mpeg1l1 = 1; break;
					case 2: pes->is_audio_mpeg1l2 = 1; break;
					case 1: pes->is_audio_mpeg1l3 = 1; break;
				}
			}
		}
	}

	// Look into elementary streams to detect AC3/DTS
	if (pes->is_audio_ac3) {
		if (pes->real_pes_packet_len >= 2 && (pes->es_data[0] == 0x0B && pes->es_data[1] == 0x77)) {
			pes->is_audio     = 1;
			pes->is_audio_ac3 = 1;
			pes->is_audio_dts = 0;
		}
		if (pes->real_pes_packet_len >= 4 && (pes->es_data[0] == 0x7f && pes->es_data[1] == 0xfe && pes->es_data[2] == 0x80 && pes->es_data[3] == 0x01)) {
			pes->is_audio     = 1;
			pes->is_audio_ac3 = 0;
			pes->is_audio_dts = 1;
		}
	}
}

void ts_pes_es_dump(struct ts_pes *pes) {
	if (pes->is_audio && pes->mpeg_audio_header.initialized) {
		ts_pes_es_mpeg_audio_header_dump(&pes->mpeg_audio_header);
	}
}
