/*
 * MPEGTS PES functions
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
#include <inttypes.h>

#include "tsfuncs.h"

#define pes_data_size_buffer (1024)
#define pes_max_data_size    (1024*1024)

struct ts_pes *ts_pes_alloc() {
	struct ts_pes *pes = calloc(1, sizeof(struct ts_pes));
	pes->pes_data_size = pes_data_size_buffer;
	pes->pes_data = malloc(pes->pes_data_size);
	memset(pes->pes_data, 0x33, pes->pes_data_size);
	return pes;
}

void ts_pes_free(struct ts_pes **ppes) {
	struct ts_pes *pes = *ppes;
	if (pes) {
		FREE(pes->pes_data);
		FREE(*ppes);
	}
}

void ts_pes_clear(struct ts_pes *pes) {
	if (!pes)
		return;
	// save
	uint8_t *pes_data = pes->pes_data;
	uint32_t pes_data_size = pes->pes_data_size;
	// clear
	memset(pes_data, 0x33, pes_data_size);
	memset(pes, 0, sizeof(struct ts_pes));
	// restore
	pes->pes_data = pes_data;
	pes->pes_data_size = pes_data_size;
}

static void ts_pes_add_payload_to_pes_data(struct ts_pes *pes, uint8_t *payload, uint8_t payload_size) {
	uint32_t new_data_pos = pes->pes_data_pos + payload_size;
	// Check if there is enough space in pes->pes_data
	if (new_data_pos > pes->pes_data_size) {
		int old_data_size = pes->pes_data_size;
		pes->pes_data_size *= 2;
//		ts_LOGf("realloc to %d from %d\n", old_data_size, pes->pes_data_size);
		pes->pes_data = realloc(pes->pes_data, pes->pes_data_size);
		// Poison
		memset(pes->pes_data + pes->pes_data_pos, 0x34, pes->pes_data_size - old_data_size);
	}
	memcpy(pes->pes_data + pes->pes_data_pos, payload, payload_size);
	pes->pes_data_pos += payload_size;
	if (pes->pes_packet_len) {
		// If packet size is known, mark the packet as initialized
		if (pes->pes_data_pos >= pes->pes_packet_len) {
			pes->pes_data_initialized = 1;
		}
	}
}

// This function is used to determine the last PES was finished before current ts_packet
int ts_pes_is_finished(struct ts_pes *pes, uint8_t *ts_packet) {
	if (pes->pes_data_initialized)
		return 1;

	// Time to mark PES as initialized since current packet has PUSI
	if (ts_packet_is_pusi(ts_packet) && pes->real_pes_packet_len == -1) {
		pes->real_pes_packet_len = pes->pes_data_pos;
		pes->pes_data_initialized = 1;
//		ts_LOGf("packet finished, len:%d\n", pes->real_pes_packet_len);
		if (!ts_pes_parse(pes)) {
			ts_LOGf("error parsing!\n");
			ts_pes_clear(pes);
			return 0;
		}
//		ts_LOGf("parsed OK!\n");
		return 1;
	}

	return 0;
}

// Fill is_video, is_audio, is_ac3, etc..flags in PES packet
void ts_pes_fill_type(struct ts_pes *pes, struct ts_pmt *pmt, uint16_t pid) {
	int i;
	pes->is_audio = IS_AUDIO_STREAM_ID(pes->stream_id);
	pes->is_video = IS_VIDEO_STREAM_ID(pes->stream_id);
	if (pmt && pmt->initialized) {
		for (i=0;i<pmt->streams_num;i++) {
			struct ts_pmt_stream *stream = pmt->streams[i];
			if (stream->pid != pid)
				continue;

			pes->is_audio       = pes->is_audio && ts_is_stream_type_audio(stream->stream_type);
			pes->is_audio_mpeg1 = pes->is_audio && stream->stream_type == STREAM_TYPE_MPEG1_AUDIO;
			pes->is_audio_mpeg2 = pes->is_audio && stream->stream_type == STREAM_TYPE_MPEG2_AUDIO;
			// To determine if type is AC3 we need to check descriptors
			//pes->is_audio_ac3   = ts_is_stream_type_ac3(stream->stream_type); // We need to also check descriptors because this is not ENOUGH!
			pes->is_audio_aac   = pes->is_audio && stream->stream_type == STREAM_TYPE_ADTS_AUDIO;

			pes->is_video       = pes->is_video && ts_is_stream_type_video(stream->stream_type);
			pes->is_video_mpeg1 = pes->is_video && stream->stream_type == STREAM_TYPE_MPEG1_VIDEO;
			pes->is_video_mpeg2 = pes->is_video && stream->stream_type == STREAM_TYPE_MPEG2_VIDEO;
			pes->is_video_mpeg4 = pes->is_video && stream->stream_type == STREAM_TYPE_MPEG4_PART2_VIDEO;
			pes->is_video_h264  = pes->is_video && stream->stream_type == STREAM_TYPE_AVC_VIDEO;
			pes->is_video_avs   = pes->is_video && stream->stream_type == STREAM_TYPE_AVS_VIDEO;

			if (!stream->ES_info)
				break;

			// Parse stream descriptors to gather more information
			uint8_t tag, this_length;
			uint8_t *data = stream->ES_info;
			int data_len = stream->ES_info_size;
			while (data_len >= 2) {
				tag         = data[0];
				this_length = data[1];
				data       += 2;
				data_len   -= 2;
				if (this_length > data_len) {
					// Not much we can do! Give up.
					ts_LOGf("!!! Descriptor 0x%02x says length %d, but only %d bytes left\n", tag, this_length, data_len);
					break;
				}
				switch (tag) {
					case  3: { // Audio stream descriptor
						struct {
							uint8_t free_format_flag : 1,
							        ID               : 1,
							        layer            : 2,
							        vbr_flag         : 1,
							        reserved         : 3;
						} as;
						if (this_length >= 1) {
							as.free_format_flag = bit_on(data[0], bit_8);
							as.ID               = bit_on(data[0], bit_7);
							as.layer            = (data[0] &~ 0xcf) >> 4;	// 11xx1111
							as.vbr_flag         = bit_on(data[0], bit_4);
							as.reserved         = data[0] &~ 0xf0;			// 1111xxxx
							if (as.ID) {
								pes->is_audio = 1;
								pes->is_audio_mpeg1l1 = as.layer == 3;
								pes->is_audio_mpeg1l2 = as.layer == 2;
								pes->is_audio_mpeg1l3 = as.layer == 1;
							}
						}
						break;
					}
					case  5: { // Registration descriptor
						if (this_length == 4) {
							uint32_t reg_ident  = data[0] << 24;
							reg_ident          |= data[1] << 16;
							reg_ident          |= data[2] << 8;
							reg_ident          |= data[3];
							// See http://smpte-ra.org/mpegreg/mpegreg.html
							if (reg_ident == 0x41432D33) { // AC-3
								pes->is_audio = 1;
								pes->is_audio_ac3 = 1;
								//ts_LOGf("reg_desc says AC-3\n");
							}
							if (reg_ident == 0x44545331 || reg_ident == 0x44545332 || reg_ident == 0x44545333) { // DTS1, DTS2, DTS2
								pes->is_audio = 1;
								pes->is_audio_dts = 1;
								//ts_LOGf("reg_desc says DTSx\n");
							}
						}
						break;
					}
					case 0x6a: { // AC-3 descriptor
						//ts_LOGf("ac3_desc found\n");
						pes->is_audio = 1;
						pes->is_audio_ac3 = 1;
						break;
					}
					case 0x7b: { // DTS descriptor
						//ts_LOGf("ac3_desc found\n");
						pes->is_audio = 1;
						pes->is_audio_dts = 1;
						break;
					}
					case 0x56: { // teletext
						//ts_LOGf("teletext_desc found\n");
						pes->is_teletext = 1;
						break;
					}
					case 0x59: { // Subtitling descriptor
						//ts_LOGf("subtitle_desc found\n");
						pes->is_subtitle = 1;
						break;
					}
				} // switch
				data_len -= this_length;
				data += this_length;
			} // while
		}
	}
}

struct ts_pes *ts_pes_push_packet(struct ts_pes *pes, uint8_t *ts_packet, struct ts_pmt *pmt, uint16_t pid) {
	struct ts_header ts_header;
	memset(&ts_header, 0, sizeof(struct ts_header));

	uint8_t *payload = ts_packet_header_parse(ts_packet, &ts_header);
	uint8_t payload_size = ts_header.payload_size;

	if (!payload || !payload_size)
		goto OUT;

	if (ts_header.pusi) {
		// Received PUSI packet before PES END, clear the table to start gathering new one
		if (pes->ts_header.pusi)
			ts_pes_clear(pes);
		uint8_t stream_id = 0;
		int pes_packet_len = 0;
		if (payload[0] == 0x00 && payload[1] == 0x00 && payload[2] == 0x01) { // pes_start_code_prefix
			pes->ts_header = ts_header;
			stream_id = payload[3];
			pes_packet_len = (payload[4] << 8) | payload[5];
//			ts_LOGf("NEW PES. Stream_id=%02x pes_length=%d\n", stream_id, pes_packet_len);
			if (pes_packet_len == 0 && pes->real_pes_packet_len == -1) {
				ts_LOGf("!!! ERROR: New pes with pes_packed_len == 0, started before the old was finished\n");
				goto ERROR;
			}
			if (pes_packet_len > 0) {
				pes->real_pes_packet_len = pes_packet_len;
			} else {
				pes->real_pes_packet_len = -1;
			}
			pes->stream_id = stream_id;
			pes->pes_packet_len = pes_packet_len;
			ts_pes_fill_type(pes, pmt, pid);
		} else {
			ts_LOGf("!!! PES_start_code_prefix not found. Expected 0x00 0x00 0x01 but get 0x%02x 0x%02x 0x%02x! PID %03x\n",
				payload[0], payload[1], payload[2], ts_header.pid);
			goto ERROR;
		}
	}

	if (pes->stream_id) {
		ts_pes_add_payload_to_pes_data(pes, payload, payload_size);
//		ts_LOGf("Payload %d added, tot_size: %d\n", payload_size, pes->pes_data_pos);
		if (pes->pes_data_pos > pes_max_data_size) {
			ts_LOGf("PES Payload size %d exceeded pes_data_max_size: %d pid: %03x\n",
				pes->pes_data_pos, pes_max_data_size, pes->ts_header.pid);
			goto ERROR;
		}
	}

	if (pes->pes_data_initialized) {
		if (!ts_pes_parse(pes))
			goto ERROR;
	}

OUT:
	return pes;

ERROR:
	ts_pes_clear(pes);
	return pes;
}

int ts_pes_parse(struct ts_pes *pes) {
	uint8_t *data = pes->pes_data;

	if (!pes->pes_data_initialized) {
		ts_LOGf("!!! pes_data_initialized not true\n");
		return 0;
	}

	if (pes->real_pes_packet_len == -1) {
		ts_LOGf("!!! real_pes_data_len is == -1\n");
		return 0;
	}

	if (pes->pes_data_size < 6) {
		ts_LOGf("!!! PES data_size < 6\n");
		return 0;
	}

	if (!(data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x01)) { // pes_start_code_prefix
		ts_LOGf("!!! PES_start_code_prefix error! Expected 0x00 0x00 0x01 but get 0x%02x 0x%02x 0x%02x! PID %03x\n",
			data[0], data[1], data[2], pes->ts_header.pid);
		return 0;
	}

	pes->stream_id      = data[3];						// 8 bits
	pes->pes_packet_len = (data[4] << 8) | data[5];		// 16 bits
	int dpos = 6;

	if (!IS_PES_STREAM_SUPPORTED(pes->stream_id)) {
		// We do not handle this streams...
		ts_LOGf("!!! Unsupported stream, ignore! (%02x) PID %03x\n", pes->stream_id, pes->ts_header.pid);
		return 0;
	}

	dpos = 6;
	if ((data[dpos] &~ 0x3f) != 0x80) {		// 10xxxxxx (first two bits must be 10 eq 0x80
		ts_LOGf("!!! No 10 bits at PES start, expected 0x80 get 0x%02x, org: %02x! PID %03x\n",
			data[dpos] &~ 0x3f, data[dpos], pes->ts_header.pid);
		return 0;
	}
	// data[dpos] = 0xff;
	pes->flags_1			= data[dpos];
	pes->scrambling			= (data[dpos] &~ 0xCF) >> 4;
	pes->priority			= bit_on(data[dpos], bit_4);
	pes->data_alignment		= bit_on(data[dpos], bit_3);
	pes->copyright			= bit_on(data[dpos], bit_2);
	pes->original_or_copy	= bit_on(data[dpos], bit_1);

	dpos = 7;
	// data[dpos] = 0xff;
	pes->flags_2			= data[dpos];
	pes->PTS_flag			= bit_on(data[dpos], bit_8);
	pes->DTS_flag			= bit_on(data[dpos], bit_7);
	pes->ESCR_flag			= bit_on(data[dpos], bit_6);
	pes->ES_rate_flag		= bit_on(data[dpos], bit_5);
	pes->trick_mode_flag	= bit_on(data[dpos], bit_4);
	pes->add_copy_info_flag	= bit_on(data[dpos], bit_3);
	pes->pes_crc_flag		= bit_on(data[dpos], bit_2);
	pes->pes_extension_flag	= bit_on(data[dpos], bit_1);
	dpos = 8;

	pes->pes_header_len		= data[dpos];
	dpos = 9;

	if (!pes->PTS_flag && pes->DTS_flag)	// Invalid, can't have only DTS flag
		return 0;

	if (pes->PTS_flag && !pes->DTS_flag) {
		ts_decode_pts_dts(&data[dpos], &pes->PTS);
		dpos += 5;
		pes->have_pts = 1;
	}

	if (pes->PTS_flag && pes->DTS_flag) {
		ts_decode_pts_dts(&data[dpos], &pes->PTS);
		pes->have_pts = 1;
		dpos += 5;

		ts_decode_pts_dts(&data[dpos], &pes->DTS);
		pes->have_dts = 1;
		dpos += 5;
	}

	if (pes->ESCR_flag) {
		uint64_t ESCR_base;
		uint32_t ESCR_extn;
		ESCR_base = (data[dpos+4] >>  3) |
					(data[dpos+3] <<  5) |
					(data[dpos+2] << 13) |
					(data[dpos+1] << 20) |
				((((uint64_t)data[dpos]) & 0x03) << 28) |
				((((uint64_t)data[dpos]) & 0x38) << 27);
		ESCR_extn = (data[dpos+5] >> 1) | (data[dpos+4] << 7);
		pes->ESCR = ESCR_base * 300 + ESCR_extn;
		dpos += 6;
	}

	if (pes->ES_rate_flag) {
		// Not decoded...
		dpos += 3;
	}

	if (pes->trick_mode_flag) {
		// Not decoded...
		dpos += 1;
	}

	if (pes->add_copy_info_flag) {
		// Not decoded...
		dpos += 1;
	}

	if (pes->pes_crc_flag) {
		// Not decoded...
		dpos += 2;
	}

	if (pes->pes_extension_flag) {
		// data[dpos] = 0xff;
		pes->flags_3							= data[dpos];
		pes->pes_private_data_flag				= bit_on(data[dpos], bit_8);	// 1xxxxxxx
		pes->pack_header_field_flag				= bit_on(data[dpos], bit_7);	// x1xxxxxx
		pes->program_packet_seq_counter_flag	= bit_on(data[dpos], bit_6);	// xx1xxxxx
		pes->p_std_buffer_flag					= bit_on(data[dpos], bit_5);	// xxx1xxxx
		pes->reserved2							= (data[dpos] &~ 0x0e) >> 1;	// xxxx111x
		pes->pes_extension2_flag				= bit_on(data[dpos], bit_1);	// xxxxxxx1

		if (pes->pes_private_data_flag) {
			pes->pes_private_data_1 = (pes->pes_private_data_1 << 8) | data[dpos+7];
			pes->pes_private_data_1 = (pes->pes_private_data_1 << 8) | data[dpos+6];
			pes->pes_private_data_1 = (pes->pes_private_data_1 << 8) | data[dpos+5];
			pes->pes_private_data_1 = (pes->pes_private_data_1 << 8) | data[dpos+4];
			pes->pes_private_data_1 = (pes->pes_private_data_1 << 8) | data[dpos+3];
			pes->pes_private_data_1 = (pes->pes_private_data_1 << 8) | data[dpos+2];
			pes->pes_private_data_1 = (pes->pes_private_data_1 << 8) | data[dpos+1];
			pes->pes_private_data_1 = (pes->pes_private_data_1 << 8) | data[dpos+0];
			dpos += 8;
			pes->pes_private_data_2 = (pes->pes_private_data_2 << 8) | data[dpos+7];
			pes->pes_private_data_2 = (pes->pes_private_data_2 << 8) | data[dpos+6];
			pes->pes_private_data_2 = (pes->pes_private_data_2 << 8) | data[dpos+5];
			pes->pes_private_data_2 = (pes->pes_private_data_2 << 8) | data[dpos+4];
			pes->pes_private_data_2 = (pes->pes_private_data_2 << 8) | data[dpos+3];
			pes->pes_private_data_2 = (pes->pes_private_data_2 << 8) | data[dpos+2];
			pes->pes_private_data_2 = (pes->pes_private_data_2 << 8) | data[dpos+1];
			pes->pes_private_data_2 = (pes->pes_private_data_2 << 8) | data[dpos+0];
			dpos += 8;
		}

		if (pes->pack_header_field_flag) {
			pes->pack_header_len = data[dpos];
			pes->pack_header = pes->pes_data + 1 + dpos;	// Pointer into *pes_data
			dpos += 1 + pes->pack_header_len;
		}

		if (pes->program_packet_seq_counter_flag) {
			// Not decoded
			dpos += 2;
		}

		if (pes->p_std_buffer_flag) {
			if ((data[dpos] &~ 0x3f) != 0x40) {		// 01xxxxxx (first two bits must be 01 eq 0x40
				return 0;
			}
			// Not decoded...
			dpos += 2;
		}

		if (pes->pes_extension2_flag) {
			pes->pes_extension_field_len = data[dpos] &~ 0x80;		// x1111111
			pes->pes_extension2 = pes->pes_data + 1 + dpos;	// Pointer into *pes_data
			dpos += 1 + pes->pes_extension_field_len;
		}
	}

	int maxstuffing = 32; // Maximum 32 stuffing bytes
	// Skip stuffing bytes (8 is minimum PES header len)
	while ((--maxstuffing > 0) && (dpos-8 <= pes->pes_header_len) && (data[dpos] == 0xff)) {
		dpos++;
	}

	pes->es_data      = pes->pes_data + dpos;
	pes->es_data_size = pes->real_pes_packet_len - dpos;
	pes->initialized  = 1;

	if (pes->data_alignment)
		ts_pes_es_parse(pes);

	return 1;
}

#define min(a,b) ((a < b) ? a : b)

void ts_pes_dump(struct ts_pes *pes) {
	if (!pes->initialized)
		return;
	ts_LOGf("PES packet\n");
	ts_packet_header_dump(&pes->ts_header);
	ts_LOGf("  * Content    : %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
		pes->is_audio			? "Audio "		: "",
		pes->is_audio_mpeg1		? "MP1 "		: "",
		pes->is_audio_mpeg1l1	? "Layer1 "		: "",
		pes->is_audio_mpeg1l2	? "Layer2 "		: "",
		pes->is_audio_mpeg1l3	? "Layer3 "		: "",
		pes->is_audio_mpeg2		? "MP2 "		: "",
		pes->is_audio_aac		? "AAC "		: "",
		pes->is_audio_ac3		? "AC3 "		: "",
		pes->is_audio_dts		? "DTS "		: "",
		pes->is_video			? "Video "		: "",
		pes->is_video_mpeg1		? "MPEG1 "		: "",
		pes->is_video_mpeg2		? "MPEG2 "		: "",
		pes->is_video_mpeg4		? "MPEG4p2 "	: "",
		pes->is_video_h264		? "H.264 "		: "",
		pes->is_video_avs		? "AVS "		: "",
		pes->is_teletext		? "Teletext "	: "",
		pes->is_subtitle		? "Subtitles "	: ""
	);
	char *stream_id_text = h222_stream_id_desc(pes->stream_id);
	ts_LOGf("  * Stream_id  : 0x%02x (%d) %s\n", pes->stream_id, pes->stream_id, stream_id_text);
	FREE(stream_id_text);
	ts_LOGf("  * Packet len : 0x%04x (%d) real_len: %d %s\n",
		pes->pes_packet_len, pes->pes_packet_len, pes->real_pes_packet_len-pes->pes_header_len-6, pes->is_video ? "VIDEO" : (pes->is_audio ? "AUDIO" : "OTHER"));
	ts_LOGf("  * Header len : %d\n", pes->pes_header_len);
	ts_LOGf("  * Flags 1    : 0x%02x | scrambling=%d priority=%d data_align=%d copyright=%d org_or_copy=%d\n",
		pes->flags_1,
		pes->scrambling,
		pes->priority,
		pes->data_alignment,
		pes->copyright,
		pes->original_or_copy
	);
	ts_LOGf("  * Flags 2    : 0x%02x | %s%s%s%s%s%s%s%s\n",
		pes->flags_2,
		pes->PTS_flag			? "PTS "		: "",
		pes->DTS_flag			? "DTS "		: "",
		pes->ESCR_flag			? "ESCR "		: "",
		pes->ES_rate_flag		? "ES_rate "	: "",
		pes->trick_mode_flag	? "Trick_mode "	: "",
		pes->add_copy_info_flag	? "Add_copy "	: "",
		pes->pes_crc_flag		? "PES_CRC "	: "",
		pes->pes_extension_flag	? "PES_Ext "	: ""
	);
	if (pes->PTS_flag && pes->have_pts)
		ts_LOGf("  * PTS        : %"PRIu64" (%"PRIu64" ms) (%"PRIu64".%04"PRIu64" sec)\n",
			pes->PTS,
			pes->PTS / 90,
			pes->PTS / 90000, (pes->PTS % 90000) / 9
		);
	if (pes->DTS_flag && pes->have_dts)
		ts_LOGf("  * DTS        : %"PRIu64" (%"PRIu64" ms) (%"PRIu64".%04"PRIu64" sec)\n",
			pes->DTS,
			pes->DTS / 90,
			pes->DTS / 90000, (pes->DTS % 90000) / 9
		);
	if (pes->ESCR_flag)
		ts_LOGf("  * ESCR       : %"PRIu64"\n", pes->ESCR);
	if (pes->ES_rate_flag)
		ts_LOGf("  * ES_rate    : %lu\n" , (unsigned long)pes->ES_rate * 50); // In units of 50 bytes

	if (pes->pes_extension_flag) {
		ts_LOGf("  * Ext flags  : 0x%02x | %s%s%s%s%s\n",
			pes->flags_3,
			pes->pes_private_data_flag				? "Private_data_flag "	: "",
			pes->pack_header_field_flag				? "Pack_header_flag "	: "",
			pes->program_packet_seq_counter_flag	? "Prg_pack_seq_flag "	: "",
			pes->p_std_buffer_flag					? "P-STD_buf_flag "		: "",
			pes->pes_extension2_flag				? "Ext2_flag "			: ""
		);
	}

	if (pes->pes_private_data_flag) {
		ts_LOGf("  * PES priv_data : 0x%08llx%08llx\n",
			(unsigned long long)pes->pes_private_data_1,
			(unsigned long long)pes->pes_private_data_2);
	}

	if (pes->pack_header_field_flag) {
		ts_LOGf("  * Pack_header ... \n");
	}

	if (pes->program_packet_seq_counter_flag) {
		ts_LOGf("  * Prg_seq_cnt : %d\n", pes->program_packet_seq_counter);
	}

	ts_LOGf("  - Private    : pes_data_pos:%u es_data_size:%u\n",
		pes->pes_data_pos,
		pes->es_data_size
	);

	char *phex = ts_hex_dump(pes->pes_data, min(32, pes->pes_data_pos), 0);
	ts_LOGf("  - PES dump   : %s...\n", phex);
	free(phex);

	if (pes->es_data) {
		char *hex = ts_hex_dump(pes->es_data, min(32, pes->es_data_size), 0);
		ts_LOGf("  - ES dump    : %s...\n", hex);
		free(hex);
	}
}
