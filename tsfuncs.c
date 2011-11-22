/*
 * MPEGTS functions
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
#include <sys/time.h>

#include "tsfuncs.h"

void ts_packet_init_null(uint8_t *ts_packet) {
	memset(ts_packet, 0xff, TS_PACKET_SIZE);
	ts_packet[0] = 0x47;
	ts_packet[1] = 0x1f;
	ts_packet[2] = 0xff;
	ts_packet[3] = 0x00;
}

void ts_packet_set_scrambled(uint8_t *ts_packet, enum ts_scrambled_type stype) {
	ts_packet_set_not_scrambled(ts_packet);
	if (stype == scrambled_with_even_key)
		ts_packet[3] |= 2 << 6;
	if (stype == scrambled_with_odd_key)
		ts_packet[3] |= 3 << 6;
	if (stype == scrambled_reserved)
		ts_packet[3] |= 1 << 6;
}

uint8_t ts_packet_get_payload_offset(uint8_t *ts_packet) {
	if (ts_packet[0] != 0x47)
		return 0;

	uint8_t adapt_field   = (ts_packet[3] &~ 0xDF) >> 5; // 11x11111
	uint8_t payload_field = (ts_packet[3] &~ 0xEF) >> 4; // 111x1111

	if (!adapt_field && !payload_field) // Not allowed
		return 0;

	if (adapt_field) {
		uint8_t adapt_len = ts_packet[4];
		if (payload_field && adapt_len > 182) // Validity checks
			return 0;
		if (!payload_field && adapt_len > 183)
			return 0;
		if (adapt_len + 4 > 188) // adaptation field takes the whole packet
			return 0;
		return 4 + 1 + adapt_len; // ts header + adapt_field_len_byte + adapt_field_len
	} else {
		return 4; // No adaptation, data starts directly after TS header
	}
}

void ts_decode_pts_dts(uint8_t *data, uint64_t *value) {
	uint64_t pts1 = ((unsigned int)data[0] & 0x0E) >> 1;
	uint64_t pts2 = ((unsigned int)data[1] << 7) | (((unsigned int)data[2] & 0xFE) >> 1);
	uint64_t pts3 = ((unsigned int)data[3] << 7) | (((unsigned int)data[4] & 0xFE) >> 1);
	*value = (pts1 << 30) | (pts2 << 15) | pts3;
}

/*
 * guard 2 == pts
 * guard 3 == pts before dts
 * guard 1 == dts
 */
void ts_encode_pts_dts(uint8_t *data, int guard, uint64_t value) {
	#define MAX_PTS_VALUE 0x1FFFFFFFFLL
	while (value > MAX_PTS_VALUE)
		value -= MAX_PTS_VALUE;

	unsigned int pts1 = (unsigned int)((value >> 30) & 0x07);
	unsigned int pts2 = (unsigned int)((value >> 15) & 0x7FFF);
	unsigned int pts3 = (unsigned int)( value        & 0x7FFF);

	data[0] =  (guard << 4) | (pts1 << 1) | 0x01;
	data[1] =  (pts2 & 0x7F80) >> 7;
	data[2] = ((pts2 & 0x007F) << 1) | 0x01;
	data[3] =  (pts3 & 0x7F80) >> 7;
	data[4] = ((pts3 & 0x007F) << 1) | 0x01;
}

// Return 0 on failure
// Return payload_ofs on success
int ts_packet_has_pes(uint8_t *ts_packet, uint16_t *pes_packet_len) {
	uint8_t payload_ofs;
	uint8_t *payload;

	if (!ts_packet_is_pusi(ts_packet))
		goto ERR;

	payload_ofs = ts_packet_get_payload_offset(ts_packet);
	if (!payload_ofs)
		goto ERR;

	if (payload_ofs + 6 + 2 >= 188) // 6 bytes pes header, 2 bytes pes flags
		goto ERR;

	payload = ts_packet + payload_ofs;
	if (payload[0] == 0x00 && payload[1] == 0x00 && payload[2] == 0x01) { // pes_start_code_prefix
		uint8_t stream_id  = payload[3];
		if (pes_packet_len)
			*pes_packet_len = (payload[4] << 8) | payload[5];
		// We do not handle this streams...
		if (!IS_PES_STREAM_SUPPORTED(stream_id))
			goto ERR;
		return payload_ofs;
	}

ERR:
	return 0;
}

int ts_packet_has_pts_dts(uint8_t *ts_packet, uint64_t *pts, uint64_t *dts) {
	*pts = NO_PTS;
	*dts = NO_DTS;

	uint8_t payload_ofs = ts_packet_has_pes(ts_packet, NULL);
	if (!payload_ofs)
		goto ERR;

	uint8_t *data = ts_packet + payload_ofs;
	uint8_t *data_end = ts_packet + 188;
	if ((data[6] &~ 0x3f) != 0x80) // 10xxxxxx (first two bits must be 10 eq 0x80
		goto ERR;

	if (data + 7 >= data_end) goto ERR;
	uint8_t pts_flag = bit_on(data[7], bit_8); // PES flags 2
	uint8_t dts_flag = bit_on(data[7], bit_7); // PES flags 2

	if (!pts_flag && dts_flag)	// Invalid, can't have only DTS flag
		return 0;

	if (pts_flag && !dts_flag) {
		if (data + 14 >= data_end) goto ERR;
		ts_decode_pts_dts(&data[9], pts);
	} else if (pts_flag && dts_flag) {
		if (data + 19 >= data_end) goto ERR;
		ts_decode_pts_dts(&data[9], pts);
		ts_decode_pts_dts(&data[14], dts);
	}
	return 1;

ERR:
	return 0;
}

void ts_packet_change_pts(uint8_t *ts_packet, uint64_t pts) {
	uint8_t payload_offset = ts_packet_get_payload_offset(ts_packet);
	if (!payload_offset)
		return;
	uint8_t *data = ts_packet + payload_offset;
	ts_encode_pts_dts(&data[9], 2, pts);
}

void ts_packet_change_pts_dts(uint8_t *ts_packet, uint64_t pts, uint64_t dts) {
	uint8_t payload_offset = ts_packet_get_payload_offset(ts_packet);
	if (!payload_offset)
		return;
	uint8_t *data = ts_packet + payload_offset;
	ts_encode_pts_dts(&data[9],  3, pts);
	ts_encode_pts_dts(&data[14], 1, dts);
}


int ts_packet_has_pcr(uint8_t *ts_packet) {
	if (ts_packet[0] == 0x47) { // TS packet
		if (bit_on(ts_packet[3], bit_6)) { // Packet have adaptation field
			if (ts_packet[4] > 6) { // Adaptation field length is > 6
				if (bit_on(ts_packet[5], bit_5)) { // The is PCR field
					return 1;
				} else {
//					ts_LOGf("!no PCR field\n");
				}
			} else {
//				ts_LOGf("!not enough adaptation len (%d), need at least 7\n", ts_packet[4]);
			}
		} else {
//			ts_LOGf("!no adaptation field\n");
		}
	} else {
//		ts_LOGf("!no ts packet start (0x%02x) need 0x47\n", ts_packet[0]);
	}
	return 0;
}

uint64_t ts_packet_get_pcr_ex(uint8_t *ts_packet, uint64_t *pcr_base, uint16_t *pcr_ext) {
	uint8_t *data = ts_packet + 6; // Offset in TS packet
	*pcr_base  = (uint64_t)data[0] << 25;
	*pcr_base += (uint64_t)data[1] << 17;
	*pcr_base += (uint64_t)data[2] << 9;
	*pcr_base += (uint64_t)data[3] << 1;
	*pcr_base += (uint64_t)data[4] >> 7;
	*pcr_ext   = ((uint16_t)data[4] & 0x01) << 8;
	*pcr_ext  += (uint16_t)data[5];
	//ts_LOGf("get pcr_base=%10llu pcr_ext=%4u pcr=%llu\n", *pcr_base, *pcr_ext, *pcr_base * 300ll + *pcr_ext);
	return *pcr_base * 300ll + *pcr_ext;
}

uint64_t ts_packet_get_pcr(uint8_t *ts_packet) {
	uint64_t pcr_base;
	uint16_t pcr_ext;
	return ts_packet_get_pcr_ex(ts_packet, &pcr_base, &pcr_ext);
}


void ts_packet_set_pcr_ex(uint8_t *ts_packet, uint64_t pcr_base, uint16_t pcr_ext) {
	//ts_LOGf("set pcr_base=%10llu pcr_ext=%4u pcr=%llu\n", pcr_base, pcr_ext, pcr);
	// 6 is the PCR offset in ts_packet (4 bytes header, 1 byte adapt field len)
	ts_packet[6 + 0] = (pcr_base >> 25) & 0xFF;
	ts_packet[6 + 1] = (pcr_base >> 17) & 0xFF;
	ts_packet[6 + 2] = (pcr_base >> 9)  & 0xFF;
	ts_packet[6 + 3] = (pcr_base >> 1)  & 0xFF;
	ts_packet[6 + 4] = 0x7e | ((pcr_ext >> 8) & 0x01) | ((pcr_base & 0x01) <<7 ); // 0x7e == 6 reserved bits
	ts_packet[6 + 5] = pcr_ext & 0xFF;
}

void ts_packet_set_pcr(uint8_t *ts_packet, uint64_t pcr) {
	uint64_t pcr_base = pcr / 300;
	uint16_t pcr_ext = pcr % 300;
	ts_packet_set_pcr_ex(ts_packet, pcr_base, pcr_ext);
}

uint8_t *ts_packet_header_parse(uint8_t *ts_packet, struct ts_header *ts_header) {
	if (ts_packet[0] != 0x47) {
		// ts_LOGf("*** TS packet do not start with sync byte 0x47 but with 0x%02x\n", ts_packet[0]);
		goto return_error;
	}

	ts_header->tei  = (ts_packet[1] &~ 0x7f) >> 7; // x1111111
	ts_header->pusi = (ts_packet[1] &~ 0xbf) >> 6; // 1x111111
	ts_header->prio = (ts_packet[1] &~ 0xdf) >> 5; // 11x11111
	ts_header->pid  = (ts_packet[1] &~ 0xE0) << 8 | ts_packet[2]; // 111xxxxx xxxxxxxx

	ts_header->scramble      = (ts_packet[3] &~ 0x3F) >> 6; // xx111111
	ts_header->adapt_field   = (ts_packet[3] &~ 0xDF) >> 5; // 11x11111
	ts_header->payload_field = (ts_packet[3] &~ 0xEF) >> 4; // 111x1111
	ts_header->continuity    = (ts_packet[3] &~ 0xF0);      // 1111xxxx

	if (!ts_header->adapt_field) {
		ts_header->adapt_len   = 0;
		ts_header->adapt_flags = 0;
		ts_header->payload_offset = 4;
	} else {
		ts_header->adapt_len = ts_packet[4];
		if (ts_header->adapt_len) {
			ts_header->adapt_flags = ts_packet[5];
		}
		ts_header->payload_offset = 5 + ts_header->adapt_len; // 2 bytes see above
	}

	if (!ts_header->adapt_field && !ts_header->payload_field) // Not allowed
		goto return_error;

	if (!ts_header->payload_field)
		return NULL;

	if (ts_header->payload_field && ts_header->adapt_len > 182) // Validity checks
		goto return_error;
	if (!ts_header->payload_field && ts_header->adapt_len > 183)
		goto return_error;

	if (ts_header->payload_offset > TS_MAX_PAYLOAD_SIZE) // Validity check
		goto return_error;

	ts_header->payload_size = TS_PACKET_SIZE - ts_header->payload_offset;

	return ts_packet + ts_header->payload_offset;

return_error:
	memset(ts_header, 0, sizeof(struct ts_header));
	return NULL;
}

void ts_packet_header_generate(uint8_t *ts_packet, struct ts_header *ts_header) {
	memset(ts_packet, 0xFF, TS_PACKET_SIZE);
	ts_packet[0]  = 0x47;

	ts_packet[1]  = 0;
	ts_packet[1]  = ts_header->tei  << 7;			// x1111111
	ts_packet[1] |= ts_header->pusi << 6;			// 1x111111
	ts_packet[1] |= ts_header->prio << 5;			// 11x11111
	ts_packet[1] |= ts_header->pid >> 8;			// 111xxxxx xxxxxxxx
	ts_packet[2]  = ts_header->pid &~ 0xff00;

	ts_packet[3]  = 0;
	ts_packet[3]  = ts_header->scramble << 6;		// xx111111
	ts_packet[3] |= ts_header->adapt_field << 5;	// 11x11111
	ts_packet[3] |= ts_header->payload_field << 4;	// 111x1111
	ts_packet[3] |= ts_header->continuity;			// 1111xxxx

	if (ts_header->adapt_field) {
		ts_packet[4] = ts_header->adapt_len;
		ts_packet[5] = ts_header->adapt_flags;
	}
}

void ts_packet_header_dump(struct ts_header *ts_header) {
	ts_LOGf("*** tei:%d pusi:%d prio:%d pid:%04x (%d) scramble:%d adapt:%d payload:%d adapt_len:%d adapt_flags:%d | pofs:%d plen:%d\n",
		ts_header->tei,
		ts_header->pusi,
		ts_header->prio,
		ts_header->pid,
		ts_header->pid,
		ts_header->scramble,
		ts_header->adapt_field,
		ts_header->payload_field,
		ts_header->adapt_len,
		ts_header->adapt_flags,
		ts_header->payload_offset,
		ts_header->payload_size
	);
}
