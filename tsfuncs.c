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
		if (adapt_len + 1 + 4 >= 188) // adaptation field takes the whole packet
			return 0;
		return 4 + 1 + adapt_len; // ts header + adapt_field_len_byte + adapt_field_len
	} else {
		return 4; // No adaptation, data starts directly after TS header
	}
}

/*
 * Decode a PTS or DTS value.
 *
 * - `data` is the 5 bytes containing the encoded PTS or DTS value
 * - `required_guard` should be 2 for a PTS alone, 3 for a PTS before
 *   a DTS, or 1 for a DTS after a PTS
 * - `value` is the PTS or DTS value as decoded
 *
 * Returns 0 if the PTS/DTS value is decoded successfully, 1 if an error occurs
 */
int ts_decode_pts_dts(uint8_t *data, int required_guard, uint64_t *value) {
  uint64_t      pts1,pts2,pts3;
  int           marker;
  char         *what;
  int           guard = (data[0] & 0xF0) >> 4;

  // Rather than try to use casts to make the arithmetic come out right on both
  // Linux-with-gcc (old-style C rules) and Windows-with-VisualC++ (C99 rules),
  // it's simpler just to use intermediates that won't get cast to "int".
  unsigned int  data0 = data[0];
  unsigned int  data1 = data[1];
  unsigned int  data2 = data[2];
  unsigned int  data3 = data[3];
  unsigned int  data4 = data[4];

  switch (required_guard) {
    case 2:  what = "PTS"; break;  // standalone
    case 3:  what = "PTS"; break;  // before a DTS
    case 1:  what = "DTS"; break;  // always after a PTS
    default: what = "???"; break;
  }

  if (guard != required_guard)
  {
    ts_LOGf("!!! decode_pts_dts(), Guard bits at start of %s data are %x, not %x\n", what, guard, required_guard);
  }

  pts1 = (data0 & 0x0E) >> 1;
  marker = data0 & 0x01;
  if (marker != 1)
  {
    ts_LOGf("!!! decode_pts_dts(), First %s marker is not 1\n",what);
    return 0;
  }

  pts2 = (data1 << 7) | ((data2 & 0xFE) >> 1);
  marker = data2 & 0x01;
  if (marker != 1)
  {
    ts_LOGf("!!! decode_pts_dts(), Second %s marker is not 1\n",what);
    return 0;
  }

  pts3 = (data3 << 7) | ((data4 & 0xFE) >> 1);
  marker = data4 & 0x01;
  if (marker != 1)
  {
    ts_LOGf("!!! decode_pts_dts(), Third %s marker is not 1\n",what);
    return 0;
  }

  *value = (pts1 << 30) | (pts2 << 15) | pts3;
  return 1;
}

/*
 * Encode a PTS or DTS.
 *
 * - `data` is the array of 5 bytes into which to encode the PTS/DTS
 * - `guard_bits` are the required guard bits: 2 for a PTS alone, 3 for
 *   a PTS before a DTS, or 1 for a DTS after a PTS
 * - `value` is the PTS or DTS value to be encoded
 */
void ts_encode_pts_dts(uint8_t *data, int guard_bits, uint64_t value) {
  int   pts1,pts2,pts3;

#define MAX_PTS_VALUE 0x1FFFFFFFFLL

  if (value > MAX_PTS_VALUE)
  {
    char        *what;
    uint64_t     temp = value;
    while (temp > MAX_PTS_VALUE)
      temp -= MAX_PTS_VALUE;
    switch (guard_bits)
    {
    case 2:  what = "PTS alone"; break;
    case 3:  what = "PTS before DTS"; break;
    case 1:  what = "DTS after PTS"; break;
    default: what = "PTS/DTS/???"; break;
    }
    ts_LOGf("!!! value %llu for %s is more than %llu - reduced to %llu\n",value,what,MAX_PTS_VALUE,temp);
    value = temp;
  }

  pts1 = (int)((value >> 30) & 0x07);
  pts2 = (int)((value >> 15) & 0x7FFF);
  pts3 = (int)( value        & 0x7FFF);

  data[0] =  (guard_bits << 4) | (pts1 << 1) | 0x01;
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
		if (!ts_decode_pts_dts(&data[9], 2, pts))
			goto ERR;
	} else if (pts_flag && dts_flag) {
		if (data + 19 >= data_end) goto ERR;
		if (!ts_decode_pts_dts(&data[9], 3, pts))
			goto ERR;
		if (!ts_decode_pts_dts(&data[14], 1, dts))
			goto ERR;
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
