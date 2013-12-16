/*
 * MPEG/DVB descriptor parsing
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
#include <netdb.h>

#include "tsfuncs.h"

static void dvb_print_string(char *pad, char *prefix, uint8_t *input, int text_length) {
	if (text_length < 0) {
		ts_LOGf("%s  !!! %s text_length < 0, %d\n", pad, prefix, text_length);
		return;
	}
	if (text_length == 0) {
		ts_LOGf("%s  %s \"\" (size: %d)\n", pad, prefix, text_length);
		return;
	}
	char *text = calloc(1, text_length + 1);
	memcpy(text, input, text_length);
	if (text[0] < 32)
		ts_LOGf("%s  %s \"%s\" (charset: 0x%02x size: %d)\n", pad, prefix, text+1, text[0], text_length-1);
	else
		ts_LOGf("%s  %s \"%s\" (size: %d)\n", pad, prefix, text, text_length);
	free(text);
}

void ts_descriptor_dump(uint8_t *desc_data, int desc_data_len) {
	char *pad  = "        * ";
	uint8_t *data = desc_data;
	int data_len = desc_data_len;
	while (data_len >= 2) {
		int i;
		uint8_t tag         = data[0];
		uint8_t this_length = data[1];

//		ts_LOGf("%sDescriptor tag: 0x%02x (%d) size: %d\n", padA, tag, tag, this_length);

		data     += 2;
		data_len -= 2;

		if (this_length > data_len) {
			// Not much we can do - try giving up?
			ts_LOGf("%s!!! Descriptor 0x%02x says length %d, but only %d bytes left\n", pad, tag, this_length, data_len);
			return;
		}

		switch (tag) {
			case  2: { // Video stream descriptor
				char *dump = ts_hex_dump(data, this_length, 0);
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Video stream descriptor: %s\n", pad, tag, tag, this_length, dump);
				free(dump);
				struct {
					uint8_t multiple_frame_rate_flag     : 1,
					        frame_rate_code              : 4,
					        mpeg1_only_flag              : 1,
					        constraint_parameter_flag    : 1,
					        still_picture_flag           : 1;
					uint8_t profile_and_level_indication;
					uint8_t chroma_format                : 2,
					        frame_rate_extension_flag    : 1,
					        reserved                     : 5;
					uint8_t escape:1, profile:3, level:4;
				} vs;
				if (this_length >= 1) {
					vs.multiple_frame_rate_flag     = bit_on(data[0], bit_8);
					vs.frame_rate_code              = (data[0] &~ 0x80) >> 3; // 1xxxx111
					vs.mpeg1_only_flag              = bit_on(data[0], bit_3);
					vs.constraint_parameter_flag    = bit_on(data[0], bit_2);
					vs.still_picture_flag           = bit_on(data[0], bit_1);
					ts_LOGf("%s  - multiple_frame_rate_flag     : %d\n", pad, vs.multiple_frame_rate_flag);
					ts_LOGf("%s  - frame_rate_code              : %d (%s)\n", pad, vs.frame_rate_code,
						vs.frame_rate_code == 0 ? "forbidden" :
						vs.frame_rate_code == 1 ? "23.976" :
						vs.frame_rate_code == 2 ? "24.00" :
						vs.frame_rate_code == 3 ? "25.00" :
						vs.frame_rate_code == 4 ? "29.97" :
						vs.frame_rate_code == 5 ? "30.00" :
						vs.frame_rate_code == 6 ? "50.00" :
						vs.frame_rate_code == 7 ? "59.94" :
						vs.frame_rate_code == 8 ? "60.00" : "reserved"
					);
					ts_LOGf("%s  - mpeg1_only_flag              : %d\n", pad, vs.mpeg1_only_flag);
					ts_LOGf("%s  - constraint_parameter_flag    : %d\n", pad, vs.constraint_parameter_flag);
					ts_LOGf("%s  - still_picture_flag           : %d\n", pad, vs.still_picture_flag);
				}
				if (this_length >= 2 && vs.mpeg1_only_flag == 0) {
					vs.profile_and_level_indication = data[1];
					vs.chroma_format                = data[2] >> 6;				// xx111111
					vs.frame_rate_extension_flag    = bit_on(data[2], bit_6);	// 11x11111
					vs.reserved                     = data[2] &~ 0xE0;			// 111xxxxx
					vs.profile                      = (vs.profile_and_level_indication &~ 0x8f) >> 4;	// x111xxxx
					vs.level                        =  vs.profile_and_level_indication &~ 0xf0;			// xxxx1111
					ts_LOGf("%s  - profile_and_level_indication : 0x%02x, Profile: %d (%s), Level: %d (%s)\n", pad,
						vs.profile_and_level_indication,

						vs.profile,
						vs.profile == 1 ? "High"               :
						vs.profile == 2 ? "Spatially Scalable" :
						vs.profile == 3 ? "SNR Scalable"       :
						vs.profile == 4 ? "Main"               :
						vs.profile == 5 ? "Simple"             : "Reserved",

						vs.level,
						vs.level == 4  ? "High"      :
						vs.level == 6  ? "High 1440" :
						vs.level == 8  ? "Main"      :
						vs.level == 10 ? "Low"       : "Reserved"
					);
					ts_LOGf("%s  - chroma_format                : %d (%s)\n", pad, vs.chroma_format,
						vs.chroma_format == 0 ? "reserved" :
						vs.chroma_format == 1 ? "4:2:0" :
						vs.chroma_format == 2 ? "4:2:2" :
						vs.chroma_format == 3 ? "4:4:4" : "unknown"
					);
					ts_LOGf("%s  - frame_rate_extension_flag    : %d\n", pad, vs.frame_rate_extension_flag);
					ts_LOGf("%s  - reserved                     : 0x%x\n", pad, vs.reserved);
				}
				break;
			}
			case  3: { // Audio stream descriptor
				char *dump = ts_hex_dump(data, this_length, 0);
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Audio stream descriptor: %s\n", pad, tag, tag, this_length, dump);
				free(dump);
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
					ts_LOGf("%s  - free_format_flag : %d\n", pad, as.free_format_flag);
					ts_LOGf("%s  - ID               : %d (%s)\n", pad, as.ID, as.ID ? "MPEG Audio" : "Other");
					ts_LOGf("%s  - layer            : %d (%s)\n", pad, as.layer,
						as.layer == 0 ? "reserved" :
						as.layer == 1 ? "Layer III" :
						as.layer == 2 ? "Layer II" :
						as.layer == 3 ? "Layer I" : "reserved"
					);
					ts_LOGf("%s  - vbr_audio_flag   : %d\n", pad, as.vbr_flag);
					ts_LOGf("%s  - reserved         : 0x%x\n", pad, as.reserved);
				}
				break;
			}
			case  5: { // Registration descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Registration descriptor\n", pad, tag, tag, this_length);
				uint32_t reg_ident  = data[0] << 24;
				reg_ident          |= data[1] << 16;
				reg_ident          |= data[2] << 8;
				reg_ident          |= data[3];
				// See http://smpte-ra.org/mpegreg/mpegreg.html
				ts_LOGf("%s  Registration ident: 0x%04x (%c%c%c%c)\n", pad, reg_ident,
					data[0], data[1], data[2], data[3]);
				dvb_print_string(pad, "Registration data :", &data[4], this_length-4);
				break;
			}
			case  6: { // I see this in data, so might as well "explain" it
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Data stream alignment descriptor: Alignment type: 0x%02x (%s)\n",
					pad, tag, tag, this_length,
					data[0],
					data[0] == 0x00 ? "Reserved" :
					data[0] == 0x01 ? "Slice, or video access unit" :
					data[0] == 0x02 ? "Video access unit" :
					data[0] == 0x03 ? "GOP, or SEQ" :
					data[0] == 0x04 ? "SEQ" : "Reserved"
				);
				break;
			}
			case  9: { // CA descriptor
				uint16_t CA_ID = (data[0] << 8) | data[1];
				uint16_t CA_PID = ((data[2] & 0x1F) << 8) | data[3];
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, CA descriptor: CAID 0x%04x (%02d) | CA PID 0x%04x (%d) | %s\n",
					pad,
					tag, tag,
					this_length,
					CA_ID, CA_ID,
					CA_PID, CA_PID,
					ts_get_CA_sys_txt(ts_get_CA_sys(CA_ID))
				);
				break;
			}
			case 10: { // We'll assume the length is a multiple of 4
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Language descriptor:\n", pad, tag, tag, this_length);
				for (i=0; i<this_length/4; i++) {
					uint8_t audio_type = *(data+(i*4)+3);
					ts_LOGf("%s  Lang: %c%c%c Type: (%d) %s\n", pad,
							*(data+(i*4)+0), *(data+(i*4)+1), *(data+(i*4)+2),
							audio_type,
							(audio_type == 0 ? "" :
							 audio_type == 1 ? "clean effects" :
							 audio_type == 2 ? "visual impaired commentary" :
							 audio_type == 3 ? "clean effects" : "reserved")
					);
				}
				break;
			}
			case 14: { // Maximum bitrate descriptor
				uint32_t max_bitrate = ((data[0] &~ 0xc0) << 16) | (data[1] << 8) | data[2]; // 11xxxxxx xxxxxxxx xxxxxxxx
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Maximum bitrate descriptor: 0x%04x (%u Bytes/sec)\n",
					pad, tag, tag, this_length,
					max_bitrate, max_bitrate * 50); // The value is in units of 50 bytes/second
				break;
			}
			case 0x40: { // Network name descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Network name descriptor\n", pad, tag, tag, this_length);
				dvb_print_string(pad, "Network name:", &data[0], this_length);
				break;
			}
			case 0x41: { // service_list_descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Service_list_descriptor\n", pad, tag, tag, this_length);
				for (i=0; i<this_length; i+=3) {
					uint16_t service_id;
					uint8_t service_type;
					service_id   = data[i + 0] << 8;
					service_id  |= data[i + 1];
					service_type = data[i + 2];
					ts_LOGf("%s  Service_Id: 0x%04x (%d) Type: 0x%02x (%d)\n", pad,
						service_id, service_id,
						service_type, service_type);
				}
				break;
			}
			case 0x44: { // cable_delivery_descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Cable_delivery_system descriptor\n", pad, tag, tag, this_length);
				uint32_t freq, symbol_rate;
				uint16_t reserved;
				uint8_t FEC_outer, FEC_inner;
				uint8_t modulation;
				freq           = data[0] << 24;
				freq          |= data[1] << 16;
				freq          |= data[2] << 8;
				freq          |= data[3];			// 4 bytes
				reserved       = data[4] << 8;		// 11111111
				reserved      |= data[5] &~ 0x0f;	// 1111xxxx
				FEC_outer      = data[5] &~ 0xf0;	// xxxx1111
				modulation     = data[6];			// 1 byte
				symbol_rate    = data[7] << 24;
				symbol_rate   |= data[8] << 16;
				symbol_rate   |= data[9] << 8;		// 28 bits, the last 4 bits are FEC_inner
				symbol_rate   |= data[10];			// 28 bits, the last 4 bits are FEC_inner
				FEC_inner      = data[10] &~ 0xf0;
				ts_LOGf("%s  Frequency  : 0x%08x\n", pad, freq);
				ts_LOGf("%s  FEC_outer  : %s (0x%x) (reserved 0x%03x)\n"  , pad,
					(FEC_outer == 0 ? "Not defined" :
					 FEC_outer == 1 ? "no outer FEC coding" :
					 FEC_outer == 2 ? "RS (204/188)" : "Reserved"),
					FEC_outer, reserved >> 4);
				ts_LOGf("%s  Modulation : %s (%d/0x%02x)\n", pad,
					(modulation == 0 ? "Not defined" :
					 modulation == 1 ? "16-QAM" : 
					 modulation == 2 ? "32-QAM" : 
					 modulation == 3 ? "64-QAM" : 
					 modulation == 4 ? "128-QAM" : 
					 modulation == 5 ? "256-QAM" : "Reserved"),
					modulation, modulation);
				ts_LOGf("%s  symbol_rate: 0x%07x\n", pad, symbol_rate);
				ts_LOGf("%s  FEC_inner  : 0x%x\n"  , pad, FEC_inner);
				break;
			}
			case 0x45: { // VBI_data_descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, VBI_data descriptor (not decoded!!!)\n", pad, tag, tag, this_length);
				break;
			}
			case 0x48: { // Service descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Service descriptor:\n", pad, tag, tag, this_length);
				ts_LOGf("%s  Service type : %s\n", pad,
					data[0] == 0x01 ? "digital tv service" :
					data[0] == 0x02 ? "digital radio service" : "other");
				uint8_t provider_name_length = data[1];
				dvb_print_string(pad, "Provider name:", &data[2], provider_name_length);
				uint8_t service_name_length = data[2 + provider_name_length];
				dvb_print_string(pad, "Service name :", &data[3 + provider_name_length], service_name_length);
				break;
			}
			case 0x4d: { // short_event_descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Short event descriptor:\n", pad, tag, tag, this_length);
				ts_LOGf("%s  Lang : %c%c%c\n", pad, data[0], data[1], data[2]);
				uint8_t event_name_length = data[3];
				dvb_print_string(pad, "Event:", &data[4], event_name_length);
				uint8_t text_length = data[4 + event_name_length];
				dvb_print_string(pad, "Text :", &data[5 + event_name_length], text_length);
				break;
			}
			case 0x4e: { // extended_event_descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Extended event descriptor:\n", pad, tag, tag, this_length);
				uint8_t desc_number = data[0] >> 4;			// xxxx 1111
				uint8_t last_desc_number = data[0] &~ 0xf0;	// 1111 xxxx
				ts_LOGf("%s  Desc_number: %d Last Desc_number: %d\n", pad, desc_number, last_desc_number);
				ts_LOGf("%s  Lang    : %c%c%c\n", pad, data[1], data[2], data[3]);
				uint8_t items_length = data[4];
				ts_LOGf("%s  ItemsLen: %d\n", pad, items_length);
				i = 5;
				while (i < items_length+5) {
					uint8_t item_desc_len = data[i++];
					if (item_desc_len)
						dvb_print_string(pad, "  - Desc:", &data[i], item_desc_len);
					i += item_desc_len;
					uint8_t item_len = data[i++];
					if (item_len)
						dvb_print_string(pad, "  - Text:", &data[i], item_len);
					i += item_len;
				}
				uint8_t text_length = data[5 + items_length];
				dvb_print_string(pad, "Text    :", &data[6 + items_length], text_length);
				break;
			}
			case 0x50: { // Component descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Component descriptor:\n", pad, tag, tag, this_length);
				uint8_t reserved       = data[0] >> 4;		// 1111 xxxx
				uint8_t stream_content = data[0] &~ 0xF0;	// xxxx 1111
				uint8_t component_type = data[1];			// See Table 26 ETSI EN 300 468
				uint8_t component_tag  = data[2];

				ts_LOGf("%s  Stream_content: %d Component_type:%d Component_tag:%d res:0x%x\n", pad,
					stream_content, component_type, component_tag, reserved);
				ts_LOGf("%s  Lang : %c%c%c\n", pad, data[3], data[4], data[5]);
				dvb_print_string(pad, "Text :", &data[6], this_length-6);
				break;
			}
			case 0x52: { // Stream identifier descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Stream identifier descriptor: Component_tag: 0x%02x (%d)\n",
					pad, tag, tag, this_length,
					data[0], data[0]);
				break;
			}
			case 0x54: { // Content descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Content descriptor:\n", pad, tag, tag, this_length);
				for (i=0; i<this_length; i+=2) {
					uint8_t c1 = data[i + 0] >> 4;
					uint8_t c2 = data[i + 0] &~ 0xf0;
					uint8_t u1 = data[i + 1] >> 4;
					uint8_t u2 = data[i + 1] &~ 0xf0;
					ts_LOGf("%s  Content1: %d Content2: %d User1: %d User2: %d\n", pad, c1, c2, u1 ,u2);
				}
				break;
			}
			case 0x55: { // Parental rating descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Parental rating descriptor:\n", pad, tag, tag, this_length);
				for (i=0; i<this_length; i+=4) {
					ts_LOGf("%s  Country: %c%c%c\n", pad, data[i+0], data[i+1], data[i+2]);
					if (data[i+3] == 0)
						ts_LOGf("%s  Rating : undefined\n", pad);
					else if (data[i+3] >= 0x01 && data[i+3] <= 0x0f)
						ts_LOGf("%s  Rating : min age %d years\n", pad, data[i+3] + 3);
					else
						ts_LOGf("%s  Rating : private - 0x%02x (%d)\n", pad, data[i+3], data[i+3]);
				}
				break;
			}
			case 0x56: { // teletext
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Teletext descriptor:\n", pad, tag, tag, this_length);
				for (i=0; i<this_length; i+= 5) {
					int teletext_type, teletext_magazine, teletext_page;
					ts_LOGf("%s  Lang: %c%c%c\n", pad, data[i], data[i+1], data[i+2]);
					teletext_type     = (data[i+3] & 0xF8) >> 3;
					teletext_magazine = (data[i+3] & 0x07);
					teletext_page     = data[i+4];
					ts_LOGf("%s  Type: %d, Desc: %s\n", pad, teletext_type,
							(teletext_type == 1 ? "Initial" :
							 teletext_type == 2 ? "Subtitles" :
							 teletext_type == 3 ? "Additional info" :
							 teletext_type == 4 ? "Program schedule" :
							 teletext_type == 5 ? "Hearing impaired subtitles" : "(reserved)")
					);
					ts_LOGf("%s  Magazine: %d, Page: %d\n", pad, teletext_magazine, teletext_page);
				}
				break;
			}
			case 0x58: { // local_timeoffset
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Local timeoffset descriptor\n", pad, tag, tag, this_length);
				if (this_length % 13 != 0) {
					ts_LOGf("%s  !!! length %% 13 != 0 (%d)\n", pad, this_length);
					break;
				}
				while (this_length > 0) {
					uint16_t mjd, lto, lto_next;
					uint32_t bcd;
					time_t ts;
					struct tm tm;
					uint8_t region_id, reserved, polarity;
					ts_LOGf("%s  Country code: %c%c%c\n", pad, data[0], data[1], data[2]);
					region_id	 = data[ 3] >> 2;			// xxxxxx11
					reserved	 =(data[ 3] &~ 0xfd) >> 1;	// 111111x1
					polarity	 =(data[ 3] &~ 0xfe);		// 1111111x
					lto			 = data[ 4] << 8;
					lto			|= data[ 5];
					mjd			 = data[ 6] << 8;
					mjd			|= data[ 7];
					bcd			 = data[ 8] << 16;
					bcd			|= data[ 9] << 8;
					bcd			|= data[10];
					lto_next	 = data[11] << 8;
					lto_next	|= data[12];
					ts = ts_time_decode_mjd(mjd, bcd, &tm);
					ts_LOGf("%s  Region_id   : %d\n", pad, region_id);
					ts_LOGf("%s  Reserved    : %d\n", pad, reserved);
					ts_LOGf("%s  LTO polarity: %d\n", pad, polarity);
					ts_LOGf("%s  LTO         : %c%04x\n", pad, polarity ? '-' : '+', lto);
					ts_LOGf("%s  Change time : (%04d-%02d-%02d %02d:%02d:%02d) /0x%04x%06x, %ld/\n", pad,
						tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
						tm.tm_hour, tm.tm_min, tm.tm_sec,
						mjd, bcd, ts);
					ts_LOGf("%s  LTO next    : %c%04x\n", pad, polarity ? '-' : '+', lto_next);
					data += 13;
					data_len -= this_length;
					this_length -= 13;
				}
				break;
			}

			case 0x59: {
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Subtitling descriptor:\n", pad, tag, tag, this_length);
				for (i=0; i+8 <= this_length; i+=8) {
					char lang[4];
					unsigned int subtitling_type     =  data[i+3];
					unsigned int composition_page_id = (data[i+4] << 8) | data[i+5];
					unsigned int ancillary_page_id   = (data[i+6] << 8) | data[i+7];
					lang[0] = data[i + 0];
					lang[1] = data[i + 1];
					lang[2] = data[i + 2];
					lang[3] = 0;
					ts_LOGf("%s  Lang: %s, Sub_type: %u, Composition_page_id: %u, Ancillary_page_id: %u\n",
						pad, lang, subtitling_type, composition_page_id, ancillary_page_id);
				}
				break;
			}
			case 0x5f: { // Private NorDig descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Private Nordig descriptor:\n", pad, tag, tag, this_length);
				for (i=0; i<this_length; i+=4) {
					uint8_t u1 = data[i + 0] ;
					uint8_t u2 = data[i + 1] ;
					uint8_t u3 = data[i + 2] ;
					uint8_t u4 = data[i + 3] ;
					ts_LOGf("%s  Data1: 0x%02x Data2: %02x Data3: %02x Data4: %02x\n", pad, u1, u2, u3 ,u4);
				}
				break;
			}
			case 0x62: { // frequency_list_descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Frequency_list_descriptor\n", pad, tag, tag, this_length);
				uint8_t reserved    = data[0] >> 2;		// 111111xx
				uint8_t coding_type = data[0] &~ 0xfc;	// xxxxxx11
				ts_LOGf("%s  Coding_type: %s (%d/0x%x) Reserved: 0x%x\n", pad,
						(coding_type == 0 ? "Not defined" :
						 coding_type == 1 ? "Satellite" :
						 coding_type == 2 ? "Cable" :
						 coding_type == 3 ? "Terrestrial" : "Reserved"),
						 coding_type, coding_type, reserved);
				for (i=1; i<this_length; i+=4) {
					uint32_t centre_freq;
					centre_freq  = data[i + 0] << 24;
					centre_freq |= data[i + 1] << 16;
					centre_freq |= data[i + 2] << 8;
					centre_freq |= data[i + 3];
					ts_LOGf("%s  Frequency: 0x%08x\n", pad, centre_freq);
				}
				break;
			}

			case 0x69: { // PDC descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, PDC descriptor: Prg_id_label: 0x%02x%02x%02x\n",
					pad, tag, tag, this_length,
					data[0] &~ 0xf0, data[1], data[2]);
				break;
			}
			case 0x6a: {
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, AC-3 descriptor\n", pad, tag, tag, this_length);
				break;
			}

			case 0x83: { // Private descriptor! LCN Logical channel descriptor
				ts_LOGf("%sTag 0x%02x (%02d), sz: %d, Logical channel descriptor\n", pad, tag, tag, this_length);
				for (i=0; i<this_length; i+=4) {
					uint16_t service_id;
					uint8_t visible;
//					uint8_t reserved1;
					uint16_t lcn;
					service_id   = data[i + 0] << 8;
					service_id  |= data[i + 1];
					visible      = data[i+2] >> 7;			// x1111111
//					reserved1    = data[i+2] &~ 0x80 >> 6;		// 1x111111
					lcn          = data[i+2] &~ 0xc0 << 8;		// 11xxxxxx
					lcn         |= data[i+3];			// xxxxxxxx
					ts_LOGf("%s  Service_ID: 0x%04x (%4d) LCN: %3d Visible: %d\n",
						pad, service_id, service_id, lcn, visible);
				}
				break;
			}

			default: {
				char *dump = ts_hex_dump(data, this_length, 0);
				ts_LOGf("%s*** Unknown Tag 0x%02x (%02d), sz: %d, data: %s\n", pad, tag, tag, this_length, dump);
				free(dump);
				break;
			}
		}
		data_len -= this_length;
		data += this_length;
	}
}
