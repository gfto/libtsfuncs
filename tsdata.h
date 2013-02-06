/*
 * Data defintions
 * Copyright (C) 2010-2011 Unix Solutions Ltd.
 *
 * Released under MIT license.
 * See LICENSE-MIT.txt for license terms.
 */
#ifndef LIBTS_TSDATA_H
#define LIBTS_TSDATA_H

#include <netdb.h>
#include <time.h>

#ifndef FREE
	#define FREE(x) if(x) { free(x); x=NULL; }
#endif

#define TS_PACKET_SIZE       188
#define TS_MAX_PAYLOAD_SIZE  (TS_PACKET_SIZE-4)

struct ts_header {
	uint8_t		sync_byte;			// Always 0x47

	uint16_t	tei           : 1,	// Transport Error Indicator (TEI)
				pusi          : 1,	// Payload Unit Start Indicator
				prio          : 1,	// Transport Priority
				pid           : 13;	// PID

	uint8_t		scramble      : 2,	// 00 - not scrambled, 01 - reserved, 10 - scrambled with even key,  11 - scrambled with odd key
				adapt_field   : 1,
				payload_field : 1,
				continuity    : 4;

	// The variables bellow this line depends may not exist in a packet
	uint8_t		adapt_len;			// adaptation field length
	uint8_t		adapt_flags;		// adaptation field flags

	uint8_t		payload_size;		// Payload size inside the packet
	uint8_t		payload_offset;		// Payload offset inside the packet
};

struct ts_section_header {
	uint8_t		pointer_field;

	uint8_t		table_id;

	uint16_t	section_syntax_indicator: 1,	// Section Syntax Indicator
				private_indicator       : 1,	// Private section indicator
				reserved1               : 2,	// 2 reserved bits
				section_length          : 12;	// Section lenth

	uint16_t	ts_id_number;					// Transport stream id (in PAT), Program number (in PMT)

	uint8_t		reserved2              : 2,
				version_number         : 5,
				current_next_indicator : 1;

	uint8_t		section_number;
	uint8_t		last_section_number;

	// The variables bellow this line are not in the physical packet
	int			section_pos;					// Up to this pos the section data has come
	int			initialized;					// Set to 1 when whole sectino is initialized

	int			section_data_len;				// Full section length (3 + section_length)
	uint8_t		*section_data;					// The whole section data
	uint8_t		*packet_data;					// TS packet(s) that were used to transfer the table.

	int			num_packets;					// From how much packets this section is build

	int			data_len;						// Data size without the CRC32 (4 bytes)
	uint8_t		*data;							// Offset into section_data (where the section data start without the section header)

	uint32_t	CRC;
};

struct ts_pat_program {
	uint16_t	program;
	uint16_t	reserved:3,
				pid:13;
};

struct ts_pat {
	struct ts_header			ts_header;
	struct ts_section_header	*section_header;

	struct ts_pat_program		**programs;

	// The variables bellow are nor part of the physical packet
	int							programs_max;	// How much programs are allocated
	int							programs_num;	// How much programs are initialized
	uint8_t						initialized;	// Set to 1 when full table is initialized
};

enum CA_system {
	CA_SECA,		// 0x0100 - 0x01FF Canal Plus (SECA/Mediaguard)
	CA_VIACCESS,	// 0x0500 - 0x05FF France Telecom
	CA_IRDETO,		// 0x0600 - 0x06FF Irdeto
	CA_VIDEOGUARD,	// 0x0900 - 0x09FF News Datacom (NDS/Videoguard)
	CA_CONAX,		// 0x0B00 - 0x0BFF Norwegian Telekom
	CA_CRYPTOWORKS,	// 0x0D00 - 0x0DFF CrytoWorks
	CA_NAGRA,		// 0x1800 - 0x18FF Kudelski SA (Nagravision)
	CA_DRECRYPT,	// 0x4AE0 - 0x4AE1 OOO Cifra (DRE-Crypt)
	CA_BULCRYPT,	// 0x5581 & 0x4AEE Bulcrypt
	CA_GRIFFIN,		// 0x5501 & 0x5504 & 0x5511 Griffin (Not in dvbservices.com registration)
	CA_DGCRYPT,		// 0x4ABF          DGCrypt (Beijing Compunicate Technology Inc.)
	CA_UNKNOWN,
};

struct ts_cat {
	struct ts_header			ts_header;
	struct ts_section_header	*section_header;

	int							program_info_size;
	uint8_t						*program_info;

	// The variables bellow are nor part of the physical packet
	uint8_t						initialized;	// Set to 1 when full table is initialized
};

struct ts_pmt_stream {
	uint8_t		stream_type;

	uint16_t	reserved1    : 3,
				pid          : 13;

	uint16_t	reserved2    : 4,
				ES_info_size : 12;

	uint8_t		*ES_info;
};

struct ts_pmt {
	struct ts_header			ts_header;
	struct ts_section_header	*section_header;

	uint16_t					reserved1         : 3,
								PCR_pid           : 13;

	uint16_t					reserved2         : 4,
								program_info_size : 12;
	uint8_t						*program_info;

	struct ts_pmt_stream		**streams;

	// The variables bellow are nor part of the physical packet
	int							streams_max;	// How much streams are allocated
	int							streams_num;	// How much streams are initialized
	uint8_t						initialized;	// Set to 1 when full table is initialized
};


struct ts_sdt_stream {
	uint16_t	service_id;

	uint8_t		reserved1                  : 6,
				EIT_schedule_flag          : 1,
				EIT_present_following_flag : 1;

	uint16_t	running_status             : 3,
				free_CA_mode               : 1,
				descriptor_size            : 12;

	uint8_t		*descriptor_data;
};

struct ts_sdt {
	struct ts_header			ts_header;
	struct ts_section_header	*section_header;

	uint16_t					original_network_id;
	uint8_t						reserved;

	struct ts_sdt_stream		**streams;

	// The variables bellow are nor part of the physical packet
	int							streams_max;	// How much streams are allocated
	int							streams_num;	// How much streams are initialized
	uint8_t						initialized;	// Set to 1 when full table is initialized
};



struct ts_nit_stream {
	uint16_t	transport_stream_id;
	uint16_t	original_network_id;

	uint16_t	reserved1       : 4,
				descriptor_size : 12;

	uint8_t		*descriptor_data;
};

struct ts_nit {
	struct ts_header			ts_header;
	struct ts_section_header	*section_header;

	uint16_t					reserved1         : 4,
								network_info_size : 12;

	uint8_t						*network_info;

	uint16_t					reserved2         : 4,
								ts_loop_size      : 12;

	struct ts_nit_stream		**streams;

	// The variables bellow are nor part of the physical packet
	int							streams_max;	// How much streams are allocated
	int							streams_num;	// How much streams are initialized
	uint8_t						initialized;	// Set to 1 when full NIT table is initialized
};


struct ts_eit_stream {
	uint16_t	event_id;
	uint64_t	start_time_mjd	: 16,
				start_time_bcd	: 24,	// Total 40, start_time
				duration_bcd	: 24;

	uint16_t	running_status	: 3,
				free_CA_mode	: 1,
				descriptor_size	: 12;

	uint8_t		*descriptor_data;
};

struct ts_eit {
	struct ts_header			ts_header;
	struct ts_section_header	*section_header;

	uint16_t					transport_stream_id;
	uint16_t					original_network_id;
	uint8_t						segment_last_section_number;
	uint8_t						last_table_id;

	struct ts_eit_stream		**streams;

	// The variables bellow are nor part of the physical packet
	int							streams_max;	// How much streams are allocated
	int							streams_num;	// How much streams are initialized
	uint8_t						initialized;	// Set to 1 when full eit table is initialized
};

struct ts_tdt {
	struct ts_header			ts_header;
	struct ts_section_header	*section_header;

	uint16_t	mjd;							// This both are part of one 40 bit field (UTC_time)
	uint32_t	bcd;							// Only 24 bits are used

	// The below fields are only in TOT packets, table_id 0x73
	uint16_t	reserved_3				: 4,
				descriptors_size        : 12;
	uint8_t		*descriptors;

	// The variables bellow are nor part of the physical packet
	time_t		utc;	// decoded UTC_time
	struct tm	tm;		// decoded UTC_time

	uint8_t		initialized;
};

struct ts_privsec {
	struct ts_header			ts_header;
	struct ts_section_header	*section_header;
	uint8_t						initialized;
};

// PMT stream types
enum ts_stream_type {
	STREAM_TYPE_MPEG1_VIDEO			= 0x01, // MPEG-1 video
	STREAM_TYPE_MPEG2_VIDEO			= 0x02,	// H.262 - MPEG-2 video

	STREAM_TYPE_MPEG1_AUDIO			= 0x03, // MPEG-1 audio
	STREAM_TYPE_MPEG2_AUDIO			= 0x04, // MPEG-2 audio

	STREAM_TYPE_ADTS_AUDIO			= 0x0F,	// AAC ADTS
	STREAM_TYPE_MPEG4_PART2_VIDEO	= 0x10, // DIVX - MPEG-4 part 2

	STREAM_TYPE_AVC_VIDEO			= 0x1B,	// H.264 - MPEG-4 part 10
	STREAM_TYPE_AVS_VIDEO			= 0x42,	// Chinese AVS

	STREAM_TYPE_DOLBY_DVB_AUDIO		= 0x06, // 0x06 - Private stream, look at stream descriptors for AC-3 descriptor
	STREAM_TYPE_DOLBY_ATSC_AUDIO	= 0x81, // 0x81 - Private stream in ATSC (US system, probably we shouldn't care)
};

// ------------------------------------------------------------
// PES packet stream ids
// See H.222.0 Table 2-17 and Table 2-18
#define STREAM_ID_PROGRAM_STREAM_MAP		0xbc
#define STREAM_ID_PRIVATE_STREAM_1			0xbd
#define STREAM_ID_PADDING_STREAM			0xbe
#define STREAM_ID_PRIVATE_STREAM_2			0xbf
#define STREAM_ID_ECM_STREAM				0xf0
#define STREAM_ID_EMM_STREAM				0xf1
#define STREAM_ID_DSMCC_STREAM				0xf2
#define STREAM_ID_13522_STREAM				0xf3
#define STREAM_ID_H222_A_STREAM				0xf4
#define STREAM_ID_H222_B_STREAM				0xf5
#define STREAM_ID_H222_C_STREAM				0xf6
#define STREAM_ID_H222_D_STREAM				0xf7
#define STREAM_ID_H222_E_STREAM				0xf8
#define STREAM_ID_ANCILLARY_STREAM			0xf9
#define STREAM_ID_PROGRAM_STREAM_DIRECTORY	0xff

#define IS_AUDIO_STREAM_ID(id)				((id) >= 0xc0 && (id) <= 0xdf)
#define IS_VIDEO_STREAM_ID(id)				((id) >= 0xe0 && (id) <= 0xef)
#define IS_PES_STREAM_SUPPORTED(id)			(!(id == STREAM_ID_PROGRAM_STREAM_MAP       || \
											   id == STREAM_ID_PADDING_STREAM           || \
										       id == STREAM_ID_PRIVATE_STREAM_2         || \
										       id == STREAM_ID_ECM_STREAM               || \
											   id == STREAM_ID_EMM_STREAM               || \
										       id == STREAM_ID_PROGRAM_STREAM_DIRECTORY || \
										       id == STREAM_ID_DSMCC_STREAM             || \
										       id == STREAM_ID_H222_E_STREAM))


struct mpeg_audio_header {
	uint32_t	syncword		: 12,
				ID				: 1,
				layer			: 2,
				protection_bit	: 1,
				bitrate_index	: 4,
				sampl_freq		: 2,
				padding_bit		: 1,
				private_bit		: 1,
				mode			: 2,
				mode_extension	: 2,
				copyright		: 1,
				org_home		: 1,
				emphasis		: 2;

	uint8_t		initialized;
};

struct ts_pes {
	struct ts_header ts_header;

	uint32_t	have_pts		: 1,		// Have PTS in the PES (init from PES header)
				have_dts		: 1,		// Have DTS in the PES (init from PES header)
				is_audio		: 1,		// PES carries audio (mpeg2 or AC3) (init from PES stream_id and PMT stream_type and descriptors)
				is_audio_mpeg1	: 1,		// PES carries MP1 audio (init from PMT stream_id)
				is_audio_mpeg1l1: 1,		// PES carries MP1 audio Layer I (init from PMT audio descriptor)
				is_audio_mpeg1l2: 1,		// PES carries MP1 audio Layer II (init from PMT audio descriptor)
				is_audio_mpeg1l3: 1,		// PES carries MP1 audio Layer III (init from PMT audio descriptor)
				is_audio_mpeg2	: 1,		// PES carries MP2 audio (init from PMT stream_id)
				is_audio_aac	: 1,		// PES carries AAC audio (init from PMT stream_id)
				is_audio_ac3	: 1,		// PES carries AC3 audio (init from stream_id and PMT descriptors and elmentary stream)
				is_audio_dts	: 1,		// PES carries DTS audio (init from stream_id and elementary stream)
				is_video		: 1,		// PES carries video (mpeg2 or H.264) (init from PES stream_id)
				is_video_mpeg1	: 1,		// PES carries mpeg1 video (init from PES stream_id)
				is_video_mpeg2	: 1,		// PES carries mpeg2 video (init from PES stream_id)
				is_video_mpeg4	: 1,		// PES carries mpeg4 part 2 video (init from PES stream_id)
				is_video_h264	: 1,		// PES carries H.264 video (init from PES stream_id)
				is_video_avs	: 1,		// PES carries AVS video (init from PES stream_id)
				is_teletext		: 1,		// PES carries teletext (init from PMT descriptors)
				is_subtitle		: 1;		// PES carries subtitles (init from PMT descriptors)

	uint8_t		stream_id;					// If !0 then the PES has started initializing
	uint16_t	pes_packet_len;				// Allowed to be 0 for video streams
	int			real_pes_packet_len;		// if pes_packet_len is > 0 the this is eq to pes_packet_len
											// if pes_packet_len is = 0 this is set to -1 until very last packet

	uint8_t		flags_1;					// Bellow flags
	uint8_t		reserved1			: 2,	// Always eq 2 (10 binary)
				scrambling			: 2,
				priority			: 1,
				data_alignment		: 1,
				copyright			: 1,
				original_or_copy	: 1;

	uint8_t		flags_2;					// Bellow flags
	uint8_t		PTS_flag			: 1,
				DTS_flag			: 1,
				ESCR_flag			: 1,
				ES_rate_flag		: 1,
				trick_mode_flag		: 1,
				add_copy_info_flag	: 1,
				pes_crc_flag		: 1,
				pes_extension_flag	: 1;

	uint8_t		pes_header_len;

	uint64_t	PTS;						// if (PTS_flag)
	uint64_t	DTS;						// if (DTS_flag)
	uint64_t	ESCR;						// if (ESCR_flag)
	uint32_t	ES_rate;					// if (ES_rate_flag)

	uint16_t	trick_mode_control	: 2,	// if (trick_mode_flag)
				field_id			: 2,
				intra_slice_refresh	: 1,
				freq_truncation		: 2,
				rep_ctrl			: 5,
				tm_reserved			: 4;

	uint8_t		reserved_add		: 1,	// if (add_copy_info_flag)
				add_copy_info		: 7;

	uint16_t	prev_pes_crc;				// if (pes_crc_flag)

	// PES extension
	uint8_t		flags_3;					// Bellow flags
	uint8_t		pes_private_data_flag			: 1,
				pack_header_field_flag			: 1,
				program_packet_seq_counter_flag	: 1,
				p_std_buffer_flag				: 1,
				reserved2						: 3,
				pes_extension2_flag				: 1;

	uint64_t	pes_private_data_1;					// if (pes_private_data_flag)
	uint64_t	pes_private_data_2;					// The whole field is 128 bits

	uint8_t		pack_header_len;					// if (pack_header_field_flag)
	uint8_t		*pack_header;						// Pointer into *pes_data

	uint8_t		reserved3					: 1,	// if (program_packet_seq_counter_flag)
				program_packet_seq_counter	: 7;

	uint8_t		mpeg1_mpeg2_identifier		: 1,
				original_stuff_length		: 6;

	uint16_t	p_std_reserved				: 2,	// Always 1, if (p_std_buffer_flag)
				p_std_buffer_scale			: 1,
				p_std_buffer_size			: 13;

	uint16_t	reserved4					: 1,	// if (pes_extension2_flag)
				pes_extension_field_len		: 7;
	uint8_t		*pes_extension2;					// Pointer into *pes_data

	// Private data
	uint8_t		*pes_data;				// Whole packet is stored here
	uint32_t	pes_data_pos;			// How much data is filled in pes_data
	uint32_t	pes_data_size;			// Total allocated for pes_data
	uint8_t		pes_data_initialized;	// Set to 1 when all of the pes_data is in *pes_data and the parsing can start

	// More private data
	uint8_t		*es_data;				// Pointer to start of data after PES header, initialized when the packet is fully assembled
	uint32_t	es_data_size;			// Full pes packet length (used for video streams, otherwise equal to pes_packet_len)
	uint8_t		initialized;			// Set to 1 when the packet is fully assembled

	// Extra data
	struct mpeg_audio_header mpeg_audio_header;
};

struct pes_entry {
	uint16_t		pid;
	struct ts_pes	*pes;
	struct ts_pes	*pes_next;
};

struct pes_array {
	int max;
	int cur;
	struct pes_entry **entries;
};

typedef uint8_t pidmap_t[0x2000];

#endif
