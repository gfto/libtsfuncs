/*
 * NIT descriptor generator
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

static void ts_nit_regenerate_packet_data(struct ts_nit *nit) {
	uint8_t *ts_packets;
	int num_packets;
	ts_nit_generate(nit, &ts_packets, &num_packets);
	memcpy(nit->section_header->packet_data, ts_packets, num_packets * TS_PACKET_SIZE);
	nit->section_header->num_packets = num_packets;
	free(ts_packets);
}

struct ts_nit *ts_nit_init(struct ts_nit *nit, uint16_t network_id) {
	nit->ts_header.pid            = 0x10;
	nit->ts_header.pusi           = 1;
	nit->ts_header.payload_field  = 1;
	nit->ts_header.payload_offset = 4;

	nit->section_header->table_id                 = 0x40;
	nit->section_header->version_number           = 1;
	nit->section_header->current_next_indicator   = 1;
	nit->section_header->section_syntax_indicator = 1;
	nit->section_header->private_indicator        = 1;
	nit->section_header->section_length           = 9 + 4; // Empty section, +4 (16+16) for NIT table data
	nit->section_header->ts_id_number             = network_id;
	nit->section_header->reserved1                = 3;
	nit->section_header->reserved2                = 3;

	nit->reserved1           = 0xf;
	nit->network_info_size   = 0;		// 16 bits
	nit->reserved2           = 0xf;
	nit->ts_loop_size        = 0;		// 16 bits

	nit->streams_num = 0;

	nit->initialized = 1;

	ts_nit_regenerate_packet_data(nit);

	return nit;
}

struct ts_nit *ts_nit_alloc_init(uint16_t network_id) {
	struct ts_nit *nit = ts_nit_alloc();
	if (!nit)
		return NULL;
	return ts_nit_init(nit, network_id);
}

int ts_nit_add_network_name_descriptor(struct ts_nit *nit, char *network_name) {
	if (!network_name || strlen(network_name) > 255)
		return 0;

	nit->network_info_size = strlen(network_name) + 2;

	uint8_t *descriptor = calloc(1, nit->network_info_size);
	int dpos = 0;
	descriptor[dpos + 0] = 0x40;						// Network name descriptor
	descriptor[dpos + 1] = nit->network_info_size - 2;	// -2 Because of two byte header
	dpos += 2;
	char *name = network_name;
	while (name[0]) {
		descriptor[dpos++] = name[0];
		name++;
	}
	nit->network_info = descriptor;
	nit->section_header->section_length += nit->network_info_size;

	ts_nit_regenerate_packet_data(nit);

	return 1;
}

static int ts_nit_add_stream(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint8_t *desc, uint8_t desc_size) {
	if (nit->streams_num == nit->streams_max - 1 || desc_size == 0) {
		FREE(desc);
		return 0;
	}

	int stream_len = 2 + 2 + 1 + 1 + desc_size;
	if (stream_len + nit->section_header->section_length > 4093) {
		ts_LOGf("NIT no space left, max 4093, current %d will become %d!\n",
			nit->section_header->section_length,
			stream_len + nit->section_header->section_length);
		free(desc);
		return 0;
	}

	nit->ts_loop_size                   += stream_len;
	nit->section_header->section_length += stream_len;

	struct ts_nit_stream *sinfo = calloc(1, sizeof(struct ts_nit_stream));
	sinfo->transport_stream_id = ts_id;			// 2 bytes
	sinfo->original_network_id = org_net_id;	// 2 bytes
	sinfo->reserved1           = 15;			// 1 byte
	sinfo->descriptor_size     = desc_size;		// 1 byte
	sinfo->descriptor_data     = desc;			// desc_size bytes

	nit->streams[nit->streams_num] = sinfo;
	nit->streams_num++;

	ts_nit_regenerate_packet_data(nit);

	return 1;
}

// freq_type 0 == undefined
// freq_type 1 == satellite
// freq_type 2 == cable
// freq_type 3 == terrestrial
static int ts_nit_add_frequency_list_descriptor(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint8_t freq_type, uint32_t *freqs, uint8_t num_freqs) {
	uint8_t i;
	if (!num_freqs || num_freqs > 63)
		return 0;
	int desc_size = 2 + 1 + num_freqs * 4;		// 2 for header desc header, 1 for coding type, 4 for each frequency
	uint8_t *desc = calloc(1, desc_size);
	int dpos = 0;
	desc[dpos + 0] = 0x62;				// frequency_list_descriptor
	desc[dpos + 1] = desc_size - 2;		// -2 Because of two byte header
	desc[dpos + 2] = 0xfc | freq_type;	// 6 bits reserved, 2 bits freq_type
	dpos += 3;
	for(i=0;i<num_freqs;i++) {
		uint32_t freq = freqs[i];
		desc[dpos + 0] = ((freq &~ 0x00ffffff) >> 24);
		desc[dpos + 1] = ((freq &~ 0xff00ffff) >> 16);
		desc[dpos + 2] = ((freq &~ 0xffff00ff) >>  8);
		desc[dpos + 3] =  (freq &~ 0xffffff00);
		dpos += 4;
	}
	return ts_nit_add_stream(nit, ts_id, org_net_id, desc, desc_size);
}


int ts_nit_add_frequency_list_descriptor_cable(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint32_t *freqs, uint8_t num_freqs) {
	return ts_nit_add_frequency_list_descriptor(nit, ts_id, org_net_id, 2, freqs, num_freqs);
}

int ts_nit_add_cable_delivery_descriptor(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint32_t freq, uint8_t modulation, uint32_t symbol_rate) {
	int desc_size = 13;
	uint8_t *desc = calloc(1, desc_size);
	desc[ 0] = 0x44;							// cable_delivey_system_descriptor
	desc[ 1] = 11;								// -2 Because of two byte header
	desc[ 2] = ((freq &~ 0x00ffffff) >> 24);	// 32 bits, frequency
	desc[ 3] = ((freq &~ 0xff00ffff) >> 16);
	desc[ 4] = ((freq &~ 0xffff00ff) >>  8);
	desc[ 5] =  (freq &~ 0xffffff00);
	desc[ 6] = 0xff;								// 8 bits reserved
	desc[ 7] = 0xf0;								// 4 bits reserved, 4 bits FEC_outer (0 == not defined)
	desc[ 8] = modulation;							// 8 bits reserved
	desc[ 9] = (symbol_rate >> 20) &~ 0xffffff00;	// 28 bits, symbol_rate
	desc[10] = (symbol_rate >> 12) &~ 0xffffff00;
	desc[11] = (symbol_rate >> 4 ) &~ 0xffffff00;
	desc[12] = (symbol_rate &~ 0xfffffff0) << 4;	// 4 bits
	desc[12] |= 0;									// 4 bits FEC_inner (0 == not defined)
	return ts_nit_add_stream(nit, ts_id, org_net_id, desc, desc_size);
}

int ts_nit_add_service_list_descriptor(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint32_t *services, uint8_t num_services) {
	uint8_t i;
	if (!num_services || num_services > 85) // 85 * 3 == 255
		return 0;
	int desc_size = 2 + num_services * 3;		// 2 for header desc header, 3 for each service
	uint8_t *desc = calloc(1, desc_size);
	int dpos = 0;
	desc[dpos + 0] = 0x41;				// service_list_descriptor
	desc[dpos + 1] = desc_size - 2;		// -2 Because of two byte header
	dpos += 2;
	for(i=0;i<num_services;i++) {
		uint32_t srv = services[i];
		desc[dpos + 0] = (srv &~ 0xff00ffff) >> 16;	// service_id (16 bits)
		desc[dpos + 1] = (srv &~ 0xffff00ff) >>  8;
		desc[dpos + 2] = (srv &~ 0xffffff00);		// service_type (8 bits)
		dpos += 3;
	}
	return ts_nit_add_stream(nit, ts_id, org_net_id, desc, desc_size);
}

int ts_nit_add_nordig_specifier_descriptor(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id) {
	int desc_size = 2 + 4;		// 2 for header desc header, 3 for each service
	uint8_t *desc = calloc(1, desc_size);
	int dpos = 0;
	desc[dpos + 0] = 0x5f;				// service_list_descriptor
	desc[dpos + 1] = desc_size - 2;		// -2 Because of two byte header
	desc[dpos + 2] = 0x00;				// -2 Because of two byte header
	desc[dpos + 3] = 0x00;				// -2 Because of two byte header
	desc[dpos + 4] = 0x00;				// -2 Because of two byte header
	desc[dpos + 5] = 0x29;				// -2 Because of two byte header
	dpos += 6;

	return ts_nit_add_stream(nit, ts_id, org_net_id, desc, desc_size);
}

int ts_nit_add_lcn_descriptor(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint32_t *services, uint8_t num_services) {
	uint8_t i;
	if (!num_services || num_services > 85) 		// 85 * 3 == 255
		return 0;
	int desc_size = 2 + num_services * 4;			// 2 for header desc header, 4 for each service
	uint8_t *desc = calloc(1, desc_size);
	int dpos = 0;
	desc[dpos + 0] = 0x83;					// service_lcn_descriptor
	desc[dpos + 1] = desc_size - 2;				// -2 Because of two byte header
	dpos += 2;
	for(i=0;i<num_services;i++) {
		uint32_t srv = services[i];
		desc[dpos + 0] = (srv &~ 0x00ffffff) >> 24;	// service_id (16 bits)
		desc[dpos + 1] = (srv &~ 0xff00ffff) >> 16;	// service_id
		desc[dpos + 2] = (srv &~ 0xffff00ff) >>  8;	// visible (1 bit), private (1 bit), first (6 bits) from lcn_number 
		desc[dpos + 3] = (srv &~ 0xffffff00);		// second (8 bits) lcn_number
		dpos += 4;
	}
	return ts_nit_add_stream(nit, ts_id, org_net_id, desc, desc_size);
}


int ts_nit_add_stream_descriptors(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint32_t freq, uint8_t modulation, uint32_t symbol_rate, uint32_t *lcn_services, uint32_t *svc_services, uint8_t num_services) {
	
	int desc_size = 13 + 6 + 2 + 2 + num_services * 4 + num_services * 3;		// 2 for header desc header, + ....
	
	uint8_t *desc = calloc(1, desc_size);

	desc[ 0] = 0x44;							// cable_delivey_system_descriptor
	desc[ 1] = 11;								// -2 Because of two byte header
	desc[ 2] = ((freq &~ 0x00ffffff) >> 24);	// 32 bits, frequency
	desc[ 3] = ((freq &~ 0xff00ffff) >> 16);
	desc[ 4] = ((freq &~ 0xffff00ff) >>  8);
	desc[ 5] =  (freq &~ 0xffffff00);
	desc[ 6] = 0xff;								// 8 bits reserved
	desc[ 7] = 0xf0;								// 4 bits reserved, 4 bits FEC_outer (0 == not defined)
	desc[ 8] = modulation;							// 8 bits reserved
	desc[ 9] = (symbol_rate >> 20) &~ 0xffffff00;	// 28 bits, symbol_rate
	desc[10] = (symbol_rate >> 12) &~ 0xffffff00;
	desc[11] = (symbol_rate >> 4 ) &~ 0xffffff00;
	desc[12] = (symbol_rate &~ 0xfffffff0) << 4;	// 4 bits
	desc[12] |= 0;									// 4 bits FEC_inner (0 == not defined)

	uint8_t i;
	if (!num_services || num_services > 85) // 85 * 3 == 255
		return 0;
	
	int desc_svc_size = 2 + num_services * 3;		// 2 for header desc header, 3 for each service
	

	int dpos = 13;

	desc[dpos + 0] = 0x41;				// service_list_descriptor
	desc[dpos + 1] = desc_svc_size - 2;		// -2 Because of two byte header
	dpos += 2;
	for(i=0;i<num_services;i++) {
		uint32_t srv = svc_services[i];
		desc[dpos + 0] = (srv &~ 0xff00ffff) >> 16;	// service_id (16 bits)
		desc[dpos + 1] = (srv &~ 0xffff00ff) >>  8;
		desc[dpos + 2] = (srv &~ 0xffffff00);		// service_type (8 bits)
		dpos += 3;
	}

	int desc_prv_size = 2 + 4;		// 2 for header desc header, 3 for each service

	desc[dpos + 0] = 0x5f;				// service_list_descriptor
	desc[dpos + 1] = desc_prv_size - 2;		// -2 Because of two byte header
	desc[dpos + 2] = 0x00;				// -2 Because of two byte header
	desc[dpos + 3] = 0x00;				// -2 Because of two byte header
	desc[dpos + 4] = 0x00;				// -2 Because of two byte header
	desc[dpos + 5] = 0x29;				// -2 Because of two byte header
	dpos += 6;

	if (!num_services || num_services > 85) 		// 85 * 3 == 255
		return 0;
	int desc_lcn_size = 2 + num_services * 4;			// 2 for header desc header, 4 for each service

	desc[dpos + 0] = 0x83;					// service_lcn_descriptor
	desc[dpos + 1] = desc_lcn_size - 2;				// -2 Because of two byte header
	dpos += 2;
	for(i=0;i<(num_services);i++) {
		uint32_t srv = lcn_services[i];
		desc[dpos + 0] = (srv &~ 0x00ffffff) >> 24;	// service_id (16 bits)
		desc[dpos + 1] = (srv &~ 0xff00ffff) >> 16;	// service_id
		desc[dpos + 2] = (srv &~ 0xffff00ff) >>  8;	// visible (1 bit), private (1 bit), first (6 bits) from lcn_number 
		desc[dpos + 3] = (srv &~ 0xffffff00);		// second (8 bits) lcn_number
		dpos += 4;
	}


	return ts_nit_add_stream(nit, ts_id, org_net_id, desc, desc_size);
}

