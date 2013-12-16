/*
 * Main header file
 * Copyright (C) 2010-2011 Unix Solutions Ltd.
 *
 * Released under MIT license.
 * See LICENSE-MIT.txt for license terms.
 */
#ifndef LIBTS_TSFUNCS_H
#define LIBTS_TSFUNCS_H

#include <time.h>
#include <netdb.h>

#include "tsdata.h"

#include "log.h"

// Usage bit_on(0xff, 0x02)
#define bit_on(__bit, __mask) ((__bit & __mask) ? 1 : 0)

#define bit_1 (0x01)
#define bit_2 (0x02)
#define bit_3 (0x04)
#define bit_4 (0x08)
#define bit_5 (0x10)
#define bit_6 (0x20)
#define bit_7 (0x40)
#define bit_8 (0x80)


#define NO_PCR (-1ull)
#define NO_PCR_BASE (-1ull)
#define NO_PCR_EXT  (0xffff)
#define NO_PCR (-1ull)
#define NO_PTS (-1ull)
#define NO_DTS (-1ull)

enum ts_scrambled_type {
	not_scrambled           = 0x00,
	scrambled_reserved      = 0x01,
	scrambled_with_odd_key  = 0x02,
	scrambled_with_even_key = 0x03
};

// Packet manipulation
void            ts_packet_init_null (uint8_t *ts_packet);

static inline int ts_packet_is_pusi(uint8_t *ts_packet) {
	return (ts_packet[1] &~ 0xbf) >> 6;
}

static inline uint16_t ts_packet_get_pid(uint8_t *ts_packet) {
	return (ts_packet[1] &~ 0xE0) << 8 | ts_packet[2];
}

static inline void ts_packet_set_pid(uint8_t *ts_packet, uint16_t new_pid) {
	ts_packet[1]  = (ts_packet[1] &~ 0x1f) | (new_pid >> 8);	// 111xxxxx xxxxxxxx
	ts_packet[2]  = new_pid &~ 0xff00;
}

static inline uint8_t ts_packet_get_cont(uint8_t *ts_packet) {
	return (ts_packet[3] &~ 0xF0);	// 1111xxxx
}

static inline void ts_packet_set_cont(uint8_t *ts_packet, uint8_t value) {
	// Mask the last 4 bits (continuity), then set the continuity
	ts_packet[3] =  (ts_packet[3] &~ 0x0F) | (value &~ 0xF0);
}

static inline void ts_packet_inc_cont(uint8_t *ts_packet, uint8_t increment) {
	ts_packet_set_cont(ts_packet, ts_packet_get_cont(ts_packet) + increment);
}

static inline int ts_packet_get_scrambled(uint8_t *ts_packet) {
	return ts_packet[3] >> 6; // 0 is not scamlbed, 1 is reserved, 2 or 3 mean scrambled
}

static inline int ts_packet_is_scrambled(uint8_t *ts_packet) {
	return ts_packet_get_scrambled(ts_packet) > 1;
}

static inline void ts_packet_set_not_scrambled(uint8_t *ts_packet) {
	ts_packet[3] = ts_packet[3] &~ 0xc0; // Mask top two bits (11xxxxxx)
}

void            ts_packet_set_scrambled(uint8_t *ts_packet, enum ts_scrambled_type stype);
uint8_t         ts_packet_get_payload_offset(uint8_t *ts_packet);

int				ts_packet_has_pcr		(uint8_t *ts_packet);
uint64_t		ts_packet_get_pcr_ex	(uint8_t *ts_packet, uint64_t *pcr_base, uint16_t *pcr_ext);
uint64_t		ts_packet_get_pcr		(uint8_t *ts_packet);
void			ts_packet_set_pcr_ex	(uint8_t *ts_packet, uint64_t pcr_base, uint16_t pcr_ext);
void			ts_packet_set_pcr		(uint8_t *ts_packet, uint64_t pcr);

/*
 * guard 2 == pts
 * guard 3 == pts before dts
 * guard 1 == dts
 */
void			ts_encode_pts_dts		(uint8_t *data, int guard, uint64_t value);
void			ts_decode_pts_dts		(uint8_t *data, uint64_t *value);

int				ts_packet_has_pes		(uint8_t *ts_packet, uint16_t *pes_packet_len);
int				ts_packet_has_pts_dts	(uint8_t *ts_packet, uint64_t *pts, uint64_t *dts);

void			ts_packet_change_pts		(uint8_t *ts_packet, uint64_t pts);
void			ts_packet_change_pts_dts	(uint8_t *ts_packet, uint64_t pts, uint64_t dts);

// TS packet headers
uint8_t *       ts_packet_header_parse    (uint8_t *ts_packet, struct ts_header *ts_header);
void            ts_packet_header_generate (uint8_t *ts_packet, struct ts_header *ts_header);
void            ts_packet_header_dump     (struct ts_header *ts_header);

// Sections
uint8_t *					ts_section_header_parse		(uint8_t *ts_packet, struct ts_header *ts_header, struct ts_section_header *ts_section_header);
void						ts_section_header_generate	(uint8_t *ts_packet, struct ts_section_header *ts_section_header, uint8_t start);
void						ts_section_header_dump		(struct ts_section_header *t);
void						ts_section_dump				(struct ts_section_header *sec);
void						ts_section_header_set_private_vars	(struct ts_section_header *ts_section_header);

int ts_section_is_same(struct ts_section_header *s1, struct ts_section_header *s2);

uint8_t *					ts_section_data_alloc_section	(void);
uint8_t *					ts_section_data_alloc_packet	(void);

struct ts_section_header *	ts_section_data_alloc			(void);
void						ts_section_data_clear			(struct ts_section_header *sec);
void						ts_section_data_free			(struct ts_section_header **ts_section_header);

void						ts_section_data_copy			(struct ts_section_header *src, struct ts_section_header *dst);

void						ts_section_add_packet		(struct ts_section_header *sec, struct ts_header *ts_header, uint8_t *ts_packet);

uint32_t					ts_section_data_calculate_crc	(uint8_t *section_data, int section_data_size);
void						ts_section_data_gen_ts_packets	(struct ts_header *ts_header, uint8_t *section_data, int section_data_sz, uint8_t pointer_field, uint8_t **packets, int *num_packets);


// PAT
struct ts_pat *	ts_pat_alloc		(void);
struct ts_pat * ts_pat_init			(struct ts_pat *pat, uint16_t transport_stream_id);
struct ts_pat * ts_pat_alloc_init	(uint16_t transport_stream_id);
struct ts_pat *	ts_pat_push_packet	(struct ts_pat *pat, uint8_t *ts_packet);
void            ts_pat_clear		(struct ts_pat *pat);
void            ts_pat_free			(struct ts_pat **pat);
int				ts_pat_parse		(struct ts_pat *pat);
void            ts_pat_dump			(struct ts_pat *pat);
void			ts_pat_generate		(struct ts_pat *pat, uint8_t **ts_packets, int *num_packets);

struct ts_pat *	ts_pat_copy					(struct ts_pat *pat);
void			ts_pat_regenerate_packets	(struct ts_pat *pat);

int             ts_pat_add_program	(struct ts_pat *pat, uint16_t program, uint16_t pat_pid);
int             ts_pat_del_program	(struct ts_pat *pat, uint16_t program);

int				ts_pat_is_same		(struct ts_pat *pat1, struct ts_pat *pat2);

// CAT
struct ts_cat *	ts_cat_alloc		(void);
struct ts_cat *	ts_cat_push_packet	(struct ts_cat *cat, uint8_t *ts_packet);
void            ts_cat_clear		(struct ts_cat *cat);
void            ts_cat_free			(struct ts_cat **cat);
int				ts_cat_parse		(struct ts_cat *cat);
void            ts_cat_dump			(struct ts_cat *cat);
struct ts_cat *	ts_cat_copy			(struct ts_cat *cat);
int				ts_cat_is_same		(struct ts_cat *cat1, struct ts_cat *cat2);

enum CA_system	ts_get_CA_sys		(uint16_t CA_id);
char *			ts_get_CA_sys_txt	(enum CA_system CA_sys);

int				ts_get_emm_info		(struct ts_cat *cat, enum CA_system CA_sys, uint16_t *CA_id, uint16_t *CA_pid);
int				ts_get_ecm_info		(struct ts_pmt *pmt, enum CA_system CA_sys, uint16_t *CA_id, uint16_t *CA_pid);

int				ts_get_emm_info_by_caid	(struct ts_cat *cat, uint16_t caid, uint16_t *ca_pid);
int				ts_get_ecm_info_by_caid	(struct ts_pmt *pmt, uint16_t caid, uint16_t *ca_pid);

int				ts_get_emm_info_by_pid	(struct ts_cat *cat, uint16_t *caid, uint16_t ca_pid);
int				ts_get_ecm_info_by_pid	(struct ts_pmt *pmt, uint16_t *caid, uint16_t ca_pid);

// PMT
struct ts_pmt *	ts_pmt_alloc		(void);
struct ts_pmt *	ts_pmt_push_packet	(struct ts_pmt *pmt, uint8_t *ts_packet);
void            ts_pmt_clear		(struct ts_pmt *pmt);
void            ts_pmt_free			(struct ts_pmt **pmt);
int				ts_pmt_parse		(struct ts_pmt *pmt);
void            ts_pmt_dump			(struct ts_pmt *pmt);
void			ts_pmt_generate		(struct ts_pmt *pmt, uint8_t **ts_packets, int *num_packets);

struct ts_pmt *	ts_pmt_copy					(struct ts_pmt *pmt);
void			ts_pmt_regenerate_packets	(struct ts_pmt *pmt);

int				ts_pmt_is_same		(struct ts_pmt *pmt1, struct ts_pmt *pmt2);

// NIT
struct ts_nit * ts_nit_alloc		(void);
struct ts_nit * ts_nit_init			(struct ts_nit *nit, uint16_t network_id);
struct ts_nit * ts_nit_alloc_init	(uint16_t network_id);
struct ts_nit *	ts_nit_push_packet	(struct ts_nit *nit, uint8_t *ts_packet);
void			ts_nit_clear		(struct ts_nit *nit);
void			ts_nit_free			(struct ts_nit **nit);
int				ts_nit_parse		(struct ts_nit *nit);
void			ts_nit_dump			(struct ts_nit *nit);
void			ts_nit_generate		(struct ts_nit *nit, uint8_t **ts_packets, int *num_packets);

int				ts_nit_add_network_name_descriptor			(struct ts_nit *nit, char *network_name);
int				ts_nit_add_frequency_list_descriptor_cable	(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint32_t *freqs, uint8_t num_freqs);
int				ts_nit_add_cable_delivery_descriptor		(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint32_t freq, uint8_t modulation, uint32_t symbol_rate);
int				ts_nit_add_service_list_descriptor			(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint32_t *services, uint8_t num_services);
int				ts_nit_add_nordig_specifier_descriptor		(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id);
int				ts_nit_add_lcn_descriptor					(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint32_t *services, uint8_t num_services);
int 			ts_nit_add_stream_descriptors				(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint32_t freq, uint8_t modulation, uint32_t symbol_rate, uint32_t *lcn_services, uint32_t *svc_services, uint8_t num_services);


struct ts_nit *	ts_nit_copy			(struct ts_nit *nit);
int				ts_nit_is_same		(struct ts_nit *nit1, struct ts_nit *nit2);

// SDT
struct ts_sdt *	ts_sdt_alloc		(void);
struct ts_sdt * ts_sdt_init			(struct ts_sdt *sdt, uint16_t org_network_id, uint16_t transport_stream_id);
struct ts_sdt * ts_sdt_alloc_init	(uint16_t org_network_id, uint16_t transport_stream_id);
struct ts_sdt *	ts_sdt_push_packet	(struct ts_sdt *sdt, uint8_t *ts_packet);
void            ts_sdt_clear		(struct ts_sdt *sdt);
void            ts_sdt_free			(struct ts_sdt **sdt);
int				ts_sdt_parse		(struct ts_sdt *sdt);
void            ts_sdt_dump			(struct ts_sdt *sdt);
void			ts_sdt_generate		(struct ts_sdt *sdt, uint8_t **ts_packets, int *num_packets);

int             ts_sdt_add_service_descriptor(struct ts_sdt *sdt, uint16_t service_id, uint8_t video, char *provider_name, char *service_name);

struct ts_sdt *	ts_sdt_copy			(struct ts_sdt *sdt);
int				ts_sdt_is_same		(struct ts_sdt *sdt1, struct ts_sdt *sdt2);

// EIT
struct ts_eit * ts_eit_alloc				(void);
struct ts_eit *	ts_eit_init					(struct ts_eit *eit, uint16_t service_id, uint16_t transport_stream_id, uint16_t org_network_id, uint8_t table_id, uint8_t sec_number, uint8_t last_sec_number);
struct ts_eit *	ts_eit_alloc_init			(uint16_t service_id, uint16_t transport_stream_id, uint16_t org_network_id, uint8_t table_id, uint8_t sec_number, uint8_t last_sec_number);
struct ts_eit *	ts_eit_alloc_init_pf		(uint16_t service_id, uint16_t transport_stream_id, uint16_t org_network_id, uint8_t sec_number, uint8_t last_sec_number);	// Shortcut using table_id 0x4e
struct ts_eit *	ts_eit_alloc_init_schedule	(uint16_t service_id, uint16_t transport_stream_id, uint16_t org_network_id, uint8_t sec_number, uint8_t last_sec_number);	// Shortcut using table_id 0x50

struct ts_eit *	ts_eit_push_packet	(struct ts_eit *eit, uint8_t *ts_packet);

void			ts_eit_clear		(struct ts_eit *eit);
void			ts_eit_free			(struct ts_eit **eit);
int				ts_eit_parse		(struct ts_eit *eit);
void			ts_eit_dump			(struct ts_eit *eit);
void			ts_eit_generate		(struct ts_eit *eit, uint8_t **ts_packets, int *num_packets);

struct ts_eit *	ts_eit_copy					(struct ts_eit *eit);
void			ts_eit_regenerate_packets	(struct ts_eit *eit);

int				ts_eit_add_short_event_descriptor	(struct ts_eit *eit, uint16_t event_id, uint8_t running, time_t start_time, int duration_sec, char *event_name, char *event_short_descr);
int				ts_eit_add_extended_event_descriptor(struct ts_eit *eit, uint16_t event_id, uint8_t running, time_t start_time, int duration_sec, char *text);

int				ts_eit_is_same		(struct ts_eit *eit1, struct ts_eit *eit2);

// TDT
struct ts_tdt *	ts_tdt_alloc(void);
struct ts_tdt *	ts_tdt_init			(struct ts_tdt *tdt, time_t ts);
struct ts_tdt *	ts_tot_init			(struct ts_tdt *tot, time_t ts);
struct ts_tdt *	ts_tdt_alloc_init	(time_t ts);
struct ts_tdt *	ts_tot_alloc_init	(time_t ts);
void			ts_tdt_clear		(struct ts_tdt *tdt);
void			ts_tdt_free			(struct ts_tdt **tdt);

int				ts_tdt_parse		(struct ts_tdt *tdt);
struct ts_tdt *	ts_tdt_push_packet	(struct ts_tdt *tdt, uint8_t *ts_packet);
void			ts_tdt_generate		(struct ts_tdt *tdt, uint8_t **ts_packets, int *num_packets);
void			ts_tdt_dump			(struct ts_tdt *tdt);

void			ts_tdt_set_time		(struct ts_tdt *tdt, time_t ts);

void			ts_tot_set_localtime_offset			(struct ts_tdt *tdt, time_t now, time_t change_time, uint8_t polarity, uint16_t ofs, uint16_t ofs_next);
void			ts_tot_set_localtime_offset_sofia	(struct ts_tdt *tdt, time_t now);

struct ts_tdt *	ts_tdt_copy			(struct ts_tdt *tdt);
int				ts_tdt_is_same		(struct ts_tdt *tdt1, struct ts_tdt *tdt2);

// Private section
struct ts_privsec *	ts_privsec_alloc(void);
void				ts_privsec_clear		(struct ts_privsec *pprivsec);
void				ts_privsec_free			(struct ts_privsec **pprivsec);

struct ts_privsec *	ts_privsec_push_packet	(struct ts_privsec *privsec, uint8_t *ts_packet);
int					ts_privsec_is_same		(struct ts_privsec *p1, struct ts_privsec *p2);
void				ts_privsec_dump			(struct ts_privsec *privsec);

void				ts_privsec_copy			(struct ts_privsec *src, struct ts_privsec *dst);

// Time
uint32_t		ts_time_encode_bcd	(int duration_sec);
void			ts_time_decode_bcd	(int duration_bcd, int *duration_sec, int *hour, int *min, int *sec);

void			ts_time_encode_mjd	(uint16_t *mjd, uint32_t *bcd, time_t *ts, struct tm *tm);
time_t			ts_time_decode_mjd	(uint16_t mjd, uint32_t bcd, struct tm *tm);

// Descriptors
void            ts_descriptor_dump      (uint8_t *desc_data, int desc_data_len);
int             ts_is_stream_type_video (uint8_t stream_type);
int             ts_is_stream_type_ac3   (uint8_t stream_type);
int             ts_is_stream_type_audio (uint8_t stream_type);
char *          h222_stream_type_desc   (uint8_t stream_type);
char *			h222_stream_id_desc		(uint8_t stream_id);

// PES
struct ts_pes *		ts_pes_alloc			(void);
void				ts_pes_clear			(struct ts_pes *pes);
void				ts_pes_free				(struct ts_pes **pes);

void				ts_pes_fill_type		(struct ts_pes *pes, struct ts_pmt *pmt, uint16_t pid);
int					ts_pes_is_finished		(struct ts_pes *pes, uint8_t *ts_packet);
struct ts_pes *		ts_pes_push_packet		(struct ts_pes *pes, uint8_t *ts_packet, struct ts_pmt *pmt, uint16_t pid);

int					ts_pes_parse			(struct ts_pes *pes);
void				ts_pes_dump				(struct ts_pes *pes);

struct pes_array *		pes_array_alloc			(void);
void					pes_array_dump			(struct pes_array *pa);
void					pes_array_free			(struct pes_array **ppa);

struct pes_entry *		pes_array_push_packet	(struct pes_array *pa, uint16_t pid, struct ts_pat *pat, struct ts_pmt *pmt, uint8_t *ts_packet);

// ES functions
int		ts_pes_es_mpeg_audio_header_parse		(struct mpeg_audio_header *mpghdr, uint8_t *data, int datasz);
void	ts_pes_es_mpeg_audio_header_dump		(struct mpeg_audio_header *mpghdr);
void	ts_pes_es_parse							(struct ts_pes *pes);
void	ts_pes_es_dump							(struct ts_pes *pes);


// CRC
uint32_t        ts_crc32      (uint8_t *data, int data_size);
uint32_t		ts_crc32_section			(struct ts_section_header *section_header);
int				ts_crc32_section_check		(struct ts_section_header *section_header, char *table);

// Misc
int				dec2bcd						(int dec);
int				bcd2dec						(int bcd);
void			ts_compare_data   			(char *prefix, uint8_t *a, uint8_t *b, int size);
void			ts_hex_dump_buf    			(char *buf, int bufsz, uint8_t *d, int size, int col);
char *			ts_hex_dump      			(uint8_t *d, int size, int col);
void			ts_print_bytes				(char *prefix, uint8_t *d, int size);
char *			init_dvb_string_utf8		(char *text);
char *			init_dvb_string_iso_8859_5	(char *text);
int				ts_is_psi_pid				(uint16_t pid, struct ts_pat *pat);

void			pidmap_clear				(pidmap_t *pm);
void			pidmap_set					(pidmap_t *pm, uint16_t pid);
void			pidmap_set_val				(pidmap_t *pm, uint16_t pid, uint8_t val);
int				pidmap_get					(pidmap_t *pm, uint16_t pid);

#endif
