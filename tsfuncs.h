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

int             ts_packet_is_pusi   (uint8_t *ts_packet);

uint16_t        ts_packet_get_pid   (uint8_t *ts_packet);
void            ts_packet_set_pid   (uint8_t *ts_packet, uint16_t new_pid);

uint8_t         ts_packet_get_cont  (uint8_t *ts_packet);
void            ts_packet_set_cont  (uint8_t *ts_packet, uint8_t value);
void            ts_packet_inc_cont  (uint8_t *ts_packet, uint8_t increment);

uint8_t         ts_packet_get_payload_offset(uint8_t *ts_packet);

int             ts_packet_is_scrambled(uint8_t *ts_packet);
void            ts_packet_set_scrambled(uint8_t *ts_packet, enum ts_scrambled_type stype);

int				ts_packet_has_pcr		(uint8_t *ts_packet);
uint64_t		ts_packet_get_pcr_ex	(uint8_t *ts_packet, uint64_t *pcr_base, uint16_t *pcr_ext);
uint64_t		ts_packet_get_pcr		(uint8_t *ts_packet);
void			ts_packet_set_pcr_ex	(uint8_t *ts_packet, uint64_t pcr_base, uint16_t pcr_ext);
void			ts_packet_set_pcr		(uint8_t *ts_packet, uint64_t pcr);

void			ts_encode_pts_dts		(uint8_t *data, int guard_bits, uint64_t value);
int				ts_decode_pts_dts		(uint8_t *data, int required_guard, uint64_t *value);

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

uint8_t *					ts_section_data_alloc_section	();
uint8_t *					ts_section_data_alloc_packet	();

struct ts_section_header *	ts_section_data_alloc			();
void						ts_section_data_free			(struct ts_section_header **ts_section_header);

void						ts_section_add_packet		(struct ts_section_header *sec, struct ts_header *ts_header, uint8_t *ts_packet);

uint32_t					ts_section_data_calculate_crc	(uint8_t *section_data, int section_data_size);
void						ts_section_data_gen_ts_packets	(struct ts_header *ts_header, uint8_t *section_data, int section_data_sz, uint8_t pointer_field, uint8_t **packets, int *num_packets);


// PAT
struct ts_pat *	ts_pat_alloc		();
struct ts_pat * ts_pat_alloc_init	(uint16_t transport_stream_id);
struct ts_pat *	ts_pat_push_packet	(struct ts_pat *pat, uint8_t *ts_packet);
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
struct ts_cat *	ts_cat_alloc		();
struct ts_cat *	ts_cat_push_packet	(struct ts_cat *cat, uint8_t *ts_packet);
void            ts_cat_free			(struct ts_cat **cat);
int				ts_cat_parse		(struct ts_cat *cat);
void            ts_cat_dump			(struct ts_cat *cat);
int				ts_cat_is_same		(struct ts_cat *cat1, struct ts_cat *cat2);

enum CA_system	ts_get_CA_sys		(uint16_t CA_id);
char *			ts_get_CA_sys_txt	(enum CA_system CA_sys);

int				ts_get_emm_info		(struct ts_cat *cat, enum CA_system CA_sys, uint16_t *CA_id, uint16_t *CA_pid);
int				ts_get_ecm_info		(struct ts_pmt *pmt, enum CA_system CA_sys, uint16_t *CA_id, uint16_t *CA_pid);

// PMT
struct ts_pmt *	ts_pmt_alloc		();
struct ts_pmt * ts_pmt_alloc_init	(uint16_t org_network_id, uint16_t transport_stream_id);
struct ts_pmt *	ts_pmt_push_packet	(struct ts_pmt *pmt, uint8_t *ts_packet, uint16_t pmt_pid);
void            ts_pmt_free			(struct ts_pmt **pmt);
int				ts_pmt_parse		(struct ts_pmt *pmt);
void            ts_pmt_dump			(struct ts_pmt *pmt);
void			ts_pmt_generate		(struct ts_pmt *pmt, uint8_t **ts_packets, int *num_packets);

struct ts_pmt *	ts_pmt_copy					(struct ts_pmt *pmt);
void			ts_pmt_regenerate_packets	(struct ts_pmt *pmt);

int				ts_pmt_is_same		(struct ts_pmt *pmt1, struct ts_pmt *pmt2);

// NIT
struct ts_nit * ts_nit_alloc		();
struct ts_nit * ts_nit_alloc_init	(uint16_t network_id);
struct ts_nit *	ts_nit_push_packet	(struct ts_nit *nit, uint8_t *ts_packet);
void			ts_nit_free			(struct ts_nit **nit);
int				ts_nit_parse		(struct ts_nit *nit);
void			ts_nit_dump			(struct ts_nit *nit);
void			ts_nit_generate		(struct ts_nit *nit, uint8_t **ts_packets, int *num_packets);

int				ts_nit_add_network_name_descriptor			(struct ts_nit *nit, char *network_name);
int				ts_nit_add_frequency_list_descriptor_cable	(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint32_t *freqs, uint8_t num_freqs);
int				ts_nit_add_cable_delivery_descriptor		(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint32_t freq, uint8_t modulation, uint32_t symbol_rate);
int				ts_nit_add_service_list_descriptor			(struct ts_nit *nit, uint16_t ts_id, uint16_t org_net_id, uint32_t *services, uint8_t num_services);

// SDT
struct ts_sdt *	ts_sdt_alloc		();
struct ts_sdt * ts_sdt_alloc_init	(uint16_t org_network_id, uint16_t transport_stream_id);
struct ts_sdt *	ts_sdt_push_packet	(struct ts_sdt *sdt, uint8_t *ts_packet);
void            ts_sdt_free			(struct ts_sdt **sdt);
int				ts_sdt_parse		(struct ts_sdt *sdt);
void            ts_sdt_dump			(struct ts_sdt *sdt);
void			ts_sdt_generate		(struct ts_sdt *sdt, uint8_t **ts_packets, int *num_packets);

int             ts_sdt_add_service_descriptor(struct ts_sdt *sdt, uint16_t service_id, uint8_t video, char *provider_name, char *service_name);

// EIT
struct ts_eit * ts_eit_alloc				();
struct ts_eit *	ts_eit_alloc_init			(uint16_t service_id, uint16_t transport_stream_id, uint16_t org_network_id, uint8_t table_id, uint8_t sec_number, uint8_t last_sec_number);
struct ts_eit *	ts_eit_alloc_init_pf		(uint16_t service_id, uint16_t transport_stream_id, uint16_t org_network_id, uint8_t sec_number, uint8_t last_sec_number);	// Shortcut using table_id 0x4e
struct ts_eit *	ts_eit_alloc_init_schedule	(uint16_t service_id, uint16_t transport_stream_id, uint16_t org_network_id, uint8_t sec_number, uint8_t last_sec_number);	// Shortcut using table_id 0x50

struct ts_eit *	ts_eit_push_packet	(struct ts_eit *eit, uint8_t *ts_packet);

void			ts_eit_free			(struct ts_eit **eit);
int				ts_eit_parse		(struct ts_eit *eit);
void			ts_eit_dump			(struct ts_eit *eit);
void			ts_eit_generate		(struct ts_eit *eit, uint8_t **ts_packets, int *num_packets);

struct ts_eit *	ts_eit_copy					(struct ts_eit *eit);
void			ts_eit_regenerate_packets	(struct ts_eit *eit);

int				ts_eit_add_short_event_descriptor	(struct ts_eit *eit, uint16_t event_id, uint8_t running, time_t start_time, int duration_sec, char *event_name, char *event_short_descr);
int				ts_eit_add_extended_event_descriptor(struct ts_eit *eit, uint16_t event_id, uint8_t running, time_t start_time, int duration_sec, char *text);

// TDT
struct ts_tdt *	ts_tdt_alloc_init	(time_t ts);
struct ts_tdt *	ts_tot_alloc_init	(time_t ts);
void			ts_tdt_free			(struct ts_tdt **tdt);

int				ts_tdt_parse		(struct ts_tdt *tdt, uint8_t *ts_packet);
void			ts_tdt_generate		(struct ts_tdt *tdt, uint8_t *ts_packet);
void			ts_tdt_dump			(struct ts_tdt *tdt);

void			ts_tdt_set_time		(struct ts_tdt *tdt, time_t ts);

void			ts_tot_set_localtime_offset			(struct ts_tdt *tdt, time_t now, time_t change_time, uint8_t polarity, uint16_t ofs, uint16_t ofs_next);
void			ts_tot_set_localtime_offset_sofia	(struct ts_tdt *tdt);

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
struct ts_pes *		ts_pes_alloc			();
void				ts_pes_free				(struct ts_pes **pes);
struct ts_pes *		ts_pes_reset			(struct ts_pes *pes);

void				ts_pes_fill_type		(struct ts_pes *pes, struct ts_pmt *pmt, uint16_t pid);
int					ts_pes_is_finished		(struct ts_pes *pes, uint8_t *ts_packet);
struct ts_pes *		ts_pes_push_packet		(struct ts_pes *pes, uint8_t *ts_packet, struct ts_pmt *pmt, uint16_t pid);

int					ts_pes_parse			(struct ts_pes *pes);
void				ts_pes_dump				(struct ts_pes *pes);

struct pes_array *		pes_array_alloc			();
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

// Misc
int				dec2bcd						(int dec);
int				bcd2dec						(int bcd);
void			ts_compare_data   			(char *prefix, uint8_t *a, uint8_t *b, int size);
char *			ts_hex_dump      			(uint8_t *d, int size);
void			ts_print_bytes				(char *prefix, uint8_t *d, int size);
char *			init_dvb_string_utf8		(char *text);
char *			init_dvb_string_iso_8859_5	(char *text);
int				ts_is_psi_pid				(uint16_t pid, struct ts_pat *pat);

// Shortcuts
int parse_tdt   (uint8_t *ts_packet, int dump);

#endif
