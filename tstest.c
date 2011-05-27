#include "tsfuncs.h"

#define NOW 1234567890

void ts_pat_test() {
	struct ts_pat *pat = ts_pat_alloc_init(0x7878);

	ts_pat_dump(pat);
	ts_pat_add_program(pat, 1, 0x100);
	ts_pat_add_program(pat, 2, 0x100);
	ts_pat_add_program(pat, 3, 0x100);
	ts_pat_dump(pat);

	ts_pat_del_program(pat, 2);
	ts_pat_dump(pat);

	ts_pat_del_program(pat, 3);
	ts_pat_dump(pat);

	int i;
	for (i=0;i<10;i++) {
		ts_pat_add_program(pat, i+10, (i+5)*10);
	}

	ts_pat_dump(pat);

	ts_pat_free(&pat);
}

int ts_sdt_test() {
	struct ts_sdt *sdt = ts_sdt_alloc_init(1, 2);

	ts_sdt_add_service_descriptor(sdt, 1007, 1, "BULSATCOM", "bTV");
	ts_sdt_dump(sdt);

	int i;
	for (i=0;i<25;i++) {
		ts_sdt_add_service_descriptor(sdt, 9,  0, "PROVIDER", "SERVICE33333333333333333333333333333333333333333333333333333333333333");
		ts_sdt_add_service_descriptor(sdt, 13, 0, "PROddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddVIDER", "SERVICE");
		ts_sdt_add_service_descriptor(sdt, 7,  0, "PROVIDER", "SERVICE");
	}
	ts_sdt_dump(sdt);

//	write(1, sdt->section_header->packet_data, sdt->section_header->num_packets * 188);
	ts_sdt_free(&sdt);
	return 0;
}

void ts_eit_test1(struct ts_eit *eit) { // Exactly one TS packet (188 bytes)
//int ts_eit_add_short_event_descriptor(struct ts_eit *eit, uint16_t event_id, uint8_t running, time_t start_time, int duration_sec, char *event_name, char *event_short_descr) {

	ts_eit_add_short_event_descriptor(eit, 4, 1, NOW, 3600,
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy****");
}

void ts_eit_test2(struct ts_eit *eit) { // One TS packet + 2 bytes (2 bytes of the CRC are in the next packet
	ts_eit_add_short_event_descriptor(eit, 4, 1, NOW, 3600,
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy**");
}

void ts_eit_test3(struct ts_eit *eit) { // Test 4096 PSI packet
	int i;
	for (i=0;i<15;i++) {
		// Maximum descriptor size, 255 bytes
		if (ts_eit_add_short_event_descriptor(eit, 4, 1, NOW, 3600, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") != 1) {
			break;
		}
	}
	ts_eit_add_short_event_descriptor(eit, 4, 1, NOW, 3600, "00000000000000000000000", "1111111111111111111111111111111");
}

void ts_eit_test4(struct ts_eit *eit) { // Test almost full PSI packet on the TS packet boundary
	int i;
	for (i=0;i<15;i++) {
		// Maximum descriptor size, 255 bytes
		if (ts_eit_add_short_event_descriptor(eit, 4, 1, NOW, 3600, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") != 1) {
			break;
		}
	}
	ts_eit_add_short_event_descriptor(eit, 4, 1, NOW, 3600, "aaaaaaaaBBBB", NULL);
}

void ts_eit_test() {
	struct ts_eit *eit;

	eit = ts_eit_alloc_init(1, 2, 3, 1, 0, 0);
	ts_eit_test1(eit);
	ts_eit_dump(eit);
	ts_eit_free(&eit);

	eit = ts_eit_alloc_init(1, 2, 3, 1, 0, 0);
	ts_eit_test2(eit);
	ts_eit_dump(eit);
	ts_eit_free(&eit);

	eit = ts_eit_alloc_init(1, 2, 3, 1, 0, 0);
	ts_eit_test3(eit);
	ts_eit_dump(eit);
	ts_eit_free(&eit);

	eit = ts_eit_alloc_init(1, 2, 3, 1, 0, 0);
	ts_eit_test4(eit);
	ts_eit_dump(eit);
	ts_eit_free(&eit);
//	write(1, eit->section_header->packet_data, eit->section_header->num_packets * TS_PACKET_SIZE);
}

int main() {
	ts_pat_test();
	ts_sdt_test();
	ts_eit_test();
	return 0;
}
