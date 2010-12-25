#include "tsfuncs.h"

void test1(struct ts_eit *eit) { // Exactly one TS packet (188 bytes)
	ts_eit_add_short_event_descriptor(eit, 4, time(NULL), 3600,
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy****");
}

void test2(struct ts_eit *eit) { // One TS packet + 2 bytes (2 bytes of the CRC are in the next packet
	ts_eit_add_short_event_descriptor(eit, 4, time(NULL), 3600,
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy**");
}

void test3(struct ts_eit *eit) { // Test 4096 PSI packet
	int i;
	for (i=0;i<15;i++) {
		// Maximum descriptor size, 255 bytes
		if (ts_eit_add_short_event_descriptor(eit, 4, time(NULL), 3600, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") != 1) {
			break;
		}
	}
	ts_eit_add_short_event_descriptor(eit, 4, time(NULL), 3600, "00000000000000000000000", "1111111111111111111111111111111");
}

void test4(struct ts_eit *eit) { // Test almost full PSI packet on the TS packet boundary
	int i;
	for (i=0;i<15;i++) {
		// Maximum descriptor size, 255 bytes
		if (ts_eit_add_short_event_descriptor(eit, 4, time(NULL), 3600, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") != 1) {
			break;
		}
	}
	ts_eit_add_short_event_descriptor(eit, 4, time(NULL), 3600, "aaaaaaaaBBBB", NULL);
}

int main(int argc, char **argv) {
	int i;
	struct ts_eit *eit = ts_eit_alloc_init(1, 2, 3);

//	test1(eit);
//	test2(eit);
//	test3(eit);
//	test4(eit);

	ts_eit_dump(eit);
//	write(1, eit->section_header->packet_data, eit->section_header->num_packets * TS_PACKET_SIZE);

	ts_eit_free(eit);
	return 0;
}
