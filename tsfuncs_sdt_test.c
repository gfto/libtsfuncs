int ts_sdt_test() {
	struct ts_sdt *sdt = ts_sdt_alloc_init(1, 2);

	ts_sdt_add_service_descriptor(sdt, 1007, 1, "BULSATCOM", "bTV");
	ts_sdt_dump(sdt);

	int i;
	for (i=0;i<120;i++) {
		ts_sdt_add_service_descriptor(sdt, 9,  0, "PROVIDER", "SERVICE33333333333333333333333333333333333333333333333333333333333333");
		ts_sdt_add_service_descriptor(sdt, 13, 0, "PROddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddVIDER", "SERVICE");
		ts_sdt_add_service_descriptor(sdt, 7,  0, "PROVIDER", "SERVICE");
	}
	ts_sdt_dump(sdt);

	write(1, sdt->section_header->packet_data, sdt->section_header->num_packets * 188);
	ts_sdt_free(sdt);
	return 0;
}
