
void ts_test_pat() {
	struct ts_pat *pat = ts_pat_init_empty();

	ts_pat_dump(pat);
	ts_pat_check_generator(pat, 0);

	ts_pat_add_program(pat, 1, 0x100);
	ts_pat_dump(pat);
/*
//	ts_pat_check_generator(pat);

	struct ts_pat *pat1 = calloc(1, sizeof(struct ts_pat));

	ts_pat_init(pat1, pat->packet_data);
	ts_pat_dump(pat1);
	ts_pat_free(pat1);
*/
/*
	ts_pat_add_program(pat, 1, 0x100);
	ts_pat_add_program(pat, 2, 0x100);
	ts_pat_add_program(pat, 3, 0x100);
	ts_pat_dump(pat);
	ts_pat_check_generator(pat);

	ts_pat_del_program(pat, 3);
	ts_pat_dump(pat);
	ts_pat_check_generator(pat);

//	int i;
//	for (i=0;i<10;i++) {
//		ts_pat_add_program(pat, i+10, (i+5)*10);
//	}

	ts_pat_dump(pat);
	ts_pat_check_generator(pat);
*/
	ts_pat_free(pat);
}
