/*
 * Working with PES entries
 * Copyright (C) 2010-2011 Unix Solutions Ltd.
 *
 * Released under MIT license.
 * See LICENSE-MIT.txt for license terms.
 */
#include <stdlib.h>
#include <string.h>

#include "tsdata.h"
#include "tsfuncs.h"

#define START_ENTRIES 1
#define ENTRIES_INCREMENT 1

static struct pes_entry *pes_entry_alloc(uint16_t pid) {
	//ts_LOGf("Alloc pes_entry pid = %03x\n", pid);
	struct pes_entry *e = malloc(sizeof(struct pes_entry));
	e->pid = pid;
	e->pes = ts_pes_alloc();
	e->pes_next = NULL;
	return e;
}

static void pes_entry_free(struct pes_entry **pentry) {
	struct pes_entry *entry = *pentry;
	if (entry) {
		ts_pes_free(&entry->pes);
		ts_pes_free(&entry->pes_next);
		FREE(*pentry);
	}
}

static struct pes_entry *pes_entry_find(struct pes_array *pa, uint16_t pid) {
	int i;
	for (i=0;i<pa->max;i++) {
		struct pes_entry *e = pa->entries[i];
		if (e && e->pid == pid) {
			return e;
		}
	}
	return NULL;
}



struct pes_array *pes_array_alloc() {
	struct pes_array *pa = calloc(1, sizeof(struct pes_array));
	pa->max = START_ENTRIES;
	pa->entries = calloc(sizeof(struct pes_entry *), pa->max);
	return pa;
}

struct pes_array *pes_array_realloc(struct pes_array *pa) {
	pa->max += ENTRIES_INCREMENT;
	pa->entries = realloc(pa->entries, sizeof(struct pes_entry *) * pa->max);
	memset(&pa->entries[pa->cur], 0, sizeof(struct pes_entry *) * ((pa->max-1) - pa->cur));
	return pa;
}

void pes_array_dump(struct pes_array *pa) {
	int i;
	ts_LOGf("pa->max=%d\n", pa->max);
	ts_LOGf("pa->cur=%d\n", pa->cur);
	for (i=0;i<pa->max;i++) {
		ts_LOGf("pa->entry[%d]=0x%p\n", i, pa->entries[i]);
		if (pa->entries[i]) {
			ts_LOGf("pa->entry[%d]->pid=%03x\n", i, pa->entries[i]->pid);
			ts_LOGf("pa->entry[%d]->pes=%p\n", i, pa->entries[i]->pes);
			ts_pes_dump(pa->entries[i]->pes);
		}
	}
}

void pes_array_free(struct pes_array **ppa) {
	int i;
	struct pes_array *pa = *ppa;
	if (pa) {
		for (i=0;i<pa->max;i++) {
			pes_entry_free(&pa->entries[i]);
		}
		free(pa->entries);
		FREE(*ppa);
	}
}

struct pes_entry *pes_array_push_packet(struct pes_array *pa, uint16_t pid, struct ts_pat *pat, struct ts_pmt *pmt, uint8_t *ts_packet) {
	int i;

	if (ts_is_psi_pid(pid, pat))
		return NULL;

	struct pes_entry *p = pes_entry_find(pa, pid); // Find existing entry
	if (!p) { // New entry!
		int pes_carrying_pid = 0; // check if PID is mentioned in PMT
		for (i=0;i<pmt->streams_num;i++) {
			struct ts_pmt_stream *stream = pmt->streams[i];
			// Stream_type 0x80..0xff - user private
			// Stream_type 0x05       - private sections
			if (stream->pid == pid) {
				switch (stream->stream_type) {
					case 0x01: // return "11172-2 video (MPEG-1)";
					case 0x02: // return "H.262/13818-2 video (MPEG-2) or 11172-2 constrained video";
					case 0x03: // return "11172-3 audio (MPEG-1)";
					case 0x04: // return "13818-3 audio (MPEG-2)";
					case 0x06: // return "H.222.0/13818-1 PES private data";
					case 0x07: // return "13522 MHEG";
					case 0x08: // return "H.222.0/13818-1 Annex A - DSM CC";
					case 0x09: // return "H.222.1";
					case 0x0A: // return "13818-6 type A";
					case 0x0B: // return "13818-6 type B";
					case 0x0C: // return "13818-6 type C";
					case 0x0D: // return "13818-6 type D";
					case 0x0E: // return "H.222.0/13818-1 auxiliary";
					case 0x0F: // return "13818-7 Audio with ADTS transport syntax";
					case 0x10: // return "14496-2 Visual (MPEG-4 part 2 video)";
					case 0x11: // return "14496-3 Audio with LATM transport syntax (14496-3/AMD 1)";
					case 0x15: // return "Metadata in PES packets";
					case 0x1B: // return "H.264/14496-10 video (MPEG-4/AVC)";
					case 0x42: // return "AVS Video";
						pes_carrying_pid = 1;
				}
				break;
			}
		}
		if (!pes_carrying_pid) // We are not interrested
			return NULL;

		if (pa->cur >= pa->max) // Is there enough space in pes_array
			pa = pes_array_realloc(pa); // Try to get some more

		p = pes_entry_alloc(pid);
		pa->entries[pa->cur++] = p;
	}

	// Last packet finished video PES and we saved it here
	if (p->pes_next) {
		ts_pes_free(&p->pes);
		p->pes = p->pes_next;
		p->pes_next = NULL;
	}

	// Video PES packets have unknown size, so we need to look one packet in the
	// future to know when video PES is finished.
	if (ts_pes_is_finished(p->pes, ts_packet)) {
		p->pes_next = ts_pes_alloc();
		p->pes_next = ts_pes_push_packet(p->pes_next, ts_packet, pmt, pid);
	} else {
		p->pes = ts_pes_push_packet(p->pes, ts_packet, pmt, pid);
	}

	return p;
}
