/*
 * DVB time functions
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
#include <time.h>

#include "tsfuncs.h"

uint32_t ts_time_encode_bcd(int duration_sec) {
	int t_sec, t_min, t_hour, ret;
	t_sec  = duration_sec % 60;
	t_min  = (duration_sec - t_sec) / 60;
	t_hour = (t_min - t_min % 60) / 60;
	t_min  = t_min - t_hour * 60;

	ret  = dec2bcd(t_hour) << 16;
	ret |= dec2bcd(t_min ) << 8;
	ret |= dec2bcd(t_sec );

	return ret;
}

void ts_time_decode_bcd(int duration_bcd, int *duration_sec, int *hour, int *min, int *sec) {
	*hour = bcd2dec( (duration_bcd &~ 0xff00ffff) >> 16 );	// 11111111 xxxxxxxx xxxxxxxx
	*min  = bcd2dec( (duration_bcd &~ 0xffff00ff) >> 8 );	// xxxxxxxx 11111111 xxxxxxxx
	*sec  = bcd2dec( (duration_bcd &~ 0xffffff00) );		// xxxxxxxx xxxxxxxx 11111111
	if (duration_sec)
		*duration_sec = *hour * 3600 + *min * 60 + *sec;
}

void ts_time_encode_mjd(uint16_t *mjd, uint32_t *bcd, time_t *ts, struct tm *tm) {
	struct tm *ltm = tm;
	if (!ts && !tm)
		return;
	if (ts) { // Decompose ts into struct tm
		struct tm dectm;
		gmtime_r(ts, &dectm);
		ltm = &dectm;
	}
	if (!ltm) // Paranoia
		return;
	if (mjd) { // Encode ymd into mjd
		int Y = ltm->tm_year; // 1900 + Y gives the real year
		int M = ltm->tm_mon + 1;
		int D = ltm->tm_mday;
		int L = (M == 1 || M == 2) ? 1 : 0;
		*mjd = 14956 + D + (int)((Y - L) * 365.25) + (int)((M + 1 + L * 12) * 30.6001);
	}
	if (bcd) { // Encode hms into bcd
		*bcd  = 0;
		*bcd  = dec2bcd(ltm->tm_hour) << 16;
		*bcd |= dec2bcd(ltm->tm_min ) << 8;
		*bcd |= dec2bcd(ltm->tm_sec );
	}
}

time_t ts_time_decode_mjd(uint16_t mjd, uint32_t bcd, struct tm *tm) {
	int year = 0, month = 0, day = 0;
	int hour = 0, min = 0, sec = 0;
	time_t ret = 0;
	if (mjd > 0) {
		long tmp;
		// Copied from ETSI EN 300 468 (ANNEX C)
		year  = (int)((mjd - 15078.2) / 365.25);
		month = (int)((mjd - 14956.1 - (int)(year * 365.25)) / 30.6001);
		day   = mjd - 14956 - (int)(year * 365.25) - (int)(month * 30.6001);
		tmp   = (month == 14 || month == 15) ? 1 : 0;
		year  = year + tmp;
		month = month - 1 - tmp * 12;
		year  += 1900;
	}
	if (bcd > 0) {
		ts_time_decode_bcd(bcd, NULL, &hour, &min, &sec);
	}
	if (tm) {
		memset(tm, 0, sizeof(struct tm));
		tm->tm_year = year - 1900;
		tm->tm_mon  = month - 1;
		tm->tm_mday = day;
		tm->tm_hour = hour;
		tm->tm_min  = min;
		tm->tm_sec  = sec;
		ret = timegm(tm);
	}
	return ret;
}
