/*
 * Logger function
 * Copyright (C) 2010-2011 Unix Solutions Ltd.
 *
 * Released under MIT license.
 * See LICENSE-MIT.txt for license terms.
 */
#include <stdio.h>
#include <stdarg.h>

#include "log.h"

void ts_LOG_default(const char *msg) {
	fprintf(stdout, "%s", msg);
}

static void (*ts_LOG_callback)(const char *msg) = ts_LOG_default;

void ts_LOGf(const char *fmt, ...) {
	char msg[1024];
	va_list args;
	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg)-1, fmt, args);
	va_end(args);
	msg[sizeof(msg)-2] = '\n';
	msg[sizeof(msg)-1] = '\0';
	ts_LOG_callback(msg);
}

void ts_set_log_func(void (*LOG_func)(const char *msg)) {
	ts_LOG_callback = LOG_func;
}
