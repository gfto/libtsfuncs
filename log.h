/*
 * Logger function header file
 * Copyright (C) 2010-2011 Unix Solutions Ltd.
 *
 * Released under MIT license.
 * See LICENSE-MIT.txt for license terms.
 */
#ifndef LIBTS_LOG_H
#define LIBTS_LOG_H

__attribute__ ((format(printf, 1, 2)))
void ts_LOGf(const char *fmt, ...);

void ts_set_log_func(void (*LOG_func)(const char *msg));

#endif
