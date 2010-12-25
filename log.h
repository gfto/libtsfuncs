#ifndef LIBTS_LOG_H
#define LIBTS_LOG_H

__attribute__ ((format(printf, 1, 2)))
void ts_LOGf(const char *fmt, ...);

void ts_set_log_func(void (*LOG_func)(const char *msg));

#endif
