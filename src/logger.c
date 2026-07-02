#include "logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

static int           g_debug_level = LOG_LEVEL_ERROR;
static unsigned long g_log_seq     = 0;

/* ── Format common log prefix: [seq] timestamp [LEVEL] ─────────────── */
static void logger_prefix(const char *level_tag)
{
    time_t     now;
    struct tm  tm_info;
    char       time_buf[32];

    g_log_seq++;

    now = time(NULL);
    localtime_s(&tm_info, &now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

    fprintf(stdout, "[%06lu] %s [%s] ",
            g_log_seq, time_buf, level_tag);
}

void logger_init(int debug_level) {
    g_debug_level = debug_level;
    g_log_seq     = 0;
}

void logger_error(const char *fmt, ...) {
    if (g_debug_level < LOG_LEVEL_ERROR) return;
    logger_prefix("ERROR");
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stdout);
}

void logger_info(const char *fmt, ...) {
    if (g_debug_level < LOG_LEVEL_INFO) return;
    logger_prefix("INFO");
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stdout);
}

void logger_debug(const char *fmt, ...) {
    if (g_debug_level < LOG_LEVEL_DEBUG) return;
    logger_prefix("DEBUG");
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stdout);
}

void logger_trace(const char *fmt, ...) {
    if (g_debug_level < LOG_LEVEL_TRACE) return;
    logger_prefix("TRACE");
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stdout);
}
