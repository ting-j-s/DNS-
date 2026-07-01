#include "logger.h"
#include <stdio.h>
#include <stdarg.h>

static int g_debug_level = LOG_LEVEL_ERROR;

void logger_init(int debug_level) {
    g_debug_level = debug_level;
}

void logger_error(const char *fmt, ...) {
    if (g_debug_level < LOG_LEVEL_ERROR) return;
    fprintf(stdout, "[ERROR] ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stdout);
}

void logger_info(const char *fmt, ...) {
    if (g_debug_level < LOG_LEVEL_INFO) return;
    fprintf(stdout, "[INFO] ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stdout);
}

void logger_debug(const char *fmt, ...) {
    if (g_debug_level < LOG_LEVEL_DEBUG) return;
    fprintf(stdout, "[DEBUG] ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stdout);
}

void logger_trace(const char *fmt, ...) {
    if (g_debug_level < LOG_LEVEL_TRACE) return;
    fprintf(stdout, "[TRACE] ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stdout);
}
