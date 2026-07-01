#ifndef LOGGER_H
#define LOGGER_H

/* ── Log levels ───────────────────────────────────────────────── */
#define LOG_LEVEL_ERROR  0
#define LOG_LEVEL_INFO   1
#define LOG_LEVEL_DEBUG  2
#define LOG_LEVEL_TRACE  3

/* ── Public API ───────────────────────────────────────────────── */
void logger_init(int debug_level);

void logger_error(const char *fmt, ...);
void logger_info(const char *fmt, ...);
void logger_debug(const char *fmt, ...);
void logger_trace(const char *fmt, ...);

/* ── Convenience macros (include file:line) ───────────────────── */
#define LOG_ERROR(fmt, ...)  logger_error(fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)   logger_info(fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...)  logger_debug(fmt, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...)  logger_trace(fmt, ##__VA_ARGS__)

#endif /* LOGGER_H */
