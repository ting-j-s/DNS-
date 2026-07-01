#ifndef PLATFORM_WIN_H
#define PLATFORM_WIN_H

/* ── Public API ───────────────────────────────────────────────── */
int  platform_socket_init(void);
void platform_socket_cleanup(void);
int  platform_get_last_error(void);
const char *platform_get_error_message(int error_code);

#endif /* PLATFORM_WIN_H */
