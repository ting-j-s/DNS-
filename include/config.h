#ifndef CONFIG_H
#define CONFIG_H

/* ── Config object ────────────────────────────────────────────── */
typedef struct {
    int   debug_level;        /* 0=none, 1=-d, 2=-dd              */
    char  upstream_dns[64];   /* upstream DNS server IP           */
    char  filename[512];      /* resource record file path        */
    int   listen_port;        /* listening port (default 53)      */
} Config;

/* ── Public API ───────────────────────────────────────────────── */
void config_init_default(Config *cfg);
int  config_parse_args(Config *cfg, int argc, char **argv);
void config_print(const Config *cfg);

#endif /* CONFIG_H */
