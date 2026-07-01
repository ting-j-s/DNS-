#include "config.h"
#include "common.h"
#include "logger.h"
#include <string.h>

void config_init_default(Config *cfg) {
    if (!cfg) return;
    cfg->debug_level = 0;
    strncpy(cfg->upstream_dns, DEFAULT_UPSTREAM_DNS, sizeof(cfg->upstream_dns) - 1);
    cfg->upstream_dns[sizeof(cfg->upstream_dns) - 1] = '\0';
    strncpy(cfg->filename, DEFAULT_RESOURCE_FILE, sizeof(cfg->filename) - 1);
    cfg->filename[sizeof(cfg->filename) - 1] = '\0';
    cfg->listen_port = DEFAULT_LISTEN_PORT;
}

int config_parse_args(Config *cfg, int argc, char **argv) {
    if (!cfg) return -1;

    config_init_default(cfg);
    int positional = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-dd") == 0) {
            cfg->debug_level = 2;
        } else if (strcmp(argv[i], "-d") == 0) {
            cfg->debug_level = 1;
        } else {
            positional++;
            if (positional == 1) {
                strncpy(cfg->upstream_dns, argv[i], sizeof(cfg->upstream_dns) - 1);
                cfg->upstream_dns[sizeof(cfg->upstream_dns) - 1] = '\0';
            } else if (positional == 2) {
                strncpy(cfg->filename, argv[i], sizeof(cfg->filename) - 1);
                cfg->filename[sizeof(cfg->filename) - 1] = '\0';
            }
        }
    }

    return 0;
}

void config_print(const Config *cfg) {
    if (!cfg) return;
    LOG_INFO("debug_level   = %d", cfg->debug_level);
    LOG_INFO("upstream_dns  = %s", cfg->upstream_dns);
    LOG_INFO("filename      = %s", cfg->filename);
    LOG_INFO("listen_port   = %d", cfg->listen_port);
}
