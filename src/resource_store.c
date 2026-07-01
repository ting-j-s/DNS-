#include "resource_store.h"
#include "logger.h"
#include <stdio.h>
#include <string.h>

/* ── Maximum line length for resource file ────────────────────────── */
#define RESOURCE_FILE_MAX_LINE  512

/* ── Helper: convert string to lower-case in place ────────────────── */
static void str_tolower(char *s)
{
    for (; *s; s++) {
        if (*s >= 'A' && *s <= 'Z') {
            *s = (char)(*s + ('a' - 'A'));
        }
    }
}

/* ── Helper: parse IPv4 dotted string into network-byte-order uint32
 *   bytes[0] = first octet (lowest address, correct for DNS wire) ── */
static int parse_ipv4(const char *str, uint32_t *ip_out)
{
    int a, b, c, d;
    int n;
    char extra;
    uint8_t *bytes;

    /* sscanf with %c catches trailing garbage (e.g. "1.2.3.4.5")      */
    n = sscanf(str, "%d.%d.%d.%d%c", &a, &b, &c, &d, &extra);
    if (n != 4) return -1;
    if (a < 0 || a > 255 || b < 0 || b > 255 ||
        c < 0 || c > 255 || d < 0 || d > 255) {
        return -1;
    }

    bytes = (uint8_t *)ip_out;
    bytes[0] = (uint8_t)a;
    bytes[1] = (uint8_t)b;
    bytes[2] = (uint8_t)c;
    bytes[3] = (uint8_t)d;
    return 0;
}

/* ── Helper: check if IP is 0.0.0.0 ──────────────────────────────── */
static int is_ip_zero(uint32_t ip)
{
    const uint8_t *bytes = (const uint8_t *)&ip;
    return (bytes[0] == 0 && bytes[1] == 0 &&
            bytes[2] == 0 && bytes[3] == 0);
}

/* ── Helper: strip leading whitespace ─────────────────────────────── */
static const char *skip_leading_space(const char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

/* ── Public API ───────────────────────────────────────────────────── */

void resource_store_init(ResourceStore *store)
{
    if (!store) return;
    store->count = 0;
    memset(store->records, 0, sizeof(store->records));
}

int resource_store_load_file(ResourceStore *store, const char *filename)
{
    FILE *fp;
    char line[RESOURCE_FILE_MAX_LINE];
    int line_num = 0;
    int loaded = 0;

    if (!store || !filename) return -1;

    fp = fopen(filename, "r");
    if (!fp) {
        LOG_ERROR("Cannot open resource file: %s", filename);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char ip_str[64];
        char domain[DNS_MAX_NAME_LEN + 1];
        int n;
        ResourceRecord *rec;
        const char *p;

        line_num++;

        /* Strip trailing newline / carriage-return */
        {
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' ||
                               line[len - 1] == '\r')) {
                line[--len] = '\0';
            }
        }

        /* Skip leading whitespace */
        p = skip_leading_space(line);

        /* Skip empty lines and comments */
        if (*p == '\0' || *p == '#' || *p == ';') {
            continue;
        }

        /* ── Parse legacy format: <IP> <domain> ──────────────────── */
        n = sscanf(p, "%63s %255s", ip_str, domain);
        if (n != 2) {
            LOG_DEBUG("resource file line %d: malformed, skipping", line_num);
            continue;
        }

        /* Check table capacity */
        if (store->count >= RESOURCE_STORE_MAX_RECORDS) {
            LOG_ERROR("resource file: table full (%d records), "
                      "stopping load", RESOURCE_STORE_MAX_RECORDS);
            break;
        }

        /* Lower-case the domain name before storing */
        str_tolower(domain);

        rec = &store->records[store->count];

        /* ── Check for BLOCK (0.0.0.0) ──────────────────────────── */
        {
            uint32_t ip;
            if (parse_ipv4(ip_str, &ip) != 0) {
                LOG_DEBUG("resource file line %d: invalid IP '%s', skipping",
                          line_num, ip_str);
                continue;
            }

            if (is_ip_zero(ip)) {
                /* Blocking entry — will trigger NXDOMAIN in Phase 2-2 */
                rec->kind   = RR_KIND_BLOCK;
                rec->type   = DNS_QTYPE_A;
                rec->class_ = DNS_QCLASS_IN;
                rec->ttl    = 0;
                strncpy(rec->name, domain, DNS_MAX_NAME_LEN);
                rec->name[DNS_MAX_NAME_LEN] = '\0';
                loaded++;
                store->count++;
                continue;
            }

            /* Normal A record */
            rec->kind          = RR_KIND_A;
            rec->type          = DNS_QTYPE_A;
            rec->class_        = DNS_QCLASS_IN;
            rec->ttl           = 60;
            rec->rdata.ipv4_addr = ip;
            strncpy(rec->name, domain, DNS_MAX_NAME_LEN);
            rec->name[DNS_MAX_NAME_LEN] = '\0';
            loaded++;
            store->count++;
        }
    }

    fclose(fp);
    LOG_INFO("loaded resource records: %d", loaded);
    return 0;
}

const ResourceRecord *resource_store_lookup(const ResourceStore *store,
                                            const char *qname,
                                            uint16_t qtype,
                                            uint16_t qclass)
{
    char qname_lower[DNS_MAX_NAME_LEN + 1];
    int i;

    if (!store || !qname) return NULL;

    /* Phase 2: only support A-record lookups.  Other types deferred to
     * Phase 5. */
    if (qtype != DNS_QTYPE_A || qclass != DNS_QCLASS_IN) {
        return NULL;
    }

    /* Make a lower-case copy of qname for case-insensitive comparison */
    {
        size_t len = strlen(qname);
        if (len > DNS_MAX_NAME_LEN) return NULL;
        memcpy(qname_lower, qname, len + 1);
    }
    str_tolower(qname_lower);

    for (i = 0; i < store->count; i++) {
        const ResourceRecord *rec = &store->records[i];
        if (rec->type == qtype && rec->class_ == qclass) {
            if (strcmp(rec->name, qname_lower) == 0) {
                return rec;
            }
        }
    }

    return NULL;
}
