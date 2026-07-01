#define _WIN32_WINNT 0x0600   /* Required for inet_pton (Vista+) */
#include "resource_store.h"
#include "logger.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ws2tcpip.h>

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

/* ── Helper: case-insensitive string equality ─────────────────────── */
static int str_case_eq(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = (char)((*a >= 'A' && *a <= 'Z') ? (*a + ('a' - 'A')) : *a);
        char cb = (char)((*b >= 'A' && *b <= 'Z') ? (*b + ('a' - 'A')) : *b);
        if (ca != cb) return 0;
        a++; b++;
    }
    return (*a == '\0' && *b == '\0');
}

/* ── Helper: check if first token is a known extended-format keyword ─ */
static int is_known_type_keyword(const char *s)
{
    static const char *keywords[] = {
        "A", "AAAA", "CNAME", "NS", "PTR", "MX", "BLOCK"
    };
    int i;
    for (i = 0; i < 7; i++) {
        if (str_case_eq(s, keywords[i])) {
            return 1;
        }
    }
    return 0;
}

/* ── Helper: strip leading whitespace ─────────────────────────────── */
static const char *skip_leading_space(const char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

/* ── Helper: strip inline comment (first # or ; preceded by space) ── */
static void strip_inline_comment(char *line)
{
    char *p;
    for (p = line; *p; p++) {
        if (*p == '#' || *p == ';') {
            if (p == line || *(p - 1) == ' ' || *(p - 1) == '\t') {
                *p = '\0';
                return;
            }
        }
    }
}

/* ── Helper: split line into whitespace-delimited tokens ──────────── */
static int tokenize_line(char *line, char *tokens[], int max_tokens)
{
    int count = 0;
    char *p = line;

    while (*p && count < max_tokens) {
        /* Skip leading whitespace */
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') break;

        tokens[count++] = p;

        /* Scan to end of token */
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) {
            *p = '\0';
            p++;
        }
    }

    return count;
}

/* ── Helper: normalize a domain name (lowercase, strip trailing dot) ─ */
static void normalize_domain(const char *src, char *dst, int dst_size)
{
    size_t len;

    if (!src || !dst || dst_size <= 0) return;

    len = strlen(src);

    /* Strip trailing dot (FQDN → relative name) */
    while (len > 0 && src[len - 1] == '.') {
        len--;
    }

    if (len >= (size_t)dst_size) {
        len = (size_t)(dst_size - 1);
    }

    memcpy(dst, src, len);
    dst[len] = '\0';
    str_tolower(dst);
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

/* ── Helper: parse IPv6 string into 16-byte array ─────────────────── */
static int parse_ipv6(const char *text, uint8_t out[16])
{
    if (!text || !out) return -1;
    /* inet_pton returns 1 on success, 0 on invalid, -1 on error        */
    if (inet_pton(AF_INET6, text, out) != 1) {
        return -1;
    }
    return 0;
}

/* ── Helper: check if IP is 0.0.0.0 ──────────────────────────────── */
static int is_ip_zero(uint32_t ip)
{
    const uint8_t *bytes = (const uint8_t *)&ip;
    return (bytes[0] == 0 && bytes[1] == 0 &&
            bytes[2] == 0 && bytes[3] == 0);
}

/* ── Helper: add a record to the store ────────────────────────────── */
static int resource_store_add_record(ResourceStore *store,
                                     const ResourceRecord *record)
{
    if (!store || !record) return -1;

    if (store->count >= RESOURCE_STORE_MAX_RECORDS) {
        LOG_ERROR("resource file: table full (%d records), "
                  "stopping load", RESOURCE_STORE_MAX_RECORDS);
        return -1;
    }

    memcpy(&store->records[store->count], record, sizeof(ResourceRecord));
    store->count++;
    return 0;
}

/* ── Parse a legacy-format line: <IP> <domain> ────────────────────── */
static int parse_legacy_line(ResourceStore *store,
                             char *tokens[], int token_count,
                             int line_num)
{
    const char *ip_str = tokens[0];
    const char *domain  = tokens[1];
    ResourceRecord rec;
    uint32_t ip;

    (void)token_count;  /* unused — extra tokens ignored */

    if (parse_ipv4(ip_str, &ip) != 0) {
        LOG_DEBUG("resource file line %d: invalid IP '%s', skipping",
                  line_num, ip_str);
        return -1;
    }

    memset(&rec, 0, sizeof(rec));
    rec.class_ = DNS_QCLASS_IN;

    normalize_domain(domain, rec.name, sizeof(rec.name));

    if (is_ip_zero(ip)) {
        /* Blocking entry — will trigger NXDOMAIN */
        rec.kind = RR_KIND_BLOCK;
        rec.type = DNS_QTYPE_A;
        rec.ttl  = 0;
    } else {
        /* Normal A record */
        rec.kind          = RR_KIND_A;
        rec.type          = DNS_QTYPE_A;
        rec.ttl           = 60;
        rec.rdata.ipv4_addr = ip;
    }

    return resource_store_add_record(store, &rec);
}

/* ── Parse an extended-format line: <TYPE> <name> [values...] ─────── */
static int parse_extended_line(ResourceStore *store,
                               char *tokens[], int token_count,
                               int line_num)
{
    const char *type_str = tokens[0];
    ResourceRecord rec;

    memset(&rec, 0, sizeof(rec));
    rec.class_ = DNS_QCLASS_IN;
    rec.ttl    = 60;

    /* ── A: A name ipv4 ──────────────────────────────────────────── */
    if (str_case_eq(type_str, "A")) {
        if (token_count < 3) {
            LOG_DEBUG("resource file line %d: A needs <name> <ipv4>",
                      line_num);
            return -1;
        }
        rec.kind = RR_KIND_A;
        rec.type = DNS_QTYPE_A;
        normalize_domain(tokens[1], rec.name, sizeof(rec.name));
        if (parse_ipv4(tokens[2], &rec.rdata.ipv4_addr) != 0) {
            LOG_DEBUG("resource file line %d: invalid IPv4 '%s'",
                      line_num, tokens[2]);
            return -1;
        }
        return resource_store_add_record(store, &rec);
    }

    /* ── AAAA: AAAA name ipv6 ────────────────────────────────────── */
    if (str_case_eq(type_str, "AAAA")) {
        if (token_count < 3) {
            LOG_DEBUG("resource file line %d: AAAA needs <name> <ipv6>",
                      line_num);
            return -1;
        }
        rec.kind = RR_KIND_AAAA;
        rec.type = DNS_QTYPE_AAAA;
        normalize_domain(tokens[1], rec.name, sizeof(rec.name));
        if (parse_ipv6(tokens[2], rec.rdata.ipv6_addr) != 0) {
            LOG_DEBUG("resource file line %d: invalid IPv6 '%s'",
                      line_num, tokens[2]);
            return -1;
        }
        return resource_store_add_record(store, &rec);
    }

    /* ── CNAME: CNAME alias canonical ────────────────────────────── */
    if (str_case_eq(type_str, "CNAME")) {
        if (token_count < 3) {
            LOG_DEBUG("resource file line %d: CNAME needs <alias> <canonical>",
                      line_num);
            return -1;
        }
        rec.kind = RR_KIND_CNAME;
        rec.type = DNS_QTYPE_CNAME;
        normalize_domain(tokens[1], rec.name, sizeof(rec.name));
        normalize_domain(tokens[2], rec.rdata.domain_name,
                         sizeof(rec.rdata.domain_name));
        return resource_store_add_record(store, &rec);
    }

    /* ── NS: NS domain ns-host ───────────────────────────────────── */
    if (str_case_eq(type_str, "NS")) {
        if (token_count < 3) {
            LOG_DEBUG("resource file line %d: NS needs <domain> <ns-host>",
                      line_num);
            return -1;
        }
        rec.kind = RR_KIND_NS;
        rec.type = DNS_QTYPE_NS;
        normalize_domain(tokens[1], rec.name, sizeof(rec.name));
        normalize_domain(tokens[2], rec.rdata.domain_name,
                         sizeof(rec.rdata.domain_name));
        return resource_store_add_record(store, &rec);
    }

    /* ── PTR: PTR reverse-name host-name ─────────────────────────── */
    if (str_case_eq(type_str, "PTR")) {
        if (token_count < 3) {
            LOG_DEBUG("resource file line %d: PTR needs <reverse> <host>",
                      line_num);
            return -1;
        }
        rec.kind = RR_KIND_PTR;
        rec.type = DNS_QTYPE_PTR;
        normalize_domain(tokens[1], rec.name, sizeof(rec.name));
        normalize_domain(tokens[2], rec.rdata.domain_name,
                         sizeof(rec.rdata.domain_name));
        return resource_store_add_record(store, &rec);
    }

    /* ── MX: MX domain preference exchange ───────────────────────── */
    if (str_case_eq(type_str, "MX")) {
        int pref;
        char extra;

        if (token_count < 4) {
            LOG_DEBUG("resource file line %d: MX needs <domain> <pref> "
                      "<exchange>", line_num);
            return -1;
        }

        if (sscanf(tokens[2], "%d%c", &pref, &extra) != 1 ||
            pref < 0 || pref > 65535) {
            LOG_DEBUG("resource file line %d: invalid MX preference '%s'",
                      line_num, tokens[2]);
            return -1;
        }

        rec.kind = RR_KIND_MX;
        rec.type = DNS_QTYPE_MX;
        normalize_domain(tokens[1], rec.name, sizeof(rec.name));
        rec.rdata.mx.preference = (uint16_t)pref;
        normalize_domain(tokens[3], rec.rdata.mx.exchange,
                         sizeof(rec.rdata.mx.exchange));
        return resource_store_add_record(store, &rec);
    }

    /* ── BLOCK: BLOCK domain ─────────────────────────────────────── */
    if (str_case_eq(type_str, "BLOCK")) {
        rec.kind = RR_KIND_BLOCK;
        rec.type = DNS_QTYPE_A;   /* for old resource_store_lookup compat */
        rec.ttl  = 0;
        normalize_domain(tokens[1], rec.name, sizeof(rec.name));
        return resource_store_add_record(store, &rec);
    }

    /* ── Unknown type ────────────────────────────────────────────── */
    LOG_DEBUG("resource file line %d: unknown type '%s'",
              line_num, type_str);
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Public API
 * ═══════════════════════════════════════════════════════════════════════ */

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
    int count_by_kind[8] = {0};  /* indexed by ResourceRecordKind */

    if (!store || !filename) return -1;

    fp = fopen(filename, "r");
    if (!fp) {
        LOG_ERROR("Cannot open resource file: %s", filename);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *tokens[8];
        int token_count;
        const char *p;
        int kind_before;

        line_num++;

        /* Strip trailing newline / carriage-return */
        {
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' ||
                               line[len - 1] == '\r')) {
                line[--len] = '\0';
            }
        }

        /* Strip inline comments (# or ; preceded by whitespace) */
        strip_inline_comment(line);

        /* Trim trailing whitespace */
        {
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == ' ' ||
                               line[len - 1] == '\t')) {
                line[--len] = '\0';
            }
        }

        /* Skip leading whitespace and check for empty line */
        p = skip_leading_space(line);
        if (*p == '\0') {
            continue;
        }

        /* Tokenize */
        token_count = tokenize_line(line, tokens, 8);
        if (token_count < 2) {
            LOG_DEBUG("resource file line %d: too few tokens, skipping",
                      line_num);
            continue;
        }

        /* Dispatch based on first token */
        kind_before = store->count;

        if (is_known_type_keyword(tokens[0])) {
            if (parse_extended_line(store, tokens, token_count, line_num) == 0) {
                loaded++;
                if (store->count > kind_before) {
                    ResourceRecordKind k =
                        store->records[store->count - 1].kind;
                    if (k >= 0 && k < 8) {
                        count_by_kind[(int)k]++;
                    }
                }
            }
        } else {
            /* Try legacy format */
            if (parse_legacy_line(store, tokens, token_count, line_num) == 0) {
                loaded++;
                if (store->count > kind_before) {
                    ResourceRecordKind k =
                        store->records[store->count - 1].kind;
                    if (k >= 0 && k < 8) {
                        count_by_kind[(int)k]++;
                    }
                }
            }
        }
    }

    fclose(fp);

    LOG_INFO("loaded resource records: %d", loaded);
    LOG_DEBUG("record summary: A=%d AAAA=%d NS=%d CNAME=%d PTR=%d "
              "MX=%d BLOCK=%d",
              count_by_kind[RR_KIND_A],
              count_by_kind[RR_KIND_AAAA],
              count_by_kind[RR_KIND_NS],
              count_by_kind[RR_KIND_CNAME],
              count_by_kind[RR_KIND_PTR],
              count_by_kind[RR_KIND_MX],
              count_by_kind[RR_KIND_BLOCK]);

    /* Dump all records at DEBUG level for diagnostics */
    {
        int i;
        for (i = 0; i < store->count; i++) {
            const ResourceRecord *rec = &store->records[i];
            char val_buf[64];

            switch (rec->kind) {
            case RR_KIND_A:
                resource_record_ipv4_to_string(rec->rdata.ipv4_addr,
                                               val_buf, sizeof(val_buf));
                LOG_DEBUG("record[%d]: kind=A name=%s value=%s",
                          i, rec->name, val_buf);
                break;
            case RR_KIND_AAAA:
                LOG_DEBUG("record[%d]: kind=AAAA name=%s",
                          i, rec->name);
                break;
            case RR_KIND_CNAME:
                LOG_DEBUG("record[%d]: kind=CNAME name=%s value=%s",
                          i, rec->name, rec->rdata.domain_name);
                break;
            case RR_KIND_NS:
                LOG_DEBUG("record[%d]: kind=NS name=%s value=%s",
                          i, rec->name, rec->rdata.domain_name);
                break;
            case RR_KIND_PTR:
                LOG_DEBUG("record[%d]: kind=PTR name=%s value=%s",
                          i, rec->name, rec->rdata.domain_name);
                break;
            case RR_KIND_MX:
                snprintf(val_buf, sizeof(val_buf),
                         "pref=%u exch=%s",
                         rec->rdata.mx.preference,
                         rec->rdata.mx.exchange);
                LOG_DEBUG("record[%d]: kind=MX name=%s %s",
                          i, rec->name, val_buf);
                break;
            case RR_KIND_BLOCK:
                LOG_DEBUG("record[%d]: kind=BLOCK name=%s",
                          i, rec->name);
                break;
            default:
                break;
            }
        }
    }

    return 0;
}

/* ── Legacy single-record lookup (Phase 2–4 compatible) ───────────── */
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

/* ── Multi-record lookup (Phase 5+) ───────────────────────────────── */
int resource_store_lookup_set(const ResourceStore *store,
                              const char *qname,
                              uint16_t qtype,
                              uint16_t qclass,
                              ResourceAnswerSet *out_set)
{
    char qname_lower[DNS_MAX_NAME_LEN + 1];
    int i;

    /* ── Parameter validation ──────────────────────────────────────── */
    if (!store || !qname || !out_set) {
        return -1;
    }

    /* ── Initialize output ──────────────────────────────────────────── */
    memset(out_set, 0, sizeof(*out_set));

    /* ── Only support IN class for now ──────────────────────────────── */
    if (qclass != DNS_QCLASS_IN) {
        return 0;
    }

    /* ── Lower-case qname ───────────────────────────────────────────── */
    {
        size_t len = strlen(qname);
        if (len > DNS_MAX_NAME_LEN) return 0;
        memcpy(qname_lower, qname, len + 1);
    }
    str_tolower(qname_lower);

    /* ── Scan for matching records ──────────────────────────────────── */
    for (i = 0; i < store->count; i++) {
        const ResourceRecord *rec = &store->records[i];

        /* Name must match (case-insensitive) */
        if (strcmp(rec->name, qname_lower) != 0) {
            continue;
        }

        /* BLOCK match by name — takes precedence, return immediately */
        if (rec->kind == RR_KIND_BLOCK) {
            out_set->is_blocked = 1;
            return 0;
        }

        /* Normal record: also match type and class */
        if (rec->type == qtype && rec->class_ == qclass) {
            if (out_set->count >= RESOURCE_ANSWER_MAX_RECORDS) {
                break;
            }
            resource_record_copy(&out_set->records[out_set->count], rec);
            out_set->count++;
        }
    }

    return 0;
}
