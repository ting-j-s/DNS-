#ifndef RESOURCE_RECORD_H
#define RESOURCE_RECORD_H

#include <stdint.h>
#include "dns_packet.h"

/* ── Resource record kind ──────────────────────────────────────────── */
typedef enum {
    RR_KIND_NONE  = 0,
    RR_KIND_A     = 1,
    RR_KIND_AAAA  = 2,
    RR_KIND_NS    = 3,
    RR_KIND_CNAME = 4,
    RR_KIND_PTR   = 5,
    RR_KIND_MX    = 6,
    RR_KIND_BLOCK = 7
} ResourceRecordKind;

/* ── Unified resource record ───────────────────────────────────────── */
typedef struct {
    ResourceRecordKind kind;
    char     name[DNS_MAX_NAME_LEN + 1];   /* lower-case domain name  */
    uint16_t type;                          /* DNS_QTYPE_A, etc.      */
    uint16_t class_;                        /* DNS_QCLASS_IN          */
    uint32_t ttl;                           /* time-to-live (seconds) */

    union {
        /* RR_KIND_A */
        uint32_t ipv4_addr;                 /* network byte order     */

        /* RR_KIND_AAAA */
        uint8_t  ipv6_addr[16];             /* network byte order     */

        /* RR_KIND_NS / RR_KIND_CNAME / RR_KIND_PTR */
        char     domain_name[DNS_MAX_NAME_LEN + 1];

        /* RR_KIND_MX */
        struct {
            uint16_t preference;
            char     exchange[DNS_MAX_NAME_LEN + 1];
        } mx;

        /* RR_KIND_BLOCK: rdata unused */
    } rdata;
} ResourceRecord;

/* ── Maximum records in a single answer set ────────────────────────── */
#define RESOURCE_ANSWER_MAX_RECORDS  16

/* ── Answer set (lookup result) ────────────────────────────────────── */
typedef struct ResourceAnswerSet {
    ResourceRecord records[RESOURCE_ANSWER_MAX_RECORDS];
    int count;
    int is_blocked;     /* 1 = domain is blocked → return NXDOMAIN     */
} ResourceAnswerSet;

/* ── Utility ───────────────────────────────────────────────────────── */

/* Convert ResourceRecordKind enum to human-readable string.
 * Returns "NONE" for unknown values.                                   */
const char *resource_record_kind_to_string(ResourceRecordKind kind);

/* Map a DNS QTYPE value to the corresponding ResourceRecordKind.
 * Returns RR_KIND_NONE for unsupported types.                          */
ResourceRecordKind resource_record_kind_from_dns_type(uint16_t qtype);

/* Map a ResourceRecordKind to its DNS QTYPE value.
 * Returns 0 for RR_KIND_BLOCK and RR_KIND_NONE.                        */
uint16_t resource_record_kind_to_dns_type(ResourceRecordKind kind);

/* Deep-copy a resource record.  Returns 0 on success, -1 on NULL.      */
int resource_record_copy(ResourceRecord *dst, const ResourceRecord *src);

/* Convert IPv4 address (network byte order) to dotted-decimal string.
 * Returns 0 on success, -1 if output buffer is NULL or too small.      */
int resource_record_ipv4_to_string(uint32_t ipv4_addr,
                                   char *out, int out_size);

/* Convert a ResourceRecord's IPv4 to dotted string (convenience).
 * Kept for backward compatibility with Phase 2–4 code.
 * Returns buf on success, NULL if rr is not an A record.               */
const char *resource_record_ip_str(const ResourceRecord *rr,
                                   char *buf, int buf_size);

#endif /* RESOURCE_RECORD_H */
