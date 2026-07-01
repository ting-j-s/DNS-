#ifndef RESOURCE_RECORD_H
#define RESOURCE_RECORD_H

#include <stdint.h>
#include "dns_packet.h"

/* ── Resource record kind ──────────────────────────────────────────── */
typedef enum {
    RR_KIND_NONE  = 0,
    RR_KIND_A     = 1,
    RR_KIND_BLOCK = 2
} ResourceRecordKind;

/* ── Unified resource record ───────────────────────────────────────── */
typedef struct {
    ResourceRecordKind kind;
    char     name[DNS_MAX_NAME_LEN + 1];   /* lower-case domain name  */
    uint16_t type;                          /* DNS_QTYPE_A, etc.      */
    uint16_t class_;                        /* DNS_QCLASS_IN          */
    uint32_t ttl;                           /* time-to-live (seconds) */
    union {
        uint32_t ipv4_addr;                 /* network byte order     */
    } rdata;
} ResourceRecord;

/* ── Utility ───────────────────────────────────────────────────────── */
const char *resource_record_ip_str(const ResourceRecord *rr,
                                   char *buf, int buf_size);

#endif /* RESOURCE_RECORD_H */
