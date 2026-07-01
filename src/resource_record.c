#include "resource_record.h"
#include <stdio.h>
#include <string.h>

/* ── Convert ResourceRecordKind to human-readable string ─────────────── */
const char *resource_record_kind_to_string(ResourceRecordKind kind)
{
    switch (kind) {
    case RR_KIND_A:     return "A";
    case RR_KIND_AAAA:  return "AAAA";
    case RR_KIND_NS:    return "NS";
    case RR_KIND_CNAME: return "CNAME";
    case RR_KIND_PTR:   return "PTR";
    case RR_KIND_MX:    return "MX";
    case RR_KIND_BLOCK: return "BLOCK";
    default:            return "NONE";
    }
}

/* ── Map DNS QTYPE → ResourceRecordKind ──────────────────────────────── */
ResourceRecordKind resource_record_kind_from_dns_type(uint16_t qtype)
{
    switch (qtype) {
    case DNS_QTYPE_A:     return RR_KIND_A;
    case DNS_QTYPE_AAAA:  return RR_KIND_AAAA;
    case DNS_QTYPE_NS:    return RR_KIND_NS;
    case DNS_QTYPE_CNAME: return RR_KIND_CNAME;
    case DNS_QTYPE_PTR:   return RR_KIND_PTR;
    case DNS_QTYPE_MX:    return RR_KIND_MX;
    default:              return RR_KIND_NONE;
    }
}

/* ── Map ResourceRecordKind → DNS QTYPE ──────────────────────────────── */
uint16_t resource_record_kind_to_dns_type(ResourceRecordKind kind)
{
    switch (kind) {
    case RR_KIND_A:     return DNS_QTYPE_A;
    case RR_KIND_AAAA:  return DNS_QTYPE_AAAA;
    case RR_KIND_NS:    return DNS_QTYPE_NS;
    case RR_KIND_CNAME: return DNS_QTYPE_CNAME;
    case RR_KIND_PTR:   return DNS_QTYPE_PTR;
    case RR_KIND_MX:    return DNS_QTYPE_MX;
    case RR_KIND_BLOCK: return 0;
    default:            return 0;
    }
}

/* ── Deep-copy a resource record ─────────────────────────────────────── */
int resource_record_copy(ResourceRecord *dst, const ResourceRecord *src)
{
    if (!dst || !src) return -1;
    memcpy(dst, src, sizeof(ResourceRecord));
    return 0;
}

/* ── Convert IPv4 address (network byte order) to dotted string ──────── */
int resource_record_ipv4_to_string(uint32_t ipv4_addr,
                                   char *out, int out_size)
{
    const uint8_t *bytes;

    if (!out || out_size < 16) return -1;

    bytes = (const uint8_t *)&ipv4_addr;
    snprintf(out, (size_t)out_size, "%u.%u.%u.%u",
             bytes[0], bytes[1], bytes[2], bytes[3]);
    return 0;
}

/* ── Convenience: ResourceRecord IPv4 to dotted string ────────────────── */
const char *resource_record_ip_str(const ResourceRecord *rr,
                                   char *buf, int buf_size)
{
    if (!rr || rr->kind != RR_KIND_A || !buf || buf_size < 16) {
        return NULL;
    }
    resource_record_ipv4_to_string(rr->rdata.ipv4_addr, buf, buf_size);
    return buf;
}
