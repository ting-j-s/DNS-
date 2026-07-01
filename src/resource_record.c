#include "resource_record.h"
#include <stdio.h>

/* ── Convert stored IPv4 (network byte order) to dotted string ─────── */
const char *resource_record_ip_str(const ResourceRecord *rr,
                                   char *buf, int buf_size)
{
    const uint8_t *bytes;

    if (!rr || rr->kind != RR_KIND_A || !buf || buf_size < 16) {
        return NULL;
    }

    bytes = (const uint8_t *)&rr->rdata.ipv4_addr;
    /* bytes[0] = most-significant octet in network byte order,
     * which on little-endian is the lowest-addressed byte. */
    snprintf(buf, (size_t)buf_size, "%u.%u.%u.%u",
             bytes[0], bytes[1], bytes[2], bytes[3]);
    return buf;
}
