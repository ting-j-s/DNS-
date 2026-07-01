#include "dns_packet.h"
#include "dns_name.h"
#include "logger.h"
#include <string.h>
#include <winsock2.h>

/* ── QTYPE → human-readable string ─────────────────────────────── */
const char *dns_qtype_to_string(uint16_t qtype)
{
    switch (qtype) {
    case DNS_QTYPE_A:     return "A";
    case DNS_QTYPE_NS:    return "NS";
    case DNS_QTYPE_CNAME: return "CNAME";
    case DNS_QTYPE_PTR:   return "PTR";
    case DNS_QTYPE_MX:    return "MX";
    case DNS_QTYPE_AAAA:  return "AAAA";
    default:              return "UNKNOWN";
    }
}

/* ── QCLASS → human-readable string ────────────────────────────── */
const char *dns_qclass_to_string(uint16_t qclass)
{
    switch (qclass) {
    case DNS_QCLASS_IN: return "IN";
    default:            return "UNKNOWN";
    }
}

/* ── Parse complete DNS query (Header + Question) ──────────────── */
int dns_packet_parse_query(const uint8_t *packet,
                           int packet_len,
                           DnsQuery *out_query)
{
    int next_offset;
    uint16_t qtype_raw;
    uint16_t qclass_raw;

    /* ── 1. Parameter validation ────────────────────────────────── */
    if (!packet || !out_query) {
        return -1;
    }
    if (packet_len < DNS_HEADER_SIZE) {
        LOG_DEBUG("packet too short: %d < %d", packet_len, DNS_HEADER_SIZE);
        return -2;
    }

    /* ── 2. Zero-initialise output ──────────────────────────────── */
    memset(out_query, 0, sizeof(*out_query));

    /* ── 3. Parse header fields (network → host byte order) ─────── */
    out_query->header.id      = ntohs(*(uint16_t *)(packet + 0));
    out_query->header.flags   = ntohs(*(uint16_t *)(packet + 2));
    out_query->header.qdcount = ntohs(*(uint16_t *)(packet + 4));
    out_query->header.ancount = ntohs(*(uint16_t *)(packet + 6));
    out_query->header.nscount = ntohs(*(uint16_t *)(packet + 8));
    out_query->header.arcount = ntohs(*(uint16_t *)(packet + 10));

    LOG_DEBUG("DNS header parsed: id=%u flags=0x%04x qdcount=%u "
              "ancount=%u nscount=%u arcount=%u",
              out_query->header.id,
              out_query->header.flags,
              out_query->header.qdcount,
              out_query->header.ancount,
              out_query->header.nscount,
              out_query->header.arcount);

    /* ── 4. Only support QDCOUNT == 1 ───────────────────────────── */
    if (out_query->header.qdcount != 1) {
        LOG_DEBUG("unsupported qdcount: %u (expected 1)",
                  out_query->header.qdcount);
        return -3;
    }

    /* ── 5. Decode QNAME from offset 12 ─────────────────────────── */
    {
        int rc = dns_name_decode(packet,
                                 packet_len,
                                 DNS_HEADER_SIZE,
                                 out_query->question.qname,
                                 sizeof(out_query->question.qname),
                                 &next_offset);
        if (rc != 0) {
            LOG_DEBUG("dns_name_decode failed: rc=%d", rc);
            return -4;
        }
    }

    /* ── 6. Read QTYPE and QCLASS ───────────────────────────────── */
    if (next_offset + 4 > packet_len) {
        LOG_DEBUG("question fields truncated: next_offset=%d + 4 > %d",
                  next_offset, packet_len);
        return -5;
    }

    qtype_raw  = ntohs(*(uint16_t *)(packet + next_offset));
    qclass_raw = ntohs(*(uint16_t *)(packet + next_offset + 2));

    out_query->question.qtype  = qtype_raw;
    out_query->question.qclass = qclass_raw;
    out_query->question_end_offset = next_offset + 4;

    LOG_DEBUG("DNS question parsed: qname=%s qtype=%s(%u) qclass=%s(%u) "
              "next_offset=%d",
              out_query->question.qname,
              dns_qtype_to_string(qtype_raw),  qtype_raw,
              dns_qclass_to_string(qclass_raw), qclass_raw,
              next_offset);

    /* ── 7. Success ─────────────────────────────────────────────── */
    return 0;
}

/* ── Build DNS A-record response ──────────────────────────────────── */
int dns_packet_build_a_response(const uint8_t *query_packet,
                                int query_len,
                                const DnsQuery *query,
                                uint32_t ipv4_addr,
                                uint32_t ttl,
                                uint8_t *response,
                                int response_size)
{
    int question_len;
    int answer_offset;
    int response_len;
    uint16_t req_flags, resp_flags;

    /* ── 1. Parameter validation ────────────────────────────────── */
    if (!query_packet || !query || !response)            return -1;
    if (query_len < DNS_HEADER_SIZE)                     return -2;

    /* Phase 2-2: only A/IN supported */
    if (query->question.qtype  != DNS_QTYPE_A)           return -3;
    if (query->question.qclass != DNS_QCLASS_IN)          return -3;

    question_len  = query->question_end_offset - DNS_HEADER_SIZE;
    if (question_len <= 0 || question_len > (query_len - DNS_HEADER_SIZE))
        return -4;

    response_len  = DNS_HEADER_SIZE + question_len + 16;
    if (response_len > response_size)                    return -5;

    memset(response, 0, (size_t)response_len);

    /* ── 2. Build header ────────────────────────────────────────── */
    req_flags = query->header.flags;
    resp_flags = 0x8000;                      /* QR = 1               */
    resp_flags |= (req_flags & 0x7800);       /* Opcode (4 bits)      */
    resp_flags |= (req_flags & 0x0100);       /* RD                    */
    resp_flags |= 0x0080;                     /* RA = 1                */
    /* RCODE = 0 (already zero from resp_flags initial value)         */

    *(uint16_t *)(response + 0)  = htons(query->header.id);
    *(uint16_t *)(response + 2)  = htons(resp_flags);
    *(uint16_t *)(response + 4)  = htons(1);   /* QDCOUNT = 1       */
    *(uint16_t *)(response + 6)  = htons(1);   /* ANCOUNT = 1       */
    *(uint16_t *)(response + 8)  = htons(0);   /* NSCOUNT = 0       */
    *(uint16_t *)(response + 10) = htons(0);   /* ARCOUNT = 0       */

    /* ── 3. Copy Question section verbatim ──────────────────────── */
    memcpy(response + DNS_HEADER_SIZE,
           query_packet + DNS_HEADER_SIZE,
           (size_t)question_len);

    /* ── 4. Build Answer section ────────────────────────────────── */
    answer_offset = DNS_HEADER_SIZE + question_len;

    /* NAME: compression pointer → question QNAME at offset 12      */
    *(uint16_t *)(response + answer_offset +  0) = htons(0xC00C);
    /* TYPE = A                                                      */
    *(uint16_t *)(response + answer_offset +  2) = htons(DNS_QTYPE_A);
    /* CLASS = IN                                                    */
    *(uint16_t *)(response + answer_offset +  4) = htons(DNS_QCLASS_IN);
    /* TTL                                                           */
    *(uint32_t *)(response + answer_offset +  6) = htonl(ttl);
    /* RDLENGTH = 4                                                  */
    *(uint16_t *)(response + answer_offset + 10) = htons(4);
    /* RDATA: IPv4 address (network byte order)                      */
    memcpy(response + answer_offset + 12, &ipv4_addr, 4);

    return response_len;
}

/* ── Build DNS NXDOMAIN response (Name Error) ──────────────────────── */
int dns_packet_build_nxdomain_response(const uint8_t *query_packet,
                                       int query_len,
                                       const DnsQuery *query,
                                       uint8_t *response,
                                       int response_size)
{
    int question_len;
    int response_len;
    uint16_t req_flags, resp_flags;

    /* ── 1. Parameter validation ────────────────────────────────── */
    if (!query_packet || !query || !response)            return -1;
    if (query_len < DNS_HEADER_SIZE)                     return -2;

    question_len  = query->question_end_offset - DNS_HEADER_SIZE;
    if (question_len <= 0 || question_len > (query_len - DNS_HEADER_SIZE))
        return -3;

    response_len  = DNS_HEADER_SIZE + question_len;
    if (response_len > response_size)                    return -4;

    memset(response, 0, (size_t)response_len);

    /* ── 2. Build header ────────────────────────────────────────── */
    req_flags = query->header.flags;
    resp_flags = 0x8000;                      /* QR = 1               */
    resp_flags |= (req_flags & 0x7800);       /* Opcode (4 bits)      */
    resp_flags |= (req_flags & 0x0100);       /* RD                    */
    resp_flags |= 0x0080;                     /* RA = 1                */
    resp_flags |= 0x0003;                     /* RCODE = 3 NXDOMAIN    */

    *(uint16_t *)(response + 0)  = htons(query->header.id);
    *(uint16_t *)(response + 2)  = htons(resp_flags);
    *(uint16_t *)(response + 4)  = htons(1);   /* QDCOUNT = 1       */
    *(uint16_t *)(response + 6)  = htons(0);   /* ANCOUNT = 0       */
    *(uint16_t *)(response + 8)  = htons(0);   /* NSCOUNT = 0       */
    *(uint16_t *)(response + 10) = htons(0);   /* ARCOUNT = 0       */

    /* ── 3. Copy Question section verbatim ──────────────────────── */
    memcpy(response + DNS_HEADER_SIZE,
           query_packet + DNS_HEADER_SIZE,
           (size_t)question_len);

    return response_len;
}
