#include "dns_packet.h"
#include "dns_name.h"
#include "logger.h"
#include "resource_record.h"
#include <string.h>

/* ── Safe byte-wise read/write helpers ───────────────────────────────
 *  Avoid unaligned pointer casts (*(uint16_t*)(packet+N)).
 *  All DNS wire-format fields are big-endian; these functions convert
 *  between wire format and host byte order implicitly.                 */

static uint16_t read_u16_be(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t read_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           (uint32_t)p[3];
}

static void write_u16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static void write_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

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

/* ── TC (Truncation) flag check ─────────────────────────────────── */

/* DNS Header flags layout (big-endian, byte offset 2-3):
 *  bit 15    QR (0=query, 1=response)
 *  bit 11-14 Opcode
 *  bit 10    AA (Authoritative Answer)
 *  bit  9    TC (Truncation) — 0x0200
 *  bit  8    RD (Recursion Desired)
 *  bit  7    RA (Recursion Available)
 *  bit  4-6  Z  (reserved, must be zero)
 *  bit  0-3  RCODE                                            */

int dns_packet_is_truncated(const uint8_t *packet, int packet_len)
{
    if (!packet || packet_len < DNS_HEADER_SIZE) {
        return 0;
    }

    uint16_t flags = read_u16_be(packet + 2);
    return (flags & 0x0200) ? 1 : 0;
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

    /* ── 3. Parse header fields (big-endian wire → host byte order) ─ */
    out_query->header.id      = read_u16_be(packet + 0);
    out_query->header.flags   = read_u16_be(packet + 2);
    out_query->header.qdcount = read_u16_be(packet + 4);
    out_query->header.ancount = read_u16_be(packet + 6);
    out_query->header.nscount = read_u16_be(packet + 8);
    out_query->header.arcount = read_u16_be(packet + 10);

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

    qtype_raw  = read_u16_be(packet + next_offset);
    qclass_raw = read_u16_be(packet + next_offset + 2);

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

/* ── Encode a dotted domain name into DNS wire format ─────────────────
 *  Example: "real.example.com" → \x04real\x07example\x03com\x00
 *  Returns the number of bytes written (including the terminating zero),
 *  or a negative value on error.
 *  - Empty string or "." encodes as a single \x00 (root domain).
 *  - Labels are limited to 63 octets each.
 *  - Total output must fit in buffer_size.                               */
static int dns_name_encode(uint8_t *buffer, int buffer_size,
                           const char *name)
{
    int total;
    const char *p;

    if (!buffer || !name)   return -1;
    if (buffer_size < 1)    return -1;

    /* ── Root domain: "." or empty string ─────────────────────────── */
    if (name[0] == '\0' || (name[0] == '.' && name[1] == '\0')) {
        buffer[0] = 0;
        return 1;
    }

    total = 0;
    p = name;

    while (*p) {
        const char *dot;
        int label_len;

        dot = strchr(p, '.');
        if (dot) {
            label_len = (int)(dot - p);
        } else {
            label_len = (int)strlen(p);
        }

        /* Validate label length */
        if (label_len > 63)  return -2;
        if (label_len == 0)  return -3;   /* empty label / consecutive dots */

        /* Check space: 1 length byte + label + possible terminating NUL */
        if (total + 1 + label_len + 1 > buffer_size) return -4;

        buffer[total++] = (uint8_t)label_len;
        memcpy(buffer + total, p, (size_t)label_len);
        total += label_len;

        if (dot) {
            p = dot + 1;
        } else {
            break;
        }
    }

    /* ── Terminating zero ─────────────────────────────────────────── */
    if (total + 1 > buffer_size) return -4;
    buffer[total++] = 0;

    return total;
}

/* ── Extract cache-able Answer RRs from an upstream DNS response ────────
 *  Parses the Answer Section only.  Filters: class == IN, type == qtype,
 *  ttl > 0.  Stores up to RESOURCE_ANSWER_MAX_RECORDS records in out_set.
 *  Returns 1 if at least one record extracted, 0 if none, negative on error. */
int dns_packet_extract_answer_set(const uint8_t *packet,
                                  int packet_len,
                                  const char *qname,
                                  uint16_t qtype,
                                  uint16_t qclass,
                                  struct ResourceAnswerSet *out_set,
                                  uint32_t *out_min_ttl)
{
    uint16_t flags, qdcount, ancount, nscount, arcount;
    uint16_t rcode;
    int qr;
    int offset;
    int i;
    uint32_t running_min_ttl;
    int added;

    /* ── 1. Parameter validation ──────────────────────────────────── */
    if (!packet || !qname || !out_set || !out_min_ttl) return -1;
    if (packet_len < DNS_HEADER_SIZE)                   return -2;

    /* Only cache IN-class queries */
    if (qclass != DNS_QCLASS_IN)                         return -1;

    memset(out_set, 0, sizeof(*out_set));
    *out_min_ttl = 0;

    /* ── 2. Parse header ──────────────────────────────────────────── */
    /* ID is at bytes 0-1 (ignored for answer extraction) */
    flags   = read_u16_be(packet + 2);
    qdcount = read_u16_be(packet + 4);
    ancount = read_u16_be(packet + 6);
    nscount = read_u16_be(packet + 8);
    arcount = read_u16_be(packet + 10);

    (void)nscount;   /* not used in this phase */
    (void)arcount;

    qr  = (flags >> 15) & 0x1;
    rcode = flags & 0x000F;

    LOG_TRACE("extract_answer: flags=0x%04x qr=%d rcode=%u "
              "qdcount=%u ancount=%u",
              flags, qr, rcode, qdcount, ancount);

    /* Must be a response with NOERROR */
    if (qr != 1) {
        LOG_DEBUG("extract_answer: not a DNS response (QR=%d)", qr);
        return 0;
    }
    if (rcode != 0) {
        LOG_DEBUG("extract_answer: rcode=%u, not caching", rcode);
        return 0;
    }
    if (ancount == 0) {
        LOG_DEBUG("extract_answer: ancount=0, nothing to cache");
        return 0;
    }
    if (qdcount != 1) {
        LOG_DEBUG("extract_answer: unexpected qdcount=%u", qdcount);
        return 0;
    }

    /* ── 3. Skip Question Section ─────────────────────────────────── */
    {
        char temp_qname[DNS_MAX_NAME_LEN + 1];
        int name_end;
        int rc;

        rc = dns_name_decode(packet, packet_len, DNS_HEADER_SIZE,
                             temp_qname, sizeof(temp_qname), &name_end);
        if (rc != 0) {
            LOG_DEBUG("extract_answer: question name decode failed: rc=%d", rc);
            return -2;
        }
        if (name_end + 4 > packet_len) {
            LOG_DEBUG("extract_answer: question section truncated");
            return -2;
        }

        LOG_TRACE("extract_answer: upstream question qname=%s", temp_qname);

        /* Skip QTYPE (2) + QCLASS (2) */
        offset = name_end + 4;
    }

    /* ── 4. Iterate Answer Section ────────────────────────────────── */
    running_min_ttl = 0xFFFFFFFFu;
    added = 0;

    for (i = 0; i < (int)ancount; i++) {
        char     rr_name[DNS_MAX_NAME_LEN + 1];
        int      name_end;
        uint16_t rr_type, rr_class;
        uint32_t rr_ttl;
        uint16_t rr_rdlength;
        int      rdata_offset;
        int      rc;

        /* Decode NAME (may use compression pointers) */
        rc = dns_name_decode(packet, packet_len, offset,
                             rr_name, sizeof(rr_name), &name_end);
        if (rc != 0) {
            LOG_DEBUG("extract_answer: RR[%d] name decode failed: rc=%d", i, rc);
            return -2;
        }

        /* Read TYPE + CLASS + TTL + RDLENGTH (10 bytes) */
        if (name_end + 10 > packet_len) {
            LOG_DEBUG("extract_answer: RR[%d] header truncated at offset %d",
                      i, name_end);
            return -2;
        }

        rr_type     = read_u16_be(packet + name_end);
        rr_class    = read_u16_be(packet + name_end + 2);
        rr_ttl      = read_u32_be(packet + name_end + 4);
        rr_rdlength = read_u16_be(packet + name_end + 8);
        rdata_offset = name_end + 10;

        if (rdata_offset + rr_rdlength > packet_len) {
            LOG_DEBUG("extract_answer: RR[%d] rdata truncated: "
                      "rdata_offset=%d, rdlength=%u, packet_len=%d",
                      i, rdata_offset, rr_rdlength, packet_len);
            return -2;
        }

        LOG_TRACE("extract_answer: RR[%d] name=%s type=%u class=%u "
                  "ttl=%u rdlength=%u",
                  i, rr_name, rr_type, rr_class, rr_ttl, rr_rdlength);

        /* ── Filter: class == IN, type == qtype, ttl > 0 ────────── */
        if (rr_class != DNS_QCLASS_IN) {
            LOG_TRACE("extract_answer: RR[%d] class != IN, skip", i);
            offset = rdata_offset + rr_rdlength;
            continue;
        }
        if (rr_type != qtype) {
            LOG_TRACE("extract_answer: RR[%d] type %u != qtype %u, skip",
                      i, rr_type, qtype);
            offset = rdata_offset + rr_rdlength;
            continue;
        }
        if (rr_ttl == 0) {
            LOG_DEBUG("extract_answer: RR[%d] ttl=0, skip", i);
            offset = rdata_offset + rr_rdlength;
            continue;
        }

        /* ── Check capacity ──────────────────────────────────────── */
        if (added >= RESOURCE_ANSWER_MAX_RECORDS) {
            LOG_DEBUG("extract_answer: answer set full (%d records), "
                      "truncating", RESOURCE_ANSWER_MAX_RECORDS);
            break;
        }

        /* ── Parse RDATA by type ─────────────────────────────────── */
        {
            ResourceRecord *rec = &out_set->records[added];

            /* Set common fields */
            strncpy(rec->name, qname, DNS_MAX_NAME_LEN);
            rec->name[DNS_MAX_NAME_LEN] = '\0';
            rec->type   = rr_type;
            rec->class_ = rr_class;
            rec->ttl    = rr_ttl;

            switch (rr_type) {
            case DNS_QTYPE_A:
                if (rr_rdlength != 4) {
                    LOG_DEBUG("extract_answer: A rdlength=%u != 4, skip",
                              rr_rdlength);
                    goto skip_rr;
                }
                rec->kind = RR_KIND_A;
                memcpy(&rec->rdata.ipv4_addr, packet + rdata_offset, 4);
                break;

            case DNS_QTYPE_AAAA:
                if (rr_rdlength != 16) {
                    LOG_DEBUG("extract_answer: AAAA rdlength=%u != 16, skip",
                              rr_rdlength);
                    goto skip_rr;
                }
                rec->kind = RR_KIND_AAAA;
                memcpy(rec->rdata.ipv6_addr, packet + rdata_offset, 16);
                break;

            case DNS_QTYPE_NS:
                rec->kind = RR_KIND_NS;
                {
                    int dummy_next;
                    rc = dns_name_decode(packet, packet_len, rdata_offset,
                                         rec->rdata.domain_name,
                                         sizeof(rec->rdata.domain_name),
                                         &dummy_next);
                    if (rc != 0) {
                        LOG_DEBUG("extract_answer: NS rdata name decode "
                                  "failed: rc=%d", rc);
                        goto skip_rr;
                    }
                }
                break;

            case DNS_QTYPE_CNAME:
                rec->kind = RR_KIND_CNAME;
                {
                    int dummy_next;
                    rc = dns_name_decode(packet, packet_len, rdata_offset,
                                         rec->rdata.domain_name,
                                         sizeof(rec->rdata.domain_name),
                                         &dummy_next);
                    if (rc != 0) {
                        LOG_DEBUG("extract_answer: CNAME rdata name decode "
                                  "failed: rc=%d", rc);
                        goto skip_rr;
                    }
                }
                break;

            case DNS_QTYPE_PTR:
                rec->kind = RR_KIND_PTR;
                {
                    int dummy_next;
                    rc = dns_name_decode(packet, packet_len, rdata_offset,
                                         rec->rdata.domain_name,
                                         sizeof(rec->rdata.domain_name),
                                         &dummy_next);
                    if (rc != 0) {
                        LOG_DEBUG("extract_answer: PTR rdata name decode "
                                  "failed: rc=%d", rc);
                        goto skip_rr;
                    }
                }
                break;

            case DNS_QTYPE_MX:
                if (rr_rdlength < 3) {
                    LOG_DEBUG("extract_answer: MX rdlength=%u < 3, skip",
                              rr_rdlength);
                    goto skip_rr;
                }
                rec->kind = RR_KIND_MX;
                rec->rdata.mx.preference = read_u16_be(packet + rdata_offset);
                {
                    int dummy_next;
                    rc = dns_name_decode(packet, packet_len,
                                         rdata_offset + 2,
                                         rec->rdata.mx.exchange,
                                         sizeof(rec->rdata.mx.exchange),
                                         &dummy_next);
                    if (rc != 0) {
                        LOG_DEBUG("extract_answer: MX exchange name decode "
                                  "failed: rc=%d", rc);
                        goto skip_rr;
                    }
                }
                break;

            default:
                /* Unsupported type — skip */
                LOG_TRACE("extract_answer: unsupported type %u, skip", rr_type);
                goto skip_rr;
            }

            /* ── Successfully added ──────────────────────────────── */
            if (rr_ttl < running_min_ttl) {
                running_min_ttl = rr_ttl;
            }
            added++;
        }

    skip_rr:
        offset = rdata_offset + rr_rdlength;
    }

    /* ── 5. Finalise ──────────────────────────────────────────────── */
    out_set->count = added;

    if (added == 0) {
        LOG_DEBUG("extract_answer: no cache-able records found for "
                  "qname=%s, qtype=%s(%u)",
                  qname, dns_qtype_to_string(qtype), qtype);
        return 0;
    }

    *out_min_ttl = running_min_ttl;

    LOG_DEBUG("extract_answer: cached %d records for qname=%s, qtype=%s(%u), "
              "min_ttl=%u",
              added, qname, dns_qtype_to_string(qtype), qtype,
              running_min_ttl);

    return 1;
}

/* ── Build DNS A-record response (single-record convenience) ───────── */
int dns_packet_build_a_response(const uint8_t *query_packet,
                                int query_len,
                                const DnsQuery *query,
                                uint32_t ipv4_addr,
                                uint32_t ttl,
                                uint8_t *response,
                                int response_size)
{
    ResourceAnswerSet answer_set;

    /* Wrap the single A record in a temporary answer set and delegate
     * to the multi-record builder.  This keeps response construction
     * logic in one place.                                                */
    memset(&answer_set, 0, sizeof(answer_set));
    answer_set.count = 1;
    answer_set.is_blocked = 0;
    answer_set.records[0].kind            = RR_KIND_A;
    answer_set.records[0].type            = DNS_QTYPE_A;
    answer_set.records[0].class_          = DNS_QCLASS_IN;
    answer_set.records[0].ttl             = ttl;
    answer_set.records[0].rdata.ipv4_addr = ipv4_addr;

    return dns_packet_build_a_response_set(query_packet, query_len,
                                           query, &answer_set,
                                           response, response_size);
}

/* ── Build DNS A-record response with ANCOUNT >= 1 ────────────────────
 *  Delegates to the general RR builder; kept for backward compatibility
 *  and for its A-only validation semantics.                               */
int dns_packet_build_a_response_set(const uint8_t *query_packet,
                                    int query_len,
                                    const DnsQuery *query,
                                    const struct ResourceAnswerSet *answer_set,
                                    uint8_t *response,
                                    int response_size)
{
    int i;

    /* ── Basic checks (detailed validation done in callee) ─────────── */
    if (!query_packet || !query || !answer_set || !response) return -1;
    if (answer_set->count <= 0 ||
        answer_set->count > RESOURCE_ANSWER_MAX_RECORDS)  return -2;
    if (query->question.qtype  != DNS_QTYPE_A)            return -3;
    if (query->question.qclass != DNS_QCLASS_IN)           return -3;

    /* ── Validate all records are A/IN (Phase 5-3 strict check) ────── */
    for (i = 0; i < answer_set->count; i++) {
        const ResourceRecord *rec = &answer_set->records[i];
        if (rec->kind   != RR_KIND_A)     return -5;
        if (rec->type   != DNS_QTYPE_A)   return -5;
        if (rec->class_ != DNS_QCLASS_IN) return -5;
    }

    return dns_packet_build_rr_response_set(query_packet, query_len,
                                            query, answer_set,
                                            response, response_size);
}

/* ── Build DNS response for any supported RR type ────────────────────── */
int dns_packet_build_rr_response_set(const uint8_t *query_packet,
                                     int query_len,
                                     const DnsQuery *query,
                                     const struct ResourceAnswerSet *answer_set,
                                     uint8_t *response,
                                     int response_size)
{
    int question_len;
    int answer_offset;
    int response_len;
    uint16_t req_flags, resp_flags;
    int i;

    /* Per-record pre-computed RDATA info                                 */
    uint8_t name_buf[RESOURCE_ANSWER_MAX_RECORDS][256];
    int     name_len[RESOURCE_ANSWER_MAX_RECORDS];
    int     rdlength[RESOURCE_ANSWER_MAX_RECORDS];

    /* Fixed-size portion of each answer RR:                               *
     *  NAME (compression ptr) = 2                                         *
     *  TYPE                   = 2                                         *
     *  CLASS                  = 2                                         *
     *  TTL                    = 4                                         *
     *  RDLENGTH               = 2                                         *
     *  TOTAL                  = 12                                        */
    #define ANSWER_FIXED_SIZE  12

    /* ── 1. Parameter validation ────────────────────────────────── */
    if (!query_packet || !query || !answer_set || !response)
        return -1;
    if (response_size <= 0)
        return -1;
    if (answer_set->count <= 0 ||
        answer_set->count > RESOURCE_ANSWER_MAX_RECORDS)
        return -2;
    if (answer_set->is_blocked)
        return -3;   /* BLOCK must use build_nxdomain_response */
    if (query->question.qclass != DNS_QCLASS_IN)
        return -4;

    question_len = query->question_end_offset - DNS_HEADER_SIZE;
    if (question_len <= 0 || question_len > (query_len - DNS_HEADER_SIZE))
        return -5;
    if (query->question_end_offset > query_len)
        return -5;

    /* ── 2. Validate records + pre-compute RDATA lengths ──────────── */
    for (i = 0; i < answer_set->count; i++) {
        const ResourceRecord *rec = &answer_set->records[i];

        /* Every record must match the query type */
        if (rec->type   != query->question.qtype) return -6;
        if (rec->class_ != DNS_QCLASS_IN)         return -6;
        if (rec->kind   == RR_KIND_BLOCK)         return -6;

        name_len[i] = 0;   /* only used by name-carrying types */

        switch (rec->kind) {
        case RR_KIND_A:
            rdlength[i] = 4;
            break;

        case RR_KIND_AAAA:
            rdlength[i] = 16;
            break;

        case RR_KIND_CNAME:
        case RR_KIND_NS:
        case RR_KIND_PTR:
            name_len[i] = dns_name_encode(name_buf[i],
                                          (int)sizeof(name_buf[i]),
                                          rec->rdata.domain_name);
            if (name_len[i] < 0) {
                LOG_DEBUG("dns_name_encode failed for %s: rc=%d",
                          rec->rdata.domain_name, name_len[i]);
                return -7;
            }
            rdlength[i] = name_len[i];
            break;

        case RR_KIND_MX:
            name_len[i] = dns_name_encode(name_buf[i],
                                          (int)sizeof(name_buf[i]),
                                          rec->rdata.mx.exchange);
            if (name_len[i] < 0) {
                LOG_DEBUG("dns_name_encode failed for MX exchange %s: rc=%d",
                          rec->rdata.mx.exchange, name_len[i]);
                return -7;
            }
            rdlength[i] = 2 + name_len[i];  /* PREFERENCE + exchange */
            break;

        default:
            LOG_DEBUG("unsupported RR kind %d in answer_set",
                      (int)rec->kind);
            return -8;
        }
    }

    /* ── 3. Calculate total response length ──────────────────────── */
    response_len = DNS_HEADER_SIZE + question_len;
    for (i = 0; i < answer_set->count; i++) {
        response_len += ANSWER_FIXED_SIZE + rdlength[i];
    }
    if (response_len > response_size) {
        LOG_DEBUG("response buffer too small: need %d, have %d",
                  response_len, response_size);
        return -9;
    }
    if (response_len > DNS_MAX_PACKET_SIZE) {
        LOG_DEBUG("response exceeds DNS max packet size: %d > %d",
                  response_len, DNS_MAX_PACKET_SIZE);
        return -10;
    }

    memset(response, 0, (size_t)response_len);

    /* ── 4. Build header ────────────────────────────────────────── */
    req_flags = query->header.flags;
    resp_flags = 0x8000;                      /* QR = 1               */
    resp_flags |= (req_flags & 0x7800);       /* Opcode (4 bits)      */
    resp_flags |= (req_flags & 0x0100);       /* RD                    */
    resp_flags |= 0x0080;                     /* RA = 1                */

    write_u16_be(response + 0,  query->header.id);
    write_u16_be(response + 2,  resp_flags);
    write_u16_be(response + 4,  1);                            /* QDCOUNT */
    write_u16_be(response + 6,  (uint16_t)answer_set->count);  /* ANCOUNT */
    write_u16_be(response + 8,  0);                            /* NSCOUNT */
    write_u16_be(response + 10, 0);                            /* ARCOUNT */

    /* ── 5. Copy Question section verbatim ──────────────────────── */
    memcpy(response + DNS_HEADER_SIZE,
           query_packet + DNS_HEADER_SIZE,
           (size_t)question_len);

    /* ── 6. Build Answer section ────────────────────────────────── */
    answer_offset = DNS_HEADER_SIZE + question_len;

    for (i = 0; i < answer_set->count; i++) {
        const ResourceRecord *rec = &answer_set->records[i];
        uint32_t ttl;
        int off;

        off = answer_offset;
        ttl = rec->ttl;
        if (ttl == 0) ttl = 60;   /* default TTL for local records */

        /* Common fixed fields                                          */
        write_u16_be(response + off +  0, 0xC00C);      /* NAME ptr     */
        write_u16_be(response + off +  2, rec->type);   /* TYPE         */
        write_u16_be(response + off +  4, rec->class_); /* CLASS        */
        write_u32_be(response + off +  6, ttl);         /* TTL          */
        write_u16_be(response + off + 10, (uint16_t)rdlength[i]);

        /* Type-specific RDATA                                           */
        switch (rec->kind) {
        case RR_KIND_A:
            memcpy(response + off + 12, &rec->rdata.ipv4_addr, 4);
            break;

        case RR_KIND_AAAA:
            memcpy(response + off + 12, rec->rdata.ipv6_addr, 16);
            break;

        case RR_KIND_CNAME:
        case RR_KIND_NS:
        case RR_KIND_PTR:
            memcpy(response + off + 12, name_buf[i],
                   (size_t)name_len[i]);
            break;

        case RR_KIND_MX:
            write_u16_be(response + off + 12, rec->rdata.mx.preference);
            memcpy(response + off + 14, name_buf[i],
                   (size_t)name_len[i]);
            break;

        default:
            break;
        }

        answer_offset += ANSWER_FIXED_SIZE + rdlength[i];
    }

    #undef ANSWER_FIXED_SIZE
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

    write_u16_be(response + 0,  query->header.id);
    write_u16_be(response + 2,  resp_flags);
    write_u16_be(response + 4,  1);   /* QDCOUNT = 1       */
    write_u16_be(response + 6,  0);   /* ANCOUNT = 0       */
    write_u16_be(response + 8,  0);   /* NSCOUNT = 0       */
    write_u16_be(response + 10, 0);   /* ARCOUNT = 0       */

    /* ── 3. Copy Question section verbatim ──────────────────────── */
    memcpy(response + DNS_HEADER_SIZE,
           query_packet + DNS_HEADER_SIZE,
           (size_t)question_len);

    return response_len;
}
