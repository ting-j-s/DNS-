#ifndef DNS_PACKET_H
#define DNS_PACKET_H

#include <stdint.h>

/* ── DNS protocol constants ─────────────────────────────────────── */
#define DNS_HEADER_SIZE      12
#define DNS_MAX_PACKET_SIZE  512
#define DNS_MAX_NAME_LEN     255

/* ── QTYPE values ───────────────────────────────────────────────── */
#define DNS_QTYPE_A     1
#define DNS_QTYPE_NS    2
#define DNS_QTYPE_CNAME 5
#define DNS_QTYPE_PTR   12
#define DNS_QTYPE_MX    15
#define DNS_QTYPE_AAAA  28

/* ── QCLASS values ──────────────────────────────────────────────── */
#define DNS_QCLASS_IN   1

/* ── DNS Header (12 bytes, wire format) ─────────────────────────── */
typedef struct {
    uint16_t id;        /* Transaction ID                         */
    uint16_t flags;     /* QR/Opcode/AA/TC/RD/RA/Z/RCODE         */
    uint16_t qdcount;   /* Question count                         */
    uint16_t ancount;   /* Answer record count                    */
    uint16_t nscount;   /* Authority record count                 */
    uint16_t arcount;   /* Additional record count                */
} DnsHeader;

/* ── DNS Question ───────────────────────────────────────────────── */
typedef struct {
    char     qname[DNS_MAX_NAME_LEN + 1];  /* Decoded domain name  */
    uint16_t qtype;                         /* Query type           */
    uint16_t qclass;                        /* Query class          */
} DnsQuestion;

/* ── DNS Query (header + single question) ───────────────────────── */
typedef struct {
    DnsHeader   header;
    DnsQuestion question;
    int         question_end_offset;  /* byte offset after QCLASS      */
} DnsQuery;

/* ── DNS packet parsing ─────────────────────────────────────────── */
int dns_packet_parse_query(const uint8_t *packet,
                           int packet_len,
                           DnsQuery *out_query);

/* ── DNS response construction ──────────────────────────────────── */

/* Forward declaration — full definition in resource_record.h.
 *  Using a tagged struct avoids a circular include of resource_record.h
 *  (which itself includes dns_packet.h for DNS constants).            */
struct ResourceAnswerSet;

int dns_packet_build_a_response(const uint8_t *query_packet,
                                int query_len,
                                const DnsQuery *query,
                                uint32_t ipv4_addr,
                                uint32_t ttl,
                                uint8_t *response,
                                int response_size);

/* Build a DNS A-record response with ANCOUNT >= 1.
 *  answer_set must contain 1..RESOURCE_ANSWER_MAX_RECORDS entries,
 *  all of which must be RR_KIND_A / DNS_QTYPE_A / DNS_QCLASS_IN.
 *  Returns response length on success, negative on error.              */
int dns_packet_build_a_response_set(const uint8_t *query_packet,
                                    int query_len,
                                    const DnsQuery *query,
                                    const struct ResourceAnswerSet *answer_set,
                                    uint8_t *response,
                                    int response_size);

/* Build a DNS response for any supported RR type (A/AAAA/CNAME/NS/PTR/MX).
 *  All records in answer_set must match query->question.qtype.
 *  BLOCK must not enter this function (use build_nxdomain_response).
 *  Returns response length on success, negative on error.              */
int dns_packet_build_rr_response_set(const uint8_t *query_packet,
                                     int query_len,
                                     const DnsQuery *query,
                                     const struct ResourceAnswerSet *answer_set,
                                     uint8_t *response,
                                     int response_size);

int dns_packet_build_nxdomain_response(const uint8_t *query_packet,
                                       int query_len,
                                       const DnsQuery *query,
                                       uint8_t *response,
                                       int response_size);

/* ── Upstream answer extraction ────────────────────────────────── */

/* Parse the Answer Section of an upstream DNS response and extract
 * cache-able records into out_set.
 *
 *  - packet / packet_len : raw upstream DNS response
 *  - qname / qtype / qclass : original query parameters (used as cache key)
 *  - out_set : receives extracted records (only type == qtype, class == IN)
 *  - out_min_ttl : receives the minimum TTL among extracted records
 *
 *  Returns  1 if at least one cache-able record was extracted,
 *           0 if no cache-able records found (NXDOMAIN, empty answer, etc.),
 *          -1 on parameter error,
 *          -2 on parse error.                                            */
int dns_packet_extract_answer_set(const uint8_t *packet,
                                  int packet_len,
                                  const char *qname,
                                  uint16_t qtype,
                                  uint16_t qclass,
                                  struct ResourceAnswerSet *out_set,
                                  uint32_t *out_min_ttl);

/* ── TC (Truncation) flag check ─────────────────────────────────── */

/* Check the TC bit in DNS header flags.
 *  Returns 1 if TC=1 (message truncated),
 *          0 if TC=0 or packet is NULL / too short.                   */
int dns_packet_is_truncated(const uint8_t *packet, int packet_len);

/* ── Human-readable type/class strings ──────────────────────────── */
const char *dns_qtype_to_string(uint16_t qtype);
const char *dns_qclass_to_string(uint16_t qclass);

#endif /* DNS_PACKET_H */
