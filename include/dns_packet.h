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
int dns_packet_build_a_response(const uint8_t *query_packet,
                                int query_len,
                                const DnsQuery *query,
                                uint32_t ipv4_addr,
                                uint32_t ttl,
                                uint8_t *response,
                                int response_size);

int dns_packet_build_nxdomain_response(const uint8_t *query_packet,
                                       int query_len,
                                       const DnsQuery *query,
                                       uint8_t *response,
                                       int response_size);

/* ── Human-readable type/class strings ──────────────────────────── */
const char *dns_qtype_to_string(uint16_t qtype);
const char *dns_qclass_to_string(uint16_t qclass);

#endif /* DNS_PACKET_H */
