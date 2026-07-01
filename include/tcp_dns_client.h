#ifndef TCP_DNS_CLIENT_H
#define TCP_DNS_CLIENT_H

#include <stdint.h>

/* ── DNS-over-TCP constants ──────────────────────────────────────────── */
#define TCP_DNS_MAX_MESSAGE_SIZE  4096
#define TCP_DNS_DEFAULT_TIMEOUT_MS 3000

/* ═══════════════════════════════════════════════════════════════════════
 *  tcp_dns_query — send a DNS query over TCP and read the full response
 *
 *  Parameters
 *  ──────────
 *    server_ip       upstream DNS server IPv4 address (dotted-decimal)
 *    server_port     upstream DNS server port (typically 53)
 *    query           complete DNS message to send (no TCP length prefix)
 *    query_len       byte-length of the DNS message
 *    response        output buffer for the DNS response (no length prefix)
 *    response_size   size of the output buffer in bytes
 *    timeout_ms      send / receive timeout in milliseconds;
 *                    a value <= 0 uses TCP_DNS_DEFAULT_TIMEOUT_MS
 *
 *  Return
 *  ──────
 *    > 0  —  DNS message length written to response (no TCP length prefix)
 *    -1   —  parameter error (NULL argument, invalid length, etc.)
 *    -2   —  socket creation failed
 *    -3   —  address resolution failed
 *    -4   —  connection failed
 *    -5   —  send failed
 *    -6   —  receive of length prefix failed
 *    -7   —  response length invalid / exceeds buffer
 *    -8   —  receive of response body failed
 *
 *  The caller must have already called WSAStartup (via platform_win).
 * ═══════════════════════════════════════════════════════════════════════ */
int tcp_dns_query(const char *server_ip,
                  uint16_t server_port,
                  const uint8_t *query,
                  int query_len,
                  uint8_t *response,
                  int response_size,
                  int timeout_ms);

#endif /* TCP_DNS_CLIENT_H */
