#ifndef DNS_NAME_H
#define DNS_NAME_H

#include <stdint.h>

/* ── DNS name decoder ──────────────────────────────────────────────
 *
 * Decode a DNS domain name from a raw packet starting at `offset`.
 * Supports standard labels and compression pointers (RFC 1035 §4.1.4).
 *
 * Parameters:
 *   packet      - raw DNS packet buffer
 *   packet_len  - total packet length in bytes
 *   offset      - byte offset where the name starts
 *   out_name    - caller-provided buffer for the decoded name
 *   out_size    - size of out_name buffer
 *   next_offset - *next_offset = byte after the name (or after the
 *                 compression pointer) on success
 *
 * Returns:
 *    0 on success
 *   -1 invalid parameter
 *   -2 out of bounds
 *   -3 bad compression pointer
 *   -4 output buffer too small
 *   -5 compression pointer loop detected
 */
int dns_name_decode(const uint8_t *packet,
                    int packet_len,
                    int offset,
                    char *out_name,
                    int out_size,
                    int *next_offset);

#endif /* DNS_NAME_H */
