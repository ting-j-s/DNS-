#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stdint.h>
#include <winsock2.h>

#include "dns_packet.h"   /* DNS_MAX_PACKET_SIZE, DNS_MAX_NAME_LEN */

/* ── Transaction table constants ──────────────────────────────────── */
#define TRANSACTION_TABLE_SIZE  1024
#define DNS_RELAY_TIMEOUT_MS    3000

/* ── Single DNS relay transaction ─────────────────────────────────── */
typedef struct {
    int used;

    uint16_t relay_id;          /* ID sent to upstream DNS              */
    uint16_t client_id;         /* Original client DNS ID               */

    char qname[DNS_MAX_NAME_LEN + 1];
    uint16_t qtype;
    uint16_t qclass;

    struct sockaddr_in client_addr;
    int client_addr_len;

    /* Saved upstream query (relay_id version) for TCP fallback         */
    uint8_t query_packet[DNS_MAX_PACKET_SIZE];
    int     query_len;

    uint64_t start_time_ms;
    uint64_t expire_time_ms;
} DnsTransaction;

/* ── Transaction table ────────────────────────────────────────────── */
typedef struct {
    DnsTransaction items[TRANSACTION_TABLE_SIZE];
    uint16_t next_relay_id;
} TransactionTable;

/* ── Public API ───────────────────────────────────────────────────── */

/* Initialise the table to empty state */
void transaction_table_init(TransactionTable *table);

/* Get current time in milliseconds (monotonic, platform-dependent) */
uint64_t transaction_now_ms(void);

/* Add a new transaction; assigns a unique relay_id via out_relay_id.
 * Returns  0 on success,
 *         -1 on parameter error,
 *         -2 if no free relay_id could be allocated,
 *         -3 if the table is full.                                   */
int transaction_add(TransactionTable *table,
                    uint16_t client_id,
                    const char *qname,
                    uint16_t qtype,
                    uint16_t qclass,
                    const struct sockaddr_in *client_addr,
                    int client_addr_len,
                    uint16_t *out_relay_id);

/* Find a transaction by relay_id (used when upstream responds).
 * Returns pointer to the transaction, or NULL if not found.          */
DnsTransaction *transaction_find_by_relay_id(TransactionTable *table,
                                             uint16_t relay_id);

/* Remove a transaction (caller must already have a valid pointer).    */
void transaction_remove(TransactionTable *table,
                        DnsTransaction *tx);

/* Remove all expired transactions. Returns the number removed.        */
int transaction_cleanup_expired(TransactionTable *table);

/* Return the number of currently active (used) transactions.          */
int transaction_count_used(const TransactionTable *table);

/* Save the relay_id-rewritten query packet for potential TCP fallback.
 *  Must be called AFTER dns_packet_set_id has replaced client_id with
 *  relay_id in the send buffer.
 *  Returns  0 on success,
 *          -1 on parameter error (NULL table / packet, invalid len),
 *          -2 if relay_id not found.                                   */
int transaction_set_query_packet(TransactionTable *table,
                                 uint16_t relay_id,
                                 const uint8_t *query_packet,
                                 int query_len);

#endif /* TRANSACTION_H */
