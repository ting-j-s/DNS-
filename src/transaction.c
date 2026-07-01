#define _WIN32_WINNT 0x0600   /* Required for GetTickCount64 */
#include "transaction.h"
#include "logger.h"
#include <string.h>
#include <windows.h>

/* ── Check if a relay_id is already in use ────────────────────────── */
static int transaction_relay_id_in_use(const TransactionTable *table,
                                       uint16_t relay_id)
{
    int i;
    for (i = 0; i < TRANSACTION_TABLE_SIZE; i++) {
        if (table->items[i].used &&
            table->items[i].relay_id == relay_id) {
            return 1;
        }
    }
    return 0;
}


/* ── Public API ───────────────────────────────────────────────────── */

uint64_t transaction_now_ms(void)
{
    return (uint64_t)GetTickCount64();
}


void transaction_table_init(TransactionTable *table)
{
    if (!table) return;

    memset(table, 0, sizeof(*table));
    table->next_relay_id = 1;
}


int transaction_add(TransactionTable *table,
                    uint16_t client_id,
                    const char *qname,
                    uint16_t qtype,
                    uint16_t qclass,
                    const struct sockaddr_in *client_addr,
                    int client_addr_len,
                    uint16_t *out_relay_id)
{
    int i;
    int slot;
    uint16_t candidate;
    int attempts;
    uint64_t now;

    /* ── Parameter validation ────────────────────────────────────── */
    if (!table || !qname || !client_addr || !out_relay_id) {
        return -1;
    }

    /* ── Find a free slot ────────────────────────────────────────── */
    slot = -1;
    for (i = 0; i < TRANSACTION_TABLE_SIZE; i++) {
        if (!table->items[i].used) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        LOG_ERROR("transaction_add: table full (%d entries)",
                  TRANSACTION_TABLE_SIZE);
        return -3;
    }

    /* ── Allocate a unique relay_id ──────────────────────────────── */
    candidate = table->next_relay_id;
    attempts = 0;

    while (attempts < 65535) {
        if (candidate == 0) {
            candidate = 1;
        }

        if (candidate != client_id &&
            !transaction_relay_id_in_use(table, candidate)) {
            break;
        }

        candidate++;
        attempts++;

        if (candidate == 0) {
            candidate = 1;
        }
    }

    if (attempts >= 65535) {
        LOG_ERROR("transaction_add: no free relay_id after %d attempts",
                  attempts);
        return -2;
    }

    /* Advance next_relay_id for future allocations */
    table->next_relay_id = candidate + 1;
    if (table->next_relay_id == 0) {
        table->next_relay_id = 1;
    }

    /* ── Populate the transaction ────────────────────────────────── */
    now = transaction_now_ms();

    table->items[slot].used            = 1;
    table->items[slot].relay_id        = candidate;
    table->items[slot].client_id       = client_id;

    strncpy(table->items[slot].qname, qname, DNS_MAX_NAME_LEN);
    table->items[slot].qname[DNS_MAX_NAME_LEN] = '\0';

    table->items[slot].qtype           = qtype;
    table->items[slot].qclass          = qclass;

    memcpy(&table->items[slot].client_addr,
           client_addr, sizeof(struct sockaddr_in));
    table->items[slot].client_addr_len = client_addr_len;

    table->items[slot].start_time_ms   = now;
    table->items[slot].expire_time_ms  = now + DNS_RELAY_TIMEOUT_MS;

    *out_relay_id = candidate;

    LOG_DEBUG("transaction_add: client_id=%u, relay_id=%u, qname=%s, "
              "slot=%d, expires=%llu",
              client_id, candidate, qname, slot,
              (unsigned long long)table->items[slot].expire_time_ms);

    return 0;
}


DnsTransaction *transaction_find_by_relay_id(TransactionTable *table,
                                             uint16_t relay_id)
{
    int i;

    if (!table) return NULL;

    for (i = 0; i < TRANSACTION_TABLE_SIZE; i++) {
        if (table->items[i].used &&
            table->items[i].relay_id == relay_id) {
            return &table->items[i];
        }
    }

    return NULL;
}


void transaction_remove(TransactionTable *table,
                        DnsTransaction *tx)
{
    if (!table || !tx) return;

    LOG_DEBUG("transaction_remove: relay_id=%u, client_id=%u, qname=%s",
              tx->relay_id, tx->client_id, tx->qname);

    memset(tx, 0, sizeof(*tx));
    tx->used = 0;
}


int transaction_cleanup_expired(TransactionTable *table)
{
    int i;
    int removed = 0;
    uint64_t now;

    if (!table) return 0;

    now = transaction_now_ms();

    for (i = 0; i < TRANSACTION_TABLE_SIZE; i++) {
        if (table->items[i].used &&
            now >= table->items[i].expire_time_ms) {

            LOG_DEBUG("transaction timeout: relay_id=%u, client_id=%u, "
                      "qname=%s, expired=%llu, now=%llu",
                      table->items[i].relay_id,
                      table->items[i].client_id,
                      table->items[i].qname,
                      (unsigned long long)table->items[i].expire_time_ms,
                      (unsigned long long)now);

            memset(&table->items[i], 0, sizeof(table->items[i]));
            table->items[i].used = 0;
            removed++;
        }
    }

    if (removed > 0) {
        LOG_DEBUG("transaction_cleanup_expired: removed %d entries", removed);
    }

    return removed;
}


int transaction_set_query_packet(TransactionTable *table,
                                 uint16_t relay_id,
                                 const uint8_t *query_packet,
                                 int query_len)
{
    DnsTransaction *tx;

    if (!table || !query_packet || query_len <= 0) {
        return -1;
    }

    if (query_len > DNS_MAX_PACKET_SIZE) {
        return -1;
    }

    tx = transaction_find_by_relay_id(table, relay_id);
    if (!tx) {
        return -2;
    }

    memcpy(tx->query_packet, query_packet, (size_t)query_len);
    tx->query_len = query_len;

    LOG_DEBUG("transaction_set_query_packet: relay_id=%u, bytes=%d",
              relay_id, query_len);

    return 0;
}


int transaction_count_used(const TransactionTable *table)
{
    int i;
    int count = 0;

    if (!table) return 0;

    for (i = 0; i < TRANSACTION_TABLE_SIZE; i++) {
        if (table->items[i].used) {
            count++;
        }
    }

    return count;
}
