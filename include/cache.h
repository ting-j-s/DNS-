#ifndef CACHE_H
#define CACHE_H

#include <stdint.h>
#include "resource_record.h"

/* ── Cache table constants ─────────────────────────────────────────── */
#define CACHE_TABLE_SIZE         256
#define CACHE_BUCKET_MAX_RECORDS  16

/* ── Single cache entry ────────────────────────────────────────────── */
typedef struct {
    int used;

    char qname[DNS_MAX_NAME_LEN + 1];   /* lower-case, no trailing dot */
    uint16_t qtype;
    uint16_t qclass;

    ResourceAnswerSet answer_set;

    uint64_t expire_time_ms;            /* absolute expiration (monotonic) */
} CacheEntry;

/* ── Cache table ─────────────────────────────────────────────────────
 *  Entries are allocated on the heap to avoid stack overflow
 *  (sizeof(CacheTable) ≈ 2.2 MB with CACHE_TABLE_SIZE == 256).         */
typedef struct {
    CacheEntry *entries;
    int        size;    /* == CACHE_TABLE_SIZE */
} CacheTable;

/* ── Public API ────────────────────────────────────────────────────── */

/* Allocate and initialise the cache.  Returns 0 on success, -1 on error. */
int cache_table_init(CacheTable *cache);

/* Release all heap memory held by the cache.  Safe to call on an
 * already-destroyed or zero-initialised table.                          */
void cache_table_destroy(CacheTable *cache);

/* Get current time in milliseconds (monotonic — GetTickCount64).
 * Equivalent to transaction_now_ms but exposed independently so cache
 * can be tested / used without coupling to the transaction module.     */
uint64_t cache_now_ms(void);

/* Look up a cached answer set by (qname, qtype, qclass).
 *  - qname is normalised internally (lowercased, trailing dot stripped).
 *  - On hit, copies the cached answer_set into *out_set and returns 1.
 *  - On miss (not found or expired), returns 0; expired entries are
 *    deleted during lookup.
 *  - On error (NULL arguments, etc.), returns a negative value.          */
int cache_lookup(CacheTable *cache,
                 const char *qname,
                 uint16_t qtype,
                 uint16_t qclass,
                 ResourceAnswerSet *out_set);

/* Insert or update a cached answer set.
 *  - ttl == 0 → skip, return 0.
 *  - is_blocked → skip, return 0 (block is not cached).
 *  - Same (qname, qtype, qclass) key overwrites existing entry.
 *  - If the table is full, expired entries are cleaned once and
 *    insertion is retried; returns -2 if still full.                     */
int cache_insert(CacheTable *cache,
                 const char *qname,
                 uint16_t qtype,
                 uint16_t qclass,
                 const ResourceAnswerSet *answer_set,
                 uint32_t ttl);

/* Remove all expired entries.  Returns the number removed.              */
int cache_cleanup_expired(CacheTable *cache);

/* Return the number of currently used (non-expired) entries.            */
int cache_count_used(const CacheTable *cache);

#endif /* CACHE_H */
