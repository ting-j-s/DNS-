#define _WIN32_WINNT 0x0600   /* Required for GetTickCount64 */
#include "cache.h"
#include "logger.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <windows.h>

/* ── qname normalisation ───────────────────────────────────────────────
 *  Lowercase the domain name and strip a single trailing dot if present.
 *  dst must be at least DNS_MAX_NAME_LEN + 1 bytes.
 *  Returns 0 on success, negative on error.                               */
static int cache_normalise_qname(char *dst, int dst_size,
                                  const char *qname)
{
    const char *src;
    int len;
    int i;

    if (!dst || !qname)           return -1;
    if (dst_size < 1)             return -1;

    len = (int)strlen(qname);
    if (len > DNS_MAX_NAME_LEN)   return -2;
    if (len + 1 > dst_size)       return -3;

    /* ── Strip trailing dot ─────────────────────────────────────────── */
    if (len > 0 && qname[len - 1] == '.') {
        len--;
    }

    /* ── Lowercase into destination ──────────────────────────────────── */
    src = qname;
    for (i = 0; i < len; i++) {
        dst[i] = (char)tolower((unsigned char)src[i]);
    }
    dst[len] = '\0';

    return 0;
}

/* ── djb2 hash on (lowercase_qname, qtype, qclass) ──────────────────── */
static unsigned int cache_hash_key(const char *qname,
                                   uint16_t qtype,
                                   uint16_t qclass)
{
    unsigned long hash;
    const char *p;

    hash = 5381;

    /* Hash the (already normalised) qname */
    for (p = qname; *p; p++) {
        hash = ((hash << 5) + hash) + (unsigned char)(*p);  /* hash * 33 + c */
    }

    /* Mix in qtype and qclass */
    hash = ((hash << 5) + hash) + (qtype & 0xFF);
    hash = ((hash << 5) + hash) + ((qtype >> 8) & 0xFF);
    hash = ((hash << 5) + hash) + (qclass & 0xFF);
    hash = ((hash << 5) + hash) + ((qclass >> 8) & 0xFF);

    return (unsigned int)(hash % CACHE_TABLE_SIZE);
}

/* ── Check if a cache entry's key matches (qname, qtype, qclass) ───── */
static int cache_entry_key_match(const CacheEntry *entry,
                                  const char *qname,
                                  uint16_t qtype,
                                  uint16_t qclass)
{
    if (!entry->used) return 0;
    if (entry->qtype  != qtype)  return 0;
    if (entry->qclass != qclass) return 0;
    if (strcmp(entry->qname, qname) != 0) return 0;
    return 1;
}

/* ── Public API ─────────────────────────────────────────────────────── */

int cache_table_init(CacheTable *cache)
{
    if (!cache) return -1;

    cache->entries = (CacheEntry *)calloc((size_t)CACHE_TABLE_SIZE,
                                           sizeof(CacheEntry));
    if (!cache->entries) {
        LOG_ERROR("cache_table_init: calloc failed for %d entries",
                  CACHE_TABLE_SIZE);
        cache->size = 0;
        return -1;
    }
    cache->size = CACHE_TABLE_SIZE;
    return 0;
}


void cache_table_destroy(CacheTable *cache)
{
    if (!cache) return;
    free(cache->entries);
    cache->entries = NULL;
    cache->size = 0;
}


uint64_t cache_now_ms(void)
{
    return (uint64_t)GetTickCount64();
}


int cache_lookup(CacheTable *cache,
                 const char *qname,
                 uint16_t qtype,
                 uint16_t qclass,
                 ResourceAnswerSet *out_set)
{
    unsigned int idx;
    int probes;
    char norm_name[DNS_MAX_NAME_LEN + 1];

    /* ── Parameter validation ──────────────────────────────────────── */
    if (!cache || !qname || !out_set) {
        return -1;
    }

    /* ── Initialise output ─────────────────────────────────────────── */
    memset(out_set, 0, sizeof(*out_set));

    /* ── Normalise qname ───────────────────────────────────────────── */
    if (cache_normalise_qname(norm_name, sizeof(norm_name), qname) != 0) {
        return -2;
    }

    /* ── Linear-probe lookup ───────────────────────────────────────── */
    idx = cache_hash_key(norm_name, qtype, qclass);

    for (probes = 0; probes < cache->size; probes++) {
        CacheEntry *entry = &cache->entries[idx];

        if (!entry->used) {
            /* Empty slot — stop searching */
            return 0;
        }

        if (cache_entry_key_match(entry, norm_name, qtype, qclass)) {
            uint64_t now = cache_now_ms();

            if (now >= entry->expire_time_ms) {
                /* Expired — delete entry and return miss */
                LOG_DEBUG("cache expired: qname=%s, qtype=%s(%u)",
                          entry->qname,
                          dns_qtype_to_string(entry->qtype),
                          entry->qtype);
                memset(entry, 0, sizeof(*entry));
                return 0;
            }

            /* ── Hit — copy answer set to caller ──────────────────── */
            *out_set = entry->answer_set;

            LOG_DEBUG("cache hit: qname=%s, qtype=%s(%u), answers=%d",
                      entry->qname,
                      dns_qtype_to_string(entry->qtype),
                      entry->qtype,
                      entry->answer_set.count);
            return 1;
        }

        /* Linear probe to next slot */
        idx = (idx + 1) % cache->size;
    }

    return 0;
}


int cache_insert(CacheTable *cache,
                 const char *qname,
                 uint16_t qtype,
                 uint16_t qclass,
                 const ResourceAnswerSet *answer_set,
                 uint32_t ttl)
{
    unsigned int idx;
    unsigned int first_unused;
    int probes;
    int found_unused;
    char norm_name[DNS_MAX_NAME_LEN + 1];
    uint64_t now;
    int i;

    /* ── Parameter validation ──────────────────────────────────────── */
    if (!cache || !qname || !answer_set) {
        return -1;
    }
    if (answer_set->is_blocked) {
        /* BLOCK entries are not cached */
        return 0;
    }
    if (answer_set->count <= 0 ||
        answer_set->count > RESOURCE_ANSWER_MAX_RECORDS) {
        return -1;
    }
    if (ttl == 0) {
        LOG_DEBUG("cache skip ttl=0: qname=%s, qtype=%s(%u)",
                  qname, dns_qtype_to_string(qtype), qtype);
        return 0;
    }

    /* ── Normalise qname ───────────────────────────────────────────── */
    if (cache_normalise_qname(norm_name, sizeof(norm_name), qname) != 0) {
        return -2;
    }

    now = cache_now_ms();

    /* ── Linear-probe insert ───────────────────────────────────────── */
    idx = cache_hash_key(norm_name, qtype, qclass);
    first_unused = idx;
    found_unused  = 0;

    for (probes = 0; probes < cache->size; probes++) {
        CacheEntry *entry = &cache->entries[idx];

        if (!entry->used) {
            if (!found_unused) {
                first_unused = idx;
                found_unused  = 1;
            }
            /* Keep going — the same key might be further on */
        } else if (cache_entry_key_match(entry, norm_name, qtype, qclass)) {
            /* ── Overwrite existing entry ──────────────────────────── */
            entry->answer_set    = *answer_set;
            entry->expire_time_ms = now + (uint64_t)ttl * 1000;

            LOG_DEBUG("cache update: qname=%s, qtype=%s(%u), "
                      "ttl=%u, answers=%d",
                      entry->qname,
                      dns_qtype_to_string(entry->qtype),
                      entry->qtype,
                      ttl,
                      entry->answer_set.count);
            return 1;
        }

        idx = (idx + 1) % cache->size;
    }

    /* ── Key not found; use the first unused slot ──────────────────── */
    if (found_unused) {
        CacheEntry *entry = &cache->entries[first_unused];

        entry->used = 1;
        strncpy(entry->qname, norm_name, DNS_MAX_NAME_LEN);
        entry->qname[DNS_MAX_NAME_LEN] = '\0';
        entry->qtype  = qtype;
        entry->qclass = qclass;

        entry->answer_set     = *answer_set;
        entry->expire_time_ms = now + (uint64_t)ttl * 1000;

        LOG_DEBUG("cache insert: qname=%s, qtype=%s(%u), "
                  "ttl=%u, answers=%d",
                  entry->qname,
                  dns_qtype_to_string(entry->qtype),
                  entry->qtype,
                  ttl,
                  entry->answer_set.count);
        return 1;
    }

    /* ── Table full — try cleanup, then retry once ─────────────────── */
    {
        int cleaned;
        cleaned = cache_cleanup_expired(cache);
        LOG_DEBUG("cache table full after cleanup: cleaned=%d, retrying",
                  cleaned);

        if (cleaned > 0) {
            /* Scan again for an unused slot */
            for (i = 0; i < cache->size; i++) {
                if (!cache->entries[i].used) {
                    CacheEntry *entry = &cache->entries[i];

                    entry->used = 1;
                    strncpy(entry->qname, norm_name, DNS_MAX_NAME_LEN);
                    entry->qname[DNS_MAX_NAME_LEN] = '\0';
                    entry->qtype  = qtype;
                    entry->qclass = qclass;

                    entry->answer_set     = *answer_set;
                    entry->expire_time_ms = now + (uint64_t)ttl * 1000;

                    LOG_DEBUG("cache insert: qname=%s, qtype=%s(%u), "
                              "ttl=%u, answers=%d",
                              entry->qname,
                              dns_qtype_to_string(entry->qtype),
                              entry->qtype,
                              ttl,
                              entry->answer_set.count);
                    return 1;
                }
            }
        }
    }

    LOG_ERROR("cache table full: qname=%s, qtype=%s(%u)",
              norm_name, dns_qtype_to_string(qtype), qtype);
    return -2;
}


int cache_cleanup_expired(CacheTable *cache)
{
    int removed = 0;
    int i;
    uint64_t now;

    if (!cache) return 0;

    now = cache_now_ms();

    for (i = 0; i < cache->size; i++) {
        CacheEntry *entry = &cache->entries[i];

        if (entry->used && now >= entry->expire_time_ms) {
            LOG_DEBUG("cache cleanup expired: qname=%s, qtype=%s(%u)",
                      entry->qname,
                      dns_qtype_to_string(entry->qtype),
                      entry->qtype);
            memset(entry, 0, sizeof(*entry));
            removed++;
        }
    }

    if (removed > 0) {
        LOG_DEBUG("cache_cleanup_expired: removed %d entries", removed);
    }

    return removed;
}


int cache_count_used(const CacheTable *cache)
{
    int count = 0;
    int i;

    if (!cache) return 0;

    for (i = 0; i < cache->size; i++) {
        if (cache->entries[i].used) {
            count++;
        }
    }

    return count;
}
