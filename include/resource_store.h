#ifndef RESOURCE_STORE_H
#define RESOURCE_STORE_H

#include "resource_record.h"

/* ── Maximum records in local table ────────────────────────────────── */
#define RESOURCE_STORE_MAX_RECORDS  1024

/* ── Resource store (local static records) ─────────────────────────── */
typedef struct {
    ResourceRecord records[RESOURCE_STORE_MAX_RECORDS];
    int count;
} ResourceStore;

/* ── Public API ────────────────────────────────────────────────────── */
void resource_store_init(ResourceStore *store);

int  resource_store_load_file(ResourceStore *store, const char *filename);

/* Legacy single-record lookup (Phase 2–4 compatible).
 * Returns the first matching record for (qname, qtype, qclass),
 * or NULL if not found.                                               */
const ResourceRecord *resource_store_lookup(const ResourceStore *store,
                                            const char *qname,
                                            uint16_t qtype,
                                            uint16_t qclass);

/* New multi-record lookup (Phase 5+).
 * Searches for all matching records.  On BLOCK hit, sets
 * out_set->is_blocked = 1 and returns immediately.  Otherwise
 * fills out_set->records with up to RESOURCE_ANSWER_MAX_RECORDS
 * matching entries.
 * Returns  0 on success (including "no match" — check count and
 *            is_blocked),
 *         -1 on parameter error.                                       */
int resource_store_lookup_set(const ResourceStore *store,
                              const char *qname,
                              uint16_t qtype,
                              uint16_t qclass,
                              ResourceAnswerSet *out_set);

#endif /* RESOURCE_STORE_H */
