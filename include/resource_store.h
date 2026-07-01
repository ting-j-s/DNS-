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

const ResourceRecord *resource_store_lookup(const ResourceStore *store,
                                            const char *qname,
                                            uint16_t qtype,
                                            uint16_t qclass);

#endif /* RESOURCE_STORE_H */
