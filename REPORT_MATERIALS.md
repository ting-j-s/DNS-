# Course Design Report Materials — DNS 中继服务器

This file provides ready-to-use content for the course design report. Each section can be expanded into report chapters with diagrams, code snippets, and test results.

---

## 1. 题目 (Title)

**DNS 中继服务器设计与实现**

Design and Implementation of a DNS Relay Server

---

## 2. 设计目标 (Design Goals)

Implement a DNS relay server for Windows that supports:

- Local domain name resolution from a static resource records file
- Domain blocking (returning NXDOMAIN for specified domains)
- Upstream DNS query forwarding
- Dynamic result caching with TTL-based expiration
- Concurrent client query handling
- Multi-type resource records (A, AAAA, NS, CNAME, PTR, MX)
- DNS-over-TCP fallback for truncated UDP responses

---

## 3. 系统总体架构 (System Architecture)

### 3.1 Processing Overview

```
Client (nslookup/ping/browser)
    │  UDP DNS query
    ▼
┌─────────────────────────┐
│  DNS Relay Server       │
│  (port 53)              │
│                         │
│  1. Parse DNS query     │
│  2. Check local table   │──► BLOCK? ──► NXDOMAIN response
│  3. Check local records │──► HIT?  ──► Build & return response
│  4. Check cache         │──► HIT?  ──► Build & return response
│  5. Forward upstream    │──► MISS ──► Send via UDP to upstream
│                         │         │
│  6. TC=1?               │         │
│     └─ Yes: TCP retry   │◄────────┘
│     └─ No:  use UDP     │
│  7. Restore client ID   │
│  8. Cache the answer    │
│  9. Return to client    │
└─────────────────────────┘
    │
    ▼
Upstream DNS (8.8.8.8 / 202.106.0.20)
```

### 3.2 Key Design Decisions

| Decision                       | Rationale                                                  |
| ------------------------------ | ---------------------------------------------------------- |
| Two UDP sockets                | Separate client-side and upstream-side logic; easier dispatch |
| Single-threaded `select()`     | No synchronization complexity; sufficient for course scale |
| Transaction table (ID mapping) | Multiple clients may use the same DNS ID; relay_id avoids collision |
| Hash-based cache lookup        | Avoid O(n) scan for every query                             |
| TCP only for upstream fallback | No client TCP needed; only triggered on TC=1                 |

---

## 4. 模块划分 (Module Breakdown)

| Module            | File(s)                  | Responsibility                                            |
| ----------------- | ------------------------ | --------------------------------------------------------- |
| `main`            | `src/main.c`             | Program entry, `select()` event loop, request dispatch     |
| `config`          | `include/config.h`, `src/config.c` | Command-line parsing (`-d`, `-dd`, upstream IP, file path) |
| `logger`          | `include/logger.h`, `src/logger.c` | Debug logging with ERROR/INFO/DEBUG/TRACE levels          |
| `platform_win`    | `include/platform_win.h`, `src/platform_win.c` | `WSAStartup` / `WSACleanup`, Windows error messages |
| `udp_socket`      | `include/udp_socket.h`, `src/udp_socket.c` | UDP socket creation, bind, send, receive                  |
| `tcp_dns_client`  | `include/tcp_dns_client.h`, `src/tcp_dns_client.c` | DNS-over-TCP upstream query with 2-byte length prefix |
| `dns_packet`      | `include/dns_packet.h`, `src/dns_packet.c` | DNS header/question/answer parse and build                |
| `dns_name`        | `include/dns_name.h`, `src/dns_name.c` | DNS name label encoding/decoding, compression pointer support |
| `resource_record` | `include/resource_record.h`, `src/resource_record.c` | A/AAAA/NS/CNAME/PTR/MX record structures and helpers |
| `resource_store`  | `include/resource_store.h`, `src/resource_store.c` | Unified lookup (static file + cache), file parsing |
| `cache`           | `include/cache.h`, `src/cache.c` | Dynamic cache with hash lookup and TTL expiration        |
| `transaction`     | `include/transaction.h`, `src/transaction.c` | Transaction table, DNS ID translation, timeout cleanup   |

---

## 5. 关键数据结构 (Key Data Structures)

### 5.1 DnsHeader (12-byte wire format)

```c
typedef struct {
    uint16_t id;        // Transaction ID
    uint16_t flags;     // QR|Opcode|AA|TC|RD|RA|Z|RCODE
    uint16_t qdcount;   // Question count
    uint16_t ancount;   // Answer count
    uint16_t nscount;   // Authority count
    uint16_t arcount;   // Additional count
} DnsHeader;
```

### 5.2 DnsResourceRecord

```c
typedef struct {
    int kind;            // RR_KIND_A, RR_KIND_AAAA, RR_KIND_CNAME, etc.
    char name[256];      // Owner name
    uint16_t type;       // DNS QTYPE
    uint16_t class_;     // DNS QCLASS
    uint32_t ttl;
    uint64_t expire_time_ms;
    DnsRData rdata;      // Union of A/AAAA/NS/CNAME/PTR/MX data
} DnsResourceRecord;
```

### 5.3 DnsTransaction

```c
typedef struct {
    int used;
    uint16_t relay_id;          // ID sent to upstream
    uint16_t client_id;         // Original client ID
    char qname[256];
    uint16_t qtype, qclass;
    struct sockaddr_in client_addr;
    int client_addr_len;
    uint8_t query_packet[512];  // Saved for TCP fallback
    int query_len;
    uint64_t start_time_ms;
    uint64_t expire_time_ms;    // start_time + 3000ms
} DnsTransaction;
```

### 5.4 TransactionTable

```c
typedef struct {
    DnsTransaction items[1024];
    uint16_t next_relay_id;
} TransactionTable;
```

### 5.5 CacheTable

Hash table storing cache entries keyed by `name|type|class`. Each bucket holds a linked list of cache entries with TTL-based expiration.

---

## 6. 关键算法 (Key Algorithms)

### 6.1 DNS Name Decode (with compression pointer support)

DNS names are length-prefixed labels. A compression pointer (two bytes with top 2 bits = `11`) redirects to an earlier offset in the packet. The decoder follows pointers with loop detection (maximum 40 pointer hops) to prevent infinite loops.

### 6.2 DNS ID Translation

**Problem:** Multiple clients may use the same DNS query ID. Without ID translation, upstream responses cannot be correctly routed back to the requesting client.

**Solution:**
1. When a query is received: allocate a unique `relay_id` (guaranteed ≠ client_id)
2. Replace the DNS ID in the forwarded packet with `relay_id`
3. Store mapping `{relay_id → (client_id, client_addr, qname)}` in transaction table
4. When upstream responds: look up transaction by `relay_id`
5. Restore `client_id` in the response and send to the correct client

### 6.3 Transaction Timeout Cleanup

Each transaction has `expire_time_ms = start_time_ms + 3000`. The event loop periodically scans the table and removes expired entries. Late upstream responses for expired transactions are discarded.

### 6.4 Cache Lookup / Insert / TTL Expire

- **Key format:** `lowercase(qname)|QTYPE|QCLASS` (e.g., `www.baidu.com|1|1`)
- **Hash:** djb2 hash function on the key string, modulo bucket count
- **Insert:** store records with `expire_time_ms = now + TTL*1000`
- **Lookup:** find matching entry, check expiration, return if still valid
- **Cleanup:** periodic scan removes expired buckets

### 6.5 DNS-over-TCP Message Format

```
┌──────────────────┬──────────────────────┐
│  2-byte length   │   DNS Message         │
│  (network order) │   (512+ bytes)        │
└──────────────────┴──────────────────────┘
```

- Send: write 2-byte length prefix, then the DNS message
- Receive: read 2 bytes for length, then read exactly `length` bytes

### 6.6 TC Fallback Flow

```
1. Send query via UDP to upstream
2. Receive UDP response
3. If TC bit == 1:
   a. Re-send the same query via TCP (with 2-byte length prefix)
   b. Receive full TCP response
   c. Verify TCP response DNS ID matches relay_id
   d. If match → use TCP response as the final response
   e. If mismatch or failure → fall back to the UDP truncated response
4. If TC bit == 0:
   Use the UDP response directly
```

### 6.7 Single-threaded `select()` Concurrency Model

```c
while (running) {
    FD_ZERO(&readfds);
    FD_SET(client_udp_sock, &readfds);
    FD_SET(upstream_udp_sock, &readfds);

    select(max_fd+1, &readfds, NULL, NULL, &timeout);

    if (client_udp_sock readable) handle_client_query();
    if (upstream_udp_sock readable) handle_upstream_response();

    transaction_cleanup_expired();
    cache_cleanup_expired();
}
```

No busy-waiting. `select()` blocks until data arrives or the next timeout.

---

## 7. 主要流程 (Main Flows)

### 7.1 Client Query Main Flow

```
recvfrom() client UDP socket
  → dns_packet_parse_query()
  → resource_store_lookup()   [check static + cache]
  → if BLOCK: build_nxdomain_response → send to client
  → if local HIT: build_rr_response_set → send to client
  → if cache HIT: build_rr_response_set → send to client
  → if MISS:
      transaction_add() → get relay_id
      dns_packet_set_id(buffer, relay_id)
      transaction_set_query_packet()  [save for TC fallback]
      sendto() upstream
```

### 7.2 Upstream Response Flow

```
recvfrom() upstream UDP socket
  → dns_packet_get_id() → find transaction by relay_id
  → if not found: discard (late response)
  → if TC=1 and query_packet saved:
      tcp_dns_query() → TCP response
      verify TCP response ID == relay_id
  → dns_packet_extract_answer_set() → cache
  → dns_packet_set_id(response, client_id)
  → sendto() client
  → transaction_remove()
```

### 7.3 BLOCK Flow

```
resource_store_lookup() returns BLOCK indicator
  → dns_packet_build_nxdomain_response()
    (QR=1, RCODE=3, ANCOUNT=0)
  → sendto() client
  → no transaction, no upstream query
```

### 7.4 Timeout Cleanup Flow

```
event loop tick:
  now = GetTickCount64()
  for each transaction:
    if now >= expire_time_ms:
      log "transaction timeout"
      mark slot as unused
  return number removed
```

---

## 8. 调试问题与解决 (Debugging Issues & Solutions)

### Issue 1: DNS ID collision between concurrent clients

**Problem:** Two clients may send queries with the same DNS ID. Without translation, upstream responses would be routed to the wrong client.

**Solution:** Introduced `TransactionTable` with ID mapping. Each forwarded query gets a unique `relay_id` (explicitly ≠ client_id). On response, `relay_id` is restored to the original `client_id`.

### Issue 2: relay_id accidentally equals client_id

**Problem:** If `relay_id == client_id`, Wireshark cannot visually confirm that ID translation occurred.

**Solution:** The `transaction_add()` allocation loop explicitly skips candidates equal to `client_id`.

### Issue 3: Transaction table leaks

**Problem:** Without cleanup, stale transactions accumulate and eventually fill the table.

**Solution:** Each transaction has a 3000ms expiration. `transaction_cleanup_expired()` runs in every event loop iteration, removing expired entries.

### Issue 4: Unaligned memory access in DNS packet parsing

**Problem:** Casting `uint8_t*` packet buffer to `uint16_t*` or `uint32_t*` causes unaligned access on some architectures (undefined behavior).

**Solution:** Replaced all pointer casts with safe byte-wise helper functions: `read_u16_be()`, `write_u16_be()`, `read_u32_be()`, `write_u32_be()`.

### Issue 5: CacheTable stack overflow on Windows

**Problem:** Large cache table (with many buckets) placed on the stack exceeded the default Windows thread stack size, causing stack overflow at runtime.

**Solution:** Moved cache table to heap allocation via `cache_table_create()` / `cache_table_destroy()`.

### Issue 6: UDP truncation (TC=1) returns incomplete results

**Problem:** Some DNS responses (e.g., `google.com ANY`) exceed 512 bytes. Upstream sets TC=1 and returns a truncated response. Without TCP fallback, clients receive incomplete data.

**Solution:** Added `tcp_dns_client` module. When UDP response has TC=1, the original query is re-sent over TCP (with 2-byte length prefix). The full TCP response replaces the truncated UDP response.

### Issue 7: Selecting correct timeout value for Winsock TCP sockets

**Problem:** On Windows, `setsockopt()` with `SO_SNDTIMEO`/`SO_RCVTIMEO` requires `DWORD` (milliseconds), not `struct timeval` as on Unix.

**Solution:** Used `DWORD timeout_ms` and `sizeof(DWORD)` in the `tcp_dns_client.c` implementation.

---

## 9. 测试结果概述 (Test Results Summary)

| Category                       | Count | Result |
| ------------------------------ |:-----:| ------ |
| Local A record                 | 1     | ✅ Pass |
| Domain Blocking (NXDOMAIN)     | 2     | ✅ Pass |
| Multi-A Answer                 | 1     | ✅ Pass |
| AAAA record                    | 1     | ✅ Pass |
| CNAME record                   | 1     | ✅ Pass |
| NS record                      | 1     | ✅ Pass |
| PTR record                     | 1     | ✅ Pass |
| MX record                      | 1     | ✅ Pass |
| Upstream UDP forward           | 2     | ✅ Pass |
| Cache hit (A and MX)           | 2     | ✅ Pass |
| DNS ID translation (Wireshark) | 1     | ✅ Pass |
| Timeout cleanup                | 3     | ✅ Pass |
| TC fallback (ANY and TXT)      | 2     | ✅ Pass |
| Static table priority          | 3     | ✅ Pass |

All 22 core test items pass.

---

## 10. 当前限制 (Current Limitations)

1. Client queries are UDP only — no TCP listener on port 53
2. TCP is used only for upstream fallback (TC=1)
3. No DNSSEC validation
4. No DoH (DNS-over-HTTPS) or DoT (DNS-over-TLS)
5. No iterative resolution from root DNS servers
6. Single-threaded `select()` event loop
7. No graceful shutdown (Ctrl+C terminates directly)
8. Fixed-size cache without LRU eviction

---

## 11. 创新点 (Innovation Points)

- **C-style object encapsulation:** All modules hide internal structures, exposing only stable function interfaces
- **Safe byte-wise packet I/O:** No unaligned pointer casts; all network-byte-order reads use helper functions
- **Transaction-based concurrency:** Single-threaded `select()` with ID translation avoids threading overhead while supporting concurrent clients
- **Complete TC fallback:** Transparent UDP→TCP fallback with multiple safety layers (TCP success, TCP ID mismatch, TCP failure, query_packet not saved)
- **Unified resource store:** Static records and dynamic cache share the same lookup interface

---

## 12. 心得与总结 (Reflections)

*To be filled after completing the project.* Consider addressing:

- Understanding of the DNS protocol (RFC 1035)
- Challenges with network byte order and packet parsing
- Debugging with Wireshark
- Managing concurrent requests without multi-threading
- The value of modular design in C
- Lessons from implementing TCP fallback
