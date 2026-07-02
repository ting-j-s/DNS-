# Test Cases — DNS Relay Server

All tests assume the server is started as:

```bat
dnsrelay.exe -dd 8.8.8.8 dnsrelay.txt
```

Replace `<server-ip>` with the actual server IP. Use `127.0.0.1` for single-computer testing.

---

## 1. Build & Start

| Test ID | Test Item       | Command                        | Expected Result                       |
| ------- | --------------- | ------------------------------ | -------------------------------------- |
| T01     | Compile         | `build.bat`                    | Zero errors, zero warnings            |
| T02     | Server start    | `dnsrelay.exe -dd 8.8.8.8 dnsrelay.txt` | Binds `0.0.0.0:53`, event loop started |

---

## 2. BLOCK / Interception (验收步骤 1)

> Query a domain whose IP is `0.0.0.0` in the local file.

| Test ID | nslookup Command                           | Expected Result                          |
| ------- | ------------------------------------------ | ---------------------------------------- |
| T11     | `nslookup bad.test.com <server-ip>`        | `Non-existent domain` / NXDOMAIN         |
| T12     | `nslookup blocked.example.com <server-ip>` | `Non-existent domain` / NXDOMAIN         |

**Program output:** `=> local BLOCK NXDOMAIN sent`

**Wireshark:** No upstream forwarding for this query.

---

## 3. Local Query (验收步骤 2)

> Query a valid IP in the local file.

| Test ID | nslookup Command                         | Expected Result     |
| ------- | ---------------------------------------- | -------------------- |
| T21     | `nslookup www.test.com <server-ip>`      | `1.1.1.1`           |

**Program output:** `=> local RR response sent: qname=www.test.com, qtype=A, answers=1`

**Wireshark:** Only client ↔ relay packets. No upstream traffic.

---

## 4. Relay / Upstream Forward (验收步骤 3)

> Query a domain NOT in the local file.

| Test ID | nslookup Command                      | Expected Result                           |
| ------- | ------------------------------------- | ----------------------------------------- |
| T31     | `nslookup www.baidu.com <server-ip>`  | Returns real IPs from upstream DNS        |

**Program output:**
```
=> local miss, forward upstream: client_id=..., qname=www.baidu.com, qtype=A(1)
=> upstream forward sent: client_id=..., relay_id=..., qname=www.baidu.com, bytes=...
upstream response relayed: relay_id=..., client_id=..., qname=www.baidu.com, qtype=A(1), bytes=..., source=udp
cache inserted: qname=www.baidu.com, qtype=A(1), ttl=..., answers=..., source=udp
```

**Wireshark:** Four messages visible:
1. Client → relay (client_id)
2. Relay → upstream (relay_id, != client_id)
3. Upstream → relay (relay_id)
4. Relay → client (client_id restored)

---

## 5. Cache Hit (验收步骤 4)

> Repeat the same query immediately after step 3.

| Test ID | nslookup Command                      | Expected Result                           |
| ------- | ------------------------------------- | ----------------------------------------- |
| T41     | `nslookup www.baidu.com <server-ip>`  | Same IPs as step 3, no upstream relay     |

**Program output:**
```
cache hit response sent: qname=www.baidu.com, qtype=A, answers=..., bytes=...
```

**Wireshark:** Only client ↔ relay. **No upstream messages.** This proves cache is working.

> Note: responses are stored in memory CacheTable, not written back to `dnsrelay.txt`. The file does NOT change. Proof is in the program output and Wireshark.

---

## 6. Multi-Client (验收步骤 5)

> Two clients query simultaneously.

### Method A — Two nslookup

**Client 1:**
```bat
nslookup www.baidu.com <server-ip>
```

**Client 2 (simultaneously):**
```bat
nslookup www.qq.com <server-ip>
```

### Method B — Browser

Open a browser on the client computer, set DNS to `<server-ip>`, and rapidly click multiple links.

**Expected:**
- Server continues processing without blocking
- Each client gets correct responses
- `relay_id != client_id` for each forwarded query
- `transaction_count_used` returns to 0 when all responses arrive

---

## 7. Multi-Type Records (扩展功能)

| Test ID | nslookup Command                                  | Expected Result                         |
| ------- | ------------------------------------------------- | --------------------------------------- |
| T61     | `nslookup -type=A multi.example.com <server-ip>`   | `1.1.1.1`, `2.2.2.2`, `3.3.3.3`       |
| T62     | `nslookup -type=AAAA ipv6.example.com <server-ip>` | `2001:db8::1`                           |
| T63     | `nslookup -type=CNAME alias.example.com <server-ip>`| `canonical name = real.example.com`     |
| T64     | `nslookup -type=NS example.com <server-ip>`        | `nameserver = ns1.example.com`          |
| T65     | `nslookup -type=PTR 4.3.2.1.in-addr.arpa <server-ip>`| `name = host.example.com`            |
| T66     | `nslookup -type=MX example.com <server-ip>`        | `preference = 10, mail.example.com`     |

All use local static records. No upstream traffic. `=> local RR response sent` for each.

---

## 8. TC Fallback / TCP (扩展功能)

| Test ID | nslookup Command                            | Expected Result                          |
| ------- | ------------------------------------------- | ---------------------------------------- |
| T71     | `nslookup -type=ANY google.com <server-ip>`  | TC=1 → TCP fallback success              |
| T72     | `nslookup -type=TXT google.com <server-ip>`  | TC=1 → TCP fallback success              |

**Program output:**
```
upstream UDP response TC=1, attempting TCP fallback: qname=google.com, qtype=...
tcp fallback success: qname=google.com, qtype=..., udp_bytes=28, tcp_bytes=1205
upstream response relayed: ... source=tcp
```

**Wireshark:** Look for TCP port 53 traffic. DNS-over-TCP message has a 2-byte length prefix followed by the DNS message. `tcp_bytes` >> `udp_bytes`.

---

## 9. Timeout Handling (扩展功能)

**Start server with unreachable upstream:**

```bat
dnsrelay.exe -dd 10.255.255.1 dnsrelay.txt
```

| Test ID | nslookup Command                      | Expected Result                          |
| ------- | ------------------------------------- | ---------------------------------------- |
| T81     | `nslookup www.baidu.com <server-ip>`  | Client times out (~2s)                   |

**Program output:**
```
=> local miss, forward upstream: client_id=..., qname=www.baidu.com, qtype=A(1)
=> upstream forward sent: client_id=..., relay_id=..., qname=www.baidu.com, bytes=...
transaction timeout: relay_id=..., client_id=..., qname=www.baidu.com, qtype=A(1)
transaction_cleanup_expired: removed 1 entries
```

**Verify:**
- `transaction_count_used` returns to 0
- Local queries (`nslookup www.test.com <server-ip>`) still work normally
- Program does not crash

---

## 10. Logger Format Verification

| Test ID | Check                                    | Expected                            |
| ------- | ---------------------------------------- | ----------------------------------- |
| T91     | Sequence number                          | `[000001]`, `[000002]`, … increasing |
| T92     | Timestamp                                | `2026-07-02 20:30:12` (to second)   |
| T93     | Client IP                                | `client=127.0.0.1:xxxxx`            |
| T94     | Query type + domain                      | `qname=...`, `qtype=A(1)`           |
| T95     | Query status                             | BLOCK / STATIC / CACHE / RELAY       |
| T96     | Query result                             | IP / NXDOMAIN / cache_hit / success  |

---

## Test Summary

| Category              | Tests | Acceptance Step |
| --------------------- |:-----:|:---------------:|
| Build & Start         | 2     | —               |
| BLOCK                 | 2     | Step 1          |
| Local Query           | 1     | Step 2          |
| Relay                 | 1     | Step 3          |
| Cache Hit             | 1     | Step 4          |
| Multi-Client          | 1     | Step 5          |
| Multi-Type Records    | 6     | Extended        |
| TC Fallback           | 2     | Extended        |
| Timeout               | 1     | Extended        |
| Logger Format         | 6     | All steps       |
| **Total**             | **23**| —               |
