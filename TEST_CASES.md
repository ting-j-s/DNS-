# Test Cases — DNS Relay Server

All tests assume the server is started as:

```bat
dnsrelay.exe -dd 8.8.8.8 dnsrelay.txt
```

(except timeout test, which uses unreachable upstream `10.255.255.1`)

---

## 1. Build Test

| Test ID | Test Item          | Command                        | Expected Result                       |
| --------|--------------------|--------------------------------|---------------------------------------|
| T01     | gcc compile        | `build.bat`                    | Zero errors, zero warnings, dnsrelay.exe generated |
| T02     | release build      | `build.bat release`            | Zero errors, zero warnings            |
| T03     | clean build        | `build.bat clean`              | dnsrelay.exe removed                  |

---

## 2. Local A Record

| Test ID | Test Item          | nslookup Command                         | Expected Result     |
| --------|--------------------|------------------------------------------|---------------------|
| T11     | Legacy A record    | `nslookup www.test.com 127.0.0.1`        | `1.1.1.1`           |

---

## 3. Domain Blocking (BLOCK / NXDOMAIN)

| Test ID | Test Item          | nslookup Command                         | Expected Result                |
| --------|--------------------|------------------------------------------|--------------------------------|
| T21     | Legacy BLOCK       | `nslookup bad.test.com 127.0.0.1`        | `Non-existent domain` / NXDOMAIN |
| T22     | Extended BLOCK     | `nslookup blocked.example.com 127.0.0.1` | `Non-existent domain` / NXDOMAIN |

> Note: BLOCK must return NXDOMAIN (RCODE=3, ANCOUNT=0), NOT `0.0.0.0`.

---

## 4. Multi-A Answer

| Test ID | Test Item          | nslookup Command                         | Expected Result                        |
| --------|--------------------|------------------------------------------|----------------------------------------|
| T31     | Multi A record     | `nslookup -type=A multi.example.com 127.0.0.1` | `1.1.1.1`, `2.2.2.2`, `3.3.3.3` |

---

## 5. AAAA (IPv6) Record

| Test ID | Test Item          | nslookup Command                         | Expected Result     |
| --------|--------------------|------------------------------------------|---------------------|
| T41     | AAAA record        | `nslookup -type=AAAA ipv6.example.com 127.0.0.1` | `2001:db8::1` |

---

## 6. CNAME Record

| Test ID | Test Item          | nslookup Command                         | Expected Result                  |
| --------|--------------------|------------------------------------------|----------------------------------|
| T51     | CNAME record       | `nslookup -type=CNAME alias.example.com 127.0.0.1` | `canonical name = real.example.com` |

---

## 7. NS Record

| Test ID | Test Item          | nslookup Command                         | Expected Result             |
| --------|--------------------|------------------------------------------|-----------------------------|
| T61     | NS record          | `nslookup -type=NS example.com 127.0.0.1` | `nameserver = ns1.example.com` |

---

## 8. PTR Record

| Test ID | Test Item          | nslookup Command                         | Expected Result              |
| --------|--------------------|------------------------------------------|------------------------------|
| T71     | PTR record         | `nslookup -type=PTR 4.3.2.1.in-addr.arpa 127.0.0.1` | `name = host.example.com` |

---

## 9. MX Record

| Test ID | Test Item          | nslookup Command                         | Expected Result                                |
| --------|--------------------|------------------------------------------|------------------------------------------------|
| T81     | MX record          | `nslookup -type=MX example.com 127.0.0.1` | `preference = 10`, `mail exchanger = mail.example.com` |

---

## 10. Upstream Forwarding

| Test ID | Test Item          | nslookup Command                         | Expected Result                                      |
| --------|--------------------|------------------------------------------|------------------------------------------------------|
| T91     | Upstream forward   | `nslookup www.baidu.com 127.0.0.1`       | Returns real IP addresses from upstream DNS           |
| T92     | Upstream MX        | `nslookup -type=MX qq.com 127.0.0.1`     | Returns real MX records from upstream DNS             |

**Server log expectations (T91, first query):**
- `cache miss` or no cache hit
- `upstream UDP` relay log entry
- `cache inserted` log entry with `source=udp`

---

## 11. Cache Hit

| Test ID | Test Item          | nslookup Command (x2)                    | Expected Result                                      |
| --------|--------------------|------------------------------------------|------------------------------------------------------|
| T101    | Cache A hit        | `nslookup www.baidu.com 127.0.0.1`       | 1st: upstream forward + cache insert                  |
|         |                    | *(repeat immediately)*                   | 2nd: `cache hit response sent`, no upstream relay     |
| T102    | Cache MX hit       | `nslookup -type=MX qq.com 127.0.0.1`     | 1st: upstream forward + cache insert                  |
|         |                    | *(repeat immediately)*                   | 2nd: `cache hit response sent`, no upstream relay     |

---

## 12. DNS ID Translation (Wireshark)

| Test ID | Test Item          | Wireshark Filter          | Expected Result                          |
| --------|--------------------|---------------------------|------------------------------------------|
| T111    | ID translation     | `udp.port == 53`          | `client → relay`: client_id              |
|         |                    |                           | `relay → upstream`: relay_id             |
|         |                    |                           | `upstream → relay`: relay_id             |
|         |                    |                           | `relay → client`: client_id              |
|         |                    |                           | relay_id ≠ client_id                     |

---

## 13. Timeout Cleanup

**Start server with unreachable upstream:**

```bat
dnsrelay.exe -dd 10.255.255.1 dnsrelay.txt
```

| Test ID | Test Item          | nslookup Command                         | Expected Result                              |
| --------|--------------------|------------------------------------------|----------------------------------------------|
| T121    | Timeout cleanup    | `nslookup www.baidu.com 127.0.0.1`       | Client times out; server logs `transaction timeout` after ~3s |
| T122    | Local still works  | `nslookup www.test.com 127.0.0.1`        | Still returns `1.1.1.1` (local queries unaffected) |
| T123    | Active count       | *(after all timeouts)*                   | Server log shows active transaction count = 0, no crash |

---

## 14. TC Fallback (DNS-over-TCP)

| Test ID | Test Item          | nslookup Command                         | Expected Result                                      |
| --------|--------------------|------------------------------------------|------------------------------------------------------|
| T131    | TC fallback (ANY)  | `nslookup -type=ANY google.com 127.0.0.1` | Server log: `upstream UDP response TC=1`, `tcp fallback success` |
| T132    | TC fallback (TXT)  | `nslookup -type=TXT google.com 127.0.0.1` | Server log: `upstream UDP response TC=1`, `tcp fallback success` |

**Server log expectations:**
- `udp_bytes` < `tcp_bytes` (TCP response is the full, non-truncated response)
- Relay log entry includes `(tcp)` suffix
- Client receives complete response

---

## 15. Static Table Takes Priority

| Test ID | Test Item          | nslookup Command                         | Expected Result                              |
| --------|--------------------|------------------------------------------|----------------------------------------------|
| T141    | Static over cache  | `nslookup -type=A multi.example.com 127.0.0.1` | Returns `1.1.1.1`, `2.2.2.2`, `3.3.3.3` — no upstream query |
| T142    | Static block       | `nslookup blocked.example.com 127.0.0.1` | NXDOMAIN — no upstream query                 |
| T143    | Static MX          | `nslookup -type=MX example.com 127.0.0.1` | `preference = 10`, `mail.example.com` — no upstream query |

---

## Test Summary

| Category                       | Test Count | Expected |
| ------------------------------ |:----------:| -------- |
| Build                          | 3          | All pass |
| Local A                        | 1          | Pass     |
| BLOCK / NXDOMAIN               | 2          | Pass     |
| Multi-A                        | 1          | Pass     |
| AAAA                           | 1          | Pass     |
| CNAME                          | 1          | Pass     |
| NS                             | 1          | Pass     |
| PTR                            | 1          | Pass     |
| MX                             | 1          | Pass     |
| Upstream Forwarding            | 2          | Pass     |
| Cache Hit                      | 2          | Pass     |
| DNS ID Translation             | 1          | Pass     |
| Timeout Cleanup                | 3          | Pass     |
| TC Fallback                    | 2          | Pass     |
| Static Priority                | 3          | Pass     |
| **Total**                      | **25**     | **All pass** |
