# DNS Relay Server / DNS 中继服务器

DNS relay server for Windows, written in C. A course design project implementing a functional DNS relay with local resolution, domain blocking, upstream forwarding, dynamic caching, concurrent query support, and DNS-over-TCP fallback.

## Target

- **OS:** Windows
- **Compiler:** MinGW-w64 gcc 8.1.0
- **Language:** C (C11)
- **Socket library:** Winsock2 (`-lws2_32`)
- **Default listening port:** 53 (UDP)
- **Default upstream DNS:** 202.106.0.20

## Build

### Manual compile

```bash
gcc -Wall -Wextra -std=c11 -I include src/*.c -lws2_32 -o dnsrelay.exe
```

### Using build.bat

```bat
build.bat              # debug build (with -g -O0)
build.bat release      # optimized build (with -O2 -DNDEBUG)
build.bat clean        # remove build artifacts
```

Requires MinGW-w64 gcc in `PATH`.

## Run

```
dnsrelay [-d | -dd] [dns-server-ipaddr] [filename]
```

| Argument              | Meaning                                       |
| --------------------- | --------------------------------------------- |
| *(no flag)*           | No debug output, only errors                  |
| `-d`                  | Debug level 1: basic query information        |
| `-dd`                 | Debug level 2: verbose debug (cache, ID mapping, TC fallback, etc.) |
| `dns-server-ipaddr`   | Upstream DNS server address (default: 202.106.0.20) |
| `filename`            | Resource records file (default: dnsrelay.txt) |

### Examples

```bat
dnsrelay.exe
dnsrelay.exe -d
dnsrelay.exe -dd 8.8.8.8 dnsrelay.txt
```

> Administrator privileges may be required to bind port 53 on Windows.

## Features

| # | Feature                          | Description                                              |
|---|----------------------------------|----------------------------------------------------------|
| 1 | Local domain resolution          | Resolve domains from static resource records file        |
| 2 | Domain blocking (BLOCK/NXDOMAIN) | Return NXDOMAIN (RCODE=3) for blocked domains            |
| 3 | Upstream DNS forwarding          | Relay unresolved queries to upstream DNS via UDP         |
| 4 | DNS ID translation               | Map client IDs to relay IDs for concurrent correctness   |
| 5 | Transaction table management     | Track in-flight upstream queries with expiration         |
| 6 | Timeout cleanup                  | Expire stale transactions after 3s                       |
| 7 | Concurrent client queries        | Single-threaded `select()` event loop                    |
| 8 | Multi-type resource records      | A, AAAA, NS, CNAME, PTR, MX                             |
| 9 | Multi-A Answer                   | Return multiple A records for one domain                 |
| 10 | Dynamic cache                    | Cache upstream answers with hash-based lookup            |
| 11 | TTL expiration                   | Respect TTL; expired cache entries removed periodically  |
| 12 | DNS-over-TCP upstream query      | TCP communication with upstream DNS name servers         |
| 13 | TC fallback                      | On UDP truncation (TC=1), re-query full response via TCP |

## Resource Records File Format

The file `dnsrelay.txt` (or a custom path) supports two formats:

### Legacy format

```text
1.2.3.4   www.example.com        # A record
0.0.0.0   bad.example.com        # BLOCK (returns NXDOMAIN)
```

### Extended format

```text
A       www.example.com        1.1.1.1
A       www.example.com        2.2.2.2
AAAA    ipv6.example.com       2001:db8::1
CNAME   alias.example.com      real.example.com
NS      example.com            ns1.example.com
MX      example.com            10 mail.example.com
PTR     4.3.2.1.in-addr.arpa   host.example.com
BLOCK   bad.example.com
```

- `#` and `;` start comment lines.
- Blank lines are ignored.
- Multiple records with the same `(name, type)` are allowed.

## Project Structure

```
include/    C header files (12 files)
src/        C source files (12 files)
docs/       Documentation (6 files)
build.bat   Build script
dnsrelay.txt              Sample resource records file
README.md                 This file
```

## Architecture

### Module List

| Module            | Responsibility                                     |
| ----------------- | -------------------------------------------------- |
| `main`            | Program entry, argument parsing, event loop        |
| `config`          | Parse `-d`, `-dd`, upstream DNS, resource file path|
| `logger`          | Debug logging (ERROR/INFO/DEBUG/TRACE levels)      |
| `platform_win`    | Winsock initialization and cleanup                 |
| `udp_socket`      | UDP socket create/bind/send/receive                |
| `tcp_dns_client`  | DNS-over-TCP upstream query (with 2-byte length prefix) |
| `dns_packet`      | DNS header/question/answer parsing and construction|
| `dns_name`        | DNS name encode/decode, compression pointer support|
| `resource_record` | A/AAAA/NS/CNAME/PTR/MX record representation       |
| `resource_store`  | Static resource record file loading and local table lookup |
| `cache`           | Dynamic upstream answer cache with hash lookup and TTL expiration |
| `transaction`     | DNS ID translation, client mapping, timeout cleanup|

### Concurrency Model

Single-threaded `select()` event loop. No busy-waiting. No multi-threading.

### Processing Flow

1. Client sends UDP DNS query to port 53
2. Look up local resource records file
3. If BLOCK match → return NXDOMAIN
4. If local match → build response and return directly
5. Check dynamic cache → if hit, build response from cache
6. If miss → forward to upstream DNS with DNS ID translation
7. If upstream UDP response has TC=1 → re-query via TCP
8. Restore original client DNS ID and return response
9. Cache upstream answers with TTL

## Program Output Format

When started with `-d` or `-dd`, each log line includes:

```
[000001] 2026-07-02 20:30:12 [INFO] client=127.0.0.1:54891  id=1  qname=www.baidu.com  qtype=A(1)  qclass=IN(1)
[000001] 2026-07-02 20:30:12 [INFO]   => local miss, forward upstream: client_id=1, qname=www.baidu.com, qtype=A(1)
[000002] 2026-07-02 20:30:12 [INFO]   => upstream forward sent: client_id=1, relay_id=5, qname=www.baidu.com, bytes=31
[000003] 2026-07-02 20:30:12 [INFO] upstream response relayed: relay_id=5, client_id=1, qname=www.baidu.com, qtype=A(1), bytes=118, source=udp
[000003] 2026-07-02 20:30:12 [INFO] cache inserted: qname=www.baidu.com, qtype=A(1), ttl=47, answers=2, source=udp
```

Fields per acceptance requirements:

| Field          | Source                          |
| -------------- | ------------------------------- |
| Sequence No.   | `[000001]` — auto-increment     |
| Timestamp      | `2026-07-02 20:30:12` — to sec  |
| Client IP      | `client=127.0.0.1:54891`        |
| Query type     | `qtype=A(1)`                    |
| Domain name    | `qname=www.baidu.com`           |
| Query status   | `BLOCK NXDOMAIN sent` / `local RR response sent` / `cache hit response sent` / `upstream response relayed` / `transaction timeout` |
| Query result   | IP addresses / NXDOMAIN / cache hit / upstream success / timeout |

## Acceptance Demo (Two-Computer Setup)

### Server computer (runs dnsrelay + Wireshark)

```bat
dnsrelay.exe -dd 8.8.8.8 dnsrelay.txt
```

### Client computer

```bat
nslookup www.test.com                <server-ip>
nslookup bad.test.com                <server-ip>
nslookup -type=A multi.example.com   <server-ip>
nslookup www.baidu.com               <server-ip>
nslookup www.baidu.com               <server-ip>
nslookup -type=TXT google.com        <server-ip>
```

### Notes

1. Both computers must be on the same LAN
2. The server binds `0.0.0.0:53` — accessible from LAN clients
3. Firewall must allow inbound UDP 53 on the server
4. TC fallback requires that the server can reach external DNS TCP port 53
5. Wireshark filter: `udp.port == 53 || tcp.port == 53`

## Current Limitations

- Client-side queries: UDP only (no TCP listener on port 53)
- TCP used only for upstream fallback (TC=1)
- No DNSSEC validation
- No DoH / DoT support
- No iterative resolution from root servers
- Single-threaded `select()` model (no multi-threading)
- No graceful shutdown (`Ctrl+C` terminates directly)
- Fixed-size cache, no LRU eviction
