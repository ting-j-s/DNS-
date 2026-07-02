# Project Structure — DNS Relay Server

## Directory Layout

```
dnsrelay/
├── include/                    # C header files (12 files)
│   ├── cache.h                 # Dynamic cache interface (hash lookup, TTL)
│   ├── common.h                # Shared constants and macros
│   ├── config.h                # Command-line config (debug level, upstream, file)
│   ├── dns_name.h              # DNS name encode/decode, compression pointers
│   ├── dns_packet.h            # DNS header/question/answer parse & build
│   ├── logger.h                # Logging macros (ERROR/INFO/DEBUG/TRACE)
│   ├── platform_win.h          # Winsock init/cleanup declarations
│   ├── resource_record.h       # RR types (A/AAAA/CNAME/NS/PTR/MX), answer set
│   ├── resource_store.h        # Unified lookup: static file + cache
│   ├── tcp_dns_client.h        # DNS-over-TCP upstream client
│   ├── transaction.h           # Transaction table, DNS ID translation
│   └── udp_socket.h            # UDP socket create/bind/send/receive
│
├── src/                        # C source files (12 files)
│   ├── cache.c                 # Dynamic cache implementation
│   ├── config.c                # Command-line argument parsing
│   ├── dns_name.c              # DNS name label encoding/decoding
│   ├── dns_packet.c            # DNS packet parsing and construction
│   ├── logger.c                # Logger implementation
│   ├── main.c                  # Entry point, event loop, request dispatch
│   ├── platform_win.c          # Winsock startup/cleanup
│   ├── resource_record.c       # Resource record helpers and utilities
│   ├── resource_store.c        # File loading, unified lookup
│   ├── tcp_dns_client.c        # DNS-over-TCP send/recv with length prefix
│   ├── transaction.c           # Transaction table, ID allocation, cleanup
│   └── udp_socket.c            # UDP socket operations
│
├── build.bat                   # Build script (debug/release/clean)
├── dnsrelay.txt                # Sample resource records file
├── README.md                   # Project overview, build & run instructions
├── TEST_CASES.md               # Test cases and validation procedures
├── REPORT_MATERIALS.md         # Course design report materials
├── PROJECT_STRUCTURE.md        # This file
└── PACKAGE_CHECKLIST.md        # Final submission checklist
```

## File Descriptions

### Header Files (include/)

| File                   | Purpose                                                            |
| ---------------------- | ------------------------------------------------------------------ |
| `cache.h`              | Cache table interface: create, destroy, insert, lookup, cleanup    |
| `common.h`             | Shared constants (buffer sizes, defaults) and utility macros       |
| `config.h`             | `Config` struct and `config_parse()` for CLI argument parsing      |
| `dns_name.h`           | DNS name decompression (with pointer loop detection) and encoding  |
| `dns_packet.h`         | `DnsHeader`, `DnsQuestion`, `DnsQuery` structs; parse/build/extract/TC-check functions |
| `logger.h`             | `logger_init()`, `LOG_ERROR`, `LOG_INFO`, `LOG_DEBUG`, `LOG_TRACE` macros |
| `platform_win.h`       | Windows platform abstraction: `platform_init()` / `platform_cleanup()` |
| `resource_record.h`    | `DnsResourceRecord`, `DnsRData`, `DnsAnswerSet` types; helper functions |
| `resource_store.h`     | `ResourceStore` opaque struct; `create/destroy/load_file/lookup/insert_cache/cleanup` |
| `tcp_dns_client.h`     | `tcp_dns_query()` — single TCP DNS query with configurable timeout |
| `transaction.h`        | `TransactionTable`, `DnsTransaction` structs; add/find/remove/cleanup/set_query_packet |
| `udp_socket.h`         | `UdpSocket` struct; `create/bind/sendto/recvfrom/close` wrappers   |

### Source Files (src/)

| File                   | Key Implementation Details                                         |
| ---------------------- | ------------------------------------------------------------------ |
| `cache.c`              | djb2 hash, bucket array, TTL-based expiration, periodic cleanup    |
| `config.c`             | Parses `-d`/`-dd`, optional IP address (dotted decimal), optional filename |
| `dns_name.c`           | Label-by-label decoding, compression pointer following (max 40 hops), loop detection |
| `dns_packet.c`         | Header flag field manipulation, question section parse, answer RR construction for all types, NXDOMAIN builder, answer extraction from upstream responses, TC bit check |
| `logger.c`             | Debug level state, timestamp-prefixed output to stdout             |
| `main.c`               | `select()` event loop, client query handler (parse→lookup→branch), upstream response handler (ID restore→TC fallback→cache→reply), initialization and main() |
| `platform_win.c`       | `WSAStartup(2,2)`, `WSACleanup()`, Windows error string lookup     |
| `resource_record.c`    | RDATA formatting for A/AAAA/CNAME/NS/PTR/MX, answer set utilities  |
| `resource_store.c`     | File parser (legacy and extended formats), unified lookup chain (static→cache), case-insensitive matching |
| `tcp_dns_client.c`     | TCP connect with timeout, `send_all`/`recv_all` loops, 2-byte length prefix encode/decode, 10 error-safe `closesocket()` paths |
| `transaction.c`        | Linear-scan slot allocation, unique relay_id generation (≠ client_id), 3000ms expiration, query_packet save for TC fallback |
| `udp_socket.c`         | `socket(AF_INET, SOCK_DGRAM)`, `bind()`, `sendto()`, `recvfrom()` wrappers with error logging |

## Dependency Graph

```
main.c
  ├── config.c / config.h
  ├── logger.c / logger.h
  ├── platform_win.c / platform_win.h
  ├── udp_socket.c / udp_socket.h
  ├── dns_packet.c / dns_packet.h
  │     └── dns_name.c / dns_name.h
  ├── resource_store.c / resource_store.h
  │     ├── resource_record.c / resource_record.h
  │     └── cache.c / cache.h
  ├── transaction.c / transaction.h
  │     └── dns_packet.h
  └── tcp_dns_client.c / tcp_dns_client.h
```

## Build Output

| Target         | Command              | Output File     |
| -------------- | -------------------- | --------------- |
| Debug build    | `build.bat`          | `dnsrelay.exe`  |
| Release build  | `build.bat release`  | `dnsrelay.exe`  |
| Clean          | `build.bat clean`    | *(removes .exe)* |
