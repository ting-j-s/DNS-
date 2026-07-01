# Package Checklist — DNS Relay Server

Final submission checklist for the course design project.

---

## 1. Build Verification

- [ ] Compile with `build.bat`: zero errors, zero warnings
- [ ] Compile with `build.bat release`: zero errors, zero warnings
- [ ] Manual compile: `gcc -Wall -Wextra -std=c11 -I include src/*.c -lws2_32 -o dnsrelay.exe`: zero errors, zero warnings

## 2. Runtime Verification

- [ ] Server starts: `dnsrelay.exe -dd 8.8.8.8 dnsrelay.txt`
- [ ] Local A record: `nslookup www.test.com 127.0.0.1` → `1.1.1.1`
- [ ] BLOCK: `nslookup bad.test.com 127.0.0.1` → NXDOMAIN
- [ ] Multi-A: `nslookup -type=A multi.example.com 127.0.0.1` → 3 IPs
- [ ] AAAA: `nslookup -type=AAAA ipv6.example.com 127.0.0.1` → `2001:db8::1`
- [ ] CNAME: `nslookup -type=CNAME alias.example.com 127.0.0.1` → `real.example.com`
- [ ] NS: `nslookup -type=NS example.com 127.0.0.1` → `ns1.example.com`
- [ ] PTR: `nslookup -type=PTR 4.3.2.1.in-addr.arpa 127.0.0.1` → `host.example.com`
- [ ] MX: `nslookup -type=MX example.com 127.0.0.1` → pref=10, `mail.example.com`
- [ ] Upstream forward: `nslookup www.baidu.com 127.0.0.1` → real IPs
- [ ] Cache hit: repeat query → cache hit, no upstream relay
- [ ] TC fallback: `nslookup -type=ANY google.com 127.0.0.1` → TC=1 → TCP success

## 3. Wireshark Verification

- [ ] Client → relay packet: correct DNS query format
- [ ] Relay → client (local): valid DNS response, correct RCODE
- [ ] Relay → client (BLOCK): RCODE=3 (NXDOMAIN), ANCOUNT=0
- [ ] Relay → upstream: DNS ID is relay_id (not client_id)
- [ ] Upstream → relay: DNS ID matches relay_id
- [ ] Relay → client: DNS ID restored to client_id
- [ ] TC fallback TCP: 2-byte length prefix + DNS message
- [ ] No malformed packets

## 4. Files to Submit

### Required source files

```
include/
├── cache.h
├── common.h
├── config.h
├── dns_name.h
├── dns_packet.h
├── logger.h
├── platform_win.h
├── resource_record.h
├── resource_store.h
├── tcp_dns_client.h
├── transaction.h
└── udp_socket.h

src/
├── cache.c
├── config.c
├── dns_name.c
├── dns_packet.c
├── logger.c
├── main.c
├── platform_win.c
├── resource_record.c
├── resource_store.c
├── tcp_dns_client.c
├── transaction.c
└── udp_socket.c
```

### Required other files

```
build.bat
dnsrelay.txt
README.md
TEST_CASES.md
REPORT_MATERIALS.md
PROJECT_STRUCTURE.md
PACKAGE_CHECKLIST.md
```

### Optional files

```
.gitignore
CLAUDE.md           (development guide — may include if required)
```

## 5. Files to EXCLUDE

| Category                 | Examples                                    |
| ------------------------ | ------------------------------------------- |
| Build artifacts          | `dnsrelay.exe`                              |
| Object files             | `*.o`, `*.obj`                              |
| Precompiled headers      | `*.pch`                                     |
| IDE temporary files      | `*.ilk`, `*.pdb`, `.vs/`                    |
| Debug/Release dirs       | `Debug/`, `Release/`                        |
| Packet captures          | `*.pcapng`, `*.pcap`                        |

> If the instructor requires an executable, place `dnsrelay.exe` in a separate `bin/` folder or submit it alongside the source as specified. The source package itself should not include compiled binaries.

## 6. Code Quality Checklist

- [ ] No `printf()` outside `logger.c`
- [ ] No Winsock calls outside `platform_win.c`, `udp_socket.c`, `tcp_dns_client.c`, `main.c`
- [ ] No transaction table internals exposed outside `transaction.c`
- [ ] No cache internals exposed outside `cache.c`
- [ ] No busy-waiting loops
- [ ] No multi-threading
- [ ] All socket return values checked
- [ ] All memory operations bounds-checked
- [ ] DNS name compression pointer loops detected
- [ ] Network byte order conversions correct (`htons`/`ntohs`/`htonl`/`ntohl`)
- [ ] Magic numbers replaced with named constants

## 7. Documentation Checklist

- [ ] README.md: project description, build, run, features, limitations
- [ ] TEST_CASES.md: comprehensive test cases with commands and expected results
- [ ] REPORT_MATERIALS.md: ready-to-use content for the course design report
- [ ] PROJECT_STRUCTURE.md: directory layout, file descriptions, dependency graph
- [ ] PACKAGE_CHECKLIST.md: this file

## 8. Final Submission Package

Recommend packaging as:

```
学号_姓名_DNS中继服务器.zip
├── include/
├── src/
├── build.bat
├── dnsrelay.txt
├── README.md
├── TEST_CASES.md
├── REPORT_MATERIALS.md
├── PROJECT_STRUCTURE.md
└── PACKAGE_CHECKLIST.md
```

Or, if executable is required:

```
学号_姓名_DNS中继服务器.zip
├── src/
├── include/
├── bin/
│   └── dnsrelay.exe
├── build.bat
├── dnsrelay.txt
├── README.md
├── TEST_CASES.md
├── REPORT_MATERIALS.md
├── PROJECT_STRUCTURE.md
└── PACKAGE_CHECKLIST.md
```
