# Package Checklist — DNS Relay Server

Final submission checklist for the course design project.

---

## 1. Build Verification

- [ ] Compile with `build.bat`: zero errors, zero warnings
- [ ] Compile with `build.bat release`: zero errors, zero warnings
- [ ] Manual compile: `gcc -Wall -Wextra -std=c11 -I include src/*.c -lws2_32 -o dnsrelay.exe`: zero errors, zero warnings

## 2. Acceptance Demo Verification

Follow [ACCEPTANCE_DEMO_STEPS.md](ACCEPTANCE_DEMO_STEPS.md). Quick checklist (see `docs/ACCEPTANCE_DEMO_STEPS.md`):

- [ ] Step 1: BLOCK — `nslookup bad.test.com <server-ip>` → NXDOMAIN, no upstream
- [ ] Step 2: Local — `nslookup www.test.com <server-ip>` → 1.1.1.1, no upstream
- [ ] Step 3: Relay — `nslookup www.baidu.com <server-ip>` → real IPs, 4 Wireshark packets, relay_id ≠ client_id
- [ ] Step 4: Cache — repeat → cache hit, only 2 Wireshark packets, no upstream
- [ ] Step 5: Multi-client — two simultaneous queries, ID translation per client
- [ ] Step 6: Multi-type — AAAA/CNAME/NS/PTR/MX all from local, no upstream
- [ ] Step 7: TC fallback — `nslookup -type=TXT google.com <server-ip>` → TC=1 → TCP success
- [ ] Step 8: Timeout — `dnsrelay -dd 10.255.255.1` → timeout after ~3s, local still works

## 3. Runtime Verification (quick local)

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

## 5. Wireshark Verification

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

build.bat
dnsrelay.txt
README.md
docs/
├── TEST_CASES.md
├── REPORT_MATERIALS.md
├── PROJECT_STRUCTURE.md
├── PACKAGE_CHECKLIST.md
├── A4_ACCEPTANCE_SHEET.md
└── ACCEPTANCE_DEMO_STEPS.md

### Files to EXCLUDE

```
dnsrelay.exe
*.o  *.obj  *.pch  *.ilk  *.pdb
Debug/  Release/
*.log  *.pcapng  *.pcap
.git/  .claude/  .vs/  .vscode/
background/
```

## 7. Code Quality Checklist

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

## 8. Documentation Checklist

- [ ] `README.md`: project description, build, run, features, limitations
- [ ] `docs/TEST_CASES.md`: comprehensive test cases with commands and expected results
- [ ] `docs/REPORT_MATERIALS.md`: ready-to-use content for the course design report
- [ ] `docs/PROJECT_STRUCTURE.md`: directory layout, file descriptions, dependency graph
- [ ] `docs/PACKAGE_CHECKLIST.md`: this file
- [ ] `docs/A4_ACCEPTANCE_SHEET.md`: acceptance A4 paper template
- [ ] `docs/ACCEPTANCE_DEMO_STEPS.md`: live demo step-by-step script

## 9. Final Submission

### Report

- **Format:** Word (`.docx`)
- **Naming:** `计算机网络课程设计-学号1-学号2-学号3.docx`
- **Content:** Cover page + report body + source code listing
- **Deadline:** 7 July 23:59 (teaching cloud platform)

### Source Code Package

```
学号1-学号2-学号3.rar
├── include/
├── src/
├── docs/
├── build.bat
├── dnsrelay.txt
└── README.md
```

> Do NOT include: `dnsrelay.exe`, `*.log`, `*.o`, `Debug/`, `Release/`, `.git/`, `.claude/`, `background/`.
