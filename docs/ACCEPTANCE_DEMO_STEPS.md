# 现场验收演示步骤

按此顺序逐项演示。每一步都展示：**程序输出 + Wireshark 抓包结果 + 数据变化**。

---

## 准备

### 服务器电脑

1. 连接网络，确保可访问外部 DNS（8.8.8.8）
2. 关闭 Windows 防火墙或放行 UDP 53 入站规则
3. 打开 Wireshark，选择网卡，设置过滤条件：
   ```
   udp.port == 53 || tcp.port == 53
   ```
4. 启动程序：
   ```bat
   dnsrelay.exe -dd 8.8.8.8 dnsrelay.txt
   ```
5. 记录本机 IP（`ipconfig`，例如 192.168.1.100）

### 客户端电脑

1. 与服务器同一局域网
2. 记录服务器 IP（以下用 `<server-ip>` 代替）

---

## 演示 1：拦截功能 — BLOCK NXDOMAIN

```bat
nslookup bad.test.com <server-ip>
```

### 展示要点

| 层面 | 内容 |
|------|------|
| **客户端** | `Non-existent domain` / NXDOMAIN |
| **程序输出** | `=> local BLOCK NXDOMAIN sent: qname=bad.test.com` |
| **Wireshark** | 仅 client ↔ relay 两个 UDP 包，**无上游转发** |
| **说明** | RCODE=3, ANCOUNT=0，不是返回 IP 0.0.0.0 |

可追加一条 extended BLOCK：
```bat
nslookup blocked.example.com <server-ip>
```

---

## 演示 2：本地查询 — 静态 A 记录

```bat
nslookup www.test.com <server-ip>
```

### 展示要点

| 层面 | 内容 |
|------|------|
| **客户端** | `Address: 1.1.1.1` |
| **程序输出** | `=> local RR response sent: qname=www.test.com, qtype=A, answers=1` |
| **Wireshark** | 仅 client ↔ relay 两个 UDP 包，**无上游转发** |

---

## 演示 3：中继 — 上游转发

```bat
nslookup www.baidu.com <server-ip>
```

### 展示要点

| 层面 | 内容 |
|------|------|
| **客户端** | 返回百度真实 IP（如 `220.181.111.1`） |
| **程序输出** | ① `=> local miss, forward upstream: client_id=..., qname=www.baidu.com, qtype=A(1)` |
|            | ② `=> upstream forward sent: client_id=..., relay_id=...` |
|            | ③ `upstream response relayed: relay_id=..., client_id=..., source=udp` |
|            | ④ `cache inserted: qname=www.baidu.com, ... source=udp` |
| **Wireshark** | 四个 UDP 包： |
|            | 包1: client → relay（DNS ID = client_id） |
|            | 包2: relay → upstream（DNS ID = relay_id，≠ client_id） |
|            | 包3: upstream → relay（DNS ID = relay_id） |
|            | 包4: relay → client（DNS ID = client_id，已恢复） |
| **说明** | DNS ID 转换确保多客户端并发不会串包 |

---

## 演示 4：中继结果本地存储 — Cache Hit

**立即**再次执行：

```bat
nslookup www.baidu.com <server-ip>
```

### 展示要点

| 层面 | 内容 |
|------|------|
| **客户端** | 同样返回 `220.181.111.1` 和 `220.181.111.232` |
| **程序输出** | `=> cache hit response sent: qname=www.baidu.com, qtype=A, answers=2` |
| **Wireshark** | 仅 client ↔ relay 两个 UDP 包，**无上游转发** |
| **说明** | 中继结果存储在**内存 CacheTable**（不是写回 dnsrelay.txt），文件不变 |
|            | 用 Wireshark 证明第二次查询没有访问上游 DNS |

---

## 演示 5：多客户端

### 方式 A — 两台电脑同时查询

**客户端 1：**
```bat
nslookup www.baidu.com <server-ip>
```

**客户端 2（同时或紧接着）：**
```bat
nslookup www.qq.com <server-ip>
```

### 方式 B — 浏览器测试

客户端电脑打开浏览器，设置 DNS 为 `<server-ip>`，快速点击多个链接。

### 展示要点

| 层面 | 内容 |
|------|------|
| **程序输出** | 两个查询交错处理，互不阻塞 |
| **Wireshark** | 两个查询各有独立的 relay_id，ID 转换互不干扰 |
| **说明** | select() 单线程事件循环实现并发，无多线程 |

---

## 演示 6：扩展功能 — 多类型资源记录

全部使用本地静态记录，不访问上游：

```bat
nslookup -type=A     multi.example.com          <server-ip>
nslookup -type=AAAA  ipv6.example.com           <server-ip>
nslookup -type=CNAME alias.example.com          <server-ip>
nslookup -type=NS    example.com                <server-ip>
nslookup -type=PTR   4.3.2.1.in-addr.arpa      <server-ip>
nslookup -type=MX    example.com                <server-ip>
```

### 展示要点

| 记录类型 | 客户端预期输出 | 程序输出 |
|----------|---------------|----------|
| A (multi) | 3 个 IP 地址 | `=> local RR response sent ... answers=3` |
| AAAA | `2001:db8::1` | `=> local RR response sent ... qtype=AAAA` |
| CNAME | `canonical name = real.example.com` | `=> local RR response sent ... qtype=CNAME` |
| NS | `nameserver = ns1.example.com` | `=> local RR response sent ... qtype=NS` |
| PTR | `name = host.example.com` | `=> local RR response sent ... qtype=PTR` |
| MX | `preference = 10, mail exchanger = mail.example.com` | `=> local RR response sent ... qtype=MX` |

**Wireshark:** 全部仅 client ↔ relay，无上游转发。

---

## 演示 7：扩展功能 — TC fallback

```bat
nslookup -type=TXT google.com <server-ip>
nslookup -type=ANY google.com <server-ip>
```

### 展示要点

| 层面 | 内容 |
|------|------|
| **客户端** | 返回 TXT/ANY 记录的完整内容 |
| **程序输出** | ① `upstream UDP response TC=1, attempting TCP fallback: qname=google.com` |
|            | ② `tcp fallback success: qname=google.com, udp_bytes=28, tcp_bytes=xxx` |
|            | ③ `upstream response relayed: ... source=tcp` |
| **Wireshark** | 可见 TCP 53 端口的流量，2 字节长度前缀 + DNS 消息 |
| **说明** | UDP 截断包只有 28 字节（仅 DNS header），TCP 完整响应远大于此 |

---

## 演示 8：扩展功能 — 超时处理

**重启服务器，使用不可达上游：**

```bat
dnsrelay.exe -dd 10.255.255.1 dnsrelay.txt
```

```bat
nslookup www.baidu.com <server-ip>
```

### 展示要点

| 层面 | 内容 |
|------|------|
| **客户端** | DNS request timed out |
| **程序输出** | 约 3 秒后：`transaction timeout: relay_id=..., client_id=..., qname=www.baidu.com` |
|            | `transaction_cleanup_expired: removed 1 entries` |
|            | `transaction_count_used` 回到 0 |
| **验证** | 本地查询仍正常：`nslookup www.test.com <server-ip>` → 1.1.1.1 |
| **说明** | 超时不影响本地查询功能，程序不崩溃 |
