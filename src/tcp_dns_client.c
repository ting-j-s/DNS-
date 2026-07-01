#define _WIN32_WINNT 0x0600   /* inet_pton (ws2tcpip.h) */

#include "tcp_dns_client.h"
#include "logger.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <string.h>

/* ── Internal helpers ───────────────────────────────────────────────────
 *
 *  tcp_send_all / tcp_recv_all
 *    Loop until len bytes are sent / received, or until an unrecoverable
 *    error occurs.  These exist because TCP is a stream protocol:
 *    send() and recv() do not guarantee delivery in a single call.
 * ──────────────────────────────────────────────────────────────────────── */

static int tcp_send_all(SOCKET sock, const uint8_t *buf, int len)
{
    int total = 0;
    int remaining = len;

    while (remaining > 0) {
        int sent = send(sock, (const char *)(buf + total), remaining, 0);
        if (sent == SOCKET_ERROR) {
            return -1;
        }
        total += sent;
        remaining -= sent;
    }
    return 0;
}

static int tcp_recv_all(SOCKET sock, uint8_t *buf, int len)
{
    int total = 0;
    int remaining = len;

    while (remaining > 0) {
        int received = recv(sock, (char *)(buf + total), remaining, 0);
        if (received == 0) {
            /* Connection closed by peer */
            return -1;
        }
        if (received == SOCKET_ERROR) {
            return -2;
        }
        total += received;
        remaining -= received;
    }
    return 0;
}

/* ── Read a 2-byte big-endian unsigned integer ──────────────────────── */
static uint16_t read_u16_be_local(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

/* ── Write a 2-byte big-endian unsigned integer ─────────────────────── */
static void write_u16_be_local(uint8_t *p, uint16_t val)
{
    p[0] = (uint8_t)(val >> 8);
    p[1] = (uint8_t)(val & 0xFF);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  tcp_dns_query  — public API
 * ═══════════════════════════════════════════════════════════════════════ */
int tcp_dns_query(const char *server_ip,
                  uint16_t server_port,
                  const uint8_t *query,
                  int query_len,
                  uint8_t *response,
                  int response_size,
                  int timeout_ms)
{
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in addr;
    DWORD sock_timeout_ms;
    uint8_t len_buf[2];
    uint16_t response_len;
    int rc;

    /* ── 1. Parameter validation ────────────────────────────────────── */
    if (!server_ip || !query || !response) return -1;
    if (query_len <= 0 || query_len > TCP_DNS_MAX_MESSAGE_SIZE) return -1;
    if (response_size <= 0) return -1;

    if (timeout_ms <= 0) {
        timeout_ms = TCP_DNS_DEFAULT_TIMEOUT_MS;
    }

    /* ── 2. Create TCP socket ───────────────────────────────────────── */
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        LOG_DEBUG("tcp dns query failed: reason=socket create error, "
                  "server=%s:%u",
                  server_ip, (unsigned int)server_port);
        return -2;
    }

    /* ── 3. Set send / receive timeouts ─────────────────────────────── */
    sock_timeout_ms = (DWORD)timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
               (const char *)&sock_timeout_ms, sizeof(sock_timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               (const char *)&sock_timeout_ms, sizeof(sock_timeout_ms));

    /* ── 4. Build target address ────────────────────────────────────── */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(server_port);

    if (inet_pton(AF_INET, server_ip, &addr.sin_addr) != 1) {
        LOG_DEBUG("tcp dns query failed: reason=address parse error, "
                  "server=%s:%u",
                  server_ip, (unsigned int)server_port);
        closesocket(sock);
        return -3;
    }

    /* ── 5. Connect ─────────────────────────────────────────────────── */
    LOG_DEBUG("tcp dns connect: server=%s:%u", server_ip, (unsigned int)server_port);

    if (connect(sock, (const struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        LOG_DEBUG("tcp dns query failed: reason=connect error, "
                  "server=%s:%u",
                  server_ip, (unsigned int)server_port);
        closesocket(sock);
        return -4;
    }

    /* ── 6. Send: 2-byte length prefix + DNS message ────────────────── */
    write_u16_be_local(len_buf, (uint16_t)query_len);

    rc = tcp_send_all(sock, len_buf, 2);
    if (rc != 0) {
        LOG_DEBUG("tcp dns query failed: reason=send length prefix error");
        closesocket(sock);
        return -5;
    }

    rc = tcp_send_all(sock, query, query_len);
    if (rc != 0) {
        LOG_DEBUG("tcp dns query failed: reason=send message error, "
                  "bytes=%d", query_len);
        closesocket(sock);
        return -5;
    }

    LOG_DEBUG("tcp dns query sent: bytes=%d", query_len);

    /* ── 7. Receive: 2-byte length prefix ───────────────────────────── */
    rc = tcp_recv_all(sock, len_buf, 2);
    if (rc != 0) {
        LOG_DEBUG("tcp dns query failed: reason=recv length prefix error, "
                  "rc=%d", rc);
        closesocket(sock);
        return -6;
    }

    response_len = read_u16_be_local(len_buf);

    /* ── 8. Validate response length ────────────────────────────────── */
    if (response_len > TCP_DNS_MAX_MESSAGE_SIZE) {
        LOG_DEBUG("tcp dns query failed: reason=response length exceeds "
                  "max, len=%u", (unsigned int)response_len);
        closesocket(sock);
        return -7;
    }

    if (response_len > (uint16_t)response_size) {
        LOG_DEBUG("tcp dns query failed: reason=response buffer too small, "
                  "need=%u have=%d",
                  (unsigned int)response_len, response_size);
        closesocket(sock);
        return -7;
    }

    if (response_len < 12) {
        /* DNS header minimum is 12 bytes */
        LOG_DEBUG("tcp dns query failed: reason=response too short, "
                  "len=%u", (unsigned int)response_len);
        closesocket(sock);
        return -7;
    }

    /* ── 9. Receive: full DNS message ───────────────────────────────── */
    rc = tcp_recv_all(sock, response, (int)response_len);
    if (rc != 0) {
        LOG_DEBUG("tcp dns query failed: reason=recv message error, "
                  "expected=%u, rc=%d",
                  (unsigned int)response_len, rc);
        closesocket(sock);
        return -8;
    }

    LOG_DEBUG("tcp dns response received: bytes=%u", (unsigned int)response_len);

    /* ── 10. Cleanup ────────────────────────────────────────────────── */
    closesocket(sock);
    return (int)response_len;
}
