#include "common.h"
#include "config.h"
#include "logger.h"
#include "platform_win.h"
#include "udp_socket.h"
#include "dns_packet.h"
#include "resource_store.h"
#include <stdio.h>
#include <string.h>

/* ── Temporary pending request table (Phase 3 only) ──────────────── */

#define MAX_PENDING_REQUESTS 128

typedef struct {
    int used;
    uint16_t dns_id;
    char qname[DNS_MAX_NAME_LEN + 1];
    uint16_t qtype;
    uint16_t qclass;
    struct sockaddr_in client_addr;
    int client_addr_len;
} PendingRequest;

static PendingRequest pending_table[MAX_PENDING_REQUESTS];

static void pending_table_init(void)
{
    int i;
    for (i = 0; i < MAX_PENDING_REQUESTS; i++) {
        pending_table[i].used = 0;
    }
}

static int pending_add(uint16_t dns_id,
                       const char *qname,
                       uint16_t qtype,
                       uint16_t qclass,
                       const struct sockaddr_in *client_addr,
                       int client_addr_len)
{
    int i;
    int free_slot = -1;

    /* Check for existing entry with same dns_id (overwrite it) */
    for (i = 0; i < MAX_PENDING_REQUESTS; i++) {
        if (pending_table[i].used && pending_table[i].dns_id == dns_id) {
            LOG_DEBUG("pending_add: overwriting existing entry with id=%u", dns_id);
            free_slot = i;
            break;
        }
    }

    /* If no duplicate found, find first free slot */
    if (free_slot < 0) {
        for (i = 0; i < MAX_PENDING_REQUESTS; i++) {
            if (!pending_table[i].used) {
                free_slot = i;
                break;
            }
        }
    }

    if (free_slot < 0) {
        LOG_ERROR("pending table full (%d entries), cannot add id=%u",
                  MAX_PENDING_REQUESTS, dns_id);
        return -1;
    }

    pending_table[free_slot].used     = 1;
    pending_table[free_slot].dns_id   = dns_id;
    strncpy(pending_table[free_slot].qname, qname,
            sizeof(pending_table[free_slot].qname) - 1);
    pending_table[free_slot].qname[sizeof(pending_table[free_slot].qname) - 1] = '\0';
    pending_table[free_slot].qtype    = qtype;
    pending_table[free_slot].qclass   = qclass;
    memcpy(&pending_table[free_slot].client_addr,
           client_addr, sizeof(struct sockaddr_in));
    pending_table[free_slot].client_addr_len = client_addr_len;

    LOG_DEBUG("pending_add: id=%u, qname=%s, slot=%d", dns_id, qname, free_slot);
    return 0;
}

static PendingRequest *pending_find(uint16_t dns_id)
{
    int i;
    for (i = 0; i < MAX_PENDING_REQUESTS; i++) {
        if (pending_table[i].used && pending_table[i].dns_id == dns_id) {
            return &pending_table[i];
        }
    }
    return NULL;
}

static void pending_remove(PendingRequest *pending)
{
    if (pending) {
        LOG_DEBUG("pending_remove: id=%u, qname=%s",
                  pending->dns_id, pending->qname);
        pending->used = 0;
    }
}


/* ── Forward declarations ────────────────────────────────────────── */

static void handle_client_query(UdpSocket *client_sock,
                                UdpSocket *upstream_sock,
                                const struct sockaddr_in *upstream_addr,
                                const ResourceStore *store);

static void handle_upstream_response(UdpSocket *upstream_sock,
                                     UdpSocket *client_sock);


/* ── Handle incoming client DNS query ────────────────────────────── */
static void handle_client_query(UdpSocket *client_sock,
                                UdpSocket *upstream_sock,
                                const struct sockaddr_in *upstream_addr,
                                const ResourceStore *store)
{
    uint8_t buffer[DNS_MAX_PACKET_SIZE];
    uint8_t response[DNS_MAX_PACKET_SIZE];
    struct sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);
    char client_ip[16];
    DnsQuery query;
    int recv_len;
    int parse_ret;

    recv_len = udp_socket_recvfrom(client_sock,
                                    buffer, sizeof(buffer),
                                    &client_addr, &client_addr_len);
    if (recv_len < 0) {
        /* Error already logged by udp_socket_recvfrom */
        return;
    }

    /* Convert client address to string */
    {
        char *addr_str = inet_ntoa(client_addr.sin_addr);
        strncpy(client_ip, addr_str, sizeof(client_ip) - 1);
        client_ip[sizeof(client_ip) - 1] = '\0';
    }

    parse_ret = dns_packet_parse_query(buffer, recv_len, &query);

    if (parse_ret == 0) {
        const ResourceRecord *rr;

        LOG_INFO("client=%s:%u  id=%u  qname=%s  qtype=%s(%u)  qclass=%s(%u)",
                 client_ip,
                 ntohs(client_addr.sin_port),
                 query.header.id,
                 query.question.qname,
                 dns_qtype_to_string(query.question.qtype),
                 query.question.qtype,
                 dns_qclass_to_string(query.question.qclass),
                 query.question.qclass);

        rr = resource_store_lookup(store,
                                   query.question.qname,
                                   query.question.qtype,
                                   query.question.qclass);

        if (rr) {
            if (rr->kind == RR_KIND_A) {
                char ip_buf[16];
                int resp_len, sent;

                resource_record_ip_str(rr, ip_buf, sizeof(ip_buf));

                resp_len = dns_packet_build_a_response(
                    buffer, recv_len, &query,
                    rr->rdata.ipv4_addr, rr->ttl,
                    response, sizeof(response));

                if (resp_len > 0) {
                    sent = udp_socket_sendto(client_sock,
                                              response, resp_len,
                                              &client_addr,
                                              client_addr_len);
                    if (sent > 0) {
                        LOG_INFO("  => local A response sent: qname=%s, "
                                 "ip=%s, bytes=%d",
                                 query.question.qname, ip_buf, sent);
                    }
                    /* sendto error already logged */
                } else {
                    LOG_ERROR("  => failed to build A response: "
                              "qname=%s, rc=%d",
                              query.question.qname, resp_len);
                }
            } else if (rr->kind == RR_KIND_BLOCK) {
                int resp_len, sent;

                resp_len = dns_packet_build_nxdomain_response(
                    buffer, recv_len, &query,
                    response, sizeof(response));

                if (resp_len > 0) {
                    sent = udp_socket_sendto(client_sock,
                                              response, resp_len,
                                              &client_addr,
                                              client_addr_len);
                    if (sent > 0) {
                        LOG_INFO("  => local BLOCK NXDOMAIN sent: "
                                 "qname=%s, bytes=%d",
                                 query.question.qname, sent);
                    }
                    /* sendto error already logged */
                } else {
                    LOG_ERROR("  => failed to build NXDOMAIN response: "
                              "qname=%s, rc=%d",
                              query.question.qname, resp_len);
                }
            }
        } else {
            /* ── Local miss: forward to upstream DNS ──────────────── */
            int rc;

            LOG_INFO("  => local miss, forward upstream: "
                     "id=%u, qname=%s, qtype=%s(%u)",
                     query.header.id,
                     query.question.qname,
                     dns_qtype_to_string(query.question.qtype),
                     query.question.qtype);

            rc = pending_add(query.header.id,
                             query.question.qname,
                             query.question.qtype,
                             query.question.qclass,
                             &client_addr,
                             client_addr_len);

            if (rc == 0) {
                int sent;

                sent = udp_socket_sendto(upstream_sock,
                                          buffer, recv_len,
                                          upstream_addr,
                                          sizeof(*upstream_addr));

                if (sent > 0) {
                    LOG_INFO("  => upstream forward sent: "
                             "id=%u, qname=%s, bytes=%d",
                             query.header.id,
                             query.question.qname,
                             sent);
                } else {
                    PendingRequest *pr;
                    LOG_ERROR("  => upstream send failed: "
                              "id=%u, qname=%s",
                              query.header.id,
                              query.question.qname);
                    /* Remove the pending entry on send failure */
                    pr = pending_find(query.header.id);
                    pending_remove(pr);
                }
            } else {
                LOG_ERROR("  => pending table full, dropping query: "
                          "qname=%s", query.question.qname);
            }
        }
    } else {
        LOG_DEBUG("invalid DNS query from %s:%u, len=%d, parse_ret=%d",
                  client_ip,
                  ntohs(client_addr.sin_port),
                  recv_len,
                  parse_ret);
    }
}


/* ── Handle upstream DNS response ────────────────────────────────── */
static void handle_upstream_response(UdpSocket *upstream_sock,
                                     UdpSocket *client_sock)
{
    uint8_t buffer[DNS_MAX_PACKET_SIZE];
    struct sockaddr_in from_addr;
    int from_addr_len = sizeof(from_addr);
    int recv_len;
    uint16_t dns_id;
    PendingRequest *pending;

    recv_len = udp_socket_recvfrom(upstream_sock,
                                    buffer, sizeof(buffer),
                                    &from_addr, &from_addr_len);
    if (recv_len < 0) {
        /* Error already logged */
        return;
    }

    /* Check minimum length for DNS header */
    if (recv_len < DNS_HEADER_SIZE) {
        LOG_DEBUG("upstream response too short: bytes=%d, from=%s:%u",
                  recv_len,
                  inet_ntoa(from_addr.sin_addr),
                  ntohs(from_addr.sin_port));
        return;
    }

    /* Extract DNS ID safely (byte-wise to avoid alignment issues) */
    dns_id = ((uint16_t)buffer[0] << 8) | buffer[1];

    LOG_DEBUG("upstream response received: id=%u, bytes=%d, from=%s:%u",
              dns_id, recv_len,
              inet_ntoa(from_addr.sin_addr),
              ntohs(from_addr.sin_port));

    pending = pending_find(dns_id);

    if (!pending) {
        LOG_DEBUG("upstream response has no pending request: "
                  "id=%u, bytes=%d",
                  dns_id, recv_len);
        return;
    }

    /* Relay response back to original client */
    {
        int sent;

        sent = udp_socket_sendto(client_sock,
                                  buffer, recv_len,
                                  &pending->client_addr,
                                  pending->client_addr_len);

        if (sent > 0) {
            LOG_INFO("upstream response relayed: id=%u, qname=%s, "
                     "qtype=%s(%u), bytes=%d",
                     dns_id, pending->qname,
                     dns_qtype_to_string(pending->qtype), pending->qtype,
                     sent);
        }
        /* sendto error already logged */
    }

    pending_remove(pending);
}


/* ═══════════════════════════════════════════════════════════════════
 *  main
 * ═══════════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[]) {
    Config config;
    UdpSocket client_sock;
    UdpSocket upstream_sock;
    struct sockaddr_in upstream_addr;

    /* 1. Parse command line */
    config_parse_args(&config, argc, argv);

    /* 2. Initialize logger */
    logger_init(config.debug_level);

    /* 3. Print configuration */
    config_print(&config);

    LOG_INFO("dnsrelay starting...");

    /* 4. Initialize Winsock */
    if (platform_socket_init() != 0) {
        LOG_ERROR("Failed to initialize Winsock");
        return 1;
    }

    /* 5. Create and bind client UDP socket */
    if (udp_socket_create(&client_sock) != 0) {
        LOG_ERROR("Failed to create client UDP socket");
        platform_socket_cleanup();
        return 1;
    }

    if (udp_socket_bind(&client_sock, (uint16_t)config.listen_port) != 0) {
        LOG_ERROR("Failed to bind port %d", config.listen_port);
        udp_socket_close(&client_sock);
        platform_socket_cleanup();
        return 1;
    }

    LOG_INFO("client UDP socket bound on 0.0.0.0:%d", config.listen_port);

    /* 6. Create upstream UDP socket (no bind — system assigns ephemeral port) */
    if (udp_socket_create(&upstream_sock) != 0) {
        LOG_ERROR("Failed to create upstream UDP socket");
        udp_socket_close(&client_sock);
        platform_socket_cleanup();
        return 1;
    }

    LOG_INFO("upstream UDP socket created");

    /* 7. Construct upstream DNS address */
    memset(&upstream_addr, 0, sizeof(upstream_addr));
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port   = htons(53);

    upstream_addr.sin_addr.s_addr = inet_addr(config.upstream_dns);
    if (upstream_addr.sin_addr.s_addr == INADDR_NONE) {
        LOG_ERROR("Invalid upstream DNS address: %s", config.upstream_dns);
        udp_socket_close(&upstream_sock);
        udp_socket_close(&client_sock);
        platform_socket_cleanup();
        return 1;
    }

    LOG_INFO("upstream DNS server: %s:53", config.upstream_dns);

    /* 8. Initialize resource store and load local records */
    {
        ResourceStore store;
        resource_store_init(&store);

        if (resource_store_load_file(&store, config.filename) != 0) {
            LOG_ERROR("Failed to load resource file, exiting");
            udp_socket_close(&upstream_sock);
            udp_socket_close(&client_sock);
            platform_socket_cleanup();
            return 1;
        }

        /* Initialize temporary pending table */
        pending_table_init();

        LOG_INFO("Phase 3-3: select event loop started");

        /* 9. select event loop — listen on both client and upstream sockets */
        while (1) {
            fd_set readfds;
            SOCKET max_fd;

            FD_ZERO(&readfds);
            FD_SET(client_sock.fd, &readfds);
            FD_SET(upstream_sock.fd, &readfds);

            max_fd = (client_sock.fd > upstream_sock.fd)
                     ? client_sock.fd : upstream_sock.fd;

            {
                struct timeval timeout;
                timeout.tv_sec  = 1;
                timeout.tv_usec = 0;

                /* Windows ignores nfds; max_fd+1 is kept for clarity */
                int ready = select((int)(max_fd + 1), &readfds,
                                   NULL, NULL, &timeout);

                if (ready < 0) {
                    int err = platform_get_last_error();
                    LOG_ERROR("select() failed, WSA error: %d (%s)",
                              err, platform_get_error_message(err));
                    continue;
                }

                if (ready == 0) {
                    /* Idle — timeout fired, no sockets ready */
                    continue;
                }
            }

            if (FD_ISSET(client_sock.fd, &readfds)) {
                handle_client_query(&client_sock, &upstream_sock,
                                    &upstream_addr, &store);
            }

            if (FD_ISSET(upstream_sock.fd, &readfds)) {
                handle_upstream_response(&upstream_sock, &client_sock);
            }
        }
    }

    /* 10. Cleanup (unreachable; graceful shutdown deferred to later phases) */
    udp_socket_close(&upstream_sock);
    udp_socket_close(&client_sock);
    platform_socket_cleanup();

    return 0;
}
