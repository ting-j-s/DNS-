#include "common.h"
#include "config.h"
#include "logger.h"
#include "platform_win.h"
#include "udp_socket.h"
#include "dns_packet.h"
#include "resource_store.h"
#include "transaction.h"
#include "cache.h"
#include "tcp_dns_client.h"
#include <stdio.h>
#include <string.h>

/* ── DNS ID read/write helpers (safe byte-wise access) ───────────── */

static uint16_t dns_packet_get_id(const uint8_t *packet, int packet_len)
{
    if (!packet || packet_len < DNS_HEADER_SIZE) {
        return 0;
    }
    return ((uint16_t)packet[0] << 8) | packet[1];
}

static int dns_packet_set_id(uint8_t *packet, int packet_len, uint16_t id)
{
    if (!packet || packet_len < DNS_HEADER_SIZE) {
        return -1;
    }
    packet[0] = (uint8_t)(id >> 8);
    packet[1] = (uint8_t)(id & 0xFF);
    return 0;
}


/* ── Forward declarations ────────────────────────────────────────── */

static void handle_client_query(UdpSocket *client_sock,
                                UdpSocket *upstream_sock,
                                const struct sockaddr_in *upstream_addr,
                                const ResourceStore *store,
                                TransactionTable *tx_table,
                                CacheTable *cache);

static void handle_upstream_response(UdpSocket *upstream_sock,
                                     UdpSocket *client_sock,
                                     TransactionTable *tx_table,
                                     CacheTable *cache,
                                     const Config *config);


/* ── Handle incoming client DNS query ────────────────────────────── */
static void handle_client_query(UdpSocket *client_sock,
                                UdpSocket *upstream_sock,
                                const struct sockaddr_in *upstream_addr,
                                const ResourceStore *store,
                                TransactionTable *tx_table,
                                CacheTable *cache)
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
        ResourceAnswerSet answer_set;
        int lookup_ret;
        int handled = 0;  /* set to 1 when a local response is sent */

        LOG_INFO("client=%s:%u  id=%u  qname=%s  qtype=%s(%u)  qclass=%s(%u)",
                 client_ip,
                 ntohs(client_addr.sin_port),
                 query.header.id,
                 query.question.qname,
                 dns_qtype_to_string(query.question.qtype),
                 query.question.qtype,
                 dns_qclass_to_string(query.question.qclass),
                 query.question.qclass);

        lookup_ret = resource_store_lookup_set(store,
                                               query.question.qname,
                                               query.question.qtype,
                                               query.question.qclass,
                                               &answer_set);

        if (lookup_ret < 0) {
            LOG_ERROR("  => resource_store_lookup_set error: "
                      "qname=%s, ret=%d",
                      query.question.qname, lookup_ret);
            /* Fall through — forward upstream as a safe default */
        } else if (answer_set.is_blocked) {
            /* ── Local BLOCK: return NXDOMAIN ────────────────────── */
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
                    handled = 1;
                }
                /* sendto error already logged */
            } else {
                LOG_ERROR("  => failed to build NXDOMAIN response: "
                          "qname=%s, rc=%d",
                          query.question.qname, resp_len);
            }
        } else if (answer_set.count > 0) {
            /* ── Local RR hit (any type) ─────────────────────────── */
            int resp_len, sent;

            resp_len = dns_packet_build_rr_response_set(
                buffer, recv_len, &query,
                &answer_set,
                response, sizeof(response));

            if (resp_len > 0) {
                sent = udp_socket_sendto(client_sock,
                                          response, resp_len,
                                          &client_addr,
                                          client_addr_len);
                if (sent > 0) {
                    LOG_INFO("  => local RR response sent: "
                             "qname=%s, qtype=%s, answers=%d, bytes=%d",
                             query.question.qname,
                             dns_qtype_to_string(query.question.qtype),
                             answer_set.count, sent);
                    handled = 1;
                }
                /* sendto error already logged */
            } else {
                LOG_ERROR("  => failed to build RR response: "
                          "qname=%s, qtype=%s, rc=%d",
                          query.question.qname,
                          dns_qtype_to_string(query.question.qtype),
                          resp_len);
            }
        }
        /* else: count == 0 and not blocked → normal miss */

        /* ── Local miss or unhandled: check cache, then forward ──────── */
        if (!handled) {
            ResourceAnswerSet cache_set;
            int cache_ret;

            /* Step 2: Check dynamic cache */
            cache_ret = cache_lookup(cache,
                                     query.question.qname,
                                     query.question.qtype,
                                     query.question.qclass,
                                     &cache_set);

            if (cache_ret == 1) {
                /* ── Cache hit: build response locally ──────────────── */
                int resp_len, sent;

                resp_len = dns_packet_build_rr_response_set(
                    buffer, recv_len, &query,
                    &cache_set,
                    response, sizeof(response));

                if (resp_len > 0) {
                    sent = udp_socket_sendto(client_sock,
                                              response, resp_len,
                                              &client_addr,
                                              client_addr_len);
                    if (sent > 0) {
                        LOG_INFO("  => cache hit response sent: "
                                 "qname=%s, qtype=%s, answers=%d, bytes=%d",
                                 query.question.qname,
                                 dns_qtype_to_string(query.question.qtype),
                                 cache_set.count, sent);
                        handled = 1;
                    }
                } else {
                    LOG_ERROR("  => failed to build cache response: "
                              "qname=%s, qtype=%s, rc=%d",
                              query.question.qname,
                              dns_qtype_to_string(query.question.qtype),
                              resp_len);
                }
            } else if (cache_ret < 0) {
                LOG_ERROR("  => cache lookup error: qname=%s, ret=%d",
                          query.question.qname, cache_ret);
                /* Fall through — forward upstream for service continuity */
            }
            /* cache_ret == 0: cache miss → fall through to upstream */
        }

        /* ── Cache miss or unhandled: forward to upstream DNS ────────── */
        if (!handled) {
            uint16_t client_id;
            uint16_t relay_id = 0;
            int tx_ret;

            client_id = query.header.id;

            LOG_INFO("  => local miss, forward upstream: "
                     "client_id=%u, qname=%s, qtype=%s(%u)",
                     client_id,
                     query.question.qname,
                     dns_qtype_to_string(query.question.qtype),
                     query.question.qtype);

            tx_ret = transaction_add(tx_table,
                                     client_id,
                                     query.question.qname,
                                     query.question.qtype,
                                     query.question.qclass,
                                     &client_addr,
                                     client_addr_len,
                                     &relay_id);

            if (tx_ret != 0) {
                LOG_ERROR("  => transaction add failed: ret=%d, qname=%s",
                          tx_ret, query.question.qname);
                return;
            }

            LOG_DEBUG("transaction added: client_id=%u, relay_id=%u, "
                      "qname=%s, count=%d",
                      client_id, relay_id, query.question.qname,
                      transaction_count_used(tx_table));

            /* Replace DNS ID in buffer with relay_id */
            dns_packet_set_id(buffer, recv_len, relay_id);

            /* Save relay_id-rewritten query for TCP fallback */
            {
                int qp_ret;
                qp_ret = transaction_set_query_packet(tx_table, relay_id,
                                                      buffer, recv_len);
                if (qp_ret != 0) {
                    DnsTransaction *tx_err;
                    LOG_ERROR("  => transaction_set_query_packet failed: "
                              "ret=%d, relay_id=%u, qname=%s",
                              qp_ret, relay_id,
                              query.question.qname);
                    tx_err = transaction_find_by_relay_id(tx_table, relay_id);
                    transaction_remove(tx_table, tx_err);
                    return;
                }
            }

            {
                int sent;

                sent = udp_socket_sendto(upstream_sock,
                                          buffer, recv_len,
                                          upstream_addr,
                                          sizeof(*upstream_addr));

                if (sent > 0) {
                    LOG_INFO("  => upstream forward sent: "
                             "client_id=%u, relay_id=%u, "
                             "qname=%s, bytes=%d",
                             client_id, relay_id,
                             query.question.qname, sent);
                } else {
                    DnsTransaction *tx;
                    LOG_ERROR("  => upstream send failed: "
                              "client_id=%u, relay_id=%u, qname=%s",
                              client_id, relay_id,
                              query.question.qname);
                    /* Remove transaction on send failure */
                    tx = transaction_find_by_relay_id(tx_table, relay_id);
                    transaction_remove(tx_table, tx);
                }
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
                                     UdpSocket *client_sock,
                                     TransactionTable *tx_table,
                                     CacheTable *cache,
                                     const Config *config)
{
    uint8_t udp_buf[DNS_MAX_PACKET_SIZE];
    uint8_t tcp_buf[TCP_DNS_MAX_MESSAGE_SIZE];
    struct sockaddr_in from_addr;
    int from_addr_len = sizeof(from_addr);
    int udp_len;
    uint16_t relay_id;
    DnsTransaction *tx;

    /* ── 1. Receive UDP response from upstream ────────────────────── */
    udp_len = udp_socket_recvfrom(upstream_sock,
                                   udp_buf, sizeof(udp_buf),
                                   &from_addr, &from_addr_len);
    if (udp_len < 0) {
        /* Error already logged */
        return;
    }

    /* Check minimum length for DNS header */
    if (udp_len < DNS_HEADER_SIZE) {
        LOG_DEBUG("upstream response too short: bytes=%d, from=%s:%u",
                  udp_len,
                  inet_ntoa(from_addr.sin_addr),
                  ntohs(from_addr.sin_port));
        return;
    }

    /* Extract relay_id from upstream UDP response */
    relay_id = dns_packet_get_id(udp_buf, udp_len);

    LOG_DEBUG("upstream response received: relay_id=%u, bytes=%d, from=%s:%u",
              relay_id, udp_len,
              inet_ntoa(from_addr.sin_addr),
              ntohs(from_addr.sin_port));

    tx = transaction_find_by_relay_id(tx_table, relay_id);
    if (!tx) {
        LOG_DEBUG("upstream response has no transaction: "
                  "relay_id=%u, bytes=%d",
                  relay_id, udp_len);
        return;
    }

    /* ── 2. TC fallback decision ─────────────────────────────────────── */
    {
        uint8_t *final_buf = udp_buf;
        int      final_len = udp_len;
        int      used_tcp  = 0;

        if (dns_packet_is_truncated(udp_buf, udp_len)) {
            LOG_INFO("upstream UDP response TC=1, attempting TCP fallback: "
                     "qname=%s, qtype=%s(%u)",
                     tx->qname,
                     dns_qtype_to_string(tx->qtype),
                     tx->qtype);

            if (tx->query_len > 0) {
                int tcp_len;

                tcp_len = tcp_dns_query(config->upstream_dns, 53,
                                        tx->query_packet,
                                        tx->query_len,
                                        tcp_buf, sizeof(tcp_buf),
                                        TCP_DNS_DEFAULT_TIMEOUT_MS);

                if (tcp_len > 0) {
                    /* Verify TCP response ID matches relay_id */
                    uint16_t tcp_id;
                    tcp_id = dns_packet_get_id(tcp_buf, tcp_len);
                    if (tcp_id == relay_id) {
                        final_buf = tcp_buf;
                        final_len = tcp_len;
                        used_tcp  = 1;
                        LOG_INFO("tcp fallback success: "
                                 "qname=%s, qtype=%s(%u), "
                                 "udp_bytes=%d, tcp_bytes=%d",
                                 tx->qname,
                                 dns_qtype_to_string(tx->qtype),
                                 tx->qtype, udp_len, tcp_len);
                    } else {
                        LOG_ERROR("tcp fallback ID mismatch: "
                                  "expected=%u, got=%u, qname=%s, "
                                  "falling back to UDP truncated response",
                                  relay_id, tcp_id, tx->qname);
                    }
                } else {
                    LOG_ERROR("tcp fallback failed: "
                              "qname=%s, qtype=%s(%u), ret=%d, "
                              "falling back to UDP truncated response",
                              tx->qname,
                              dns_qtype_to_string(tx->qtype),
                              tx->qtype, tcp_len);
                }
            } else {
                LOG_ERROR("tcp fallback skipped: query_packet not saved, "
                          "qname=%s", tx->qname);
            }
        }

        /* ── 3. Extract cache-able answers ───────────────────────────── */
        {
            ResourceAnswerSet answer_set;
            uint32_t min_ttl = 0;
            int extract_ret;

            extract_ret = dns_packet_extract_answer_set(
                final_buf, final_len,
                tx->qname, tx->qtype, tx->qclass,
                &answer_set, &min_ttl);

            if (extract_ret == 1) {
                int insert_ret;
                insert_ret = cache_insert(cache,
                                          tx->qname,
                                          tx->qtype,
                                          tx->qclass,
                                          &answer_set,
                                          min_ttl);
                if (insert_ret == 1) {
                    LOG_INFO("cache inserted: qname=%s, qtype=%s(%u), "
                             "answers=%d, ttl=%u, source=%s",
                             tx->qname,
                             dns_qtype_to_string(tx->qtype),
                             tx->qtype,
                             answer_set.count,
                             min_ttl,
                             used_tcp ? "tcp" : "udp");
                } else if (insert_ret == 0) {
                    LOG_DEBUG("upstream response not cacheable: "
                              "qname=%s, qtype=%s(%u)",
                              tx->qname,
                              dns_qtype_to_string(tx->qtype),
                              tx->qtype);
                } else {
                    LOG_DEBUG("cache insert failed: ret=%d, qname=%s",
                              insert_ret, tx->qname);
                }
            } else if (extract_ret == 0) {
                LOG_DEBUG("upstream response not cacheable: "
                          "qname=%s, qtype=%s(%u)",
                          tx->qname,
                          dns_qtype_to_string(tx->qtype),
                          tx->qtype);
            } else {
                LOG_DEBUG("upstream answer parse failed: ret=%d, qname=%s",
                          extract_ret, tx->qname);
            }
        }

        /* ── 4. Restore original client DNS ID and send to client ───── */
        dns_packet_set_id(final_buf, final_len, tx->client_id);

        {
            int sent;
            sent = udp_socket_sendto(client_sock,
                                      final_buf, final_len,
                                      &tx->client_addr,
                                      tx->client_addr_len);

            if (sent > 0) {
                LOG_INFO("upstream response relayed: relay_id=%u, "
                         "client_id=%u, qname=%s, qtype=%s(%u), "
                         "bytes=%d%s",
                         relay_id, tx->client_id, tx->qname,
                         dns_qtype_to_string(tx->qtype), tx->qtype,
                         sent, used_tcp ? " (tcp)" : "");
            } else {
                LOG_ERROR("upstream response send to client failed: "
                          "relay_id=%u, client_id=%u, qname=%s",
                          relay_id, tx->client_id, tx->qname);
            }
        }
    }

    transaction_remove(tx_table, tx);

    LOG_DEBUG("transaction removed: relay_id=%u, count=%d",
              relay_id, transaction_count_used(tx_table));
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

    /* 8. Initialize resource store, transaction table, cache */
    {
        ResourceStore store;
        TransactionTable tx_table;
        CacheTable cache;

        resource_store_init(&store);
        transaction_table_init(&tx_table);
        if (cache_table_init(&cache) != 0) {
            LOG_ERROR("Failed to initialize cache table");
            udp_socket_close(&upstream_sock);
            udp_socket_close(&client_sock);
            platform_socket_cleanup();
            return 1;
        }

        if (resource_store_load_file(&store, config.filename) != 0) {
            LOG_ERROR("Failed to load resource file, exiting");
            cache_table_destroy(&cache);
            udp_socket_close(&upstream_sock);
            udp_socket_close(&client_sock);
            platform_socket_cleanup();
            return 1;
        }

        LOG_INFO("Phase 4-3: select event loop with timeout cleanup");

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
                    transaction_cleanup_expired(&tx_table);
                    continue;
                }

                if (ready == 0) {
                    /* Idle — timeout fired, no sockets ready;
                     * fall through to cleanup expired transactions */
                }
            }

            if (FD_ISSET(client_sock.fd, &readfds)) {
                handle_client_query(&client_sock, &upstream_sock,
                                    &upstream_addr, &store, &tx_table,
                                    &cache);
            }

            if (FD_ISSET(upstream_sock.fd, &readfds)) {
                handle_upstream_response(&upstream_sock, &client_sock,
                                        &tx_table, &cache, &config);
            }

            /* ── Cleanup expired transactions ─────────────────────── */
            {
                int cleaned;
                cleaned = transaction_cleanup_expired(&tx_table);
                if (cleaned > 0) {
                    LOG_INFO("transaction cleanup expired: count=%d, "
                             "active=%d",
                             cleaned,
                             transaction_count_used(&tx_table));
                }
            }

            /* ── Cleanup expired cache entries ────────────────────── */
            {
                int cache_cleaned;
                cache_cleaned = cache_cleanup_expired(&cache);
                if (cache_cleaned > 0) {
                    LOG_DEBUG("cache cleanup expired: count=%d, active=%d",
                              cache_cleaned,
                              cache_count_used(&cache));
                }
            }
        }

        /* 10. Cleanup (unreachable; graceful shutdown deferred to later phases) */
        cache_table_destroy(&cache);
    }

    udp_socket_close(&upstream_sock);
    udp_socket_close(&client_sock);
    platform_socket_cleanup();

    return 0;
}
