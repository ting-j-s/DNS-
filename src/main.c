#include "common.h"
#include "config.h"
#include "logger.h"
#include "platform_win.h"
#include "udp_socket.h"
#include "dns_packet.h"
#include "resource_store.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    Config config;
    UdpSocket client_sock;

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
        LOG_ERROR("Failed to create UDP socket");
        platform_socket_cleanup();
        return 1;
    }

    if (udp_socket_bind(&client_sock, (uint16_t)config.listen_port) != 0) {
        LOG_ERROR("Failed to bind port %d", config.listen_port);
        udp_socket_close(&client_sock);
        platform_socket_cleanup();
        return 1;
    }

    LOG_INFO("dnsrelay is listening on port %d", config.listen_port);

    /* 6. Initialize resource store and load local records */
    {
        ResourceStore store;
        resource_store_init(&store);

        if (resource_store_load_file(&store, config.filename) != 0) {
            LOG_ERROR("Failed to load resource file, exiting");
            udp_socket_close(&client_sock);
            platform_socket_cleanup();
            return 1;
        }

        LOG_INFO("Phase 2-2: local A response enabled");

        /* 7. Receive loop — parse, lookup, respond to A hits */
        while (1) {
            uint8_t buffer[DNS_MAX_PACKET_SIZE];
            uint8_t response[DNS_MAX_PACKET_SIZE];
            struct sockaddr_in client_addr;
            int client_addr_len = sizeof(client_addr);
            char client_ip[16];  /* enough for "xxx.xxx.xxx.xxx" */
            DnsQuery query;
            int recv_len;
            int parse_ret;

            recv_len = udp_socket_recvfrom(&client_sock,
                                            buffer,
                                            sizeof(buffer),
                                            &client_addr,
                                            &client_addr_len);

            if (recv_len < 0) {
                /* Error already logged by udp_socket_recvfrom */
                continue;
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

                rr = resource_store_lookup(&store,
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
                            sent = udp_socket_sendto(&client_sock,
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
                            sent = udp_socket_sendto(&client_sock,
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
                    LOG_INFO("  => local miss, "
                             "upstream relay not implemented yet: qname=%s",
                             query.question.qname);
                }
            } else {
                LOG_DEBUG("invalid DNS query from %s:%u, len=%d, parse_ret=%d",
                          client_ip,
                          ntohs(client_addr.sin_port),
                          recv_len,
                          parse_ret);
            }
        }
    }

    /* 8. Cleanup (unreachable in Phase 2-1; will be reachable once
     *    graceful shutdown is implemented in later phases) */
    udp_socket_close(&client_sock);
    platform_socket_cleanup();

    return 0;
}
