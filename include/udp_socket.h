#ifndef UDP_SOCKET_H
#define UDP_SOCKET_H

#include <stdint.h>
#include <winsock2.h>

/* ── UDP socket object ────────────────────────────────────────── */
typedef struct {
    SOCKET   fd;
    uint16_t port;
} UdpSocket;

/* ── Public API ───────────────────────────────────────────────── */
int  udp_socket_create(UdpSocket *sock);
int  udp_socket_bind(UdpSocket *sock, uint16_t port);
int  udp_socket_recvfrom(UdpSocket *sock,
                         uint8_t *buffer,
                         int buffer_size,
                         struct sockaddr_in *client_addr,
                         int *client_addr_len);
int  udp_socket_sendto(UdpSocket *sock,
                       const uint8_t *buffer,
                       int buffer_len,
                       const struct sockaddr_in *client_addr,
                       int client_addr_len);
void udp_socket_close(UdpSocket *sock);

#endif /* UDP_SOCKET_H */
