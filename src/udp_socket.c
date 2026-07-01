#include "udp_socket.h"
#include "platform_win.h"
#include "logger.h"
#include <string.h>

int udp_socket_create(UdpSocket *sock) {
    if (!sock) return -1;

    sock->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock->fd == INVALID_SOCKET) {
        int err = platform_get_last_error();
        LOG_ERROR("socket() failed, WSA error: %d (%s)",
                  err, platform_get_error_message(err));
        return -1;
    }

    sock->port = 0;
    LOG_INFO("UDP socket created");
    return 0;
}

int udp_socket_bind(UdpSocket *sock, uint16_t port) {
    if (!sock || sock->fd == INVALID_SOCKET) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(sock->fd, (const struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        int err = platform_get_last_error();
        LOG_ERROR("bind() to port %d failed, WSA error: %d (%s)",
                  port, err, platform_get_error_message(err));
        LOG_ERROR("Possible causes: insufficient permissions (run as Administrator) "
                  "or port already in use");
        return -1;
    }

    sock->port = port;
    LOG_INFO("UDP socket bound on 0.0.0.0:%d", port);
    return 0;
}

void udp_socket_close(UdpSocket *sock) {
    if (!sock) return;
    if (sock->fd != INVALID_SOCKET) {
        closesocket(sock->fd);
        LOG_INFO("UDP socket closed");
        sock->fd = INVALID_SOCKET;
    }
}

int udp_socket_recvfrom(UdpSocket *sock,
                        uint8_t *buffer,
                        int buffer_size,
                        struct sockaddr_in *client_addr,
                        int *client_addr_len) {
    int received;

    if (!sock || sock->fd == INVALID_SOCKET) {
        LOG_ERROR("udp_socket_recvfrom: invalid socket");
        return -1;
    }
    if (!buffer || buffer_size <= 0) {
        LOG_ERROR("udp_socket_recvfrom: invalid buffer");
        return -1;
    }
    if (!client_addr || !client_addr_len) {
        LOG_ERROR("udp_socket_recvfrom: invalid client_addr");
        return -1;
    }

    received = recvfrom(sock->fd,
                        (char *)buffer,
                        buffer_size,
                        0,
                        (struct sockaddr *)client_addr,
                        client_addr_len);

    if (received == SOCKET_ERROR) {
        int err = platform_get_last_error();
        LOG_ERROR("recvfrom() failed, WSA error: %d (%s)",
                  err, platform_get_error_message(err));
        return -1;
    }

    LOG_TRACE("recvfrom: received %d bytes", received);
    return received;
}

int udp_socket_sendto(UdpSocket *sock,
                      const uint8_t *buffer,
                      int buffer_len,
                      const struct sockaddr_in *client_addr,
                      int client_addr_len)
{
    int sent;

    if (!sock || sock->fd == INVALID_SOCKET) {
        LOG_ERROR("udp_socket_sendto: invalid socket");
        return -1;
    }
    if (!buffer || buffer_len <= 0) {
        LOG_ERROR("udp_socket_sendto: invalid buffer");
        return -1;
    }
    if (!client_addr || client_addr_len <= 0) {
        LOG_ERROR("udp_socket_sendto: invalid client_addr");
        return -1;
    }

    sent = sendto(sock->fd,
                  (const char *)buffer,
                  buffer_len,
                  0,
                  (const struct sockaddr *)client_addr,
                  client_addr_len);

    if (sent == SOCKET_ERROR) {
        int err = platform_get_last_error();
        LOG_ERROR("sendto() failed, WSA error: %d (%s)",
                  err, platform_get_error_message(err));
        return -1;
    }

    LOG_TRACE("sendto: sent %d bytes", sent);
    return sent;
}
