#include "platform_win.h"
#include "logger.h"
#include <winsock2.h>

static int g_initialized = 0;

int platform_socket_init(void) {
    if (g_initialized) return 0;

    WSADATA wsa_data;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        LOG_ERROR("Winsock initialization failed (code %d)", result);
        return -1;
    }

    g_initialized = 1;
    LOG_INFO("Winsock initialized (v%d.%d)",
             LOBYTE(wsa_data.wVersion), HIBYTE(wsa_data.wVersion));
    return 0;
}

void platform_socket_cleanup(void) {
    if (!g_initialized) return;
    WSACleanup();
    g_initialized = 0;
    LOG_INFO("Winsock cleanup done");
}

int platform_get_last_error(void) {
    return WSAGetLastError();
}

const char *platform_get_error_message(int error_code) {
    switch (error_code) {
    case WSAEACCES:         return "Permission denied";
    case WSAEADDRINUSE:     return "Address already in use";
    case WSAENETUNREACH:    return "Network is unreachable";
    case WSAETIMEDOUT:      return "Connection timed out";
    case WSAECONNRESET:     return "Connection reset";
    default:                return "Unknown WSA error";
    }
}
