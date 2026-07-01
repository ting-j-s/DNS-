#include "dns_name.h"
#include "logger.h"

/* Maximum compression-pointer jumps before treating as a loop */
#define DNS_NAME_MAX_JUMPS  16

int dns_name_decode(const uint8_t *packet,
                    int packet_len,
                    int offset,
                    char *out_name,
                    int out_size,
                    int *next_offset)
{
    int pos;                /* current read position in packet         */
    int w;                  /* current write position in out_name      */
    int jumped;             /* have we followed a compression pointer? */
    int jump_count;         /* number of pointer jumps followed        */
    int first_jump_next;    /* next_offset saved at first pointer      */
    uint8_t len;            /* current label length byte               */
    int label_len;          /* interpreted label length                */
    int i;

    /* ── 1. Parameter validation ─────────────────────────────────── */
    if (!packet || packet_len <= 0 || offset < 0 || offset >= packet_len ||
        !out_name || out_size <= 0 || !next_offset) {
        return -1;
    }

    out_name[0] = '\0';

    pos        = offset;
    w          = 0;
    jumped     = 0;
    jump_count = 0;
    first_jump_next = 0;

    /* ── 2. Main decode loop ─────────────────────────────────────── */
    for (;;) {
        /* Bounds check for the length byte */
        if (pos >= packet_len) {
            LOG_TRACE("dns_name_decode: length byte out of bounds "
                      "(pos=%d, packet_len=%d)", pos, packet_len);
            return -2;
        }

        len = packet[pos];

        /* ── Zero-length label → end of name ─────────────────────── */
        if (len == 0) {
            if (w == 0) {
                /* Root domain */
                if (out_size < 2) return -4;
                out_name[0] = '.';
                out_name[1] = '\0';
            } else {
                out_name[w] = '\0';
            }
            *next_offset = jumped ? first_jump_next : pos + 1;
            return 0;
        }

        /* ── Compression pointer (top two bits set) ──────────────── */
        if ((len & 0xC0) == 0xC0) {
            uint16_t pointer;

            if (pos + 1 >= packet_len) {
                LOG_TRACE("dns_name_decode: truncated compression pointer at %d",
                          pos);
                return -3;
            }

            pointer = ((uint16_t)(len & 0x3F) << 8) | packet[pos + 1];
            if (pointer >= (uint16_t)packet_len) {
                LOG_TRACE("dns_name_decode: pointer %u out of bounds (len=%d)",
                          pointer, packet_len);
                return -3;
            }

            jump_count++;
            if (jump_count > DNS_NAME_MAX_JUMPS) {
                LOG_TRACE("dns_name_decode: compression pointer loop "
                          "(jumps=%d)", jump_count);
                return -5;
            }

            /* Save next_offset at the first pointer we encounter */
            if (!jumped) {
                jumped = 1;
                first_jump_next = pos + 2;
            }
            pos = (int)pointer;
            continue;
        }

        /* ── Reserved label type (0x40, 0x80) → illegal ─────────── */
        if ((len & 0xC0) != 0x00) {
            LOG_TRACE("dns_name_decode: illegal label type 0x%02x at %d",
                      len, pos);
            return -3;
        }

        /* ── Normal label ────────────────────────────────────────── */
        label_len = (int)len;
        if (label_len > 63) {
            LOG_TRACE("dns_name_decode: label too long (%d at %d)",
                      label_len, pos);
            return -2;
        }
        if (pos + 1 + label_len > packet_len) {
            LOG_TRACE("dns_name_decode: label truncated (len=%d at %d, "
                      "packet_len=%d)", label_len, pos, packet_len);
            return -2;
        }

        /* Insert dot separator between labels */
        if (w > 0) {
            if (w + 1 >= out_size) return -4;
            out_name[w++] = '.';
        }

        /* Check space for label + NUL */
        if (w + label_len >= out_size) return -4;

        /* Copy label bytes */
        for (i = 0; i < label_len; i++) {
            out_name[w++] = packet[pos + 1 + i];
        }

        pos += 1 + label_len;
    }
}
