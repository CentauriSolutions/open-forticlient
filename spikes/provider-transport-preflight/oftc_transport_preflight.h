#ifndef OFTC_TRANSPORT_PREFLIGHT_H
#define OFTC_TRANSPORT_PREFLIGHT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    OFTC_PREFLIGHT_UDP_4500 = 1,
    OFTC_PREFLIGHT_TCP_4443 = 2
};

/* Blocking, no-token diagnostic on an IPv6 outer socket. The caller supplies
 * the current CLAT IPv4 IDi explicitly. Gateway is a hostname and must have
 * an AAAA/DNS64 result. UID is exactly 32 ASCII hex digits. Caller retains
 * and clears its PSK storage. No route, DNS setting, CHILD_SA, or ESP is installed.
 * Return: 0 authenticated EAP challenge; 1 input; 2 DNS/socket/timeout;
 * 3 SA_INIT; 4 responder AUTH; 5 EAP challenge/internal. */
int32_t oftc_provider_preflight_ipv6(
    const uint8_t *gateway, size_t gateway_len,
    const uint8_t *uid, size_t uid_len,
    const uint8_t *psk, size_t psk_len,
    const uint8_t *idi_v4, size_t idi_v4_len,
    uint32_t transport);

#ifdef __cplusplus
}
#endif
#endif
