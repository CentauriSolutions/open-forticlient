#ifndef OFTC_FFI_H
#define OFTC_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OftcHandle OftcHandle;

enum {
    OFTC_OK = 0,
    OFTC_BAD_ARGUMENT = 1,
    OFTC_NOT_CONNECTED = 2,
    OFTC_BUSY = 3,
    OFTC_CANCELLED = 4,
    OFTC_BUFFER_TOO_SMALL = 5,
    OFTC_CLOSED_HANDLE = 6,
    OFTC_INTERNAL = 7,
    OFTC_PACKET_DROPPED = 8, /* nonfatal inner packet reject; SA remains usable */
    OFTC_RECONNECT_NEEDED = 9, /* DPD grace expired; caller starts a new SA */
    OFTC_SESSION_ERROR_BASE = 100
};

enum {
    OFTC_EVENT_IP_PACKET = 1,
    OFTC_EVENT_PEER_DPD = 2,
    OFTC_EVENT_PEER_DELETED_CHILD = 3,
    OFTC_EVENT_PEER_DELETED_IKE = 4,
    OFTC_EVENT_NAT_KEEPALIVE = 5,
    OFTC_EVENT_REJECTED = 6,
    OFTC_EVENT_TIMEOUT = 7
};

enum {
    OFTC_TEARDOWN_CLEAN = 1,
    OFTC_TEARDOWN_PEER_DELETED = 2,
    OFTC_TEARDOWN_LOCAL_ONLY = 3,
    OFTC_TEARDOWN_CHILD_DELETE_UNCONFIRMED = 4,
    OFTC_TEARDOWN_IKE_DELETE_UNCONFIRMED = 5
};

typedef struct {
    uint32_t version; /* 2: family-tagged outer endpoint */
    uint8_t assigned_ipv4[4];
    uint8_t netmask[4];
    uint32_t outer_remote_family; /* 4 or 6 */
    uint8_t outer_remote[16]; /* IPv4 uses first 4 bytes, remainder zero */
    uint32_t inner_mtu;
    uint32_t route_count;
    uint32_t dns_server_count;
    uint32_t dns_domain_count;
} OftcSettings;

typedef struct {
    uint32_t transport; /* 1 UDP 4500, 2 TCP 4443 */
    uint32_t outer_family; /* 4 or 6 */
    uint8_t idi_v4[4]; /* required CLAT IDi for IPv6; zero for IPv4 */
    uint32_t tcp_fallback; /* 0 or 1; allowed only with UDP */
} OftcConnectMode;

typedef struct {
    uint32_t local;
    uint32_t peer;
    uint32_t ike;
} OftcRekeyCounts;

typedef struct {
    uint32_t family; /* 4 or 6 */
    uint8_t first[16];
    uint8_t last[16];
} OftcRoute;

/* New returns one owned reference; retain before crossing a worker queue.
 * Each retained reference must be released exactly once. The final release
 * must follow all calls on that pointer. No function accepts a stale pointer. */
OftcHandle *oftc_handle_new(void);
OftcHandle *oftc_handle_retain(OftcHandle *handle);
void oftc_handle_release(OftcHandle *handle);

/* One-shot blocking connection. All text is length-delimited UTF-8. The
 * caller retains its buffers and must erase its own PSK/token storage. */
int32_t oftc_connect(OftcHandle *handle,
    const uint8_t *gateway, size_t gateway_len,
    const uint8_t *uid, size_t uid_len,
    const uint8_t *psk, size_t psk_len,
    const uint8_t *token, size_t token_len);
/* Explicit transport selection for Gate 5. The mode contains no credentials.
 * UDP fallback may switch to TCP only if SA_INIT fails before EAP uses token. */
int32_t oftc_connect_mode(OftcHandle *handle,
    const uint8_t *gateway, size_t gateway_len,
    const uint8_t *uid, size_t uid_len,
    const uint8_t *psk, size_t psk_len,
    const uint8_t *token, size_t token_len,
    const OftcConnectMode *mode);
int32_t oftc_cancel(OftcHandle *handle);

int32_t oftc_settings(OftcHandle *handle, OftcSettings *out);
int32_t oftc_route(OftcHandle *handle, size_t index, OftcRoute *out);
int32_t oftc_dns_server(OftcHandle *handle, size_t index, uint8_t out_ipv4[4]);
int32_t oftc_dns_domain(OftcHandle *handle, size_t index,
    uint8_t *out, size_t capacity, size_t *out_len);

int32_t oftc_send_ip(OftcHandle *handle, const uint8_t *packet, size_t packet_len);
int32_t oftc_receive(OftcHandle *handle, uint8_t *out, size_t capacity,
    size_t *out_len, uint32_t *out_event);
int32_t oftc_probe_liveness(OftcHandle *handle);
/* Call periodically on a worker while receive continues. Sends or retransmits
 * one DPD without waiting. Return OFTC_RECONNECT_NEEDED after the grace window. */
int32_t oftc_tick_liveness(OftcHandle *handle);
/* Refresh the outer mapping without treating a keepalive as authenticated RX. */
int32_t oftc_send_nat_keepalive(OftcHandle *handle);
/* Explicit bounded CHILD_SA rekey probe; any failure requires tunnel cleanup. */
/* Nonsecret rekey failure stages: 120 local offer, 121 no response,
 * 122 no proposal, 123 invalid KE, 124 no additional SAs,
 * 125 unacceptable selectors, 126 other authenticated Notify,
 * 127 malformed response, 128 suite mismatch, 129 selector change,
 * 130 key derivation, 131 install, 132 old-SA delete. */
int32_t oftc_rekey_child_once(OftcHandle *handle);
/* Explicit bounded IKE_SA renewal probe; failure requires tunnel cleanup. */
int32_t oftc_rekey_ike_once(OftcHandle *handle);
int32_t oftc_rekey_counts(OftcHandle *handle, OftcRekeyCounts *out);
int32_t oftc_teardown(OftcHandle *handle, uint32_t *out_result);

#ifdef __cplusplus
}
#endif
#endif
