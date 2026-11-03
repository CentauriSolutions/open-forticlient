# Provider messages

The host talks to a running packet tunnel provider with
`NETunnelProviderSession.sendProviderMessage`. These names and replies are a
contract between host and provider builds, which are released and activated
separately, so a newer host must keep working against an older provider and the
reverse. Any reimplementation of either side keeps them byte-for-byte.

A message is the UTF-8 bytes of its name. The provider replies once, or replies
with no data (`nil`) when the message is unknown, the tunnel is not running, or
it is stopping.

| Message | Reply | Sent by |
| --- | --- | --- |
| `oftc.traffic.v1` | JSON snapshot, below | menu bar, once per second while connected |
| `oftc.rekey-counts.v1` | `child_rekeys local=<n> peer=<n> ike=<n>` | `oftc rekey-counts` |
| `oftc.rekey-child-once.v1` | `rekey_passed`, `rekey_failed stage=<n>`, `rekey_unavailable`, or `rekey_stopped` | `oftc rekey-once` |
| `oftc.rekey-ike-once.v1` | same as above | `oftc rekey-ike-once` |
| `oftc.preflight-status.v1` | `preflight_passed responder_auth_and_eap_challenge` or `preflight_failed stage=<n>` | `oftc preflight` |

## Traffic snapshot

`oftc.traffic.v1` replies with JSON written by Swift's default `JSONEncoder`:

```json
{"version":1,"sessionID":"<UUID>","receivedBytes":0,"sentBytes":0,"uptime":12345.6}
```

- `version` is 1. A host rejects any other value, and a non-finite or negative `uptime`.
- `sessionID` is fixed for one provider connection and changes on a new one, so the
  host can tell a reconnection from a counter reset.
- `receivedBytes` and `sentBytes` count inner IP bytes accepted by the engine or the
  packet flow, saturating at the maximum. ESP, IKE, dropped packets and traffic
  outside OFTC are not counted. They survive rekeys.
- `uptime` is the provider's monotonic system uptime in seconds. The host derives
  rates from consecutive samples of one session and ignores gaps over five seconds.

## Rekey probes and preflight

- `rekey_failed stage=<n>` carries a nonsecret stage code. Stages 120 to 132 are the
  CHILD rekey failures listed in `app/core/provider-ffi/oftc_ffi.h`; other values are
  the provider's own failure codes (500 plus the engine status).
- A rekey probe fails closed: a failed probe also stops the tunnel.
- `preflight_*` replies exist only after a preflight start, which opens no tunnel,
  routes or DNS. Its stage codes are 1 invalid input, 2 socket or timeout, 3 SA_INIT,
  4 responder AUTH, 5 EAP challenge.
