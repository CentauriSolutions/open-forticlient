# Architecture

The `oftc` CLI in [`client/`](../client/) invokes the signed host executable.
The host owns the nonsecret profile, Keychain PSK, browser SAML, macOS VPN
configuration, and reconnect supervisor. The NetworkExtension provider owns
the outer UDP/TCP transport, IKEv2/EAP, ESP, packet flow, routes, and DNS.
Rust code reaches the provider through an opaque C ABI; Swift handles
NetworkExtension and the crypto bridge.

```text
oftc CLI → host app → NetworkExtension provider → Rust IKE/ESP engine
                ↘ browser SAML       ↘ packetFlow / system tunnel
```

The one-time `oftc setup --import` path reads a local FortiClient profile.
Normal `connect` and supervised recovery use the OFTC
profile and Keychain item. SAML tokens are passed to the provider for a single
start and are not saved in VPN preferences, files, command arguments, or logs.

| Source | Responsibility |
| --- | --- |
| [`app/Host/`](../app/Host/) | SAML orchestration, profile and Keychain access, VPN configuration, reconnection. |
| [`app/Provider/`](../app/Provider/) | Packet tunnel lifecycle and Rust FFI adapter. |
| [`app/core/`](../app/core/) | IKEv2, EAP-MSCHAPv2, ESP, transport, lifecycle, and C ABI. |
| [`app/crypto/`](../app/crypto/) | Swift CryptoKit/CommonCrypto bridge. |
| [`app/bootstrap/`](../app/bootstrap/) | Host SAML, TLS, and device identity. |
| [`app/migration/`](../app/migration/) | FortiClient profile decryption for explicit one-time import. |
| [`app/support/`](../app/support/) | Shared host/provider bootstrap and strict tunnel settings mapping. |

The host can reconnect after a recoverable provider drop using fresh SSO when
needed. An explicit user stop disables agent autostart and stays down. The
[rollout gaps](initial-rollout-gaps.md) distinguish measured recovery paths
from untested ones.
