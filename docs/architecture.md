# Architecture

The `oftc` CLI in [`client/`](../client/) invokes the signed host executable.
The host owns the nonsecret profile, Keychain PSK, browser SAML, macOS VPN
configuration, and reconnect supervisor. The NetworkExtension provider owns
the outer UDP/TCP transport, IKEv2/EAP, ESP, packet flow, routes, and DNS.
Rust code reaches the provider through an opaque C ABI; Swift handles
NetworkExtension.

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
| [`app/Host/`](../app/Host/) | SAML orchestration, profile registry and Keychain access, per-profile VPN configuration, reconnection. |
| [`app/core/host/`](../app/core/host/), [`app/core/hostlib/`](../app/core/hostlib/) | The host verbs moving from Swift to Rust ([list](host-verbs.md)): profiles, registry, PSK Keychain. `hostlib` is the static library `OFTCAgent` links; its `oftc_host_main` runs them. |
| [`app/Provider/`](../app/Provider/) | Packet tunnel lifecycle and Rust FFI adapter. |
| [`app/core/`](../app/core/) | IKEv2, EAP-MSCHAPv2, ESP, transport, lifecycle, and C ABI. |
| [`app/bootstrap/`](../app/bootstrap/) | Host SAML, TLS, and device identity. |
| [`app/migration/`](../app/migration/) | FortiClient profile decryption for explicit one-time import. |
| [`app/support/`](../app/support/) | Shared host/provider bootstrap and strict tunnel settings mapping. |

Each configured VPN is a peer profile under `profiles/<id>/` in the host's
Application Support directory, with its own nonsecret profile, macOS VPN
entry (identified by `providerConfiguration["oftc.profile"]`), Keychain PSK,
supervisor lease, stop request, status record and connect-at-login choice.
Every profile's tunnel is a separate provider session of the one extension, so
several can be connected at once. Each supervisor is its own host process;
they take a shared file lock around browser SAML, so sign-ins (each listens on
a local callback port) happen one at a time. The login agent runs
`supervise-autostart`, which starts a supervisor for each profile whose
connect-at-login choice is on. A profile from the original single-profile
layout is migrated on first run and adopts the VPN entry that has no profile
key. Route and DNS policy across profiles is not yet enforced; see Issue 40.

The host can reconnect after a recoverable provider drop using fresh SSO when
needed. An explicit user stop stays down until the next connect and does not
change connect-at-login.

Opening the host without arguments runs the resident AppKit menu bar app.
It observes NetworkExtension status and the supervisor's nonsecret phase
record. Connection buttons invoke the CLI embedded in `Contents/Helpers`,
so the menu and terminal share registration, migration, and stop semantics.
The UI's login item is separate from the VPN agent. A one-use, expiring
startup request permits an explicit connection without enabling VPN starts
at login; registering automatic login starts uses an idle request so it
does not authenticate immediately.

The host uses the launch Apple event's login/service reason to keep automatic
launches quiet. Explicit opening and the installer handoff reveal welcome
guidance once per acknowledged host build, then an independent compact controls window on later
opens. The controls window and menu popover share presentation and actions. The acknowledgement stores only a build number and grants no service,
SSO, or activation permission. Provider readiness is queried using
SystemExtensions properties, with no activation side effect. Disabled, old,
approval-pending, ambiguous, and newer provider records remain distinct from
a matching enabled provider. Setup activation stays behind a user action and
a disconnected-status check; replacement refuses a downgrade.

The provider counts successfully accepted inner IP bytes at the Swift
packet-flow boundary. A versioned provider message returns only a session
identifier, byte totals, and a monotonic sample time. The host samples once
per second while connected, rejects stale session responses, and derives rates
from consecutive samples. Rekeying retains the counters; a new provider
connection resets them. Missing samples clear only the current rates and break the trace, preserving
last reported totals for the same connection. Status notifications alone do
not discard counters. No packet contents or credentials enter UI state.

The menu host retains at most 120 rate samples over a rolling 60-second
window. Its native sparklines use independent direction scales and break
at missing samples or sampling gaps. A continuous clock ages history through
sleep; the provider's monotonic sample clock still determines rate deltas.
This history is never persisted. Host build 24 remains compatible with the
activated build 23 provider and its existing stats message.
