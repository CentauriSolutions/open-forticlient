# Architecture

The `oftc` CLI in [`client/`](../client/) is a client of the resident host's local
socket ([ui-edge.md](ui-edge.md)): `oftc status`, `profiles` and `--version` ask the
host service, and fall back to running the signed host executable directly when none is
serving. Every other command still invokes the host executable. The host owns the
nonsecret profile, Keychain PSK, browser SAML, macOS VPN configuration, and reconnect
supervisor, all in Rust. The NetworkExtension provider owns the outer UDP/TCP
transport, IKEv2/EAP, ESP, packet flow, routes, and DNS. It is the Rust `OFTCTunnel`
system extension executable (`app/core/tunnel`, with `app/core/provider` and
`app/core/apple`) with the engine linked statically: the shipped bundle has no C ABI and
no Swift in the tunnel path (the unused `app/core/provider-ffi` crate is still in the
workspace until #49). The Rust host and
provider reach NetworkExtension, SystemExtensions and ServiceManagement through
`objc2` bindings in `app/core/apple`. Swift remains only for the UI edge.

```text
oftc CLI ⇄ host (Rust, in OFTCAgent) → NetworkExtension provider (Rust) → IKE/ESP engine
   │             ↘ browser SAML          ↘ packetFlow / system tunnel
   └─ socket, or the host executable directly
Swift menu bar UI ⇄ host over the same socket
```

The one-time `oftc setup --import` path reads a local FortiClient profile.
Normal `connect` and supervised recovery use the OFTC
profile and Keychain item. SAML tokens are passed to the provider for a single
start and are not saved in VPN preferences, files, command arguments, or logs.

| Source | Responsibility |
| --- | --- |
| [`app/Host/`](../app/Host/) | The UI edge: the menu bar app, welcome and onboarding windows, the certificate prompt, launcher alias and update check. `main.swift` hands every other verb to Rust. |
| [`app/core/host/`](../app/core/host/), [`app/core/hostlib/`](../app/core/hostlib/) | Every host verb ([list](host-verbs.md)): profiles, registry, PSK Keychain, VPN entries, gateway trust and the reconnect supervisor. `hostlib` is the static library `OFTCAgent` links (no dylib); its `oftc_host_main` runs them. |
| [`app/Provider/`](../app/Provider/) | The provider's `Info.plist` and entitlements. Its Swift sources are no longer built (`app/build.sh` does not compile them) and are slated for deletion in #49. |
| [`app/core/`](../app/core/) | IKEv2, EAP-MSCHAPv2, ESP and transport (`engine/`, `crypto/`), the provider's state machine (`provider/`), the NetworkExtension and system bindings (`apple/`), and the `OFTCTunnel` executable (`tunnel/`). |
| [`app/core/host-bootstrap/`](../app/core/host-bootstrap/) | Host SAML, TLS pins, and device identity, a library of `oftc-host`. |
| [`app/core/migration/`](../app/core/migration/) | FortiClient profile decryption for explicit one-time import. |
| [`app/support/`](../app/support/) | Strict tunnel settings mapping. |

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
key. Route and DNS policy across profiles is not yet enforced; see #40.

The host can reconnect after a recoverable provider drop using fresh SSO when
needed (`app/core/host/src/supervisor.rs`; rules in [host-verbs.md](host-verbs.md)). An explicit user stop stays down until the next connect and does not
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
This history is never persisted. The provider message that carries the counters
(`oftc.traffic.v1`) is unchanged, so a host and provider from different builds of the
same message version keep working.
