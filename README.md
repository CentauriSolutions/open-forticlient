# Open FortiClient (OFTC)

OFTC is a macOS IKEv2/IPsec VPN client for a FortiGate that uses browser SAML
authentication. Its host app manages login and reconnection; a NetworkExtension
packet-tunnel provider owns IKE, ESP, routes, and DNS. Normal connections do not
run Fortinet daemons or read FortiClient files. The app can import an existing
FortiClient profile once during setup.

## Current state

The signed and notarized v15 development app passed an IPv4 UDP connection,
explicit IKE renewal, two automatic CHILD rekeys during an uninterrupted
55-minute run, and recovery from a 75-second Ethernet outage through Wi-Fi.
A macOS VPN-style stop stayed down. See the [live evidence](docs/evidence/v15-live-gate.md)
and [initial rollout gaps](docs/initial-rollout-gaps.md). The OFTC 1.0.2
build 19 package was built from pinned commit `6bebfa6`, signed, notarized,
installed, and activated on the development Mac. A short live IPv4 UDP
connection to the approved target and explicit stop passed. Its longer
lifecycle and recovery gates remain open on that packaged build. See the
[build 19 package record](docs/evidence/v19-packaged-pilot.md).

The current colleague packet is OFTC 1.0.6 host build 27, signed and notarized.
It keeps build 26's guided upgrades, menu graphics, controls, and connection
errors. Setup's approval button now opens the Network Extensions switch
directly. It has not been installed or live-tested during this build. The earlier 1.0.3 setup/uninstall test used
a Mac mini with an existing provider record. See the
[pilot guide](docs/pilot-validation.md),
[build 27 record](docs/evidence/v27-extension-approval-switch.md), and
[earlier build 20 record](docs/evidence/v20-packaged-pilot.md).

The current checkout contains the standalone implementation. The former
Fortinet-backed controller and experiment source are preserved in Git commit
`b9ade25`; for example, `git show b9ade25:client/README.md` describes the
rollback controller. An installed app is independent of source-tree changes.

## Source and build

| Path | Purpose |
| --- | --- |
| [app/](app/) | macOS host, packet-tunnel provider, Rust IKE/ESP engine, and offline bundle build. |
| [client/](client/) | `oftc` command-line interface for the standalone app. |
| [docs/operations.md](docs/operations.md) | Setup, connection, stop, and diagnostics. |
| [docs/pilot-validation.md](docs/pilot-validation.md) | Short install and test guide for colleagues. |
| [docs/managed-deployment.md](docs/managed-deployment.md) | Narrow MDM approval policy for managed Macs. |
| [scripts/collect-pilot-report.zsh](scripts/collect-pilot-report.zsh) | Local state and connectivity report for the pilot target. |
| [docs/architecture.md](docs/architecture.md) | Component boundaries and secret handling. |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Release work and validation gates. |
| [Issues/](Issues/) | In-repo work items. |

An unsigned development bundle and the CLI can be built without changing the
installed VPN:

```sh
OFTC_BUILD_DIR=/private/tmp/oftc-build-local zsh app/build.sh
cargo test --offline --manifest-path client/Cargo.toml
cargo build --offline --release --manifest-path client/Cargo.toml
```

`app/build.sh` runs offline checks and writes only to the selected build
directory. It does not sign, install, activate, authenticate, or connect.
The source builds the OFTC 1.0.6 candidate with final bundle IDs and a small
public CLI: `setup`, `connect`, `disconnect`, `status`, and `uninstall`. See
[the man page](client/man/oftc.1) for the complete command syntax. Fresh
extension approval and live validation on the 1.0.6 package remain separate
release steps.

Build 23 adds a resident menu bar popover with Connect/Disconnect, connection
duration, and VPN traffic rates and totals. Its refined tunnel icon greys
out when disconnected. UI launch and VPN connection at login are separate
settings. See [operations](docs/operations.md) and the
[candidate validation record](docs/evidence/v23-menu-bar-candidate.md).
Host build 24 adds 60-second receiving/sending sparklines and retains recent
history while the popover is closed. It uses the existing build 23 provider.
See the [sparkline record](docs/evidence/v24-traffic-sparklines.md).
Host build 25 adds visible welcome guidance after installation and upgrades,
checks the VPN component before connecting, and opens the menu controls on
intentional app opening. See the [guided-install record](docs/evidence/v25-guided-install-and-upgrades.md)
and updated [colleague guide](docs/pilot-validation.md).
Host build 26 opens an independent compact controls window on explicit app
opening, supplies concrete menu icon masks, preserves totals through sampling
gaps, and reports safe helper failures. Installer can reach its native
app-closing step after disconnection. See the
[build 26 record](docs/evidence/v26-menu-visibility-and-upgrade-recovery.md).
Host build 27 (OFTC 1.0.6) opens the Network Extensions sheet from setup's
approval button. Setup also explains that a listed extension may not be
enabled yet. The provider is unchanged at build 23. See the
[build 27 record](docs/evidence/v27-extension-approval-switch.md).

## Scope

This project is for the machine's legitimate VPN operator and FortiGate admin.
OFTC uses the same SAML and IKE authentication; it changes client behavior, not
access control. Do not commit credentials, SAML tokens, PSKs, or raw captures.
