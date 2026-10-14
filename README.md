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
and [initial rollout gaps](docs/initial-rollout-gaps.md). The OFTC 1.0.1
build 18 candidate passed local package installation, guided CLI verification,
extension activation, and a short live IPv4 UDP connection to the approved
target. Its longer lifecycle and recovery gates remain open. See the
[build 18 package record](docs/evidence/v18-guided-setup-candidate.md) and
[live canary](docs/evidence/v18-packaged-live-canary.md).

The current checkout contains the standalone implementation. The former
Fortinet-backed controller and experiment source are preserved in Git commit
`b9ade25`; for example, `git show b9ade25:client/README.md` describes the
rollback controller. The installed build 18 app is independent of source-tree
changes.

## Source and build

| Path | Purpose |
| --- | --- |
| [app/](app/) | macOS host, packet-tunnel provider, Rust IKE/ESP engine, and offline bundle build. |
| [client/](client/) | `oftc` command-line interface for the standalone app. |
| [docs/operations.md](docs/operations.md) | Setup, connection, stop, and diagnostics. |
| [docs/pilot-validation.md](docs/pilot-validation.md) | Short install and test guide for colleagues. |
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
The source builds the OFTC 1.0.2 candidate with final bundle IDs and a small
public CLI: `setup`, `connect`, `disconnect`, `status`, and `uninstall`. See
[the man page](client/man/oftc.1) for the complete command syntax. Build 18 is
installed on this Mac. Clean-install validation on another Mac is a separate
release step.

## Scope

This project is for the machine's legitimate VPN operator and FortiGate admin.
OFTC uses the same SAML and IKE authentication; it changes client behavior, not
access control. Do not commit credentials, SAML tokens, PSKs, or raw captures.
