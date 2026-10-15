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

The OFTC 1.0.3 build 20 colleague packet is signed, notarized, and ready for
another pilot. Its app-led setup and uninstall passed an offline Mac mini test.
Fresh extension approval and live VPN traffic have not yet been tested on
1.0.3. See the [pilot guide](docs/pilot-validation.md) and
[build 20 record](docs/evidence/v20-packaged-pilot.md).

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
The source builds the OFTC 1.0.4 candidate with final bundle IDs and a small
public CLI: `setup`, `connect`, `disconnect`, `status`, and `uninstall`. See
[the man page](client/man/oftc.1) for the complete command syntax. Fresh
extension approval and live validation on the 1.0.4 package remain separate
release steps.

## Scope

This project is for the machine's legitimate VPN operator and FortiGate admin.
OFTC uses the same SAML and IKE authentication; it changes client behavior, not
access control. Do not commit credentials, SAML tokens, PSKs, or raw captures.
