# Packet-tunnel / Rust / Swift packaging spike

This joins the [Gate 0 packet-tunnel layout](../packet-tunnel/README.md) to a
small Rust dynamic library and the existing [Swift crypto bridge](../crypto/README.md).
The provider's `packetFlow.readPackets` passes a synthetic IPv4 ICMP echo
request to Rust through `oftc_packet_echo`; Rust returns the reply for
`packetFlow.writePackets`. At tunnel start it calls `oftc_crypto_probe`, which
crosses from Rust into the bundled Swift bridge and checks the public RFC 4231
HMAC-SHA256 vector. The packet path uses only TEST-NET addresses and a scoped
`integration.invalid` resolver. It contains no IKE, ESP, gateway connection,
credential handling, or general packet forwarding.

## Local reproduction

On macOS with Xcode Command Line Tools and `rustc`:

```sh
spikes/packet-tunnel-integration/build.sh
```

The script creates only ignored `build/` output. It compiles the existing
`../crypto/swift-bridge.swift` into
`IntegrationHost.app/Contents/Library/SystemExtensions/<app-id>.provider.systemextension/Contents/Frameworks/libcrypto_swift.dylib`,
and compiles `Core/packet.rs` into `liboftc_core.dylib` beside it. The Swift
provider links to `@rpath/liboftc_core.dylib` with
`@executable_path/../Frameworks`; Rust links to
`@rpath/libcrypto_swift.dylib` with `@loader_path`. A temporary Swift check
executable runs from the provider's `Contents/MacOS` directory, using those
same relative paths. It checks the Swift→Rust packet ABI, both reply checksums,
rejection of a different destination, and Rust→Swift crypto call, then is
removed before signing.

The host, provider, and two nested dylibs receive inside-out **ad hoc**
signatures. `codesign --verify --deep --strict` and `check_bundle.py` inspect
the finished bundle, exact host/provider ID relation, packet-tunnel provider
class, requested entitlements, Mach-O library install names, and rpaths. The
extension requests `packet-tunnel-provider-systemextension`; the host also
requests `system-extension.install`. These checks establish bundle structure
and local symbol loading, not authorization by Apple for extension execution.

## Result on this Mac (2026-10-07)

**Go for packaging the two dylibs with the provider; no-go for claiming a
running standalone VPN.** One clean local `build.sh` sample on macOS 27.0,
arm64, Xcode 27.0, and Rust 1.98.1 took **3.13 s** wall clock. The script
deletes its Swift module cache each run, so this is a full local rebuild, not
an incremental-build measurement. The finished app bundle occupies **524 KiB**
on disk (`du -sk`). File sizes after signing:

| Component | Size |
| --- | ---: |
| Host executable | 82,576 B |
| Provider executable | 69,152 B |
| Rust core dylib | 300,544 B |
| Swift crypto dylib | 59,664 B |

The harness passed and `codesign --verify --deep --strict` passed for the app
and both dylibs. `otool` confirmed provider→Rust and Rust→Swift relative load
paths. The bundle has no embedded provisioning profiles or signing material.

No extension was installed, activated, or loaded by macOS in this spike. The
host command actions were compiled but never invoked. No route or DNS setting
was applied, no packet entered a live `NEPacketTunnelFlow`, and no VPN/SSO/PSK
or gateway traffic occurred. Ad hoc signatures carry no Team ID and cannot
prove Developer ID provisioning, notarization, hardened runtime library
validation in the actual provider process, or target-Mac approval. This also
does not establish an authenticated CHILD_SA, ESP key/packet framing, route
and DNS behavior with assigned tunnel settings, or any UDP/TCP protected
round trip.

The next platform boundary is to give the app and extension distinct exact-ID
Developer ID provisioning profiles, sign the two nested libraries and then
the extension/app with one team, notarize, and run a narrowly scoped synthetic
packet test in the real provider process. Keep profiles and signing keys
outside the repo. After Gate 3 establishes a real authenticated CHILD_SA,
replace `oftc_packet_echo` with a session-oriented Rust ABI for outbound IP
packets and decrypted inbound packets, then perform Gate 4/5 traffic tests.

## Developer ID signing follow-up (2026-10-07)

The existing Gate 0 exact-ID profiles authorize
`com.chris.openforticlient.gate0` and
`com.chris.openforticlient.gate0.provider`; no separate integration-ID
profiles were found locally. Build with the Gate 0 ID, then pass those two
private profile paths and the installed Developer ID Application identity to
`sign-developer-id.sh`. The script verifies exact IDs, shared team, expiry,
all-device distribution, and the packet-tunnel and host-install entitlements.
It signs the Swift and Rust dylibs first, then the provider and app, all with
hardened runtime and secure timestamps. It checks the final Team ID and
Developer ID authority on all four code objects. Profiles remain only in
ignored `build/` output.

On this Mac the signed host, provider, and two dylibs passed those checks;
`codesign --verify --deep --strict` also passed outside the filesystem
sandbox. The original ad hoc harness passed before signing. The reused Gate 0
ID is for this isolated synthetic test and must not be used as a production
app identity.

The user authorized submitting this exact synthetic bundle to Apple. The
notary service **accepted** submission
`c9ab2254-7d3e-4e14-9555-f4ee93e5abc3`; stapling, ticket validation,
`codesign --verify --deep --strict`, and `spctl --assess` all passed. The
integration provider uses bundle version 3 to supersede the old Gate 0
version 2. `smoke.sh install` copied the notarized app into
`/Applications/OFTC development probe.app` and requested activation. After
System Settings approval, macOS reports version 3 as `activated enabled`.
Version 2 remains
`terminated waiting to uninstall on reboot`. All configured VPNs were
disconnected at the time of the activation request.

`smoke.sh test` requires a window with no live VPN testing. The first attempt
stopped at its active-VPN guard because Tailscale was connected; it made no
configuration or route change. Coordinate a Tailscale disconnect/restore
window before retrying. Apple's
[`NETunnelProviderManager` documentation](https://developer.apple.com/documentation/networkextension/netunnelprovidermanager)
says only one enterprise VPN configuration can be enabled at a time. This
host's test manager sets `isEnabled = true`, so enabling it while Tailscale is
connected could interrupt Tailscale before scoped route and DNS settings
apply. The script refuses an active VPN, captures the baseline route, installs
only its own VPN configuration, sends one ICMP echo through the synthetic
Rust packet path, and stops/removes that configuration with route and DNS
cleanup checks. Then run `smoke.sh cleanup` to deactivate the provider and
remove only the dedicated integration app. The signed run and cleanup outcome
are recorded below.

## Signed synthetic packet-flow result, 2026-10-07

After the operator authorized a temporary Tailscale service disable, the
installed, notarized version 3 provider completed `smoke.sh test`. The host
VPN configuration connected; `198.51.100.254/32` routed over `utun9` with
MTU 1280; `integration.invalid` resolved through the scoped test DNS server;
and one ICMP echo received its synthetic Rust-generated reply through live
`NEPacketTunnelFlow`. The script stopped and removed its own VPN configuration,
then verified the route returned to `en0` and the scoped resolver disappeared.
No gateway, SAML, or ESP was involved. Tailscale's network service was restored
to Enabled, its original Connect On Demand setting returned to true after an
explicit reconnect, and its backend remained stopped.

The later `smoke.sh cleanup` extension deactivation request did not complete
within two minutes. Its process was stopped. System Settings was used to turn
off only `OFTC Integration Provider`; `systemextensionsctl` reports version 3
as `activated disabled`. The dedicated app remains installed, with no test VPN
configuration or route/DNS setting. Remove or replace it in a later controlled
window; macOS may defer physical extension removal until reboot. The source
handoff update described below was only tested offline and was not the binary
used for this signed packet-flow result.

## Offline ephemeral start handoff (source update)

The host's `start` command now creates a fresh, 60-second, bounded
`SYNTHETIC` envelope and passes it via `startVPNTunnel(options:)`. The provider
validates it **before** its Rust/Swift crypto check or setting routes. Nil,
malformed, expired, future-dated, and non-synthetic data fail closed with a
generic error. `NETunnelProviderProtocol` still saves only the provider ID
and `integration.invalid` label; it does not store the envelope.

The existing ICMP packet echo, TEST-NET route, scoped DNS, and stop behavior
are unchanged after a valid envelope. `build.sh` includes the same codec source
in both binaries on a future build. Run the source-only check with:

```sh
zsh spikes/packet-tunnel-integration/check-ipc.sh
```

On this Mac it typechecked the actual host/provider sources against
NetworkExtension and passed 12 synthetic codec/validation checks. It did not
build or sign the app, activate the provider, modify VPN configuration, or
send packets. The already installed notarized synthetic provider is an older
binary and has **not** received this source update. A real macOS delivery test
would require rebuilding, signing, notarizing, and replacing it, followed by
an isolated packet-flow run. The separate
[`provider-ipc` note](../provider-ipc/README.md) describes the later SAML
token handoff and its process-lifecycle limits.
