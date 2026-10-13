# Gate 4 signed-provider join

`zsh spikes/signed-provider-join/build.sh` builds an **unsigned** macOS host and
NetworkExtension system extension in this directory's ignored `build/`. The
default app ID is `com.chris.openforticlient.gate0`, provider ID
`com.chris.openforticlient.gate0.provider`. The build script does not install,
activate, open a browser, or send a network packet. Version 4 was signed,
notarized, installed, and used for a no-token provider preflight. Version 5
adds reviewed nonfatal packet-drop handling. It was signed, notarized,
installed, activated, and used for the live Gate 4 packet round trip below.

The provider owns the UDP/4500 IKE/EAP/ESP `Session` through
`../provider-ffi/ffi.rs`. Swift sees only the opaque handle, authenticated
settings, and inner IP packets. The host gets a fresh SAML callback through
`../host-bootstrap/lib.rs` only for the explicit `start-live` command. It
hands a bounded `HBR1` gateway/UID/PSK/token buffer to the provider in a
60-second `startVPNTunnel(options:)` envelope with a random one-time ID. The
timestamp is sampled **after** browser SAML returns. The normal start path
reads the PSK from Keychain and places no secret in saved
`NETunnelProviderProtocol` preferences, logs, argv, or environment.
Swift/Foundation and NetworkExtension may hold transient copies despite the
best-effort buffer clearing in this spike.

## Join points

| Code | Role |
| --- | --- |
| `Host/CandidateHostBridge.swift` | Calls the existing Rust SAML bootstrap; timestamps only after acquisition. |
| `Host/main.swift` | Explicit host commands, saved manager checks, Keychain PSK, provider result polling. |
| `Host/migration.rs`, `Host/MigrationBridge.swift` | One-time profile-to-Keychain migration. Not called during tunnel start. |
| `Provider/BootstrapInput.swift` | Exact-length HBR1 validation, expiring envelope and in-process one-time ID check. |
| `Provider/preflight.rs` | No-token UDP preflight through authenticated responder AUTH and MSCHAPv2 challenge. |
| `Provider/FFISettings.swift` | Copies C ABI settings, routes and DNS into the strict `../provider-settings/SettingsMapper.swift`. |
| `Provider/PacketTunnelProvider.swift` | Worker-owned Rust connect, authenticated settings apply, packetFlow send/receive, bounded teardown. |

The provider completes a **diagnostic** `preflight` start without installing
addresses, routes, DNS, or packetFlow. The host asks the provider for a
human-readable result (`preflight_passed responder_auth_and_eap_challenge` or
`preflight_failed stage=N`) and then stops the diagnostic connection. Whether
NetworkExtension will report a provider with no tunnel settings as connected
was tested on the installed signed version 4 provider. A timeout in a later
run would not imply that IKE failed; inspect provider logs before spending a
SAML token.

Outbound packetFlow is processed one callback batch at a time, in 64-packet
worker slices; batch size alone never drops the tunnel. Inbound ESP is copied
to packetFlow only after Rust authenticates and decrypts it. A failed connect,
settings apply, packet send/receive, peer DELETE, or stop cancels the session,
performs bounded Rust teardown, removes tunnel settings, and releases the
opaque handle. The exact plain settings come from the authenticated CHILD_SA.
Non-CIDR route ranges are rejected rather than widened. On Demand must stay
off: an automatic restart has no fresh SAML token in `options`.

## Keychain preparation for a later live run

The host stores a PSK as a generic-password item with service
`<app bundle ID>.psk` and account equal to the exact gateway hostname. The
one-time `provision-psk <gateway>` command reads it from `/dev/tty` with echo
disabled, keeping it out of shell arguments and logs.
`save-profile <gateway> <saml-port> [--tcp]` saves nonsecret gateway, port, and
transport preference in
`~/Library/Application Support/<app bundle ID>/profile.json` with mode `0600`.
The default is UDP 4500 with bounded TCP 4443 fallback before EAP. The saved
profile does not contain a PSK, token, or SAML session. `show-profile` displays
its nonsecret fields. `start-profile` and `supervise-profile` use this profile
and the matching OFTC Keychain item; `--ipv6-outer <CLAT-IPv4>` supplies the
current network's IPv4 IDi when using native IPv6 outer transport. The older
`start-live` and `supervise-live` arguments remain available for controlled
tests.

If the operator does not know the plaintext,
`import-profile <FortiClient-profile>` explicitly reads the local FortiClient profile once,
copies its gateway and SAML port into the OFTC profile, and saves its PSK in
the OFTC Keychain without printing it. It validates the imported fields and
rejects an unavailable or non-PSK `AuthInfo`. It deliberately selects UDP as
the primary transport even if the FortiClient profile preferred TCP. The older
`migrate-psk <FortiClient-profile> <gateway>` calls
the existing local profile loader once and saves its plaintext result directly
to Keychain without printing it. It checks that the loaded profile's gateway
matches the requested hostname and rejects an encrypted `Enc ...` fallback
or a value equal to the saved username. The migration loader may use a local
override (`OFTC_PSK`, `FORTIGATE_PSK`, `.env`, `~/.config/oftc/psk`) before a
decryptable FortiClient `AuthInfo`. **Normal `preflight`, `start-live`,
`start-profile`, and supervised recovery use OFTC configuration and Keychain
only**; the migration commands are temporary interoperability paths
and can become a separate setup utility for a fully standalone release.

## Offline evidence and scope

The current unsigned app is about **3.7 MB** (including the one-time migration
code statically linked into the host). A full spike build with tests
took about **11 seconds** on this Mac, distinct from the existing roughly
0.5-second warm `client/` edit loop. The build passed 23 no-network preflight
Rust tests, five migration tests, synthetic HBR1/replay/late-timestamp checks,
and Swift/C ABI compilation. Independently, the existing provider FFI passed
seven offline tests, provider settings passed 15 synthetic cases, and host
bootstrap passed 16 Rust tests plus its synthetic Rust-to-Swift envelope check.
No signed provider or live packetFlow behavior is claimed by these checks.

The version 4 bundle was then signed locally with the existing exact-ID
Developer ID host/provider provisioning profiles. The host, extension, and
four dylibs share one team and secure timestamps; an unsandboxed
`codesign --verify --deep --strict` passed. The signed archive is in ignored
`build/IntegrationHost-v4-notary.zip` (SHA-256
`4174f0085a1478c9ab881045813680f12d262abcd59aef943a0dbde2e744d43a`).
Apple accepted notarization submission
`761d0b69-d314-4ae0-948c-b6df01f811ce`; stapling, ticket validation,
deep signature verification, and Gatekeeper assessment passed. Version 4 was
installed at `/Applications/OFTC development probe.app`, replaced version 3,
and its provider appeared as `activated enabled` in `systemextensionsctl`.
The exact-gateway PSK was migrated to the OFTC Keychain. With Tailscale's
network service temporarily disabled, the installed host's no-token
`preflight` returned exit 0 and the exact stage
`preflight_passed responder_auth_and_eap_challenge` on IPv4 Wi-Fi. The OFTC
VPN disconnected afterward; route `10.20.0.1` stayed on `en0`, and only `en0`
DNS remained. The OFTC VPN configuration was removed. Tailscale was restored
as `Enabled`, `Connected`, and `OnDemandEnabled : TRUE`. This proves the
installed provider can open its UDP socket, use the native crypto bridge, and
verify responder AUTH/EAP challenge without a token. It does **not** prove
SAML delivery, authenticated CHILD_SA, tunnel settings, ESP, or `packetFlow`
with this provider.

The reviewed version 5 rebuild and Session/FFI checks passed. Its prepared
notarization archive has SHA-256
`4cbbb3631af91f3ce574600a9cbf2e15184aaf8ece5a80329bb62b4e4c834995`.
After explicit user authorization, Apple accepted version 5 notarization
submission `4f2dd7be-333b-4fba-b735-0a79c3452fa4`; stapler validation,
deep signature verification, and Gatekeeper assessment passed. Version 5
replaced the installed version 4 app, and its extension appeared as
`activated enabled`. Older extension versions are queued for removal on
reboot.

## Live Gate 4 result

On IPv4 Wi-Fi, the one-shot `gate4-smoke.sh --execute ...
--leave-tailscale-off` run passed the **installed version 5** no-token provider
preflight before acquiring a fresh SAML token. The one approved token
established the UDP 4500 IKE/EAP/CHILD_SA tunnel. macOS assigned `10.77.0.12`
and routed the approved target `10.20.0.1` through `utun10`; the gateway
provided no DNS servers. One ICMP echo entered `packetFlow`, was protected by
the provider's ESP session, and received one authenticated reply in 25.662 ms
(one transmitted, one received, 0% loss).

The script exited 0 after stopping and removing the OFTC VPN configuration.
An independent post-run check found the target route back on `en0` via
`192.168.1.1` and only the `en0` DNS resolver. Tailscale was left Disabled and
Disconnected, as the user requested; **do not start or re-enable it as part of
this test cleanup**. This proves a live UDP packet-tunnel vertical slice, not
the fallback and lifecycle behavior needed for a replacement client.

The version 5 joined `Session` remains UDP-first with an IPv4 socket. A current
IPv6-only hotspot can expose IPv4 reachability through CLAT: a separate
no-token UDP probe reached verified responder AUTH and the EAP challenge there.
That makes this IPv4 provider preflight plausible on the hotspot, but it does
not prove a native IPv6 outer socket.
For version 5, TCP/4443 fallback, native IPv6 outer transport, long-lived
rekey/DPD policy, and a production credential store/UI remain subsequent work.

## Version 6 Gate 5 result

Version 6 joins the already proven direct TCP/IPv6 transport code to the
signed provider session. UDP 4500 remains the default; a bounded TCP 4443
fallback is allowed only when UDP SA_INIT fails before EAP uses the token.
An explicit `--tcp` mode is available for the Gate 5 test. Native IPv6 outer
UDP/TCP requires an explicit caller-observed CLAT IPv4 IDi. The provider FFI
now carries the resolved outer endpoint with its address family, and the
settings mapper handles an IPv6 outer address without adding an IPv4 route
exclusion. The start envelope carries only the transport choice and CLAT IDi
alongside its one-use secret payload. Expired replay IDs are evicted rather
than locking out future starts, and decoder-owned secret copies are wiped.

The v6 host and provider passed the unsigned bundle build, 76 session tests,
10 FFI tests, bootstrap checks, and Gate 5 script mock cleanup checks. The
exact Developer ID signed archive has SHA-256
`fa5b2cf8a6c19750b107c802e94741c3ff870bddff8e0ce0d680013c84182259`.
Apple accepted notarization submission
`a9613b06-e262-416c-b885-280beffed19d`; the local app is stapled and
passed ticket, deep signature, and Gatekeeper checks. Version 6 replaced the
installed v5 app and its extension is activated. A verified v5 rollback copy
is saved outside the repository. One separately approved fresh SAML token
connected over explicit TCP 4443 on IPv4 Wi-Fi. macOS assigned `10.77.0.13`,
routed `10.20.0.1` through `utun10`, and one protected packetFlow ICMP echo
received one authenticated reply in 92.525 ms. The one-attempt script stopped
and removed OFTC; an independent check found configuration absent, route
restored to `en0` via `192.168.1.1`, only `en0` DNS, and Tailscale
Disabled/Disconnected.

On the IPv6-only phone hotspot, `en0` had native IPv6 and CLAT `192.0.0.2`.
Installed-provider no-token UDP 4500 and TCP 4443 preflights each verified
responder AUTH and reached the EAP challenge. One separately approved fresh
SAML token per transport then completed IKE/EAP/CHILD_SA over a native IPv6
outer socket. The UDP run delivered one protected `packetFlow` ICMP echo and
one authenticated reply from `10.20.0.1` in 276.531 ms; the TCP run delivered
the same one-packet round trip on the RFC 9329 IKE/ESP stream in 111.811 ms.
Both runs assigned `10.77.0.13` and routed `10.20.0.1` through `utun10`.
Each one-attempt script exited 0 after stopping and removing OFTC. Independent
post-run checks found OFTC configuration absent, route back on `en0` via CLAT
gateway `192.0.0.1`, only `en0` DNS, and Tailscale still Disabled and
Disconnected per the user's instruction.

The [one-attempt Gate 5 script](gate5-smoke.sh) assumes Tailscale is already
Disabled and Disconnected and never changes it. It tests one selected
transport, sends one echo, then removes the OFTC configuration and verifies
route and DNS cleanup. The live TCP runs explicitly selected TCP; automatic
UDP-to-TCP fallback on a network that blocks UDP was not exercised. The
separately implemented liveness grace policy and CHILD_SA rekey are not
included in the signed v6 archive.

## Decision and next work

The signed provider passed the standalone feasibility spike on IPv4 and native
IPv6, with UDP and explicit TCP packet round trips. Proceed with the standalone
implementation. Before replacing the working client, prove session liveness,
IKE/CHILD_SA rekey, automatic fallback, screen lock, sleep/wake, roaming,
bounded retries, production profile ownership, and cleanup in sustained use.

## Version 7 local rekey gate

Version 7 adds a scheduled liveness tick, outer NAT keepalives, a bounded
foreground reconnect supervisor, and an explicit `rekey-once` provider message.
The frozen signed archive SHA-256 is
`ea601e2512b309f0b838ad3a69f908dbe4ee773f67993c810cc6ac32cc1b7c34`.
Apple accepted notarization submission
`5fa00180-4c2c-4a93-9b8e-e7f7333aea9c`; stapling, deep signature, and
Gatekeeper validation passed. The installed v6 app was verified and saved for
rollback; v7 is installed and its extension is activated. This archive predates
the later OFTC profile store and automatic rekey timing changes in source.

The one approved IPv4 UDP Gate 6 run used one fresh SAML token. The provider
connected, macOS assigned `10.77.0.12`, and the target route used `utun10`.
The one local CHILD_SA rekey request failed, so the script sent no post-rekey
ICMP echo and made no retry. It stopped and removed OFTC. Independent checks
found the configuration absent, the target route back on `en0` via
`172.16.8.1`, only `en0` DNS, and Tailscale still Disabled/Disconnected.
The failure stage was not retained by the v7 host, so the next build must
report a nonsecret rekey outcome before another token-bearing attempt.

## Version 8 rekey diagnostic candidate

Version 8 preserves UDP 4500 as primary and bounded TCP 4443 fallback. It
adds a host-visible, fixed nonsecret rekey result: stages 120–132 distinguish
local offer, unanswered exchange, authenticated responder Notify classes,
malformed/suite/selector response, key derivation, installation, and old-SA
DELETE. The provider replies with the stage before closing a failed tunnel.
The source also includes provisional CHILD and IKE hard reconnect deadlines;
the gateway lifetimes remain unmeasured.

The version 8 host/provider was built from the current source in
`/private/tmp/oftc-v8-rekey-build/IntegrationHost.app`, signed with the same
exact-ID Developer ID profiles as v7, and notarized by Apple under submission
`7e4666bc-2a5a-4296-92d8-e7a6012f9077`. Its signed upload archive SHA-256
is `908933d1ee0750c95cdb5bcd6e90ce625d68b9d181e3310e92dcdb8318922d9e`.
The staple, deep signature, and Gatekeeper checks passed. The host, provider,
and engine SHA-256 values are pinned in `gate6-v8-rekey-smoke.sh` and
`gate6-v8-live.sh`. The installed v7 host/provider/engine still matched their
recorded hashes after the v8 build.

| Stage | Rekey result |
| --- | --- |
| 120–121 | Local offer failed, or no rekey response arrived. |
| 122–126 | Responder Notify: `NO_PROPOSAL_CHOSEN`, `INVALID_KE_PAYLOAD`, `NO_ADDITIONAL_SAS`, `TS_UNACCEPTABLE`, or another type. |
| 127–129 | Response shape, selected ESP suite, or traffic selectors failed policy validation. |
| 130–132 | PFS key derivation, new ESP installation, or old-SA DELETE failed. |

Other provider codes retain their existing connection/control meaning. The
gate records only the integer stage and never logs the decrypted IKE response.

Offline checks passed: 21 CHILD rekey tests; 93 provider session tests with
six sandboxed loopback cases skipped; 12 provider FFI tests; the full unsigned
host/provider build checks; and syntax, argument, and mocked cleanup/rollback
checks for both v8 gate scripts. Those offline checks do not exercise a live
FortiGate rekey.

`zsh spikes/signed-provider-join/gate6-v8-live.sh --plan` describes the one-shot
install and IPv4 UDP rekey gate. Its `--execute <IKESamlPort>` path requires a
separate explicit authorization for installing v8 and consuming one fresh SAML
token. It verifies the pinned installed v7 and notarized v8 bundles, preserves
a v7 rollback copy, activates v8, and calls `gate6-v8-rekey-smoke.sh` for one
SAML start, one local CHILD rekey, and one post-rekey ICMP echo. The inner gate
stops/removes OFTC and compares route/DNS to baseline even on failure; the
outer gate restores the v7 app and verifies extension reactivation if the
attempt fails. If macOS does not re-enable v7, the script reports that state
for inspection. Neither gate changes Tailscale.
The one approved IPv4 UDP v8 gate used one fresh SAML token. The authenticated
tunnel assigned `10.77.0.12` and routed `10.20.0.1` over `utun10`. Its one
local CHILD_SA rekey received authenticated stage **122,
`NO_PROPOSAL_CHOSEN`**. The gate sent no post-rekey ICMP echo and made no
retry. The wrapper restored the exact signed v7 host/provider/engine hashes;
v7 is activated and enabled. Independent checks found OFTC configuration
absent, the target route back through `en0` via `172.16.8.1`, only `en0` DNS,
and Tailscale Disabled/Disconnected. The signed v8 candidate and v7 rollback
copy remain under the pinned `/private/tmp/oftc-v8-rekey-build/` path.

The gateway rejected the rekey SA proposal before sending a new ESP SA. The
request offered AES-256-CBC/HMAC-SHA1-96, ECP-384/group-20 PFS, and no ESN.
The accepted initial CHILD_SA used the same encryption/integrity/ESN offer,
but IKE_AUTH cannot perform a fresh DH exchange. The operator's read-only
phase-2 configuration for `vpn-ikev2-p2` confirms `aes256-sha1` is available,
`pfs enable`, and **`dhgrp 5 14`**. The group-20-only rekey offer therefore
has no PFS group in common with this gateway. This is the identified reason
for stage 122; no key material or raw IKE response was retained.

The operator chose to leave the gateway unchanged. Client v9 offers
MODP-2048/group-14 PFS for local and peer-initiated rekey, while IKE_SA_INIT
continues to use its existing P-384/group-20 exchange. The fixed-width
group-14 implementation uses SecRandomCopyBytes and constant-time Montgomery
exponentiation; independent Python modular-exponentiation vectors verify its
public and shared values. The 21 rekey tests, 93 provider session tests, 12
FFI tests, full bundle build, and mocked gate cleanup/rollback checks passed
offline. Six loopback tests remain skipped in the sandbox.

The version 9 host/provider at
`/private/tmp/oftc-v9-group14-build/IntegrationHost.app` passed Developer ID
signing, Apple notarization (submission
`744b51bc-3a8f-42bf-8d4b-b9c311e21833`), stapling, deep signature, and
Gatekeeper assessment. Its signed upload archive SHA-256 is
`beb5287f842f709912239c210e03b06a264f9b26757c28ab7e50418d573ec994`.
The host/provider/engine hashes are pinned in `gate6-v9-live.sh` and
`gate6-v9-rekey-smoke.sh`. The v9 gate requires separate approval for each
fresh-token run. It sends one encrypted ICMP echo to `10.20.0.1` only if rekey
succeeds, then removes OFTC and checks route/DNS; a failed gate restores v7.
Tailscale must stay Disabled/Disconnected and is read-only to both scripts.

The one approved v9 IPv4 UDP 4500 gate used one fresh SAML token. It assigned
`10.77.0.12`, routed `10.20.0.1` over `utun10`, completed one local CHILD_SA
rekey, and received one encrypted ICMP reply from `10.20.0.1` (one sent, one
received). The gate stopped and removed OFTC configuration and compared the
target route and DNS with the pre-connect baseline. Independent post-gate
checks found version 9 host/provider/engine hashes matching the pinned
candidate, the v9 extension activated/enabled, OFTC configuration absent,
the target route through `en0` via `172.16.8.1`, DNS only on `en0`, Tailscale
Disabled/Disconnected, and the exact v7 rollback copy preserved at
`/private/tmp/oftc-v9-group14-build/IntegrationHost-v7-rollback.app`.
V9 remains installed but disconnected. Sustained, lock/wake, roaming,
peer-initiated rekey, and IKE_SA rekey acceptance remain open.

## Version 11 sustained IPv4 candidate

V11 includes the OFTC-owned profile/Keychain and per-user LaunchAgent paths,
nonsecret successful local/peer CHILD_SA rekey counts, and bounded recovery
for established socket loss and authenticated peer DELETE. Provider teardown
uses a fresh cancellation scope to send authenticated CHILD and IKE DELETEs;
the TCP reader also accepts the IKE DELETE reply after the CHILD ESP engine is
retired. V10 was signed and notarized but superseded before installation by
these review fixes. V11 was installed and used for the live IPv4 gate below.

The v11 signed archive is
`/private/tmp/oftc-v11-sustained-build/IntegrationHost-v11-notary.zip` (SHA-256
`c1285f64d613cd2ed2dedb035dc4c399d06af051eaca1a769f4c597aa363a071`).
Apple accepted notarization submission
`54874f09-7ef7-4a31-b1e4-e08fba98958b`; stapling, deep signature, and
Gatekeeper assessment passed. The host, provider, and engine executable hashes
are pinned in [`gate7-v11-sustained.sh`](gate7-v11-sustained.sh). Offline checks
passed: 24 CLI tests, 21 CHILD rekey tests, 93 provider session tests (six
loopback tests skipped in the sandbox), 12 FFI tests, full bundle build, and
the focused UDP and TCP loopback teardown tests outside the sandbox. The gate
script passed syntax, argument, and mocked rollback checks.

`zsh spikes/signed-provider-join/gate7-v11-sustained.sh --plan` is read-only.
Its `--start` path requires a separate explicit authorization to install v11,
import the exact local profile or use the existing OFTC Keychain PSK fallback,
add a VPN configuration, start the LaunchAgent, and acquire SAML. It preserves
the exact signed v9 app and never changes Tailscale. `--finish` stops and
uninstalls the agent, removes the OFTC VPN configuration, and checks route/DNS
cleanup; `--rollback` also restores and reactivates v9.

The approved `--start` run imported the selected profile and PSK, activated
v11, and connected through `utun10` with assigned IPv4 `10.77.0.12`. The
per-user LaunchAgent needed a second `start-agent` call because launchd
deferred its first spawn. After a screen lock longer than 30 seconds, OFTC
remained connected and `10.20.0.1` answered a protected ICMP probe. The
session stayed connected for 23 minutes 17 seconds. At the end, telemetry
reported one successful automatic local CHILD_SA rekey and zero peer rekeys;
protected ICMP succeeded both immediately after the rekey and at the gate end.
The first `--finish` removed the VPN configuration but found launchd's unload
still in progress and left the agent plist. Repeating `uninstall-agent` and
`--finish` removed it and passed exact baseline route/DNS comparison.
Independent checks found the OFTC VPN configuration and agent absent, route to
`10.20.0.1` back through `en0` via `172.16.8.1`, DNS digest equal to baseline,
Tailscale Disabled/Disconnected, and version 11 installed with its extension
activated. The source CLI now kickstarts after bootstrap and waits briefly
for launchd unload before removing its plist; 24 client tests and a release
build pass. A later live start and uninstall verified both timing fixes.

The separate [Gate 8 recovery run](gate8-v11-recovery.md) found that v11 did
not automatically reconnect after either a 75-second Wi-Fi outage or its
scheduled 55-minute IKE disconnect. In the uninterrupted run, protected
traffic passed after local CHILD rekeys near 22 and 44 minutes. The supervisor
remained loaded after each disconnect, but neither run recorded a second SSO
browser-open attempt. An existing provider session could have auto-authenticated
without a prompt had OFTC opened the tab. Both runs cleaned up OFTC's agent and
VPN configuration and restored route/DNS baseline; v11 remains installed and
disconnected. Sleep/wake, forced peer loss, roaming, TCP stalls, and
IPv6-only/NAT64 paths still need live observation.

V12 was a recovery candidate. It checks a fresh NetworkExtension
manager when a retained status may be stale, gives the disconnect-error lookup
a deadline, and retries only gateway bootstrap failures known to occur before
opening the SSO browser. The full unsigned bundle build, focused host-bootstrap
and supervisor checks, and Developer ID signing passed. The frozen signed
archive is `/private/tmp/oftc-v12-recovery-build/IntegrationHost-v12-notary.zip`
(SHA-256 `1f48ffdcb2f62573b851af94dc05720031cd4e9d044500467af90886d3af602b`).
Apple accepted notarization submission
`a4442aab-fa98-4be8-8721-7db46f081639`; stapling, ticket validation, deep
signature verification, and Gatekeeper assessment passed. The approved
[Gate 9 run](gate9-v12-recovery.md) installed v12 and validated two separate
IPv4 connections. The 75-second Wi-Fi outage left the tunnel disconnected for
more than five minutes after restoration, without a second SSO browser-open
event. The uninterrupted lifetime run passed protected ICMP after two local
CHILD rekeys, then disconnected at the 55-minute IKE limit and remained down
for more than five minutes, again without a recovery browser-open event.
Both runs removed OFTC's agent and VPN configuration and restored baseline
route/DNS; Wi-Fi was on and Tailscale remained Disabled/Disconnected.

V13 was a Developer ID signed and Apple notarized diagnostic
candidate. Its supervisor records fixed nonsecret heartbeat, NetworkExtension
status, refresh, and disconnect-error transitions; a stalled preference
refresh gets a deadline. It conservatively leaves a disconnect with no error
down, since a user stop through the macOS VPN UI may also yield no error. The
CLI's explicit `standalone disconnect` now disables installed agent autostart.
Offline build, focused checks, and 24 CLI tests passed. The active legacy
VPN prevented its planned live diagnostic.

V14 passed explicit IKE renewal, CHILD rekey on the renewed IKE SA, and
protected traffic after both. Its supervisor remained running but did not
recover from a 75-second USB Ethernet outage. A process sample identified a
status-notification deadlock. V15 fixes that observer path; its
[live recovery gate](gate13-v15-current.md) passed automatic reconnection
through Wi-Fi during the approved Ethernet outage. Its separate uninterrupted
55-minute lifecycle run passed two automatic CHILD rekeys and protected
traffic beyond the old cutoff. A separate macOS VPN-style stop stayed down
without another SSO attempt. Its test cleanup restored route/DNS, and V15 was
then reconnected with protected traffic and its supervisor active. See the
[initial rollout gaps](../../docs/initial-rollout-gaps.md) before production
use.
