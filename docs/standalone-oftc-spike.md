# Spike: a standalone `oftc` VPN engine

## Decision to test

Build one packaged macOS client with no runtime dependency on Fortinet's
`fctctld`, `iked`, `fct_tunnel_ctl`, or `PrivilegedHelper`, and no strongSwan
runtime. Keep `oftc`'s existing SAML flow and supervisor. Implement the required
IKEv2, EAP, and ESP behavior in an `oftc`-owned core using reviewed crypto
libraries. For direct Developer ID distribution, package a macOS packet-tunnel
**system extension** with the app; **standalone does not imply an unprivileged
single executable**. The operator now has an Apple developer account, so test
the actual signing/provisioning path first.

The spike should prove that this *particular* gateway, account, transport, and
Mac can support a vertical slice. Limit scope to one profile, the observed
algorithms, one CHILD_SA, one split subnet, and one internal traffic probe.
Do not build a general IKEv2 implementation or user interface first.

## Results so far (2026-10-07)

- **Gate 0 passed locally.** A Developer ID signed and notarized packet-tunnel
  system extension installed and activated on this Mac. It applied a single
  test route, scoped DNS, and MTU 1280, then received and answered one ICMP
  packet through `packetFlow`. The VPN configuration, route, DNS, and app were
  removed. macOS reports the deactivated extension as `terminated waiting to
  uninstall on reboot`; physical removal needs a post-reboot check. This was
  an IPv4 local loopback probe, with no gateway, IKE, or SSO involved.
  [Evidence and reproduction](../spikes/packet-tunnel/README.md).
- **The primitive/build-cost subgate passed.** An isolated Swift bridge using
  CryptoKit, CommonCrypto, and Security passes public P-384 group-20, AES-CBC,
  HMAC-SHA1/SHA256, and random-byte tests through a Rust caller. A local warm
  rebuild of the bridge took 0.42 s; its dylib was 88,376 bytes. This does not
  validate the IKE/ESP protocol layer, bridge packaging/signing, or gateway
  acceptance. Security's direct ephemeral EC key generation failed here, so
  the complete passing route uses CryptoKit for P-384.
  [Evidence and reproduction](../spikes/crypto/README.md).
- **Gate 2 passed on this IPv4 network.** The gateway answered no-SSO
  IKE_SA_INIT over both UDP 4500 and TCP 4443, selecting
  AES-256-CBC/PRF-SHA256/integrity-SHA256/ECP-384. Both responder P-384 points
  were accepted by CryptoKit. [Packet and build evidence](../spikes/ike-sa-init/README.md).
- **Gate 3 reached EAP method selection.** A minimal encrypted IKE_AUTH
  request received EAP Request/Identity over both transports. The responder's
  PSK AUTH verified against the locally configured PSK and the captured
  SA_INIT response. After one authorized EAP Identity reply with the Mac UID on
  each transport, both selected **EAP-MSCHAPv2 (type 26)**. An additional UDP
  probe confirmed opcode 1 (Challenge) and a 16-byte challenge size. No SAML
  token, MSCHAPv2 response, or CHILD_SA was attempted.
  [Evidence and limits](../spikes/ike-auth/README.md).
- **Gate 3 passed on UDP.** The EAP-MSCHAPv2 method uses CommonCrypto and
  passes public vectors; the CHILD_SA parser and `prf+(SK_d, Ni|Nr)` handoff
  feed the tested ESP/transport engine. The joined runner passes 63 offline
  tests. After both no-SSO preflights reached the MSCHAPv2 challenge, one
  authorized SAML token completed inner and outer EAP, final responder AUTH,
  and a validated CHILD_SA on UDP. One split route and no DNS server were
  returned. No packet tunnel setting or ESP traffic was attempted.
  [Gate 3 evidence](../spikes/ike-gate3/README.md).
- **One direct UDP ESP round trip passed.** A second explicitly authorized
  fresh token established another CHILD_SA. The runner sent one encrypted ICMP
  echo to the approved internal firewall at `10.20.0.1` and authenticated the
  matching reply on UDP 4500. This proves the gateway data plane with the
  standalone engine; the macOS packet tunnel, route/DNS setup, and teardown
  are not joined yet. [Probe evidence](../spikes/ike-gate3/README.md).
- **One direct TCP ESP round trip passed.** A third explicitly authorized
  fresh token completed IKE/EAP/CHILD_SA over TCP 4443, then an RFC 9329 ESP
  record carried one ICMP echo to `10.20.0.1` and returned an authenticated
  matching reply on the same stream. This validates TCP fallback on the
  current IPv4 network, outside the packet tunnel.
  [TCP probe evidence](../spikes/tcp-live-probe/README.md).
- **One direct IPv6 outer UDP ESP round trip passed.** On the IPv6-only phone
  hotspot with CLAT `192.0.0.2`, one separately authorized fresh token
  completed EAP and CHILD_SA over an IPv6 outer UDP 4500 socket. The runner
  sent one protected ICMP echo to `10.20.0.1` and authenticated the matching
  reply. The gateway returned one split route and no DNS servers. No route,
  DNS setting, or packet tunnel was installed.
  [IPv6 ESP probe evidence](../spikes/ipv6-esp-live/README.md).
- **Gate 4 prerequisites passed offline.** An ESP codec for the offered
  AES-256-CBC/HMAC-SHA1-96 profile passes six tests, including an independent
  packet vector, integrity-before-decryption, replay, and UDP/4500
  classification. The joined runner later used live CHILD_SA keys for the
  direct UDP, TCP, and IPv6 outer UDP proofs above.
  [ESP evidence](../spikes/esp/README.md).
- **The packet-flow ABI passes offline.** A Swift packet-flow-shaped harness
  passes IP into Rust ESP, authenticates it at a synthetic peer, and returns
  decrypted IP to Swift. It checks short buffers and replay before a live
  signed-provider rebuild. [Bridge evidence](../spikes/packet-flow-bridge/README.md).
- **Provider start options pass offline API checks.** A minimal host/provider
  NetworkExtension signature check and eight synthetic envelope checks pass.
  The provider owns the IKE socket and ESP state. The signed version 5 provider
  received one fresh token through short-lived `startTunnel` options in the
  successful Gate 4 run below. [IPC evidence](../spikes/provider-ipc/README.md).
- **IPv6 outer no-token preflight passed on the phone hotspot.** The isolated
  runner passes 22 offline tests and selected a system-resolved IPv6 gateway
  endpoint on the live IPv6-only/CLAT path. UDP 4500 and TCP 4443 each
  completed SA_INIT, verified responder PSK AUTH with CLAT IPv4 IDi, and
  reached EAP Request/Identity. No token, ESP, or tunnel setting was used.
  [IPv6 evidence](../spikes/ipv6-outer/README.md).
- **TCP ESP framing passed offline.** A socket-free RFC 9329 parser/writer and
  bounded UDP fallback sketch pass eight synthetic tests. The gateway's
  actual ESP stream was subsequently exercised by the direct TCP proof above.
  [Framing evidence](../spikes/tcp-esp/README.md).
- **The combined bundle is signed and activated.** A synthetic packet path
  calls a Rust dylib and the Swift crypto bridge inside a packet-tunnel
  extension bundle. The combined app and provider are Developer ID signed,
  notarized, stapled, and activated with user approval. After a temporary
  authorized Tailscale disable, one live synthetic `packetFlow` ICMP round
  trip passed with a `/32` test route, scoped DNS, MTU 1280, and verified
  route/DNS cleanup. Tailscale's original Enabled and On Demand settings were
  restored, with its backend still stopped. The synthetic provider is now
  disabled and its app was later replaced by the joined provider.
  [Packaging evidence](../spikes/packet-tunnel-integration/README.md).
- **The joined UDP provider passed its installed no-token preflight.** Version 4 joins
  the Rust IKE/ESP session, Swift packet flow, authenticated route/DNS mapping,
  and an ephemeral host handoff. Its offline build, deep Developer ID
  signature verification, Apple notarization, and stapling passed. It was
  installed and activated, then the host's no-token `preflight` returned exit
  0 and `preflight_passed responder_auth_and_eap_challenge` from inside the
  provider on IPv4 Wi-Fi. The OFTC VPN disconnected afterward, its
  configuration was removed, route 10.20.0.1 stayed on en0, only en0 DNS
  remained, and Tailscale returned to Enabled, Connected, OnDemandEnabled
  TRUE. No token, CHILD_SA, ESP packet, or real packetFlow traffic was used.
  Version 5 was subsequently rebuilt with reviewed nonfatal packet-drop
  handling, Developer ID signed, and accepted by Apple for notarization
  (`4f2dd7be-333b-4fba-b735-0a79c3452fa4`). Stapling, deep signature
  verification, and Gatekeeper assessment passed. Version 5 then replaced the
  installed version 4 app and its extension was activated. Older extensions
  are queued for removal on reboot.
  [Candidate evidence](../spikes/signed-provider-join/README.md).
- **Gate 4 passed through the signed version 5 packet tunnel on IPv4 Wi-Fi.**
  The [one-shot smoke procedure](../spikes/signed-provider-join/gate4-smoke.sh)
  passed its installed-provider no-token preflight, then used one separately
  approved fresh SAML token to establish the UDP 4500 tunnel. macOS assigned
  `10.77.0.12` and routed `10.20.0.1` through `utun10`; the gateway supplied
  no DNS servers. Exactly one ICMP echo traversed `packetFlow` and received
  one reply in 25.662 ms (0% loss). The script exited 0 after stopping and
  removing the OFTC VPN. Independent cleanup checks found the target route
  back on `en0` via `192.168.1.1` and only the `en0` DNS resolver. Tailscale
  remains Disabled and Disconnected at the user's request.
  [Gate 4 evidence](../spikes/signed-provider-join/README.md).
- **Signed packet-flow TCP passed on IPv4 Wi-Fi.** The notarized version 6
  provider was installed and activated. One separately authorized fresh SAML
  token established IKE/EAP/CHILD_SA on the explicit TCP 4443 path; macOS
  assigned `10.77.0.13` and routed `10.20.0.1` through `utun10`. Exactly one
  ICMP echo entered `packetFlow` and received one authenticated reply in
  92.525 ms (0% loss). The one-attempt Gate 5 script stopped and removed OFTC;
  independent checks found route `en0` via `192.168.1.1`, only `en0` DNS, and
  Tailscale still Disabled/Disconnected as requested.
  [Gate 5 evidence](../spikes/signed-provider-join/README.md).
- **Signed native IPv6 packet-flow UDP and TCP passed on the IPv6-only hotspot.**
  `en0` had native IPv6 and CLAT `192.0.0.2`. The installed version 6 provider
  first reached authenticated responder AUTH and the EAP challenge in separate
  no-token UDP 4500 and TCP 4443 preflights. One separately approved fresh
  SAML token per transport then established a live CHILD_SA and carried exactly
  one encrypted `packetFlow` ICMP echo to `10.20.0.1`: UDP returned one reply in
  276.531 ms; TCP returned one reply in 111.811 ms on the same RFC 9329 IKE/ESP
  stream. Each run assigned `10.77.0.13`, routed the target through `utun10`,
  exited 0 after removing OFTC, and left only `en0` DNS. Independent cleanup
  checks found the target route back on `en0` via CLAT gateway `192.0.0.1` and
  Tailscale still Disabled/Disconnected as requested.
  [Gate 5 evidence](../spikes/signed-provider-join/README.md).

**Spike decision: go for standalone implementation.** A signed `oftc` provider
has independently completed the short protected packet round trip on IPv4 UDP,
IPv4 TCP, native IPv6 UDP, and native IPv6 TCP, without a Fortinet or strongSwan
runtime. The TCP live tests selected TCP explicitly; automatic fallback on a
network that blocks UDP remains to be exercised. The full read-only gateway
phase 1/network-ID metadata inventory was not obtained, but authenticated
exchanges and replies establish the observed profile needed for this decision.
This is a feasibility result, not replacement acceptance. IKE/CHILD_SA rekey,
liveness scheduling and reconnect, repeated lock/wake/roam, sustained traffic,
automatic fallback, and production profile ownership remain open in
[Issue 13](../Issues/013-replace-fortinet-vpn-daemons.md).

## Original risk questions

The Gate 0–5 evidence above resolves these feasibility questions for the
observed gateway profile. Sustained operation and automatic fallback remain
replacement work.

1. Can we sign, install, start, and operate a packet-tunnel system extension on
   this Mac with the `packet-tunnel-provider-systemextension` entitlement? Apple
   supports a macOS app extension only through the App Store; direct Developer
   ID distribution uses a system extension. `NEPacketTunnelProvider` supplies a
   packet flow and tunnel IP, route, DNS, and MTU settings. A Rust core can live
   behind a minimal native adapter. If provisioning is unavailable, assess a
   privileged helper and direct virtual-interface integration separately.
2. Will the gateway accept an independently implemented IKEv2 initiator using
   the observed proposals and EAP identity, with no Fortinet-private notify?
   Does the selected phase 1 require `FORTICLIENT_CONNECT` or a network ID?
3. Can the observed MSCHAPv2 method complete with the single-use SAML token,
   and what are the required mode-config, traffic-selector, and TCP ESP settings?
   The bootstrap `UID` must equal the EAP identity, and the single-use `tokenid`
   is the EAP secret; the callback `username` is different on this gateway.
4. Can one user-space ESP implementation carry encrypted packets over both
   UDP NAT-T and TCP fallback, including return traffic, on an IPv6-only/NAT64
   path? This is what removes the `fct_tunnel_ctl` descriptor failure.

## TUN and cryptography choices

BoringTun is a user-space **WireGuard** implementation, not an IKEv2/ESP
implementation. Its library deliberately omits the network and tunnel stacks;
its macOS CLI happens to use `utun`. Its WireGuard handshake and crypto cannot
negotiate with this FortiGate IPsec profile. Do not add it as a dependency.

A user-space TUN is viable: the system extension's `packetFlow` gives `oftc`
IP packets to encrypt into ESP and accepts decrypted packets on the return
path. This avoids a separate TUN crate or kernel driver. Direct `utun` access
is a possible command-line experiment, but then `oftc` must own privileged
route/DNS setup and recovery; it does not prove the intended app packaging.

The observed profile needs P-384 ECDH, HMAC-SHA1/SHA256 as IKE PRFs and
authenticators, AES-256-CBC plus HMAC for IKE/ESP, and secure random bytes.
The **protocol** still needs IKE's PRF+ key schedule, AUTH calculations,
padding, integrity-before-decryption, ESP sequence/anti-replay, and rekey.
Do not implement the cryptographic primitives. First try a thin native
adapter to macOS Security (raw P-384 ECDH and random bytes) and CommonCrypto
(AES-CBC and HMAC); CryptoKit's P-384 key agreement is another option in the
native adapter. Check byte encoding and known-answer vectors before committing
to either route. CryptoKit's AES API exposes GCM, not this profile's CBC mode.

Keep the existing dependency-free `client/` crate and its fast edit/build loop.
Prototype the IKE core separately and link it to `oftc` only after the gates
pass. Measure incremental and clean build time plus release binary size before
accepting any crypto or parser crate; a small system-framework bridge may be
cheaper than a large Rust dependency tree, but FFI correctness must be tested.

## Gates, ordered to avoid wasted implementation

Each gate produces a short record: network/address family, transport, last
completed exchange, selected proposals, gateway diagnostic, local tunnel state,
and next experiment. Keep tokens, PSKs, and raw captures out of the repo.
Stop at a failed gate and identify its cause before adding features.

Use review caps rather than delivery estimates: one workday for Gate 0,
one workday for Gate 1, two focused days for Gate 2, and a check-in after each
day of Gates 3–5. If a cap is reached without the stated evidence, document
the specific blocker and re-estimate before writing the next layer. Gate 3 is
the largest sunk-cost risk because it requires a real IKEv2 state machine
before gateway acceptance can be proved.

| Gate | Smallest experiment | Pass / decision |
| --- | --- | --- |
| 0. macOS packaging | Build a minimal Developer ID signed packet-tunnel **system extension** and host app. Start and stop it, read/write a test packet, apply one test IP, route, DNS, and MTU, then confirm cleanup. No VPN or SSO. | Certificate, provisioning profile, `packet-tunnel-provider-systemextension` entitlement, install/approval, and packet I/O work on the target Mac. If unavailable, price the privileged-helper path before writing IKE or ESP. |
| 1. gateway and crypto contract | From existing known-good metadata and read-only FortiGate config/diagnostics, resolve Issue 8's EAP method, selected phase 1, network ID, transforms, identities, and the actual TCP `fortinet-esp` mode. Identify a network where UDP 4500 passes. In a separate tiny executable, verify raw P-384 ECDH, AES-CBC, HMAC-SHA1/SHA256, and random bytes using macOS system frameworks and known-answer vectors. | The wire profile, failure diagnostics, and a low-cost crypto implementation route are specific enough to proceed. No new SSO token unless existing evidence is insufficient. |
| 2. transport and IKE_SA_INIT | Implement just the observed IKE_SA_INIT offer, SPI/nonce/DH exchange, NAT detection, retransmission, and response parsing. First try UDP 4500, then independently try `IKETCP` and length framing on TCP 4443. Neither probe needs SSO. | The gateway selects the correct phase 1 and replies on both paths. If only one path answers, isolate routing, phase-1 selection, and private notify behavior before adding authentication. A TCP handshake alone does not pass. |
| 3. authenticated exchange | Implement IKE key derivation, encrypted IKE_AUTH, responder PSK `AUTH` verification, the observed EAP method, client EAP completion, and mode-config/CHILD_SA negotiation. Feed one `oftc` SAML token in memory, with the bootstrap UID as EAP identity. Pair one attempt with FortiGate IKE/FNBAM diagnostics. | IKE and CHILD_SA succeed independently of Fortinet processes. Classify any rejection as PSK/AUTH, EAP, token binding, identity, transform, selector, or private-notify policy before a retry. If the current phase 1 mandates Fortinet identity, decide whether an administrator-controlled standards-based phase 1 is acceptable. |
| 4. one protected UDP packet | Derive CHILD_SA keys; implement minimal ESP encrypt/decrypt, SPI/sequence, integrity, replay protection, padding, and UDP encapsulation. Join it to the packet-tunnel flow. Reach one internal host and receive its response; verify split route, DNS, MTU, and teardown. | A real protected round trip works over UDP 4500 with no Fortinet component. This is a UDP milestone, not yet a complete replacement. |
| 5. TCP fallback and NAT64 | Send **both IKE and ESP** on the same RFC 9329 stream. Use bounded UDP attempts before fallback. Repeat the packet round trip on the restricted network and IPv6-only/NAT64 tether, trying IPv4 through 464XLAT and DNS64 IPv6 as appropriate. | End-to-end traffic works over TCP 4443 and an IPv6-only outer path. A TCP SYN, SAML redirect, or IKE-only connection is insufficient. |

Gate 0 and a no-SSO Gate 2 probe are the early stop signals. Gate 3 necessarily
requires real protocol implementation, so timebox it and avoid breadth: one
algorithm suite and one selected EAP method. Do not spend another SSO token
without a specific diagnosed correction. No automatic reconnect or polished
CLI before Gate 5.

## Core to build if the gates pass

- **IKEv2 control plane:** SA_INIT, IKE_AUTH/EAP, CHILD_SA creation and rekey,
  INFORMATIONAL/DELETE, strict message-ID matching, duplicate/retransmission
  handling, DPD, and key/secret lifecycle. Accept the observed proposals only
  for the prototype; use vetted cryptographic primitives rather than writing
  AES, HMAC, ECDH, or a random-number generator. The current profile offers
  AES-256-CBC, HMAC-SHA1 or SHA2-256, and ECP-384 for IKE; ESP offers
  AES-256-CBC/HMAC-SHA1. Verify the negotiated values at Gate 1.
- **Transport:** UDP NAT-T first; TCP 4443 fallback with RFC 9329 `IKETCP`,
  length framing, and IKE/ESP demultiplexing. Address selection must work for
  IPv4, DNS64 IPv6, and 464XLAT. Recreate the IKE SA when changing transport
  unless a proven MOBIKE transition is implemented.
- **Data plane:** user-space ESP shared by both transports, packet flow in both
  directions, anti-replay, sequence limits, traffic selectors, MTU/fragmentation,
  and CHILD_SA rekey. Keeping ESP in one backend avoids an UDP-only kernel path
  that cannot service TCP fallback.
- **macOS integration:** a packaged packet-tunnel system extension sets assigned IP,
  split routes, DNS, and MTU and hands IP packets to the core. `oftc` retains
  SAML and lifecycle control. Use a narrow in-memory IPC boundary for the
  single-use token; no token in arguments, config files, or persistent logs.

## Replacement acceptance after the spike

Before making the standalone engine the default, test repeated screen lock,
sleep/wake, roaming, IKE and CHILD_SA rekey, 30–40 s TCP stalls with late or
duplicate DPD replies, real peer death, process failure, and complete cleanup.
Run on one UDP-capable path, one restricted path requiring TCP, and the
IPv6-only/NAT64 tether. Keep the working Fortinet-backed controller available
until those tests pass ([Issue 13](../Issues/013-replace-fortinet-vpn-daemons.md)).

## References

- [Issue 14](../Issues/014-spike-standalone-oftc-engine.md), [Issue 8](../Issues/008-capture-live-eap-method-and-vendor-ids.md), [daemon replacement assessment](daemon-replacement.md), [IKE dialect](ike-dialect.md).
- [Apple Packet Tunnel Provider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider), [Network Extension entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension), [macOS deployment table](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment).
- [BoringTun](https://github.com/cloudflare/boringtun), [WireGuard cryptography](https://www.wireguard.com/protocol/), [Apple P-384 key agreement](https://developer.apple.com/documentation/cryptokit/p384/keyagreement/privatekey), [Apple CryptoKit AES modes](https://developer.apple.com/documentation/cryptokit/aes).
- [IKEv2 RFC 7296](https://www.rfc-editor.org/info/rfc7296/), [ESP RFC 4303](https://www.rfc-editor.org/info/rfc4303/), [UDP encapsulation RFC 3948](https://www.rfc-editor.org/info/rfc3948/), [TCP encapsulation RFC 9329](https://www.rfc-editor.org/info/rfc9329/) (supersedes RFC 8229).
