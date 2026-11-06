# Roadmap

The active implementation is the standalone macOS app in [`app/`](../app/) and
the `oftc` CLI in [`client/`](../client/). The earlier controller that reused
Fortinet's daemons, and the research behind this client, are under the
`legacy-controller` tag; they are no longer build inputs.

## Where things stand

Measured on real FortiGates with a signed, notarized build: IPv4 UDP and TCP
connections, explicit and scheduled IKE renewal, CHILD SA rekeying, recovery
from network loss and from sleep with fresh SSO, and two tunnels to different
gateways connected at once, each routing its own prefixes through its own
interface. Offline build checks, Developer ID signing, notarization,
installation, extension activation, and live traffic are separate claims; each
document says which one it relies on.

## Rust migration

The provider and the host are Rust (tracked in #41 to #50): the `OFTCTunnel`
extension, every host verb, the reconnect supervisor and the host's UI socket
([ui-edge.md](ui-edge.md), the `oftc status` and `profiles` clients of it) run in Rust.
Swift is the menu bar UI edge only. Done: the `Tunnel` seam, crypto, provider logic,
the NetworkExtension backend, the host bindings and verbs, the supervisor, the UI edge
socket, the bundled host service. Still open: the live gate on the development Mac
(#48), registering the host service at first run, moving the UI onto the socket,
deleting the superseded Swift and the unused C ABI crate (#49), and the project-wide
simplification pass (#50). See [swift-removal-plan.md](swift-removal-plan.md).

## GA gate

A general release (the generic package and image on GitHub, no built-in VPNs, for
colleagues on macOS 15 or later on Apple silicon) waits for all of these. Each is its
own claim; none is implied by the offline build and CI.

1. The Rust provider passes the live gate on a real FortiGate (#48): connect over UDP
   and TCP, rekey, sleep and network loss with fresh SSO.
2. A signed, notarized package installs on a Mac that has an older OFTC build: the
   app bundle is replaced cleanly, the new provider activates (it must be higher than
   any activated build; see [releasing.md](releasing.md)), saved VPNs survive, and no
   code-signature error appears.
3. A clean install on a Mac that never had OFTC works to a first connection.
4. `oftc uninstall` leaves no app, CLI, receipt, Login Items entry or system extension.
5. First run does not mislead: "Update VPN component" does not open a blank setup form (#88).
6. The release checklist in [releasing.md](releasing.md) is complete and
   [support.md](support.md) covers what a colleague sends when it fails.

## Open work

1. **Concurrent tunnels.** Detect overlapping prefixes across active tunnels
   (refuse, warn, or let the user pick a winner); exclude every other active
   gateway's outer address from each tunnel; allow at most one default
   (empty-suffix) DNS resolver and require match domains for the rest; check for
   inner-address collisions between gateways. (#40)
2. **Installer and first run on a clean Mac.** Validate fresh-install approval,
   the post-install app launch, quiet launch at login, and an update over an
   older release, from the DMG. The post-install launch was fixed and tested
   with a stand-in Installer process, not yet with the real one.
3. **Crash recovery.** The login agent uses `KeepAlive=false` because the host
   supervises recovery itself; launchd restart after a host crash has not been
   validated.
4. **Wider network acceptance.** Peer loss, Wi-Fi and tether roaming, TCP stalls,
   peer-initiated or simultaneous rekey, and sustained IPv6-only/NAT64. Short
   IPv6 and TCP packet tests show capability, not acceptance.
5. **Distribution.** GitHub releases with the generic package and image, and the
   in-app update notice pointed at them.

See [architecture.md](architecture.md) for how the pieces fit and
[operations.md](operations.md) for day-to-day use.
