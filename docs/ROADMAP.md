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

## Open work

1. **Concurrent tunnels.** Detect overlapping prefixes across active tunnels
   (refuse, warn, or let the user pick a winner); exclude every other active
   gateway's outer address from each tunnel; allow at most one default
   (empty-suffix) DNS resolver and require match domains for the rest; check for
   inner-address collisions between gateways. (Issue 40)
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
