# Offline Swift packet-flow to ESP bridge

`bridge.rs` imports the existing [`engine-integration`](../engine-integration/README.md)
module, which in turn imports the ESP and TCP framing modules. The only exported
constructor installs two **public synthetic** CHILD_SAs with matching directional
SPIs and keys. `check.swift` uses the shape of `NEPacketTunnelFlow.readPackets`
and `writePackets`, but all packets remain in memory. It opens no gateway socket,
uses no SSO/profile/PSK, installs no route, and does not activate a system
extension.

Run on macOS with Rust and Xcode Command Line Tools:

```sh
sh spikes/packet-flow-bridge/run.sh
```

The script builds into a temporary directory and removes its artifacts. The
Swift harness feeds one valid ICMP IPv4 packet to the Rust outbound ESP engine,
has a synthetic peer authenticate it, returns an encrypted ICMP reply, and
delivers the decrypted IP packet through the Swift `writePackets` stand-in. It
also checks a mismatched IPv4 total length, a short outbound buffer, a short
inbound buffer, replay rejection, and NAT keepalive classification. The invalid
packet and short buffers do not consume outbound sequence or inbound replay
state. This is an offline ABI test; no live protected traffic is established.

## ABI and ownership

| Call | Result and ownership |
| --- | --- |
| `oftc_bridge_new_synthetic(role)` | Returns an opaque Rust session or null. Role 0 is client, 1 is synthetic peer. Test-only constructor; it must not be used for a real tunnel. |
| `oftc_bridge_send_ip` | Consumes one borrowed IP packet and writes a bare UDP/4500 ESP payload to caller-owned storage. Output capacity is checked before encryption. |
| `oftc_bridge_receive_udp` | Consumes one borrowed UDP/4500 payload. Status 0 returns authenticated IP, 1 returns an IKE body, 2 means keepalive; the caller must route IKE back to the active IKE SA. Capacity is checked before replay state can advance. |
| `oftc_bridge_free` | Drops the session once, after all calls have stopped. The caller must never reuse that pointer. |

Both packet calls reset `output_len` to zero on failure. Negative status codes
are `-1` invalid ABI arguments, `-2` short output buffer, `-3` packet, policy,
or crypto rejection, and `-4` internal failure. Input, output, and length
storage must be valid for the stated sizes and must not overlap. Neither packet
pointer is retained. The engine's mutex serializes send/receive calls, while
the caller must serialize `free` against them. Swift's `Data` and output arrays
own copies of packet bytes; the temporary Rust decrypted vector is cleared
after copying. The ESP module's `Keys` destructor clears key arrays when the
session drops, but optimized-memory erasure has not been audited and is a
production hardening item. No secret key crosses the packet-call ABI.

## Gate 3 handoff and provider replacement

The test constructor must be replaced by an installer that accepts an
`AuthenticatedChildSa` produced **only after** final responder AUTH and
CHILD_SA response validation. That handoff requires the negotiated ESP suite
and ESN flag; both CHILD_SA SPIs; directional AES-256 and HMAC-SHA1 keys derived
from authenticated KEYMAT; assigned inner address; authenticated local and
remote traffic selectors; validated split routes; inner MTU; and UDP/TCP
transport selection. [`engine-integration/README.md`](../engine-integration/README.md)
defines those fields and current restrictions. The production installer should
transfer the keys directly into Rust-owned state and avoid logging or persisting
them. An actual provider must also pass IKE frames to its IKE state machine,
write outbound ESP to the selected transport, and call `writePackets` only for
status-0 authenticated IP. Teardown must close the transport, stop packet
callbacks, remove tunnel settings, and free the session in that order.

The current signed probe provider's echo call can be replaced with this
session-oriented ABI in the same `NEPacketTunnelProvider` process. This bridge
introduces no new privileged API or entitlement beyond the provider's existing
packet-tunnel capability. That replacement still needs a new signed and
notarized provider binary and a runtime packet-flow test; this offline check
does not prove macOS will route live packets into the replacement or that the
gateway accepts the negotiated ESP data path.
