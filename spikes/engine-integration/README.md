# Offline standalone engine integration

`engine.rs` joins the existing [ESP codec](../esp/README.md) and [TCP ESP
framing](../tcp-esp/README.md) without modifying either spike. It models the
handoff from an **authenticated** IKE CHILD_SA to packet-tunnel IP packets and
the selected ESP transport. All test SPIs, keys, addresses, and packets are
synthetic. It opens no sockets, reads no profile or credentials, and changes no
system route or packet tunnel.

Run on macOS with Rust and Xcode Command Line Tools:

```sh
sh spikes/engine-integration/run.sh
```

The script builds the local Swift CommonCrypto bridge, then runs 20 tests:
14 tests imported with the existing ESP and TCP modules and six integration
tests. The integration tests cover a packet-tunnel-style IPv4 and IPv6 IP
packet through outbound ESP and back through authenticated inbound ESP; UDP
4500 payload demultiplexing; RFC 9329 TCP records on a stream shared with IKE,
including split reads and the originator's once-per-connection prefix; tampered
ICV and replay rejection; unsupported SA and selector parameters; assigned
source/destination, split-route, and inner-MTU checks. Packet, policy, or MTU
rejection before encryption does not advance the outbound ESP sequence.

## Exact Gate 3 handoff

The IKE core must construct `AuthenticatedChildSa` **only after** it verifies
responder AUTH, completes EAP and final IKE_AUTH, and authenticates the
negotiated CHILD_SA response. The spike does not make that proof by itself.
The handoff requires:

| Input | Required meaning |
| --- | --- |
| `suite`, `esn` | Selected ESP transforms: AES-256-CBC plus HMAC-SHA1-96, without ESN. Other suites and ESN fail installation. |
| `peer_inbound_spi`, `local_inbound_spi` | Distinct nonzero, 32-bit CHILD_SA SPIs for sending and receiving. The peer's inbound SPI is our outbound ESP header. |
| `outbound_keys`, `inbound_keys` | Separately derived 32-byte AES encryption and 20-byte HMAC-SHA1 integrity keys for each direction. The IKE core must derive these from authenticated CHILD_SA KEYMAT; this spike never does derivation. |
| `assigned_ip` | Mode-config inner address assigned to this client. The current engine supports one inner IPv4 **or** IPv6 address per installation. |
| `local_selectors`, `remote_selectors` | Authenticated negotiated address ranges. This narrow engine accepts only protocol-any and full port range; it rejects narrower traffic selectors until enforcement is implemented. The assigned address must be inside a local selector. |
| `installed_routes` | Split routes from validated mode-config policy. Each must be inside a remote selector. Outbound destinations must match both a route and a remote selector. |
| `inner_mtu` | Effective packet-tunnel IP MTU. Packets over it are rejected before ESP encryption; IPv6 requires at least 1280. Outer path MTU discovery and fragmentation are outside this spike. |
| `transport`, `max_tcp_record` | UDP 4500 primary or already established TCP 4443 fallback, bound to the same IKE SA. TCP record capacity must fit an ESP packet at the configured inner MTU. |

The installed engine emits a bare ESP payload for UDP 4500 or `Frame::Esp`
for the **existing** TCP originator writer. That writer owns the `IKETCP`
prefix and socket writes. Inbound UDP classification or TCP stream parsing
hands IKE frames back to the IKE core; authenticated ESP IP packets alone
can be returned to the packet tunnel. Unknown SPI, bad ICV, replay, and IP
policy failures never reach the packet tunnel.

## Next live boundary

Connect the verified Gate 3 result to this handoff, the signed packet-tunnel
provider, and a UDP 4500 socket. With the tunnel's assigned address and split
route installed, prove **one encrypted IP round trip** and clean removal of
that route and DNS state. Then test ESP on the established TCP 4443 stream,
IPv6-only/NAT64 outer transport, rekey, sleep/wake, and recovery. These tests
have not been performed here. No live gateway acceptance, actual negotiated
transform/selector compatibility, or path MTU can be inferred from the offline
20-test result.
