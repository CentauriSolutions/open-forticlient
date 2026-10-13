# Offline user-space ESP spike

This directory contains a narrow ESP tunnel-mode codec for the offered
`AES-256-CBC / AUTH_HMAC_SHA1_96` CHILD_SA profile. It uses the existing
[Swift system-framework bridge](../crypto/README.md): CommonCrypto performs
AES-CBC and HMAC-SHA1, and Security supplies a fresh unpredictable 16-byte IV
for each outbound packet. No AES, HMAC, or random generator is implemented here.
The codec owns ESP framing, byte-order, minimal `1..N` padding, trailer checks,
12-byte ICV truncation, a 64-packet replay window, and 32-bit sequence limits.
It accepts IPv4 or IPv6 inner packets and requires their declared lengths to
match the bytes from the packet tunnel. The key material used in tests is public
and synthetic.

Run on macOS with Xcode Command Line Tools and Rust:

```sh
sh spikes/esp/run.sh
```

The script compiles the existing bridge source into this directory, runs the
Rust offline tests, and runs a small stripped release caller. Its outputs are
ignored locally. It never opens a socket, reads a profile, invokes SSO, touches
the packet tunnel, or changes routes. It does not need a gateway, token, PSK,
or live CHILD_SA.

## Wire contract and checks

`OutboundSa::seal` emits `SPI(4) || sequence(4) || random IV(16) ||
AES-CBC(inner IP || 1..N padding || pad length || next header) || ICV(12)`.
The ICV is the first 12 bytes of HMAC-SHA1 over all prior ESP bytes. Next
header is 4 for IPv4 or 41 for IPv6. The outbound SPI is the peer's inbound
SPI; the inbound SPI is the one allocated locally. The IKE core must supply
**separate** 32-byte encryption and 20-byte integrity keys for each direction.
It must verify that the negotiated suite is exactly this one and that extended
sequence numbers (ESN) are disabled. The codec rejects SPI zero and stops
before sequence reuse at the 32-bit limit; the IKE core must rekey earlier.

On receive, the codec checks length, SPI, and replay eligibility, computes
and compares the ICV in constant time, **then** decrypts. It validates ESP
padding, next header, and inner IP length before advancing the replay window.
A bad packet never consumes a sequence number. The single mutable inbound SA
must be serialized if the packet flow can deliver packets concurrently.
Key arrays are cleared on drop, but production secret handling and guaranteed
zeroization still need review.

For RFC 3948 UDP/4500, the ESP packet itself is the UDP payload: **no**
four-zero-byte non-ESP marker is prepended. `classify_udp4500` separates ESP,
non-ESP-marked IKE, and the one-byte `0xff` NAT keepalive; a transport layer
owns the UDP header, port checks, and socket. It does not parse IKE or perform
TCP framing. Use the same bare ESP packet inside the separately specified TCP
record only after that transport is validated.

## Offline evidence (2026-10-07, macOS arm64)

- Six tests pass. A complete fixed-IV IPv4 ESP packet matches an independent
  vector made with OpenSSL `enc -aes-256-cbc -nopad` and Python `hmac`/`sha1`
  using public sequential keys. This checks header, IV, plaintext padding,
  ciphertext, and ICV bytes, followed by successful decoding.
- Mutated IV, ciphertext, and ICV each fail authentication; an instrumented
  crypto adapter confirms zero decrypt calls before ICV acceptance. Truncated
  packets, zero sequence, wrong SPI, and authenticated packets with bad padding,
  next header, or inner IP length are rejected. A valid packet with the same
  sequence is still accepted after those malformed packets.
- Duplicate, out-of-order, 64-packet-old, and `u32::MAX` sequence behavior is
  tested. Random, CBC, or HMAC failure does not consume an outbound sequence.
  An IPv6 inner packet also passes an offline round trip.
- Warm full `run.sh` rebuild and test: **0.96–1.29 s** wall clock across two
  local samples. Separate warm
  compile samples: Swift bridge **0.41 s**, Rust test binary **0.13 s**, Rust
  stripped release caller **0.14 s**. The release caller is **342,352 B** and
  local bridge dylib **88,376 B**, or **430,728 B** together. The unstripped
  test executable is **1,166,248 B**. These are one-machine samples, not
  deployment or steady-state throughput measurements. The release caller
  dynamically loads the bridge from its own directory; app signing and stable
  bridge ABI remain separate work.

The formatting follows [RFC 4303](https://www.rfc-editor.org/rfc/rfc4303),
[RFC 3602](https://www.rfc-editor.org/rfc/rfc3602) for AES-CBC IV/padding,
[RFC 2404](https://www.rfc-editor.org/rfc/rfc2404) for HMAC-SHA1-96, and
[RFC 3948](https://www.rfc-editor.org/rfc/rfc3948) for UDP encapsulation.

## Decision and next boundary

**Go for integration of this offline codec behind the CHILD_SA interface.**
**No-go for claiming Gate 4 or a working standalone VPN yet.** The current
IKE_AUTH spike stops before client EAP completion and CHILD_SA establishment.
Until it returns an authenticated CHILD_SA, this spike cannot validate the
selected ESP transforms, derived directional keys and SPIs, ESN selection,
actual gateway ESP/UDP acceptance or return traffic, traffic selectors,
assigned address, MTU behavior, packet-tunnel coupling, or rekey timing.
TCP ESP framing and NAT64 remain later transport gates.

The next handoff is a typed CHILD_SA result from the IKE core (negotiated
suite and ESN flag, two SPIs, four directional keys, lifetime, traffic
selectors, and assigned inner address). Instantiate separate inbound/outbound
SAs only after authenticating that result. Then attach the existing packet
tunnel flow and UDP/4500 transport for one protected round trip, with live
traffic and gateway diagnostics kept out of the repository.
