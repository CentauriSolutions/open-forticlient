# No-SSO IKE_SA_INIT spike

This isolated Rust executable constructs and parses only the observed
IKE_SA_INIT exchange. It links the existing [Swift crypto bridge](../crypto/README.md)
for random bytes and ephemeral P-384; CommonCrypto supplies the SHA-1 digest in
the NAT-detection notifies. It does not read a profile, PSK, SAML token, or
Fortinet process state. Nothing in `client/` is linked or changed.

On macOS with Xcode Command Line Tools and Rust:

```sh
sh spikes/ike-sa-init/run.sh
spikes/ike-sa-init/probe --gateway GATEWAY_HOST --transport udp --family v4
spikes/ike-sa-init/probe --gateway GATEWAY_HOST --transport tcp --family v4
```

`run.sh` builds the local bridge and probe and runs the packet tests. It does
not access the network. Each probe requires an explicit gateway. UDP sends the
same IKE request at most twice, waiting 1.2 then 2.4 seconds. TCP has a
3-second connect deadline, one request, and a 4-second receive deadline.
No authentication, CHILD_SA, ESP, route, DNS, or system-extension action occurs.
Output contains only packet lengths, selected proposal, nonce length, NAT
comparison, and notify codes; packet bytes and key material are not logged.

## Request and parser boundaries

- IKEv2 header: random nonzero 8-byte initiator SPI, zero responder SPI,
  exchange 34, initiator flag, message ID 0, exact big-endian length.
- SA: proposal 1 AES-256-CBC (transform 12, key-length TV attribute 256),
  PRF-HMAC-SHA2-256 (5), AUTH-HMAC-SHA2-256-128 (12), ECP-384 (20).
  Proposal 2 changes the PRF and integrity transforms to HMAC-SHA1 (2).
- KE: group 20, 96-byte P-384 X||Y point. Nonce: 32 random bytes.
- NAT detection: SHA-1 of both SPIs, outer IP, and port, with notify types
  16388 and 16389. Three documented Fortinet 16-byte vendor IDs follow.
  No private license or network-ID notify is fabricated.
- UDP 4500 adds a four-zero-byte non-ESP marker. TCP 4443 begins with the
  one-time ASCII `IKETCP` prefix, then a 16-bit frame length that includes
  itself, the same marker, and the IKE packet.

For this fixed offer, the IKE request is 376 bytes: the UDP datagram is 380
bytes, and the TCP frame length field is 382 (`0x017e`). The initial TCP write
is 388 bytes including the six-byte stream prefix. The 256-byte IKE replies
occupied 260-byte UDP and 262-byte TCP frames, respectively.

The parser checks exact IKE and payload lengths, SPI and message ID, response
flags, one offered proposal with all four selected transforms, KE group/point
length, nonce length, NAT notify shape, and the complete payload chain. It
reports error notify types separately. A received P-384 point is passed to
CryptoKit for validation and ECDH; the shared secret is discarded. Other
IKE exchanges and COOKIE/INVALID_KE retry handling are out of scope.

The six constructed-packet tests cover byte offsets and framing, an independent
SHA-1 NAT-hash vector, both selected proposals, response parsing, and malformed
length, message-ID, and offer rejection.

## Gateway result, 2026-10-07

The documented gateway hostname resolved to one IPv4 address. The macOS
network-service list showed the configured `Office VPN` service disconnected
before these probes. Each transport was probed once from this Mac; no SSO
session was started and no tunnel was altered.

| Transport | IKE request | IKE response | Selected proposal | NAT source / destination | Result |
| --- | ---: | ---: | --- | --- | --- |
| UDP 4500, IPv4 | 376 B | 256 B | 1: AES-256-CBC / PRF-SHA256 / INTEG-SHA256 / ECP-384 | match / mismatch | Parsed; responder P-384 point accepted |
| TCP 4443, IPv4 | 376 B | 256 B | 1: AES-256-CBC / PRF-SHA256 / INTEG-SHA256 / ECP-384 | match / mismatch | Parsed; responder P-384 point accepted |

Both responses used message ID 0, included a 16-byte nonce, and carried no
other notify code. The destination NAT-hash mismatch is consistent with the
local address being translated; this probe alone does not establish where
translation occurs. The successful TCP result includes a framed IKE response,
not just a completed TCP connection. These probes show SA_INIT acceptance on
this IPv4 network. They do not test private-notify policy at IKE_AUTH, EAP,
PSK authentication, ESP over either transport, or IPv6/NAT64.

## Local build cost

On this Mac (arm64, macOS 27, Rust 1.98.1), a full `run.sh` build and six
tests took 0.97 seconds from removed outputs with a warm Swift module cache;
another full rebuild took 0.98 seconds. These are single wall-clock samples,
not a no-op incremental build benchmark. The `probe` is 540,376 bytes and its
local `libcrypto_swift.dylib` is 88,376 bytes; the test binary is 1,170,032
bytes. Build outputs are ignored by Git.

The next decision is to use the gateway-contract spike's exact phase-1,
identity, EAP, and private-notify evidence before attempting IKE_AUTH. No
authenticated-exchange code should be inferred from this SA_INIT response.

Wire references: [IKEv2 RFC 7296](https://www.rfc-editor.org/rfc/rfc7296.html),
[TCP encapsulation RFC 9329](https://www.rfc-editor.org/rfc/rfc9329.html), and
[the repository's observed dialect](../../docs/ike-dialect.md).
