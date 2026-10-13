# RFC 9329 TCP IKE/ESP framing spike (2026-10-07)

`lib.rs` is a standard-library-only, socket-free framing and fallback sketch
for standalone `oftc` (Issue 14). Run `sh spikes/tcp-esp/run.sh` from the repo
root. It builds a temporary test executable in `/private/tmp`; no gateway or
network configuration is touched.

## Evidence and wire contract

The [recorded gateway contract](../gateway-contract/README.md) has TCP 4443,
`transport auto`, and **`fortinet-esp disable`**. [Fortinet documentation]
states that this setting uses standards-based TCP ESP encapsulation for
FortiClient dial-up,
while its enabled mode uses proprietary ESP framing. That configuration and the
existing TCP IKE_SA_INIT/IKE_AUTH observations make [RFC 9329] the appropriate
framing target. The setting alone does **not** prove the actual ESP bytes on this
gateway; no CHILD_SA or ESP stream has been observed by this spike.

The sketch implements the following RFC 9329 boundaries:

- The TCP originator sends `IKETCP` exactly once per connection. The responder
  begins with a length field, not a prefix. A replacement connection gets a
  fresh prefix.
- Every big-endian, two-byte length includes its own two bytes. An IKE record
  adds four zero marker bytes before the IKE message; an ESP record starts
  directly with its nonzero SPI. The decoder emits IKE and ESP separately.
- TCP read boundaries do not matter. The parser buffers a prefix, length, or
  one payload incrementally; it handles partial and coalesced records. The
  default maximum record is 8192 bytes and can be configured up to 65535. Use
  bounded socket reads because one `feed` call collects its output frames.
- Length 0/1, over-limit records, invalid prefix, and payloads too short to
  carry a four-byte type discriminator close this sketch's decoder. Length 2
  is ignored. The one-byte `0xff` NAT keepalive (length 3) is silently dropped;
  the client should not generate it on TCP. EOF discards any partial record.
- The decoder passes marker-classified IKE and ESP bytes to their protocol
  layers even if the inner packet is malformed. In particular, an IKE syntax
  error may require `INVALID_SYNTAX` on the existing TCP connection; the
  framing layer cannot make that decision. The encoder validates outgoing
  minimum sizes and the IKE header's declared length.
- `OriginatorWriter` uses `write_all` and becomes unusable after a write error.
  ESP with an unknown but nonzero SPI is passed upward; the IKE/ESP SA layer
  must decide whether it belongs to a CHILD_SA and authenticate it.

`Fallback` models one bounded initial negotiation: initial UDP IKE_SA_INIT,
one UDP retransmission by default, then one TCP connection and a **new**
IKE_SA_INIT. Its TCP action explicitly requires a new initiator SPI and
recalculated NAT detection payloads. The caller owns finite timers, fresh
randomness, IKE packet construction, and socket lifecycle. An IKE SA selected
for TCP must keep its IKE and CHILD_SA ESP traffic on that same connection
until deleted or an explicit MOBIKE transition occurs.

## Local result and remaining gate

`run.sh` passes eight synthetic tests covering exact bytes, one-time prefix,
IKE/ESP demultiplexing, partial and coalesced reads, empty records, NAT
keepalives, malformed lengths/payloads, clean and truncated EOF, short writes,
write failure, and bounded fallback. These tests establish parser behavior
only. They do not establish gateway interoperation, IKE authentication, ESP
encryption/integrity, tunnel reachability, NAT64, or lock/wake recovery.

After a real authenticated CHILD_SA exists, validate on the restricted network
that TCP 4443 carries both directions of ESP in the same stream as IKE. Record
only redacted framing metadata: record lengths, marker presence, SPI match to
the negotiated CHILD_SA, and the encrypted packet round-trip result. Verify
the selected ESP proposal and traffic selectors from safe gateway diagnostics;
do not retain raw captures, keys, tokens, or PSKs. Only that round trip can
close the TCP data-plane part of Gate 5.

[RFC 9329]: https://www.rfc-editor.org/rfc/rfc9329.html
[Fortinet documentation]: https://docs.fortinet.com/document/fortigate/7.4.10/administration-guide/351073/encapsulate-esp-packets-within-tcp-headers
