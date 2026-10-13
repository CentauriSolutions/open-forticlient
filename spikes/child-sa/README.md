# First CHILD_SA handoff (offline)

This module accepts the SA, TSi, TSr, and CP **bodies** from a final IKE_AUTH
response after the IKE core has verified the SK integrity check and responder
AUTH. It does not authenticate a packet itself. It opens no socket, reads no
credential, and changes no system configuration.

Run `sh spikes/child-sa/run.sh`. The eight local handoff tests and the imported
ESP/transport tests use synthetic values. The key derivation test checks a
Python `hmac` SHA-256 result computed separately from the Swift bridge used
in the test executable.

## Exact call shape

Include the existing engine module first, then this one:

```rust
#[path = "../engine-integration/engine.rs"]
mod engine;
#[path = "../child-sa/child_sa.rs"]
mod child_sa;
```

After validating the final responder AUTH:

```rust
let negotiated = child_sa::parse_final(
    summary.sa.as_deref().ok_or("missing SAr2")?,
    summary.tsi.as_deref().ok_or("missing TSi")?,
    summary.tsr.as_deref().ok_or("missing TSr")?,
    summary.cp.as_deref().ok_or("missing CP reply")?,
    first.child_spi,
    &first.offered_tsi,
    &first.offered_tsr,
)?;
let (handoff, config) = child_sa::into_engine(
    negotiated, &keys.sk_d, &ni, &nr,
    |key, data| ike_hmac_sha256(key, data).map_err(|_| child_sa::Error::Crypto),
    engine::Transport::Udp4500, 1400, 4096,
)?;
let engine = engine::Engine::install(handoff, engine::esp::SystemCrypto)?;
```

The exact `first.offered_tsi` and `first.offered_tsr` body bytes must be retained
from the initial request. The first CHILD_SA derives `prf+(SK_d, Ni | Nr)` from
the IKE_SA_INIT nonces. Output order is initiator-to-responder AES-256 key,
initiator-to-responder HMAC-SHA1 key, then responder-to-initiator keys. The
initiator's local SPI is the inbound ESP SPI; SAr2's SPI is outbound.

`config` also contains the assigned IPv4 address, optional netmask, DNS servers
and split DNS domains for packet-tunnel settings. Apply those settings only
after `Engine::install` succeeds and remove them when the SA closes. The engine
currently accepts only IPv4 inner selectors for this handoff, protocol-any,
full port range, AES-256-CBC/HMAC-SHA1-96, and no ESN.

## Route policy and selector narrowing

Every selected TSi and TSr range must be contained by a corresponding range
the initiator offered. Equality is allowed by IKEv2; selection need not always
be narrower. The assigned inner address must lie within selected TSi.

When CP contains `INTERNAL_IP4_SUBNET` (13), those subnets are used as split
routes, and each must lie within selected TSr. `config.route_source` is
`ConfigurationSubnet`. If CP omits subnets, selected TSr ranges supply the
routes, and `route_source` is `NarrowedRemoteSelector`. A wildcard TSr with no
CP subnet is rejected to avoid silently installing a default route. DNS
domains (25) are accepted only with at least one DNS server (3). The caller
must turn address ranges into exact routes and set split DNS on the packet
tunnel; this module does not install them.

## Validation limits

This spike does not prove what the live gateway returns. A gateway response
with a different ESP suite, ESP ports/protocol selector, IPv6 inner address,
vendor-only route information, or missing CP address will be classified as a
contract mismatch. Extend parsing and enforcement together after inspecting
redacted, authenticated Gate 3 diagnostics. Never relax a check just to accept
unvalidated policy. No live token, CHILD_SA, or protected packet is used here.

References: [IKEv2 RFC 7296](https://www.rfc-editor.org/rfc/rfc7296.html)
Sections 2.9, 2.17, 3.3, 3.13, 3.15; [Split DNS RFC 8598](https://www.rfc-editor.org/rfc/rfc8598.html).
