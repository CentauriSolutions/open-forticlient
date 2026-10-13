# Provider IPv6 transport preflight

This candidate is separate from the signed v4 provider. It exposes one
provider-callable Rust C ABI for a **no-token** IKEv2 preflight on an IPv6 outer
socket. The caller chooses UDP 4500 or TCP 4443; no fallback is automatic.
The gateway hostname is resolved through the system resolver, and the result
must contain a native IPv6 address (including a DNS64 synthesized address).
The caller supplies the currently observed CLAT IPv4 address as the IKE IDi;
the Rust code does not infer it from the IPv6 socket or use a saved value.

The preflight runs IKE_SA_INIT, verifies the responder's PSK AUTH, sends the
32-hex-digit UID as EAP Identity, and parses the EAP-MSCHAPv2 challenge. It
never acquires or sends a SAML token, completes EAP, installs a CHILD_SA,
sends ESP, or changes routes, DNS settings, or packetFlow settings. The caller owns and
must clear the PSK buffer. The function returns a stage code, not packet or
secret data.

```sh
sh spikes/provider-transport-preflight/run.sh
```

This builds `liboftc_transport_preflight.dylib` under `$TMPDIR` and runs 27
offline tests, including the reused SA_INIT, AUTH, and EAP codec tests. It
also checks the exported ABI symbol. The test runner sends no gateway traffic.

## ABI

See [oftc_transport_preflight.h](oftc_transport_preflight.h). Call
`oftc_provider_preflight_ipv6(gateway, uid, psk, idi_v4, transport)` with
length-delimited buffers; `idi_v4` is exactly four octets. Use transport
`OFTC_PREFLIGHT_UDP_4500` (1) first. Use `OFTC_PREFLIGHT_TCP_4443` (2) only
for a separate fallback attempt. The function is blocking and belongs on a
provider worker queue. Result `0` means the authenticated EAP challenge was
received; `1` invalid input; `2` resolution/socket/timeout; `3` SA_INIT;
`4` responder AUTH; `5` EAP challenge or internal failure.

Socket operations have fixed deadlines: DNS gives the caller up to 3 seconds,
TCP connect up to 4 seconds, and each IKE exchange at most 5 seconds. UDP
uses two sends with 2- and 3-second reply windows per exchange. The system
resolver runs on a separate short-lived thread because `getaddrinfo` has no
native deadline; if the caller times out, that resolver thread may finish
later but has no PSK, UID, or socket and cannot start IKE.

## Signed-provider integration boundary

The current signed v4 extension calls the IPv4 UDP-only
`oftc_provider_preflight` from `signed-provider-join/Provider/preflight.rs`.
A later provider revision must bundle this dylib, link its header/symbol,
select UDP or TCP, and determine the active interface's current CLAT IPv4
address before calling it. The existing HBR1 bootstrap envelope carries
gateway, UID, and PSK, but **does not carry an IDi or transport choice**;
those must come from a validated ephemeral option or be discovered in the
provider for the specific active path. No signed app currently calls this
candidate. A pass here is an offline implementation check, not a live
NetworkExtension result.
