# IPv6 outer preflight (no SSO)

This spike reuses the existing SA_INIT and IKE_AUTH codecs with an IPv6
`UdpSocket` or `TcpStream`. It resolves the gateway through the Mac's current
system resolver and **requires an IPv6 result**. On the known IPv6-only phone
tether, that result should be the DNS64-synthesized address of the IPv4-only
FortiGate. It does not embed a NAT64 prefix or assume a particular one.

The default sends only IKE_SA_INIT and verifies the selected transform, peer
P-384 point, and NAT detection payloads. `--idi-v4 ADDRESS` additionally sends
one initial IKE_AUTH request and verifies the gateway's PSK AUTH. It stops at
the EAP Identity request. It never sends a machine UID, SAML token, EAP
response, client AUTH, or ESP packet, and it never installs a route or VPN.
An IPv4 IDi can be carried inside IKE_AUTH over an IPv6 outer socket; whether
this gateway accepts that identity combination is deliberately a live question.

Build and run the offline tests:

```sh
sh spikes/ipv6-outer/run.sh
```

The runner passed 22 tests on 2026-10-07, including resolver-family selection,
independently calculated IPv6 NAT-D hashes for ports 4500 and 4443, and a
synthetic IPv6 response with both matching and mismatching NAT-D values. The
build command sends no packet. Reused codec tests account for the other tests.

## Tether and no-SSO live probe for Gate 5

1. Connect the Mac to the known IPv6-only phone hotspot; turn off other uplinks
   so the gateway route uses the tether. Keep the existing FortiClient tunnel
   disconnected. Check the Mac has a usable global IPv6 address and a route to
   the resolved gateway. On the observed T-Mobile setup, the 464XLAT IPv4 shim
   was `192.0.0.2`; verify the current address rather than assuming it.
2. With the tether active, inspect `scutil --dns` and run
   `dns-sd -G v6 "$GATEWAY"` (stop it with Ctrl-C). Confirm the system resolver
   returns a synthesized IPv6 address for the IPv4-only gateway. Set
   `GATEWAY` to the profile's hostname. If this returns only IPv4, the probe
   fails before opening a socket; that is a resolver/network setup result.
3. Run `spikes/ipv6-outer/ipv6-outer --gateway "$GATEWAY"` on **UDP 4500
   first**. This makes two bounded sends of one identical SA_INIT request and
   checks the actual IKE reply. If UDP has no reply, run the independent
   `--transport tcp` probe on TCP 4443. A TCP SYN alone is not a pass: it must
   receive and parse an IKE_SA_INIT response using the `IKETCP` prefix and
   RFC 9329 length framing.
4. If SA_INIT succeeds, run the same transport with `--idi-v4 ADDRESS`, where
   `ADDRESS` is the current CLAT IPv4 address. This loads the locally installed
   `Office VPN` PSK and stops after verifying the responder's PSK AUTH and reporting
   the requested EAP type. It does not spend an SSO token. If the gateway
   rejects this IPv4 IDi over IPv6, a true IPv6 IDi variant should be tried
   before treating the outer transport as unsupported.

The two NAT-D match flags may be false across NAT64 because the gateway sees
translated IPv4 addresses and ports. A mismatch is a translation signal, not
by itself an IKE failure. Keep UDP 4500 encapsulation for later IKE and ESP.
The probe prints only stage, suite, match flags, EAP type, and notify codes;
it does not print PSK, keys, packet bytes, or token data. Record the resolved
address family, transport, last successful exchange, selected proposal, and
gateway diagnostic without saving raw packet captures or secrets.

This preflight does **not** complete Gate 5. After Gate 4's authenticated UDP
packet round trip works on an ordinary IPv4 path, Gate 5 still requires a
fresh authenticated CHILD_SA and a real protected packet round trip on the
IPv6-only tether. Repeat that round trip first on UDP 4500 and then, where
UDP is restricted, with **both IKE and ESP on the same TCP 4443 stream**.
Recreate the IKE SA when switching transport. Verify reply traffic, split
routes, DNS, MTU, and clean teardown; classify any failure before another
single-use SSO attempt.

Wire rules: [IKEv2 NAT detection and UDP encapsulation, RFC 7296 §2.23](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.23)
and [IKE/ESP TCP encapsulation, RFC 9329](https://www.rfc-editor.org/rfc/rfc9329.html).

## Live no-token result, 2026-10-07

On the operator's IPv6-only phone hotspot, `scutil --nwi` reported a global
IPv6 address and CLAT `192.0.0.2` on `en0`. The system resolver returned an
IPv6 gateway endpoint. Independent UDP 4500 and TCP 4443 probes each received
a valid IKE_SA_INIT response selecting AES-256-CBC/SHA256/ECP-384. The
responder's NAT-D hashes differed from the local values, as expected across
NAT64. With `--idi-v4 192.0.0.2`, both transports then verified the
responder's PSK AUTH and received EAP Request/Identity. Neither probe sent a
UID, SAML token, EAP reply, ESP packet, route, or VPN setting. The remaining
Gate 5 question is authenticated EAP/CHILD_SA plus an ESP reply on this path.
