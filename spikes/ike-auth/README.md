# No-SSO IKE_AUTH and responder AUTH spike

This isolated Rust probe continues the [SA_INIT spike](../ike-sa-init/README.md)
with an encrypted IKE_AUTH request. The default path does not authenticate
the client or reply to EAP; the opt-in path replies to EAP Identity and stops
at the gateway's next request. Neither path creates a CHILD_SA or uses a SAML
token. The installed FortiClient profile supplies the gateway PSK locally; the probe never prints or transmits
the PSK. The current request contains IDi as the local IPv4 address, one ESP
AES-256-CBC/HMAC-SHA1 proposal, wildcard IPv4 traffic selectors, and a small
mode-config request. It omits Fortinet private notifies.

Build and test locally:

```sh
sh spikes/ike-auth/run.sh
```

An explicit `--gateway HOST --transport udp|tcp` runs one bounded IPv4 network
probe. UDP retransmits at most once at each exchange; TCP uses RFC 9329
`IKETCP` and length framing. **By default**, the executable stops after its
first IKE_AUTH response. It sends no machine UID, EAP reply, or SAML token.
Packet bytes, PSK, and decrypted payloads are not logged.

The probe derives the IKE SA keys from P-384 ECDH and the two nonces, verifies
the 16-byte HMAC-SHA256 ICV before AES-256-CBC decryption, then checks the
responder's method-2 PSK AUTH over the signed SA_INIT response, initiator nonce,
and MACed IDr. A local test checks the AUTH construction against an independent
Python `hmac` vector. This validates the responder with the configured PSK;
an integrity check using SA-derived keys alone would not establish identity.

## Gateway result, 2026-10-07

The `Office VPN` macOS service was disconnected. On this IPv4 network, one probe
per transport reached the same stage:

| Transport | SA_INIT | IKE_AUTH response | Responder PSK AUTH | EAP |
| --- | --- | --- | --- | --- |
| UDP 4500 | accepted | decrypted, integrity checked | verified | Request/Identity (code 1, type 1) |
| TCP 4443 | accepted | decrypted, integrity checked | verified | Request/Identity (code 1, type 1) |

After explicit authorization for this gateway, `--send-uid` was run once on
each transport. It verified responder PSK AUTH, sent the Mac's persistent
FortiClient UID in one encrypted EAP Response/Identity, and received:

| Transport | Next gateway EAP request | Vendor |
| --- | --- | --- |
| UDP 4500 | Type 26, MSCHAPv2 | IETF standard type (no expanded vendor field) |
| TCP 4443 | Type 26, MSCHAPv2 | IETF standard type (no expanded vendor field) |

Both replies were integrity checked and had no other notify code. No SAML
token, EAP method response, client AUTH, or CHILD_SA was attempted. The gateway
accepted these exchanges without `FORTICLIENT_CONNECT` or a network-ID notify;
this does not prove those notifies are irrelevant later. The selected EAP
method is now known for this UID/profile on both transports. Client
authentication, assigned address, ESP, and IPv6 remain untested.

Type 26 is the Microsoft EAP-MSCHAPv2 code point used by the installed client;
[Microsoft's wire specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-chap/6cdfa42c-173a-4780-80e1-8872abdeaa30)
also identifies Type `0x1A` and the MSCHAPv2 challenge opcode. The current
[IANA EAP registry](https://www.iana.org/assignments/eap-numbers) labels type
26 `MS-EAP-Authentication` and separately lists type 29 as `EAP-MSCHAP-V2`.
After separate explicit authorization, one additional UDP probe parsed the
type-26 inner **opcode 1 (Challenge)** and **16-byte challenge size**. It did
not log challenge bytes or send a method response or token. The parser's
challenge shape also passed an offline test. This resolves the type-label
ambiguity for the observed gateway exchange; the full method remains untested.

The next Gate 3 experiment is a minimal MSCHAPv2 challenge/response and final
IKE_AUTH/CHILD_SA negotiation using one fresh single-use SAML token in memory.
Pair that attempt with gateway IKE/FNBAM diagnostics and classify any rejection
before consuming another token.

Wire rules: [IKEv2 RFC 7296, sections 2.15–2.16](https://www.rfc-editor.org/rfc/rfc7296.html),
[TCP encapsulation RFC 9329](https://www.rfc-editor.org/rfc/rfc9329.html).
