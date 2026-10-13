# Gateway contract for standalone `oftc` (2026-10-07)

This is a redacted Gate 1 record for the existing `Office VPN` profile. Evidence is the installed `vpn.plist` and generated `iked.conf` read locally today, the operator's read-only `show full-configuration` output for gateway phase 1 and system settings, plus the prior successful FortiClient/`oftc` diagnostics in [Issue 2](../../Issues/002-enable-test-server-side-client-resume.md), [Issue 6](../../Issues/006-prototype-reuse-iked-replace-tray.md), [Issue 8](../../Issues/008-capture-live-eap-method-and-vendor-ids.md), and the [dialect map](../../docs/ike-dialect.md). No new login, token use, or active-tunnel change was made for this record. The pasted full configuration is **not** copied into the repo.

## Established profile and observed wire behavior

| Area | Evidence-backed contract |
| --- | --- |
| Gateway phase 1 | Read-only gateway config confirms **`vpn-ikev2`**: dynamic peer, IKEv2, PSK, mode config and EAP enabled; `eap-identity send-request`, local ID configured with `localid-type auto`, and `authusrgrp` configured. A prior gateway IKE debug accepted the Fortinet IKE_SA_INIT offer and matched a proposal. The configured local-ID value is omitted here. |
| IKE offer and match | Current generated `iked.conf`: AES-256-CBC with HMAC-SHA1 **or** HMAC-SHA2-256, ECP-384/DH group 20. Gateway config: `proposal aes256-sha256 aes256gcm-prfsha256`, `dhgrp 14 19 20`, lifetime 86400 s. **Inference:** AES-256-CBC/SHA2-256/group 20 is the sole overlap. The negotiated integrity/PRF tuple was not separately captured. |
| CHILD_SA offer | Current generated `iked.conf`: ESP AES-256-CBC/HMAC-SHA1, ECP-384/group 20 with PFS; lifetime 43200 s. The generated file repeats this same offer. The successful tunnel proves a compatible CHILD_SA, but the selected ESP transform was not separately logged. |
| Authentication and identity | Gateway authenticates with a phase-1 PSK; client uses EAP without an initial client `AUTH`. The `/saml_login` bootstrap **UID must equal the EAP identity**: gateway SAML cache and FNBAM diagnostics proved this binding. The single-use callback `tokenid` is the EAP secret. The callback `username` is not the EAP identity. Client profile `LocalID` is empty, while the gateway has a nonempty local ID; on-wire IDi type/value and IDr remain unverified. No UID, token, or PSK is recorded here. |
| EAP method | Client profile `IKEEAPMethod=0` means automatic selection. A later authorized no-SSO probe using the configured UID received EAP-MSCHAPv2 (IETF vendor 0, type 26) after EAP Identity on both UDP and TCP. The prior GTC hypothesis was wrong. The token-bearing exchange has not been tested. |
| Fortinet IKE_SA_INIT metadata | `iked` emits three 16-byte VIDs: `4c53427b6d465d1b337bb755a37a7fef`, `b4f01ca951e9da8d0bafbbd34ad3044e`, `c1dc4350476b98a429b91781914ca43e`. The gateway recognized all three in prior debug. Client profile `NetworkID=0`; gateway debug reported reading private `VPN_NETWORK_ID` (0xF050), but the exact notify payload bytes and whether it is required remain unverified. Gateway config has `network-overlay disable`, `dev-id-notification disable`, and `ems-sn-check disable`; these settings do not prove 0xF050 or 0xF100 may be omitted. `FORTICLIENT_CONNECT` (0xF100, license data) is emitted in **both** IKE_SA_INIT and IKE_AUTH and decoded by the gateway on the working path. `DEV_ID_NOTIFY` (0xF103) is conditional on SASE mode, disabled in this profile; `CLIENT_RESUME` (0xF118) is conditional. |
| Mode config | Current `iked.conf` requests IPv4 address, netmask, DNS server, protected subnet, internal DNS domain, and Unity `AUTO_NEGOTIATE`, `ALWAYS_UP`, `SAVE_PASSWD`, `SPLIT_EXCLUDE`. Prior working sessions received a virtual IPv4 address and split include route. The exact returned attribute codes/values and IKE traffic selectors have not been retained as a redacted wire record. |
| Transport | Client profile: NAT-T enabled, UDP 4500 primary, TCP 4443 fallback. Gateway config: `nattraversal enable`, `transport auto`, **`fortinet-esp disable`**, and system `ike-tcp-port 4443`. On the tested network, **both official FortiClient and `oftc` received no UDP 4500 IKE_SA_INIT reply**. A prior no-SSO TCP run received a SYN reply and exchanged IKE_SA_INIT and IKE_AUTH using the six-byte `IKETCP` stream prefix. This proves TCP IKE reachability there, not UDP reachability or ESP framing. |

For TCP, [RFC 9329](https://www.rfc-editor.org/rfc/rfc9329.html) specifies one originator `IKETCP` prefix, then a two-byte network-order length per record **including that length field**, a four-byte zero marker before IKE, and ESP without that marker. The prior record confirms the prefix and IKE exchange; a redacted parsed trace has not confirmed each length or ESP record. The confirmed `fortinet-esp disable` setting matches [Fortinet's standards-based mode for FortiClient dial-up](https://docs.fortinet.com/document/fortigate/7.4.10/administration-guide/351073/encapsulate-esp-packets-within-tcp-headers); actual ESP records still need validation.

## Exact remaining evidence

1. **CHILD_SA gateway config and selected algorithms/identity:** read-only `show full-configuration vpn ipsec phase2-interface` for the entry whose `phase1name` is `vpn-ikev2`, with internal addresses and selectors redacted. From an *existing* successful session, a redacted `diagnose vpn ike gateway list name <active vpn-ikev2 instance>` or existing IKE debug could show the chosen IKE proposal/PRF, IDi/IDr type, and CHILD_SA proposal/traffic selectors. Such diagnostics can include key material; share only those named fields, never raw output.
2. **EAP:** method selection was resolved by the later
   [no-SSO IKE_AUTH probe](../ike-auth/README.md): IETF vendor 0, MSCHAPv2
   type 26 on both transports. A token-bearing challenge/response remains open.
3. **UDP path:** subsequently resolved on this Mac's IPv4 network by the
   [no-SSO SA_INIT probe](../ike-sa-init/README.md), which received and parsed a
   gateway IKE response on UDP 4500. This supersedes the earlier negative UDP
   observation above; it does not prove UDP works on every network.
4. **Private notify policy:** a no-SSO SA_INIT response after omitting 0xF050/0xF100 would prove only that those notifies are unnecessary for *that exchange*; no response would remain ambiguous. Neither outcome establishes whether IKE_AUTH without 0xF100 is accepted. The latter needs a later authorized, diagnosed EAP attempt. A passive FortiClient capture only proves what FortiClient sent.

## Gate 2 decision

The **no-SSO IKE_SA_INIT probe can proceed on TCP 4443** with the overlapping AES-256-CBC/SHA2-256/group-20 offer and RFC 9329 framing; EAP and a SAML token are not needed for SA_INIT. Start with one bounded, logged probe and classify a missing response as transport, phase-1 selection, transform, or private-notify ambiguity rather than a policy verdict. The UDP half requires a UDP-capable path or corresponding gateway receive/response evidence. Gate 1 is therefore not fully closed: selected EAP method, exact negotiated IKE tuple/IDs and CHILD_SA settings, and a working UDP path remain open.

**Later result:** both UDP and TCP SA_INIT probes succeeded on 2026-10-07,
selecting AES-256-CBC/SHA256/ECP-384. The subsequent
[IKE_AUTH probe](../ike-auth/README.md) verified responder PSK AUTH and received
EAP Request/Identity on both paths without private notifies. After the
authorized UID reply, both paths selected MSCHAPv2. The full CHILD_SA contract
and ESP framing remain open.

**Subsequent live interoperability result:** the standalone runner completed
EAP-MSCHAPv2 and authenticated a CHILD_SA on both UDP 4500 and TCP 4443, then
received an integrity-checked ESP reply over each transport. It did not send
the Fortinet-private SA_INIT or IKE_AUTH notifies, so they are not required for
this gateway/profile's tested full exchange. The selected ESP suite, assigned
IPv4 address, narrowed selectors, and split route were parsed from the
authenticated exchange; [Gate 3](../ike-gate3/README.md) and the
[TCP proof](../tcp-live-probe/README.md) record those checks without secrets.
The signed version 5 provider subsequently passed one UDP packetFlow echo and
reply with the assigned address and split route; see the
[Gate 4 result](../signed-provider-join/README.md). A read-only phase-2
configuration record and a redacted identity-type comparison remain useful
documentation, but no longer block the observed vertical slice.
