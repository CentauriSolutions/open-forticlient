# FortiClient's IKEv2 dialect

Extracted from the bundled `iked` (an OpenIKED fork). These are the pieces a
replacement must reproduce for the FortiGate to accept it as a FortiClient. All
numeric tables below were dumped from the daemon's own name-map arrays
(`_ikev2_n_map`, `_ikev2_cfg_map`, `_ikev2_exchange_map`, etc.).

This is historical protocol analysis. The standalone OFTC provider passed
authenticated traffic without Fortinet's private license notify; see
Issue 3.

## Vendor IDs (IKE_SA_INIT)

`ikev2_init_ike_sa_peer` sends **three 16-byte vendor IDs** (each built with
`ikev2_add_vendor_id`), then conditionally the Fortinet notify payloads. The
three VID constants were read straight out of the daemon's `__TEXT,__const`
(consecutive 16-byte slots at `0x1004bca40`/`0x50`/`0x60` in the thinned x86_64
`iked`):

| # | 16-byte VID (hex) | Meaning |
|---|-------------------|---------|
| 1 | `4c53427b6d465d1b337bb755a37a7fef` | binary constant (preimage unknown) |
| 2 | `b4f01ca951e9da8d0bafbbd34ad3044e` | **MD5("Fortinet Endpoint Control")** — verified |
| 3 | `c1dc4350476b98a429b91781914ca43e` | binary constant (preimage unknown) |

VID #2 is confirmed to be the MD5 digest of the ASCII string `Fortinet Endpoint
Control`. #1 and #3 are opaque 16-byte constants (likely MD5s of version-tagged
strings); the raw bytes above are what a replacement must send verbatim to look
like FortiClient. A non-Fortinet stack can send these three VIDs to masquerade,
but see `FORTICLIENT_CONNECT` below for the part that can't be faked without the
license blob.

## Fortinet-private notify types

Standard RFC 7296 notify types are present as usual. The **private** ones
(from `_ikev2_n_map`) are the interesting part:

| Decimal | Hex (wire) | Name | Added by |
|--------:|-----------|------|----------|
| 61520 | 0xF050 | `VPN_NETWORK_ID` | `ikev2_add_network_id` (payload = `g_fct_network_id`) |
| 61696 | 0xF100 | `FORTICLIENT_CONNECT` | `ikev2_add_forticlient_connect` (payload = raw license blob from `LicGenRawLicenseInfo2`) |
| 61699 | 0xF103 | `DEV_ID_NOTIFY` | `ikev2_add_adc_emssn` (payload = EMS serial; only when `g_fct_sase_mode`) |
| 61720 | 0xF118 | `CLIENT_RESUME` | `ikev2_add_client_resume` (the session-resumption capability flag) |

(Also present in the map: standard `FRAGMENTATION_SUPPORTED` 16430,
`SIGNATURE_HASH_ALGORITHMS` 16431, `REDIRECT*`, `TICKET_*`.)

**Wire encodings verified** from each `ikev2_add_*` builder (the notify type is a
little-endian 16-bit word written at payload offset +2, so the stored word is
byte-swapped relative to the wire value): `network_id` writes `0x50f0` → wire
**0xF050**; `adc_emssn` writes `0x03f1` → wire **0xF103**; `forticlient_connect`
writes `0x00f1` → wire **0xF100**; `client_resume` passes `0xf118` straight to
`ikev2_add_notify` → wire **0xF118**. All four match the table.

### `FORTICLIENT_CONNECT` (0xF100) — the licensing gate

`ikev2_add_forticlient_connect` calls `LicGenRawLicenseInfo2(g_fct_user,
g_fct_reg_status, g_fct_emssn, g_fct_ems_tenant_id, …)` and ships the result as
the notify data, prefixed with a 2-byte `0x00F1`-family tag. The live
standalone provider later established authenticated traffic without it on the
tested gateway; the private notify was not required for that path.

Confirmed in this build: `ikev2_add_forticlient_connect` is called from **both**
`ikev2_init_ike_sa_peer` (IKE_SA_INIT) and `ikev2_init_ike_auth` (IKE_AUTH), and
its payload is `LicGenRawLicenseInfo2(g_fct_user, g_fct_reg_status, g_fct_emssn,
g_fct_ems_tenant_id, …)` tagged with the 2-byte `0x00f1` family word. So a stock
strongSwan IKE_AUTH would also omit it. Gateway acceptance is recorded in
Issue 3.

### `CLIENT_RESUME` (0xF118) + `IKE_SESSION_RESUME`

The daemon implements RFC 5723-style resumption:

- Exchange type `38 = IKE_SESSION_RESUME` (in `_ikev2_exchange_map`, alongside the
  standard 34–37).
- Notify `CLIENT_RESUME` (0xF118) advertised in IKE_SA_INIT when the SA has a
  stored resume blob.
- Log strings: `IKEV2_N_CLIENT_RESUME received/encrypted`, `client resume enabled`,
  `Enable client resumption: %d`.

This is the on-the-wire half of the server-side `set client-resume enable`
option (ROADMAP §A): the gateway keeps the SA alive for `client-resume-interval`
seconds across a network drop / sleep, and the client resumes instead of doing a
full IKE_AUTH (which would re-trigger SAML).

## Authentication shape

Matches the known strongSwan↔FortiGate recipe:

- **Remote (gateway) auth = PSK** — `iked.conf` carries a `psk` and the gateway
  sends its `AUTH` with `SHARED_KEY_MIC` (auth method 2).
- **Local (client) auth = EAP** — when `fct_use_eap()` is true (the SAML token is
  set as the EAP password), the client sends **no `AUTH` payload** in its first
  `IKE_AUTH` and authenticates via EAP. On the working connection, EAP identity
  equals the device `UID` sent to `/saml_login`, not the callback `username`;
  password/OTP = SAML `tokenid` (Issue 6, Phase 2 live validation).
- EAP methods compiled in (`_eap_type_map`): the full wpa_supplicant set incl.
  `GTC(6)`, `MSCHAP_V2(26)`, `PEAP(25)`, `TTLS(21)`, `TLS(13)`, `OTP(5)`. The
  SAML-token flow feeds the token as the EAP password. A no-SSO standalone
  exchange using the FortiClient UID received **EAP-MSCHAPv2 (IETF vendor 0,
  type 26)** after EAP Identity on both UDP 4500 and TCP 4443. No expanded vendor field was
  present. [Microsoft's wire specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-chap/6cdfa42c-173a-4780-80e1-8872abdeaa30)
  uses type `0x1A` for this method; the [IANA registry](https://www.iana.org/assignments/eap-numbers)
  currently labels type 26 differently. An additional authorized UDP probe
  confirmed inner opcode 1 (Challenge) and a 16-byte challenge, without
  logging challenge bytes. The token-bearing exchange remains untested
  (Issue 14).

## Config (mode-config) attributes requested

From `iked.conf` `request …` lines and `_ikev2_cfg_map`. Standard ones
(`INTERNAL_IP4_ADDRESS/NETMASK/DNS`, `INTERNAL_DNS_DOMAIN=25`) plus **Cisco Unity**
private attributes Fortinet reuses:

| Decimal | Name |
|--------:|------|
| 21514 | `UNITY_AUTO_NEGOTIATE` |
| 21515 | `UNITY_ALWAYS_UP` |
| 28673 | `UNITY_SAVE_PASSWD` |
| 28678 | `UNITY_SPLIT_EXCLUDE` |

The observed split tunnel handed back by the gateway: include `10.20.0.0/21`,
internal address from `10.77.0.0/16` range.

## IKE transforms observed (this gateway)

- IKE SA: `AES-256-CBC` / `HMAC-SHA1` or `HMAC-SHA2-256` / DH `ECP-384 (group 20)`.
- CHILD SA (ESP): `AES-256-CBC` / `HMAC-SHA1` / `ECP-384`.
- IKE lifetime 86400 s, CHILD lifetime 43200 s. NAT-T (UDP 4500), DPD on,
  IKE fragmentation available. TCP-fallback port 4443.

## Transport

`transport` can be `udp` (4500), `tcp` (4443), or fall back udp→tcp. This gateway
uses UDP 4500 with NAT-T by default (`TransportMode=2` in the profile).
