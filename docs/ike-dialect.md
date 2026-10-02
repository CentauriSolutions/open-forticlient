# FortiClient's IKEv2 dialect

Extracted from the bundled `iked` (an OpenIKED fork). These are the pieces a
replacement must reproduce for the FortiGate to accept it as a FortiClient. All
numeric tables below were dumped from the daemon's own name-map arrays
(`_ikev2_n_map`, `_ikev2_cfg_map`, `_ikev2_exchange_map`, etc.).

## Vendor IDs (IKE_SA_INIT)

`ikev2_init_ike_sa_peer` sends **three 16-byte vendor IDs**, then conditionally a
set of Fortinet notify payloads. One VID decodes to the ASCII string
**`Fortinet Endpoint Control`** (MD5-based VID). The other two are binary
(non-ASCII) 16-byte constants stored in the daemon's data segment — capture them
from a live `IKE_SA_INIT` or from the `iked` `__const` section when implementing.

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

### `FORTICLIENT_CONNECT` (0xF100) — the licensing gate

`ikev2_add_forticlient_connect` calls `LicGenRawLicenseInfo2(g_fct_user,
g_fct_reg_status, g_fct_emssn, g_fct_ems_tenant_id, …)` and ships the result as
the notify data, prefixed with a 2-byte `0x00F1`-family tag. **Open question:**
does the gateway *require* a valid `FORTICLIENT_CONNECT` for the free
(unregistered) tier, or does it accept EAP auth without it? If it's required,
a non-FortiClient IKE stack (strongSwan) may be rejected and we must either
reproduce the (free-tier) license blob or reuse Fortinet's `iked` (ROADMAP §C).
The string `Forticlient Connect License` / `FORTICLIENT_CONNECT` sits right next
to the free-client checks, so this needs a live test.

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
  `IKE_AUTH` and authenticates via EAP. Identity = SAML `username`,
  password/OTP = SAML `tokenid`.
- EAP methods compiled in (`_eap_type_map`): the full wpa_supplicant set incl.
  `GTC(6)`, `MSCHAP_V2(26)`, `PEAP(25)`, `TTLS(21)`, `TLS(13)`, `OTP(5)`. The
  SAML-token flow uses the token as an OTP-style password; the exact method is
  gateway-chosen (capture from a live EAP exchange to confirm — likely GTC).

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
