# SAML-over-IPsec authentication handshake

How FortiClient turns a browser SAML/SSO login into IKEv2 credentials. Reverse
-engineered from `FortiTray` (`getIpsecSAMLUrl`, `SamlExternalBrowser`,
`SamlVpnConnect`) and `iked`, and confirmed against the live gateway for the
first step.

This was the Fortinet-private binding that the standalone OFTC client now
implements. This document records how it was discovered; see
[architecture](architecture.md) for the active implementation.

## Players

- **FortiTray** — runs a short-lived **loopback HTTP server** on a random port
  (`HTTPServer.startListeningDynamic`), opens the system browser, and waits for
  the gateway to redirect back to that port.
- **Gateway** — FortiGate, SAML port `9443` (profile `IKESamlPort`).
- **Browser** — the user's default browser; does the actual IdP SSO.
- **iked** — consumes the bootstrap UID and resulting token as EAP credentials.

## Step by step

```
FortiTray                         Gateway (:9443)                 Browser / IdP
    |                                   |                               |
    | 1. POST /saml_login?              |                               |
    |    UID=<fct-uid>&REDIRECT_PORT=<p>|                               |
    |    Content-Type: x-www-form-urlencoded                           |
    |---------------------------------->|                               |
    |                                   |                               |
    | 2. 200 OK, body:                  |                               |
    |    <script>window.location=       |                               |
    |      "https://<gw>:9443/saml?<id>"|                               |
    |<----------------------------------|                               |
    |                                   |                               |
    | 3. open "https://<gw>:9443/saml?<id>" in external browser ------->|
    |                                   |   4. SAML AuthnRequest → IdP  |
    |                                   |<=============== SSO ==========>|
    |                                   |                               |
    | 5. gateway 302s browser to        |                               |
    |    http://localhost:<p>/?tokenid=<32hex>&username=<user>          |
    |<================= (browser hits our loopback server) =============|
    |                                   |                               |
    | 6. FortiTray extracts tokenid + username                          |
    |    -> gives iked bootstrap UID as EAP identity, token as password |
    |                                   |                               |
    | 7. iked runs IKEv2 + EAP over UDP 4500, with TCP 4443 fallback   |
```

### Step 1 — bootstrap request (reproducible)

FortiTray builds, in `getIpsecSAMLUrl`:

- a loopback listener on a dynamically chosen free port `p`;
- a `POST` to `https://<server>:<IKESamlPort>/saml_login?` with
  `Content-Type: application/x-www-form-urlencoded`;
- a body that includes `REDIRECT_PORT=<p>` and the FortiClient UID (`UID=`), plus
  a `UID:` request header. (String fragments seen in the binary:
  `/saml_login?`, `&REDIRECT_PORT=`, `UID`, the fallback literal `8020`.)

The gateway responds with an HTML page whose only content is a JS redirect to
`https://<server>:9443/saml?<16-hex-session-id>`.

> Verified: a hand-built `curl` POST to `/saml_login?` with a random UID and a
> `REDIRECT_PORT` returns exactly this `window.location="…/saml?<id>"` page. The
> raw `/saml?<id>` endpoint then drives the SAML flow in a browser.

The historical loopback listener and probe recipe are available with
`git show legacy-controller:tools/saml_catch.py` and
`git show legacy-controller:tools/README.md`.

### Step 5/6 — the callback

The gateway redirects the browser, after successful SSO, to:

```
http://localhost:<p>/?tokenid=<TOKENID>&username=<USERNAME>
```

FortiTray reads it two ways (it handles both a redirect and an HTML form):

- query parameters `tokenid=` / `username=` / `id=`, and
- regexes over the returned HTML body: `name="tokenid" value="([^"]+)"` and
  `name="username" value="([^"]+)"`.

`TOKENID` is a **single-use** credential (32 hex chars in the observed case).
Treat it like a password: it is consumed by one IKE auth and then dead. Nothing
in this repo stores it.

### Step 7 — into IKE

- The `UID` in the `/saml_login` bootstrap → EAP identity. Live FortiGate
  diagnostics showed its SAML auth cache is keyed by that UID; using the callback
  `username` as EAP identity failed. See Issue 6's Phase 2 live validation.
- `tokenid` → EAP password / OTP. In `iked` this is `g_fct_eap_password`; the
  helper `fct_use_eap()` simply returns "is the eap password set?", and when true
  the client authenticates with **EAP only** (it omits its own `AUTH` payload and
  lets the gateway verify via EAP). `fct_eap_peer_set_otp()` feeds the token in.

Details of the IKE exchange, the Fortinet vendor IDs, and the private notify
payloads are in [`ike-dialect.md`](ike-dialect.md).

## Gotchas

- **300 s SAML timeout** — FortiTray cancels if login takes too long
  (`authTimeout` timer).
- FortiTray adds a **hosts entry / lockdown exclusion** for the SAML FQDN during
  login and removes it after (`Adding SAML Host Entry`, `add saml host to lockdown
  exclusion`). A replacement that doesn't enable network-lockdown can ignore this.
- `UseExternalBrowser=1` here. There is also an internal-`WKWebView` path
  (`SamlVpnConnectWindowController`) for `UseExternalBrowser=0`.
- FQDN-consistency option can rewrite the redirect URL
  (`FQDN Consistency is enabled redirect url for IPsec SAML`).
