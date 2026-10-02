# Findings: why the tunnel drops on lock, and how the client is built

Captured from FortiClient `7.4.3.4323` on macOS 26 (Apple Silicon), March 2026 build.

## 1. Root cause: the client disconnects itself on screen lock

This is **client-side behavior**, not a gateway timeout or a network event.

### Log evidence

`~/Library/Application Support/Fortinet/FortiClient/Logs/fortitray.log`, at a lock:

```
AppDelegate.swift:379 System is locked/sleep
AppDelegate.swift:393 System is going to sleep
VpnManager.swift:2163 Check VPN Connect without Reauth
VpnManager.swift:2196 VPN Connection without reauthentication disabled.
VpnManager.swift:1808 Stop current VPN
VpnManager.swift:1811 Current VPN Office VPN
SamlVpnConnect.swift:377 VPN SAML - Set System Going to Sleep, stopping SAML Process
VpnManager.swift:1134 On VPN status change: TunnelRunning -> NotConnected
VpnManager.swift:1184 VPN disconnected
```

Every disconnect in the system logs (`.../Logs/fctctl.log`) is recorded as a
**user-initiated** disconnect (`ipsec_control:677 User disconnected the IPSEC
connection`), because FortiTray issues the stop command itself the moment macOS
reports the console locking.

Note `displaysleep` is 10 min but `sleep` is `0` (prevented) on this machine —
so the trigger is the **lock/display-sleep notification**, not real system sleep.

### The deciding code path (resolved — see §6)

In the `FortiTray` binary (the real VPN manager; the Electron app is just a GUI),
the screen-lock/display-sleep notification lands in the Swift method
**`AppDelegate.systemWillSleep(_:)`**. Disassembly of that method shows the
teardown is **conditional on a single boolean**:

```
systemWillSleep(_:):
    …
    if VpnManager.shared.enableClientResumption != 0 {
        // skip everything below — leave the tunnel alone
    } else {
        VpnManager.shared.connectWithoutReauthCheck()
        VpnManager.shared.checkAndStopVPN(SystemSleep: true)   // -> stopCurrentVPN(byUser:)
        VpnManager.shared.stopSAMLProcess()
    }
```

So when `enableClientResumption` is **false** (today), lock → full stop via
`checkAndStopVPN(SystemSleep:)` → `stopCurrentVPN(byUser:)` → a `DISCONNECT`
control message, logged server-side as a *user* disconnect, requiring a fresh
SAML login on return. When `enableClientResumption` is **true**, the entire stop
block is skipped and the tunnel is left up. (`VpnManager.swift` logs `System
sleep disconnect enabled` on the stop path; that string did not exist in 7.4.1,
the last version the community reports as surviving lock — consistent with the
free client simply never having the flag set.)

`-[LegacyIpsecBridge handleSystemSleep:]` / `setDisconnectOnSleep:` and
`_ipsec_system_sleep` are a *different*, legacy/racoon path that sends a
`SYSTEM_SLEEP` suspend (not a disconnect); they are not the code path that drops
this IKEv2+SAML tunnel on lock.

### Where `enableClientResumption` comes from (§6)

It is **not a local preference.** The only place it is set to a meaningful value
is `VpnManager.ipsecFgtOptions(allowSavePassword:KeepAlive:AutoConnect:ClientResumption:)`,
and there it is assigned directly as `enableClientResumption = (ClientResumption
!= 0)` — the gateway-advertised `allowClientResumption` flag, with no AND against
the profile and no license check *at that layer*. Everywhere else it is just
initialized to `0` (constructor, `startCurrentVPN`). The options arrive from the
daemon via the control socket (`ipsecFgtOptionsWithAllowSavePassword:allowKeepAlive:
allowAutoConnect:allowClientResumption:`), i.e. from what the FortiGate tells the
client during the connection.

**Consequence for the fix (see ROADMAP §0/§A/§C):** there is no client-side plist
to flip. The teardown is suppressible, but its off-switch is driven by the
*gateway*. Enabling `client-resume` on the FortiGate (Issue 2) is therefore the
cheapest thing to try — **but** it only helps if the gateway actually advertises
`allowClientResumption=1` to this free/unregistered client, which is unproven and
is the most likely place the known "free client" defect bites. The fix that does
*not* depend on Fortinet's cooperation is to replace the piece that issues the
lock-time `DISCONNECT` (ROADMAP §C / Issue 6): keep `fctctld`+`iked`, run our own
controller, and simply never send `DISCONNECT` on lock.

### "Connect without Reauth" also doesn't save us today

FortiTray has a separate "connect without reauthentication" subsystem
(`tunnelConnectWithoutReauth`, `Connect without Reauth to previous tunnel before
sleep`, `Timeout limit passed for connect without reauth`). It is **disabled
unless the profile allows keep-running / save-password / auto-connect**, and this
free profile sets all of those to 0 (`AllowKeepRunning=0`, `AllowSavePassword=0`,
`AllowAutoConnect=0`), so it does not rescue the lock case either.

## 2. Component map

| Component | Role | Location |
|-----------|------|----------|
| `FortiClient.app` | Electron GUI (`app.asar`) — buttons only | `/Applications/FortiClient.app` |
| **`FortiTray`** | The VPN brain: SAML, sleep/wake, profile, drives the daemon | `…/FortiClientAgent.app/Contents/Resources/FortiTray/FortiTray.app` |
| `iked` | IKEv2 daemon — an **OpenIKED fork with wpa_supplicant EAP** | `/Library/Application Support/Fortinet/FortiClient/bin/iked` |
| `fctctld` | Spawns `iked`/`racoon`; generates `iked.conf`/`racoon.conf` | `…/bin/fctctld` (launchd `com.fortinet.forticlient.vpn`) |
| `fct_tunnel_ctl` | PF_KEY/SADB + SPD programming for the tunnel | `…/bin/fct_tunnel_ctl` |
| PrivilegedHelper | Routes, split-DNS, firewall (root XPC helper) | `…/bin/com.fortinet.forticlient.macos.PrivilegedHelper` |

Build paths leaked in strings confirm the lineage:
`.../vpn/openiked/iked/ikev2.c`, `.../iked/eap/crypto/{crypto_openssl,tls_openssl}.c`
— so `iked` ≈ OpenIKED + an embedded EAP peer (wpa_supplicant: `wpa_printf`,
`eap_peer_set_otp`, the full `EAP-*` method set).

## 3. Runtime files worth knowing

Under `/Library/Application Support/Fortinet/FortiClient/`:

- `conf/vpn.plist` — all VPN profiles (the `Office VPN` profile here). IPsec params:
  IKEv2, aggressive, DH group 20 (ECP-384), NAT-T on, DPD on, UDP 4500 / TCP 4443,
  SAML external browser on, `IKESamlPort=9443`.
- `ipsec/iked.conf` — **world-readable**, regenerated per connect by `fctctld`.
  It is an OpenIKED config: `ikev2 "vpn" active esp …`, the IKE/child proposals,
  `psk <…>`, and a list of `request` mode-config attributes. This is the single
  most useful artifact for driving `iked` directly (see ROADMAP §C).
- `ipsec/fctvpnctrl_woker.sock` — control socket `iked`/`fctctld` talk over.
- `Logs/` — `fortitray.log` (user), `fctctl.log`/`fct_tunnel_ctl.log` (system).

The `iked.conf` proposals observed: IKE SA `aes-256 / hmac-sha1|sha2-256 / ecp384`,
child SA `aes-256 / hmac-sha1 / ecp384`, IKE lifetime 86400, child lifetime 43200.

## 4. What we proved works

- POSTing the SAML-bootstrap request to the gateway returns a real SAML URL
  (reproduced with `curl`; see `saml-ipsec-protocol.md`).
- A loopback HTTP listener receives the gateway's post-login redirect carrying
  `tokenid` + `username` — exactly what FortiTray consumes. (Captured once with
  consent to confirm the shape; the token itself is single-use and is not stored
  in this repo.)

## 5. Gateway (for reference)

- Profile `Office VPN`, server `vpn.example.com`.
- The operator has **FortiGate admin**, which unlocks the server-side option in
  ROADMAP §A.

## 6. The control socket (`vpn_control`) — fully mapped

FortiTray ↔ `fctctld` ↔ `iked` talk a simple framed protocol over two AF_UNIX
stream sockets (`/var/run/fctvpnctrl.sock` and `…/ipsec/fctvpnctrl_woker.sock`):
a **20-byte header (5× little-endian int32: length, _, command, _, flags)** plus
a body. Commands recovered from the senders: `CONNECT=1`, `DISCONNECT=5`,
`STATUS=6`, `GET_OTP=9`, `SEND_OTP=10`, `RACOON_ERROR=12`, `CERT_VERIFY=16`,
`SIGN=17`, `BANNER=21`, `SYSTEM_SLEEP=22`, `SYSTEM_WAKE_UP=23`. The SAML
`tokenid` reaches `iked` as the EAP OTP via `GET_OTP`/`SEND_OTP` →
`_iked_send_otp` → `_fct_eap_peer_set_otp`. Full schema and the connect flow are
in [`control-socket.md`](control-socket.md). This is the interface a §C
controller drives; the lock bug is literally FortiTray sending `DISCONNECT (5)`
when it could send nothing.

## 7. Daemon suspend/resume on sleep (separate from the lock drop)

`fctctld` keeps `iked` alive across real sleep/wake rather than destroying it:
`SYSTEM_SLEEP` → `_suspendIKED` (sets `__is_system_sleep`), `SYSTEM_WAKE_UP` →
`_resumeIKED` + `_do_system_wake_up` + `_handle_local_addr_changed` (log `resume
IKED success`). On wake the SA can resume via IKE session resumption (notify
`CLIENT_RESUME` 0xF118) instead of a fresh SAML login. This machinery is why
server-side `client-resume` *can* work — if the gateway advertises it to this
client (the open question in Issue 2). The daemon-side keyword appears as
`Enable Client Resumption: %d`; `iked` sends `CLIENT_RESUME` only when it holds a
resume context (gated in `_ikev2_init_ike_sa_peer`), and the generated
`iked.conf` carries no resume directive — it is driven by the FGT-advertised
option, not local config.

## 8. IKE identity confirmed from this build's `iked`

The three IKE_SA_INIT vendor IDs and the Fortinet-private notifies were read
directly out of the daemon (see [`ike-dialect.md`](ike-dialect.md) for the hex).
`FORTICLIENT_CONNECT` (0xF100, `LicGenRawLicenseInfo2` blob) is emitted in both
`IKE_SA_INIT` and `IKE_AUTH`, so whether a non-FortiClient stack (strongSwan,
§B) is accepted without it remains the §B-vs-§C decision blocker (Issue 3).
