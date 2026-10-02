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

### The deciding code path

In the `FortiTray` binary (the real VPN manager; the Electron app is just a GUI):

- `-[LegacyIpsecBridge handleSystemSleep:]` is registered for the private
  notification `com.fortinet.forticlient.vpn.willSleepNotification` (and a
  matching `...didWakeupNotification` for wake).
- There is a boolean selector **`-[LegacyIpsecBridge setDisconnectOnSleep:]`**
  and a function `_ipsec_system_sleep` — i.e. the teardown-on-sleep is gated by a
  flag. Finding what sets that flag is the highest-value lead for a *zero-code*
  fix (see ROADMAP §0).
- `VpnManager.swift` logs `System sleep disconnect enabled` on the stop path —
  this string did not exist in 7.4.1, which the community reports as the last
  version that survives lock.

### Why "Connect without Reauth" doesn't save us today

FortiTray has a whole "connect without reauthentication" subsystem
(`tunnelConnectWithoutReauth`, `Connect without Reauth to previous tunnel before
sleep`, `Timeout limit passed for connect without reauth`). But it is **disabled
unless the profile allows keep-running / save-password / auto-connect**, and this
free profile sets all of those to 0 (`AllowKeepRunning=0`, `AllowSavePassword=0`,
`AllowAutoConnect=0`). So the client takes the "disconnect and require full SAML
re-auth" branch.

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
