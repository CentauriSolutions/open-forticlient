# The `vpn_control` control-socket protocol

Historical Fortinet-backed controller research. The current OFTC client does
not use this socket; its source is under the `legacy-controller` tag.

How FortiTray (and its embedded `libipsec`) drives the privileged daemon
`fctctld`, which in turn runs `iked`/`racoon`. Reverse-engineered from
`FortiTray`'s `libipsec.c`/`vpn_control_cli.c` code and `fctctld`'s
`vpn_control.c`. This is the interface a replacement controller (ROADMAP §C,
Issue 6) must speak to reuse Fortinet's `iked` without FortiTray.

## Sockets

Both are `AF_UNIX` / `SOCK_STREAM`.

| Path | Peer | Used by |
|------|------|---------|
| `/var/run/fctvpnctrl.sock` | `fctctld` main control | FortiTray/`libipsec` (`ipseccon_connect` → `connect_fctctld`). Created by launchd job `com.fortinet.fctctl` (`com.fortinet.forticlient.vpn.plist`), `SockPathMode 0777`. |
| `…/FortiClient/ipsec/fctvpnctrl_woker.sock` | `fctctld` *worker* | `ipseccon_get_otp`, `ipsec_system_sleep`/`_wake_up`, the "simple notify" and racoon-helper calls (`connect_fctctld_from_woker_daemon`). |

`fctctld` dispatches the main socket in `_ipsec_control_process` and the worker
socket in `_ipsec_control_worker_process` (log: `Receive a ipsec control request
from worker`). `iked` itself also opens `…/ipsec/fctvpnctrl_woker.sock`
(`_connect_fctctld_from_woker_daemon`).

## Message framing

A fixed **20-byte header (five little-endian `int32`s)** followed by a body.
`length` counts the whole message including the header.

```
offset  field       notes
 0x00   length       total bytes, incl. 20-byte header (ipseccon_recv reads
                      0x14 first, mallocs `length`, then reads length-0x14 more)
 0x04   (reserved)   usually 0
 0x08   command      see table below
 0x0c   (reserved)
 0x10   field16      preserved across recv; status/flags on some messages
 0x14   body…        command-specific
```

`ipseccon_send` writes `length` bytes; `ipseccon_recv` reads the 20-byte header,
allocates `length`, then reads the remainder. (From `_ipseccon_send` /
`_ipseccon_recv` in both FortiTray and `fctctld`.)

## Commands (the `+0x08` field)

| Dec | Name (inferred) | Direction | Body |
|----:|-----------------|-----------|------|
| 1  | `CONNECT`            | client→daemon | the full connection-config struct (~0x72ac bytes) at `+0x14` — server, user, PSK, proposals, all `Ipsec*` settings (see below). Sent by `libipsec` `monitor_thread` after `ipsec_connect`. |
| 5  | `DISCONNECT`         | client→daemon | 0x40-byte gateway id. `ipsec_disconnect`; this is what a **lock-triggered stop** sends, logged server-side as a *user* disconnect. |
| 6  | `STATUS`/`EVENT`     | daemon→client | status `int32` at `+0x14`; drives `ipsec_callback`. |
| 9  | `GET_OTP`            | daemon→client (worker) | prompt string (0x400) + id (0x20) + flag `int32` at `+0x474`. `ipseccon_get_otp`. |
| 10 | `SEND_OTP`           | client→daemon | OTP string (0x400) at `+0x14` + second field (0x40). `ipsec_send_otp`. |
| 12 | `RACOON_ERROR`       | client→daemon | error code at body `+0x40`. |
| 16 | `CERT_VERIFY_RESULT` | client→daemon | `ipsec_send_cert_verify_result`. |
| 17 | `SIGN_RESULT`        | client→daemon | `ipsec_send_sign_result` (IKEv2 client-cert signing done in FortiTray via Keychain). |
| 21 | `BANNER_RESULT`      | client→daemon | `ipsec_send_banner_result`. |
| 22 | `SYSTEM_SLEEP`       | client→daemon | empty. `ipsec_system_sleep`; daemon calls `suspendIKED`. |
| 23 | `SYSTEM_WAKE_UP`     | client→daemon | empty. `ipsec_system_wake_up`; daemon calls `resumeIKED` + `do_system_wake_up`. |

(Command values are the authoritative `+0x08` opcodes read straight from each
`ipsec_*`/`ipseccon_*` sender. Names are descriptive.)

## How a connection actually comes up

1. FortiTray runs the SAML flow (see `saml-ipsec-protocol.md`) → `username`,
   `tokenid`.
2. FortiTray builds the connection-config struct (`ipsec_init_conn_config` +
   `ipsec_init_conn_adv_settings`, keyed off the profile: `IpsecIkeVersion`,
   `IpsecIkeEAPMethod`, `IpsecIkeSamlPort`, `IpsecP1DhGroup`, `IpsecXauthEnabled`,
   `IpsecVIP*`, `IpsecRemoteNetwork*`, `IpsecIPv4SplitExcludeNetworks`, …) and
   sends **`CONNECT` (1)**.
3. `fctctld` (`_do_ipsec_connect` → `_iked_connect_vpn`) writes
   `…/ipsec/iked.conf` (`_iked_conf_gen_config_file`) and starts `iked`
   (`_iked_start`), feeding the PSK on request (`Received get psk request`).
4. When `iked` needs the EAP credential it asks via **`GET_OTP` (9)** on the
   worker socket; FortiTray answers with **`SEND_OTP` (10)** carrying the
   `tokenid`. `fctctld` forwards it with `_iked_send_otp` →
   `_fct_eap_peer_set_otp` in `iked` (log `iked_sa to send OTP`).
5. Cert/sig challenges, if any, round-trip as `CERT_VERIFY_RESULT`/`SIGN_RESULT`
   (FortiTray does the Keychain crypto). Status changes come back as `STATUS` (6).

## Sleep / wake vs. the lock-disconnect

- On **real sleep/wake**, `fctctld` suspends and resumes `iked` rather than
  destroying it: `SYSTEM_SLEEP`→`suspendIKED` (`__is_system_sleep=1`),
  `SYSTEM_WAKE_UP`→`resumeIKED`+`do_system_wake_up`+`handle_local_addr_changed`.
  The SA can then resume (IKE session resumption, notify `CLIENT_RESUME` 0xF118)
  instead of a fresh SAML login.
- The **lock drop** we are fixing is a different path: FortiTray's
  `AppDelegate.systemWillSleep` issues a full **`DISCONNECT` (5)** (via
  `checkAndStopVPN(SystemSleep:)` → `stopCurrentVPN(byUser:)`) *unless*
  `VpnManager.enableClientResumption` is set — see `FINDINGS.md`.

## Peer authentication: none (Phase 0 result, 2026-10-02)

`fctctld` does **not** authenticate or authorize whoever connects to these
sockets, so a non-FortiTray process can drive it:

- It imports no code-signing / audit-token APIs (`SecCode`/`SecStaticCode`/
  `SecRequirement`/`csops`/`audit_token` all absent; the `Sec*` it has are
  keychain). No `getpeereid`. The only `getsockopt` is nanomsg's `SO_ERROR`.
- The accept loop `_run_loop` passes the accepted fd straight to
  `_accept_new_connection` / `_accept_new_connection_from_worker`, which just
  spawn a handler thread (`_ipsec_control_process` / `_ipsec_control_worker_process`)
  — no peer check in between.
- `_listen_on_socket` does `chmod(path, 0777)` after `bind`, so any uid may
  connect. `geteuid`/`getuid`/`setuid` are imported but never called — no uid gate.

Privileged side effects (routes, DNS, SPD) are done by `fctctld` itself (root) and
the PrivilegedHelper, so the controller client can stay unprivileged. The only
practical constraint is contention: stop FortiTray so two controllers aren't
driving the daemon at once.

## What a §C controller must implement

Minimum to bring a tunnel up reusing Fortinet's `iked`:

- Connect `/var/run/fctvpnctrl.sock`, send `CONNECT` (1) with a populated
  connection-config body (easiest: mirror the struct FortiTray builds, or let
  `fctctld` read the `iked.conf` it already generates).
- Serve the worker side: answer `GET_OTP` (9) with `SEND_OTP` (10) = `tokenid`,
  and handle `CERT_VERIFY_RESULT`/`SIGN_RESULT` if the profile uses client certs
  (this profile does not — EAP only).
- Consume `STATUS` (6) events for up/down state.
- **Never send `DISCONNECT` (5) on screen lock.** Optionally send
  `SYSTEM_SLEEP`/`SYSTEM_WAKE_UP` only on real sleep.

## CONNECT (cmd 1) body — the connection-config struct

The `CONNECT` body is a single ~`0x72ac`-byte struct that FortiTray serializes
verbatim (`monitor_thread` copies `conn+0xc` for `0x72ac`). Field offsets below
are **relative to the body start** and were recovered two ways that agree:
FortiTray's `ipsec_print_conn_config` reads every field in format-string order,
and `fctctld`'s `iked_conf_gen_config_file` reads the same offsets to generate
`iked.conf`. Values shown are this profile's (`Office VPN`, from `conf/vpn.plist` +
the world-readable `ipsec/iked.conf`).

| Offset | Type | Field | This profile | Source |
|-------:|------|-------|--------------|--------|
| `0x0000` | char[0x80] | server (peer FQDN) | `vpn.example.com` | profile `Server` |
| `0x0080` | char[~0xC4] | user | `chris@sfcompute.com` | profile `User` |
| `0x0144` | i32 | auth_method | `0` (0=PSK+EAP/SAML, 1=cert) | `AuthMethod` |
| `0x0148` | i32 | cert_storage | `0` | — |
| `0x014c` | cstr | **psk** | `<from iked.conf>` | decrypted `AuthInfo` |
| `0x474c` | i32 | adv_settings_enabled | `1` | — |
| `0x4750` | i32 | ike_version | `2` | `IKEVersion` |
| `0x4754` | i32 | ike_eap_method | `0` (auto) | `IKEEAPMethod` |
| `0x4758` | i32 | saml_external_browser | `1` | `UseExternalBrowser` |
| `0x475c` | i32 | saml_fido_auth | `0` | `FidoAuth` |
| `0x4760` | i32 | sso_enabled | `1` | `SSOEnabled` |
| `0x4764` | i32 | **saml_port** | `9443` | `IKESamlPort` |
| `0x4768` | char[0x10] | ike_exg_mode | `aggressive` (IKEv2 ignores) | `ExchangeMode` |
| `0x4778` | i32 | ike_dh_group | `20` | `Phase1DHGroup` |
| `0x477c` | char[0x200] | ike_dh_groups | `20` (→ ecp384) | `Phase1DHGroupNew` |
| `0x497c` | char[0x200] | p1_props | aes256 sha1/sha256 | `Phase1Proposals` (translated) |
| `0x4b7c` | i32 | p1_key_life | `86400` | `Phase1KeyLifeSec` |
| `0x4b80` | i32 | dpd_enabled | `1` | `EnableDPD` |
| `0x4b84` | i32 | natt_enabled | `1` | `EnableNATT` |
| `0x4b88` | i32 | sase_mode_enabled | `0` | `EnableSaseMode` |
| `0x4b8c` | i32 | transport_mode | `2` | `TransportMode` |
| `0x4b90` | i32 | udp_port | `4500` | `UdpPort` |
| `0x4b94` | i32 | tcp_port | `4443` | `TcpPort` |
| `0x4b9c` | i32 | xauth_enabled | `1` | `EnableXAuth` |
| `0x4ba0` | i32 | vip_enabled | `1` | `EnableVIP` |
| `0x4ba8` | i32 | mode_cfg / vip_type | `1` | `EnableModeConfig`/VIP type |
| `0x4bb0` | i32 | fragmentation | `0` | `EnableIkeFragmentation` |
| `0x4bb8` | char[0x100] | remote_net | `` | `RemoteNetAddress` |
| `0x4cd8` | char[0x100] | ipv4_split_exclude | `` | `IPv4SplitExcludeNetworks` |
| `0x4dd8` | char[0x40] | vip (addr) | `` | `VIPAddress` |
| `0x4e18` | char[0x40] | vip mask | `` | `VIPMask` |
| `0x4e58` | char[0x40] | vip dns | `` | VIP DNS |
| `0x4e98` | cstr | srcid / local-ID | `` (empty) | `LocalID` |
| `0x4f9c` | char[0x200] | p2_props | aes256 sha1 | `Phase2Proposals` (translated) |
| `0x519c` | i32 | p2_dh_group | `20` | `Phase2DHGroup` |
| `0x51a0` | char[0x20] | p2_key_life_type | `seconds` | `Phase2KeyLifeType` |
| `0x51c0` | i32 | p2_key_life | `43200` | `Phase2KeyLifeSec` |
| `0x51c4` | i32 | p2_key_life_kbytes | `5120` | `Phase2KeyLifeKbytes` |
| `0x51c8` | i32 | p2_replay_detection | `0` | `Phase2ReplayDetectionEnabled` |
| `0x51cc` | i32 | p2_pfs | `1` | `Phase2PFSEnabled` |

The daemon computes `local`/`iface` itself (resolves its own outbound address),
so the client does **not** supply them. Still-unknown bytes: the small gaps
(`0x4b98`, `0x4ba4`), the large `0x14c`–`0x474c` region beyond the PSK (cert PEM /
host-check blob, unused for this EAP-only profile), and the trailing
`0x51d0`–`0x72ac`. These are zero/default for this profile.

**Build-and-validate plan for §C-b:** populate the fields above from
`conf/vpn.plist` + `ipsec/iked.conf`, zero the rest, send `CONNECT`, and diff the
`iked.conf` the daemon regenerates against the stock one. Any field we got wrong
shows up as a diff — a deterministic check that needs just one real SAML login
(single-use token; store nothing). A captured real `CONNECT` body can serve as a
template to fill the unknown gaps if the diff is not clean.
