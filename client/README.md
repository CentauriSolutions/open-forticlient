# oftc — open-forticlient CLI

A small Rust CLI with two explicit paths. `oftc standalone` invokes the OFTC
macOS app and packet-tunnel provider. The existing `oftc connect`, `up`, and
`down` commands still drive Fortinet's `fctctld`/`iked` as the rollback path;
see [`../docs/control-socket.md`](../docs/control-socket.md) for that protocol.

## Standalone backend (opt-in)

The standalone CLI calls the installed OFTC app's `IntegrationHost` directly.
The app owns SAML, the PSK in its Keychain item, its nonsecret profile, the
NetworkExtension VPN configuration, IKE/ESP, and reconnect supervision. A
normal standalone connection does not read FortiClient files or contact its
daemons. Importing an old profile is a one-time, explicit migration action.

```bash
oftc standalone activate                   # one-time extension activation
oftc standalone import-profile "Office VPN"     # one-time profile and PSK migration
oftc standalone install-config             # one-time macOS VPN configuration
oftc standalone show-profile
oftc standalone connect                    # foreground supervisor; UDP default
oftc standalone status                     # from another terminal
oftc standalone rekey-counts               # successful CHILD_SA rekeys, local/peer
oftc standalone disconnect                 # stop VPN and disable agent autostart

# Persistent per-user operation, after the profile and VPN configuration work:
# Disconnect any official FortiClient session first; leave it installed for rollback.
oftc down                                  # only if the legacy agent is running
oftc standalone install-agent              # stage; does not start a VPN
oftc standalone start-agent                # start now and at future GUI logins
oftc standalone status                     # check VPN state
oftc standalone stop-agent                 # stop VPN and disable login starts
oftc standalone uninstall-agent            # remove the agent
```

Without a FortiClient profile, use `save-profile GATEWAY SAML_PORT` and
`provision-psk GATEWAY` instead of `import-profile`; PSK input is read from the
terminal by the app. `save-profile ... --tcp` selects TCP 4443 explicitly.
The default UDP mode has bounded TCP fallback before a SAML token is spent.
`connect-once` starts a single connection without host supervision. `--app
/absolute/path/OFTC.app` before the command selects a development app;
otherwise the CLI uses `/Applications/OFTC development probe.app`.

`install-agent` records the app host's absolute path in
`~/Library/LaunchAgents/com.open-forticlient.oftc.standalone.plist` and stages
the job disabled. It does not activate the extension, create a VPN configuration,
or connect. With a development app, use
`oftc standalone --app /absolute/path/OFTC.app install-agent`; the chosen path is
then used by `start-agent` and `stop-agent`. To change apps, stop and uninstall
the agent, then install it again with the new path. Keep that app at the chosen
path while the agent is installed.

`start-agent` enables and kickstarts the per-user job in the current GUI session.
The job runs `IntegrationHost supervise-profile` directly, with verified SAML
TLS; `--insecure-saml` cannot be persisted in the agent. `RunAtLoad` starts it
again at future GUI logins. `KeepAlive` is off because the host supervises
reconnection itself; if the host process exits, use `start-agent` to restart it.
The agent stops at logout, and the tunnel is not expected to survive logout.
Logs go to `~/Library/Logs/open-forticlient/standalone.log`.

`stop-agent` first disables future login starts, asks the host to stop the
supervisor and VPN, then unloads the job. `uninstall-agent` does the same,
waits for launchd to finish unloading, and removes the plist. It leaves the
OFTC app, VPN configuration, profile, Keychain
PSK, and log in place. Neither command touches FortiTray, the Fortinet daemons,
or the legacy `com.open-forticlient.oftc` agent. For rollback, stop the
standalone agent, then use the legacy `oftc up` path if its agent was installed.
`standalone disconnect` disables the standalone LaunchAgent when installed and
stops the VPN. Use `start-agent` to resume automatic starts. If the recorded app was removed,
`uninstall-agent` still removes the LaunchAgent after unloading it, but reports
that VPN shutdown could not be confirmed.

This path still uses the signed development bundle. A 23-minute live IPv4 UDP
run passed screen lock, automatic local CHILD_SA rekey, and post-rekey
protected traffic; see the signed-provider-join spike notes. The launchd
timing fixes above passed local tests but still need a fresh live install and
uninstall cycle. Packaging a final named app and validating recovery on
genuine path loss, sleep/wake, roaming, TCP stalls, and IPv6-only/NAT64 paths
remain release gates. Run `oftc standalone help` for the exact commands.

## Status

The legacy Fortinet-backed path includes:

- `oftc probe` — connect to `fctctld`'s control socket and confirm it accepts an
  unprivileged, non-FortiTray peer (Phase 0 check; sends nothing).
- `oftc build-connect` — load the installed profile (`vpn.plist` via `plutil`) +
  `iked.conf`, assemble the `CONNECT` body from the reverse-engineered field map,
  and write it out for inspection/diffing. Offline.
- `oftc saml` — the full SAML flow (bootstrap POST, open browser, catch the
  loopback redirect) → `(username, tokenid)`. Opens a browser; needs a real SSO.
  Token masked unless `--show-token`; never written to disk.
- `oftc trust` — show the gateway's TLS cert (subject/issuer/dates/SHA-256) and
  pin it (trust-on-first-use). Verify-by-default; `--insecure` opts out.
- `oftc connect` — the full bring-up: SAML → `CONNECT` → auto-answer the OTP
  prompt → watch `STATUS`, and never `DISCONNECT` on lock. Logs every
  control-socket message. **Needs one live SSO to validate against the gateway**
  (the message log also reveals the exact STATUS/OTP sequence).

### TLS trust

Verify-by-default against the system trust store. If the gateway uses a
self-signed or internal-CA cert, run `oftc trust` once to review and pin it
(stored under `~/.config/oftc/gateways/`), or pass `--insecure` to skip
verification. The pinned cert is then used automatically.

## Build & run

```bash
cd client
cargo build
cargo run -- probe
cargo run -- build-connect --profile "Office VPN"      # PSK omitted
cargo test
```

Release (small binary):

```bash
cargo build --release   # target/release/oftc
```

## Layout

| File | What |
|------|------|
| `src/proto.rs` | `vpn_control` wire framing (20-byte header + body) and the command set. |
| `src/connect.rs` | The `CONNECT` config struct: field offsets + a builder from a `Profile`. |
| `src/profile.rs` | Load VPN params from `vpn.plist` (`plutil`) + `iked.conf` (PSK/peer). |
| `src/saml.rs` | SAML → `(username, tokenid)` (loopback catcher + `curl` POST). |
| `src/control.rs` | Drive `fctctld`: send `CONNECT`, answer OTP, watch `STATUS`. |
| `src/tls.rs` | Gateway cert review/pin (`oftc trust`) + curl TLS flags. |
| `src/presence.rs` | Is the user at the keyboard (HID idle time, screen lock)? Gates re-opening SSO. |
| `src/state.rs` | Supervisor state file (read by `oftc status`) + macOS notifications. |
| `src/standalone.rs` | Explicit command bridge and separate per-user OFTC LaunchAgent lifecycle. |
| `src/log.rs` | Local-time timestamped `log!` for the `connect` path. |
| `src/main.rs` | CLI: `probe`, `build-connect`, `saml`, `trust`, `connect`. |

## Dependencies

Zero **crate** dependencies (std only), to keep the binary small and the tree
auditable. Two **system tools** are shelled out to instead of pulling in crates:
`plutil` (read `vpn.plist`) and `curl` (the one HTTPS POST — std has no TLS
client). When a real need appears:

- **`nom`** — not planned. The protocol is a fixed 20-byte header of five LE
  `u32`s; parsing is a handful of `from_le_bytes`, and the main job is *building*
  the fixed-offset `CONNECT` struct, which `nom` doesn't do. If STATUS/event
  bodies turn out to need richer parsing, reach for `nom` (parse) /
  `cookie-factory` (build) then — not before.
- **`bytes`** — optional ergonomics for cursor read/write; std is fine so far.
- **`clap`** — swap in if the CLI grows beyond a few subcommands.
- **`plist`** — replace the `plutil` shell-out with in-process plist parsing if
  we want to drop the runtime dependency on `plutil`.

## "Statically linked" on macOS

A fully static binary is **not possible** on macOS — `libSystem` is only
available as a dynamic library and Apple does not support static linking against
it. The release profile here produces a single self-contained binary with all
Rust code compiled in and LTO/strip applied; the only dynamic dependencies are
the OS libraries (`libSystem`, etc.), which every macOS binary links. That is the
practical equivalent of "static" on this platform. (A truly static build would
require a different target such as Linux `x86_64-unknown-linux-musl`.)

## Secrets

`build-connect --with-psk` writes the pre-shared key into the output file. That
file (and `*.bin` generally) is git-ignored; never commit it. The SAML `tokenid`
is single-use and is never written to disk.

## Install / daily use

The tunnel stays up only while a process holds fctctld's control socket, so
`oftc` runs `connect` as a per-user LaunchAgent that launchd manages, and you
poke it up/down. It must be a LaunchAgent (not a root daemon): SSO opens a
browser and catches a loopback redirect, which only works in your GUI session.

```
oftc install            # copy binary + PSK to stable paths, load the agent,
                        #   and disable FortiTray (needs a macOS admin prompt)
oftc up                 # start a supervised session: opens SSO, holds the
                        #   tunnel, and auto-reconnects after a drop
oftc down               # disconnect cleanly and stop the agent
oftc uninstall          # remove the agent and re-enable FortiTray
```

`install --keep-tray` installs only our agent (leaves FortiTray, which will
still drop the VPN on lock). `oftc doctor` reports install/engine/PSK/FortiTray
status and can disable FortiTray on its own (`--dry-run` previews the exact
privileged commands; `--restore` re-enables it).

The agent self-heals. `connect --supervise` holds the tunnel across screen lock,
and after a drop it cannot prevent — a long **suspend** kills the SA (the gateway
DPDs it out ~20–30s after wake) — it re-runs SSO + CONNECT **in-process** with
backoff (2s→20s), so the tunnel comes back on wake without `oftc up`. Each
reconnect re-runs SSO because the token is single-use: a live Okta session
completes it silently, a lapsed one shows the login page once. (Short suspends,
<~1 min, often survive outright via the ESP-in-TCP keepalive — survival is
timing-dependent, which is exactly why the reconnect path exists.) Drops also
happen while awake: when the TCP 4443 stream stalls for 15–20s, an iked DPD bug
drops valid late replies and tears the SA down (`racoon error report: -306`).
See [Issue 11](../Issues/011-survive-path-stalls-iked-dpd-bug.md).

Retry policy: the agent only starts an SSO when someone is at the keyboard
(screen unlocked, keyboard/mouse input in the last 5 minutes). A drop while
you're away (locked, asleep, lid closed) waits, and reconnects as soon as you're
back, instead of opening SSO tabs on a timer that nobody sees. When present, a
tunnel that was up ≥30s and then dropped retries after 2s; a failure before the
tunnel came up backs off 2s→20s; an SSO tab left unanswered for 5 minutes is
replaced with a fresh one and a notification.

`oftc status` shows what the agent is doing (up for how long, signing in,
reconnecting, waiting for you) and how many drops it has seen. The agent posts
a macOS notification when the VPN drops, comes back, or needs you to sign in
(set `OFTC_NOTIFY=0` in the agent's environment to silence). Log lines in
`~/Library/Logs/open-forticlient/oftc.log` are timestamped in local time, so they
line up with `fctctl.log` and `log show --predicate 'process=="iked"'`.

launchd `KeepAlive` is intentionally **off**: the supervising process, not
launchd, drives reconnection. A conditional `KeepAlive` ({`SuccessfulExit:false`})
respawn pends on a semaphore that never fires across the sleep/wake power
transition — the original "didn't reconnect after wake" bug. launchd only loads
the job; `up` starts it, `down` boots it out (it can't crash-restart the process,
so a panic stays down until the next `up`).

Limits: a LaunchAgent dies at logout (tunnel drops at logout; lock and suspend
are fine).

## Secrets

`build-connect --with-psk` writes the pre-shared key into the output file. That
file (and `*.bin` generally) is git-ignored; never commit it. The SAML `tokenid`
is single-use and is never written to disk. By default oftc **decrypts the PSK from the profile's own `AuthInfo`** (FortiClient's `Enc` format uses a key hardcoded in its binaries — see `../docs/fct-enc-crypto.md`), so a configured machine typically needs no PSK setup (caveat: `AuthInfo` holds whatever credential was saved — on some profiles that is the saved SAML username, not the key, in which case oftc ignores it and you use the override below) at all. As an override, the plaintext PSK is read from
`$FORTIGATE_PSK`, a git-ignored `.env` (`FORTIGATE_PSK=…`), or `~/.config/oftc/psk`
(0600, where `oftc install` stores it for the agent) — never from the repo.
