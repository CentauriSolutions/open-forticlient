# oftc — open-forticlient keep-alive controller (prototype)

A small Rust CLI that (eventually) brings up the FortiGate IPsec IKEv2 + SAML
tunnel by driving Fortinet's own `fctctld`/`iked` over the `vpn_control` socket,
and **never disconnects on screen lock** — the whole point of this project
(ROADMAP §C / Issue 6). See [`../docs/control-socket.md`](../docs/control-socket.md)
for the protocol this speaks.

## Status

Scaffold. Working today:

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
oftc up                 # start a connect session: opens SSO, holds the tunnel
oftc down               # disconnect cleanly and stop the agent
oftc uninstall          # remove the agent and re-enable FortiTray
```

`install --keep-tray` installs only our agent (leaves FortiTray, which will
still drop the VPN on lock). `oftc doctor` reports install/engine/PSK/FortiTray
status and can disable FortiTray on its own (`--dry-run` previews the exact
privileged commands; `--restore` re-enables it).

Limits: a LaunchAgent dies at logout (tunnel drops at logout; lock is fine).
SSO is interactive and the token is single-use, and this gateway does not
advertise client-resume to the free client, so `up` always means a browser
login and there is no silent reconnect after the SA is lost.

## Secrets

`build-connect --with-psk` writes the pre-shared key into the output file. That
file (and `*.bin` generally) is git-ignored; never commit it. The SAML `tokenid`
is single-use and is never written to disk. By default oftc **decrypts the PSK from the profile's own `AuthInfo`** (FortiClient's `Enc` format uses a key hardcoded in its binaries — see `../docs/fct-enc-crypto.md`), so a configured machine typically needs no PSK setup (caveat: `AuthInfo` holds whatever credential was saved — on some profiles that is the saved SAML username, not the key, in which case oftc ignores it and you use the override below) at all. As an override, the plaintext PSK is read from
`$FORTIGATE_PSK`, a git-ignored `.env` (`FORTIGATE_PSK=…`), or `~/.config/oftc/psk`
(0600, where `oftc install` stores it for the agent) — never from the repo.
