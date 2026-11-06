# Live release checks (`scripts/livecheck/`)

The live checks for a release (tunnels, rekeys, sleep and wake, the host service, the
installer, uninstall and reboot, readable failures) run as staged zsh scripts so that the
only thing a person does is the atomic act the script cannot do. Each stage prints
`PASS`, `FAIL` and `INFO` lines with the evidence, and writes a log. This is evidence
level "live traffic and installed behaviour on one Mac"; it does not replace the offline
build, signing or notarization checks in [releasing](releasing.md).

The harness is macOS only and uses nothing beyond what ships with macOS (zsh, `plutil`,
`launchctl`, `systemextensionsctl`, `pkgutil`, `spctl`, `stapler`, `hdiutil`, `pmset`,
`networksetup`, `screencapture`) and the repo's own binaries (`oftc`, `OFTCAgent`).

## Prerequisites

- An admin account; the password is typed once per stage that needs it (see
  [human acts](#human-acts)).
- The build under test installed (S1 to S3, S6, S7), or a release DMG (S4, S5).
- Terminal has Screen Recording permission for S7 (System Settings, Privacy & Security).
- For the sleep test, the Mac on power; for S5, nothing unsaved (it reboots the Mac).
- A config file (next section). It lives outside the repo.

## Config file

`LIVECHECK_CONFIG`, default `~/.config/oftc/livecheck.env`: `NAME=value` lines, `#`
comments, values read literally (the file is parsed, never sourced). Unknown names are
ignored with an `INFO` line. Real profile ids and addresses go here and nowhere in the
repo.

| Name | Meaning | Default |
| --- | --- | --- |
| `APP` | installed bundle | `/Applications/Open Forticlient.app` |
| `PROFILES` | space-separated profile ids S1 to S3, S5, S7 exercise | none |
| `PING_TARGETS` | `id=address` pairs: an address that answers only through that tunnel | none |
| `TCP_TARGETS` | `id=address:port` pairs for an extra TCP check (optional) | none |
| `SOAK_MINUTES`, `SOAK_INTERVAL` | S1 soak length and probe spacing (seconds) | 10, 30 |
| `SSO_TIMEOUT` | seconds to wait for a browser sign-in | 300 |
| `NETWORK_SERVICE` or `WIFI_DEVICE` | S2 network drop: a `networksetup` service name (needs sudo) or a Wi-Fi device such as `en0`; empty asks a human | empty |
| `SLEEP_SECONDS` | S2 time asleep | 60 |
| `DISCONNECT_WAIT` | S2 seconds a deliberate stop must stay stopped | 120 |
| `DMG_PATH`, `EXPECT_VERSION` | S4, S5: the release DMG and the version it must install | none |
| `FAIL_PROFILE`, `FAIL_EXPECT_CODE`, `FAIL_EXPECT_DETAIL` | S6: a profile that cannot connect, the `error.code` and a substring of `error.detail` to expect | none, `network_blocked`, `did not answer` |

Example (reserved names only):

```
PROFILES=office-vpn lab
PING_TARGETS=office-vpn=10.0.0.1 lab=192.0.2.10
NETWORK_SERVICE=Wi-Fi
DMG_PATH=/Users/me/Downloads/OFTC-1.2.3.dmg
EXPECT_VERSION=1.2.3
FAIL_PROFILE=blocked-test
```

## Running

Stages are run by name, never sourced. Every stage takes `--dry-run` (print the plan,
run nothing, touch nothing), `--config FILE` and `--run-dir DIR`.

```sh
zsh scripts/livecheck/s0-preflight.sh --dry-run
zsh scripts/livecheck/s0-preflight.sh
zsh scripts/livecheck/s1-tunnels.sh --connect
```

`s2-disturb.sh`, `s4-installer.sh` and `s5-uninstall-reboot.sh` change or disturb the
system (drop the network and sleep the Mac; run a real installer; uninstall and reboot)
and refuse to run without `--yes`. S3 also disturbs it (it restarts the host service and
re-registers it) but only touches OFTC. Unknown arguments are rejected, so a typo such as
`--noreboot` cannot reboot the Mac. Ctrl-C and SIGTERM run the cleanups (network
restore, DMG detach); if the network restore fails the stage prints
`RESTORE MANUALLY: <command>`. The admin credential a stage asked for is dropped
(`sudo -k`) when it ends, and the keepalive that refreshes it stops with the stage. Every command is printed (`RUN  ...`) before it runs. Nothing deletes
anything outside paths the run created, except `oftc uninstall` and the installer. No
stage prints or logs a PSK or a token (the only PSK-related call is `has-psk`, whose
single line says it is available), and none exports profiles (an export file holds
PSKs); a future stage that must export would have to write into a mode-0700 directory
and `rm -P` it afterwards. S4 and S5 verify the package (signature, Gatekeeper,
notarization ticket) before any installer or uninstall call and stop if a check failed.

Offline check of the harness itself (stub commands only, nothing real is touched):

```sh
zsh scripts/livecheck/selftest.sh
```

It runs in CI's lint job (about 40 seconds); `selftest.sh --run <stage> [args]` runs one
stage against the stub world for debugging.

## Reading the output

Each run makes `$TMPDIR/oftc-livecheck/<timestamp>/` (mode 0700): `<stage>.log` (every
line printed, timestamped), `<stage>-<label>.snap` snapshots, `shots/` screenshots, and
`summary.txt`, one line per stage: `S1 PASS=n FAIL=n INFO=n HUMAN-ACTS=n RESULT=OK|FAIL`,
followed by the human acts that stage asked for. A stage exits 1 on any `FAIL`, 3 when it
refuses (no `--yes`), 2 on usage errors. Pass `--run-dir` to put several stages in one
run directory. `INFO` lines are observations, not assertions (for example the transport
in use). `HUMAN >>> ACTION REQUIRED` is a single request; the script then polls for its
observable result and prints `PASS human act observed` or `FAIL ... not observed`. The
**run directory is private.** Output of noisy commands (extension list, launchctl,
`scutil`, `netstat`, `sfltool`, `install.log`, `pgrep`, `pmset`) is used but not written
to the log, and at the end of each stage profile ids become `<profile-N>`, every IPv4
address becomes `<ip>` and `gateway=` values are masked in the log and `summary.txt`.
That is best effort: review the files before sharing them, and keep them out of the
repo and out of issues. Terminal output is not masked. S5's run directory defaults to
`~/Library/Application Support/oftc-livecheck/runs/` so it survives the reboot; an
existing `--run-dir` must already be a private (0700) directory of yours.

`compare.sh BEFORE.snap AFTER.snap` diffs two snapshots and tags lines `VERSION`,
`RECEIPT`, `EXTENSION`, `LAUNCHD`, `PROCESS`, `USER-DATA`, `BUNDLE`. `snapshot.sh` prints
no secret and no profile name (profiles appear as `profile#1`).

## Stages

Each stage takes a snapshot first and last and prints their diff.

| Stage | Asserts | Human acts |
| --- | --- | --- |
| **S0** `s0-preflight.sh [--expect-connected]` | sudo credential cached, 5 GB free, installed version and provider build, `oftc --version`, extension list has no stale `terminated waiting` entry, no OFTC VPN connected (or all connected with `--expect-connected`), host service loaded, config complete | admin password |
| **S1** `s1-tunnels.sh [--connect] [--soak-minutes N]` | per profile: connected; ping at 0% loss (and a TCP connect if configured); `rekey-once` and `rekey-ike-once` pass and the `rekey-counts` total rises; traffic and state unchanged after; soak with periodic ping and state checks and no disconnect; supervisor pid:pgid pairs unchanged. Records the configured transport and, inferred from sockets, whether a TCP 4443 connection exists (the CLI does not report the transport in use). | SSO per profile with `--connect` |
| **S2** `s2-disturb.sh --yes [--only drop\|sleep\|stop] [--no-restore]` | network drop (scripted via `networksetup`, else a human): profile leaves connected, supervisor log shows `VPN disconnected; fetching error`, `starting fresh SSO recovery`, `VPN connected`, then traffic at 0% loss. Sleep: `pmset schedule wake`, `pmset sleepnow`, a jump in the wall clock between one-second ticks proves the Mac slept, same recovery assertions. Stop: `oftc disconnect`, every profile `disconnected`, no reconnect and no supervisor process for `DISCONNECT_WAIT`, no new `begin attempt` in the log; then reconnects unless `--no-restore`. The supervisor may `launchctl disable` the login agent after an unclassified drop, so check `launchctl print-disabled gui/$(id -u)` afterwards. | admin password; SSO after each recovery that does not come back alone; Wi-Fi off/on only if scripting fails |
| **S3** `s3-host.sh` | one `host serve` process; supervisors lead their own process group; `launchctl kickstart -k` gives the host a new pid while supervisor pid:pgid pairs, tunnel states and pings are unchanged; host label loaded and listed once; Login Items/BTM entry count (needs the sudo credential, else `INFO` says it is not observable); `host register` outcome (idempotent, or `INFO` when the build has no such verb); `host restart` | none |
| **S4** `s4-installer.sh --yes [--dmg P] [--skip-guard] [--reconnect]` | DMG mounts read-only; package signature (Developer ID Installer), `spctl` accepts it as notarized, `stapler validate`; **with a tunnel connected the installer refuses** (non-zero, bundle unchanged, the refusal message from `install.log` is recorded); after disconnecting and quitting the menu app, no process matches the preinstall guard; the install succeeds; bundle version and build, no `Frameworks` directory, no old `OFTC.app`, `codesign`, Gatekeeper, receipts; extension build `activated enabled` (runs `OFTCAgent activate` as the app would, records whether approval was requested); profiles, PSK presence (`has-psk` line only), pins, auto-start survived (snapshot lines compared); host service has a new pid | admin password; extension approval in System Settings only if macOS asks; SSO with `--reconnect` |
| **S5** `s5-uninstall-reboot.sh --yes [--no-reinstall] [--no-reboot] [--dmg P] [--force]` | pre phase: `oftc uninstall` exits 0; app, CLI, receipts, launch agents gone; no extension `activated enabled` (a deferred `terminated waiting to uninstall` is an `INFO`); profile directories retained; reinstall from the DMG, `activate`, `autostart on` for `PROFILES` (so connect-at-login can be tested; it is **left on**); marker file and one-shot LaunchAgent written; reboot scheduled with `shutdown -r +1`. Post phase (run by the LaunchAgent after login, which deletes its plist first): host service running, no stale extension entry, one activated extension, connect-at-login brought the tunnels up, ping at 0% loss; marker removed only if everything passed. A marker left behind, or a second pre run, reports a half-run (`--force` clears it). | admin password; approval if asked; **log in after the reboot**; SSO when connect-at-login opens it |
| **S6** `s6-failures.sh` | connect `FAIL_PROFILE`; `oftc status --json` gets `profiles[].error.code` equal to `FAIL_EXPECT_CODE`, `detail` containing `FAIL_EXPECT_DETAIL`, state `attention`, no IPv4 address in the detail, no `psk` in the document; `disconnect` clears the error | SSO for that profile |
| **S7** `s7-screenshots.sh` | numbered `screencapture -x` images in `<run>/shots/` at baseline, popover with tunnels up, popover after `disconnect`, popover after reconnect. The popover opening is observed as a change in the screen region under the menu bar. | open the menu popover (once); SSO on the reconnect |

`lc_shot name` (in `lib.sh`) takes the same numbered screenshots from any stage.

### Setting up S6

`FAIL_PROFILE` needs a profile whose gateway answers its SAML port (so the browser
sign-in works) but gets no answer to IKE over UDP 500/4500 and no answer on TCP 4443.
That is provider code 201, which `reason.rs` reports as `network_blocked` with
"The gateway did not answer over UDP or over TCP." A UDP-and-4443 block on the test
network (or a firewall rule for that one gateway address) does it; use a profile you can
afford to leave failing, and remove the rule afterwards. For a TCP-only profile 201 is
`gateway_no_answer`; set `FAIL_EXPECT_CODE` and `FAIL_EXPECT_DETAIL` accordingly.

## Human acts

Overall, for a full pass over S0 to S7:

1. **Admin password**, once per stage that uses sudo (S0, S2, S4, S5; each drops the credential when it ends): the script asks at
   its own `sudo -v` prompt.
2. **Browser SSO** whenever a tunnel is brought up: S1 `--connect`, after each S2
   recovery that needs it, S4 `--reconnect`, S5 after login, S6, S7.
3. **System Settings approvals**, only when macOS asks for the new extension (S4, S5).
4. **Log in after the S5 reboot.** The script cannot see anything before login.
5. **Open the menu popover** for S7.
6. Fallbacks, only when scripting fails: Wi-Fi off and on (S2).

The reboot and the Gatekeeper dialog of the GUI Installer are outside what a script can
do: the distribution check in the GUI installer (the app-closing declaration) needs a
**one-time manual run** of Installer.app, once per release; S4 drives `installer(8)`, and its guard test is a **real
installer attempt** that the preinstall script is expected to refuse (bundle version
unchanged is asserted); it runs the same `preinstall` and `postinstall` but not that check.

## What to look for

S4 exercises the preinstall guard, which refuses when any process's command line starts
with the app's `OFTCAgent` path, and that includes supervisors and `host serve`.
The stage records which processes the guard matches and fails if one still does after the
tunnels are disconnected and the menu app is quit; that outcome says whether an upgrade
with the resident host service can ever pass the guard.
