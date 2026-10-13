# Issue 13: staged v11 IPv4 recovery and lifetime gate

The installed v11 app is the exact Developer ID signed, notarized, stapled
artifact from Gate 7. The two later LaunchAgent timing fixes are in the Rust
CLI only. A fresh isolated CLI build passed 24 tests, and the new release
binary is pinned by SHA-256 in `gate8-v11-recovery.sh`. No new app signing,
notarization, or installation is needed for this gate.

Run `zsh spikes/signed-provider-join/gate8-v11-recovery.sh --plan` and
`--check` first. The latter is read-only. Do not run `--start`, disrupt the
network, or sleep the Mac until the operator approves those exact stages.
The gate never changes Tailscale or Fortinet services. It uses the already
stored OFTC profile and exact-gateway Keychain PSK; no profile import repeats.

| Stage | Action after approval | Expected evidence / stop condition |
| --- | --- | --- |
| Preflight | `--check` | Exact v11 host/provider/engine hashes; valid signature, staple, and Gatekeeper assessment; activated v11 extension; OFTC VPN config and agent absent; OFTC profile/PSK present; target route on `en0`; Tailscale Disabled/Disconnected. |
| Start | `--start` once | LaunchAgent runs after one `start-agent` call, without a second kickstart. OFTC opens the browser for verified-TLS SSO; an existing provider session may authenticate without a prompt. `status: 3`, route to `10.20.0.1` over `utun`, protected ICMP reply, and `agent_loaded=yes`. If connection fails, the script stops/removes OFTC. |
| Early real loss | Observe, run the approved `gate8-wifi-loss.sh --execute` to turn Wi-Fi off for 75 seconds and restore it, then observe recovery. | A new browser-open attempt after Wi-Fi returns, automatic return to `status: 3`, `utun` route, protected ICMP, and no manual `start-agent`. An existing provider session may authenticate without a prompt. If still disconnected five minutes after Wi-Fi returns, stop the gate and record failure. |
| IKE lifetime | Run independently on a fresh connection, with no deliberate network interruption. Leave it up for at least 57 minutes from its connected observation, sampling at roughly 20, 40, 54, and 57 minutes. | Child rekey counts and protected ICMP remain healthy. The source's 55-minute IKE hard limit should trigger bounded supervised reconnect and a new browser-open attempt, followed by `status: 3` and protected ICMP. An existing provider session may authenticate without a prompt. Record any unexpected earlier peer disconnect or exhausted three-per-ten-minute recovery policy. |
| Sleep/wake | Separately approved and only if the operator can restore local access. | Observe before sleep and after wake, record whether the existing SA survives or a supervised fresh-SSO recovery succeeds. Do not infer sleep behavior from screen lock. |
| Stop | `--finish` or `--rollback` | Agent plist and launchd job absent, OFTC VPN configuration absent, route and DNS digests back to pre-test baselines, Tailscale still Disabled/Disconnected. The signed v11 app, OFTC profile/Keychain PSK, and prior v9 rollback copy remain. |

`--observe` writes only UTC time, VPN status, route interface, protected ping
pass/fail, nonsecret CHILD rekey counts, launchd loaded state, and counts of
fixed supervisor messages to
`/private/tmp/oftc-issue13-v11-recovery-state/evidence.txt`. It does not copy
raw LaunchAgent logs, SAML tokens, Keychain values, or shell environment.
`--observe` never pings `10.20.0.1` unless macOS says the VPN is connected and
the target route uses `utun`.
The Wi-Fi loss script records only status and Wi-Fi power; an EXIT trap and
separate 95-second watchdog restore `en0` power if the main command exits.

Approval scope for a live run: create only OFTC's VPN configuration and its
per-user LaunchAgent, authenticate to the selected gateway through the user's
browser, use IPv4 UDP 4500 with the existing bounded TCP fallback, send
protected ICMP only to `10.20.0.1`, allow fresh SAML on bounded recovery, and
optionally perform the separately approved Wi-Fi loss and sleep/wake stages.
The rollback is `--rollback`; it returns to the currently installed but
disconnected v11 state. Check route/DNS manually if the physical network
changes its DHCP values during the test.

## Gate 8 result

The Wi-Fi loss run disconnected by 45 seconds and stayed disconnected for five
minutes after Wi-Fi returned. The independent lifetime run stayed connected
through two local CHILD rekeys, then disconnected at about 55 minutes and
remained down for more than five minutes. In both runs the supervisor process
remained loaded, but the only recorded browser-open event belonged to the
initial connection. Recovery never started a new browser SSO attempt, so the
presence or absence of a provider prompt was not the cause. Each rollback
removed OFTC's VPN configuration and agent and restored route and DNS baseline.
