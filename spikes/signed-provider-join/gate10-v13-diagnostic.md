# Issue 13: v13 IPv4 disconnect diagnosis

V11 and v12 both disconnected after a 75-second Wi-Fi outage and at the
independent 55-minute IKE hard limit. In all four cases the LaunchAgent
remained loaded, but no second SSO browser-open event occurred. That places
the observed failure before SSO. The v12 logs cannot distinguish a stalled
supervisor timer, stale NetworkExtension status, a blocked preference refresh,
or a blocked disconnect-error lookup.

Read-only macOS unified-log review after v12 narrowed this further. Both
disconnects were `plugin_initiated` according to `nesessionmanager`, consistent
with OFTC's own provider teardown. The long-lived supervisor PID remained
present through each run until its deliberate cleanup, while separate status
commands saw the VPN disconnected. Each supervisor PID logged its initial
NetworkExtension preference load, but no later preference load; separate
status commands did log theirs. This points to the supervisor not reaching
its periodic refresh, possibly because its timer did not run or because its
state guards never allowed refresh. The existing logs cannot distinguish
those cases. The v13 gate now records both loaded and running agent state.

## Frozen, uninstalled candidate

V13 adds fixed, nonsecret supervisor heartbeat and transition messages,
expires a stalled preference refresh after ten seconds, and keeps unknown
disconnects down. A nil disconnect error can also follow a user stop through
macOS, so v13 disables automatic login starts rather than spending a fresh
SAML token when the cause is unknown. Recognized network/provider failures
retain the existing bounded recovery policy. The CLI now makes `standalone
disconnect` disable an installed LaunchAgent; `start-agent` explicitly resumes
it. None of these changes proves recovery yet.

The Developer ID signed archive is
`/private/tmp/oftc-v13-supervisor-build/IntegrationHost-v13-notary.zip`, SHA-256
`cd91dd01b0b20433f91ecd977da2fb84eb95c4f532cdc16eafbf9a701bcce9d1`.
Apple accepted submission `ac72c33b-794e-4b7a-8d9c-95f835f427c4`; the
stapled app passed ticket, deep signature, and Gatekeeper checks. Exact
executable SHA-256 values:

| Component | SHA-256 |
| --- | --- |
| Host | `7b6bb0146801016d6a72f5cc116673ffe1eb326fabf4d77fe5ea16132f76aeec` |
| Provider | `d11c8529f5885c0440ef0e9c53d9dc26de82d906ba59f528843988702dd8b5ce` |
| Engine | `18b2401e3cbb62ff55f9025063a674f260ff232af04f2c344de58c25b8dd7f28` |
| Standalone CLI | `b50a8cdd756ef6fd78568daff37bd5e189127345f9333020b45e01a9801b542e` |

The full offline bundle build, focused supervisor checks, and 24 CLI tests
passed. Read-only live preflight on October 13 refused to proceed because an
active legacy VPN routes `10.20.0.1` through `utun10`; OFTC v13 was not installed
or started. Tailscale remained Disabled/Disconnected.

## One short loss run, pending separate approval

The prepared [gate script](gate10-v13-diagnostic.sh) pins the four hashes,
signatures, ticket, installed v12 baseline, profile, and network state. Its
install step saves exact v12 for rollback and activates v13. Start installs
only OFTC's VPN configuration and LaunchAgent, opens browser SSO using the
existing provider session, and requires `status: 3`, a `utun` route, and one
protected ICMP reply from `10.20.0.1`. The separate [Wi-Fi script](gate10-wifi-loss.sh)
turns `en0` off for 75 seconds and restores it with an EXIT trap plus a
95-second detached watchdog. Observe for at most five minutes after Wi-Fi
returns; record only nonsecret status, route, browser/recovery event counts,
and fixed supervisor diagnostics. If a new browser tab opens, the existing
provider session may authenticate automatically without a prompt.

Stop on unexpected VPN/configuration state or failed Wi-Fi restoration.
Cleanly remove OFTC's agent and VPN configuration, verify baseline route and
DNS, and leave v13 installed but disconnected. Preserve exact v12 as rollback;
v11 remains in its existing backup. Tailscale and Fortinet stay untouched.
The uninterrupted 55-minute lifetime test remains a separate run and is not
part of this diagnostic gate.
