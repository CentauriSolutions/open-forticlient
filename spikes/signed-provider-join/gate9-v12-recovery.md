# Issue 13: v12 IPv4 recovery validation plan

V11 Gate 8 established that the running supervisor did not open a new SSO tab
after either a 75-second Wi-Fi outage or the separate 55-minute IKE lifetime
disconnect. V12 refreshes a stale NetworkExtension status, bounds the
disconnect-error lookup, and retries gateway bootstrap failures only when no
browser has opened. These changes have passed offline checks but need a live
recovery run.

## Frozen candidate and preflight

The Developer ID signed archive is
`/private/tmp/oftc-v12-recovery-build/IntegrationHost-v12-notary.zip`, SHA-256
`1f48ffdcb2f62573b851af94dc05720031cd4e9d044500467af90886d3af602b`.
Apple accepted submission `a4442aab-fa98-4be8-8721-7db46f081639`.
The uninstalled app is stapled and passed ticket, deep signature, and
Gatekeeper checks. Exact executable SHA-256 values:

| Component | SHA-256 |
| --- | --- |
| Host | `8e220fe5fca23c644f1fe5bd750219e8006ca4e1bdb3a0edd6b8eba30da43b5e` |
| Provider | `137728030341381e9e5ef3fbbcc30ac9a607399bc83cc9104aa657030222de0a` |
| Engine | `e62b2a7f96affe6eed429fae2ecbc12dbbe0e7b195b694c77bbedc188d54bc90` |

Before live use, verify these hashes again, the currently installed exact v11
host/provider/engine hashes in `gate8-v11-recovery.sh`, valid signatures and
tickets, the v11 extension, stored OFTC profile and exact-gateway Keychain
item, absent OFTC VPN configuration and LaunchAgent, route to `10.20.0.1` on
`en0`, baseline DNS, and Tailscale Disabled/Disconnected. Preserve v11 as an
exact backup before staging v12. No Fortinet component changes.

## Two independent IPv4 runs

1. Install and activate v12, install only OFTC's VPN configuration
   and per-user LaunchAgent, and start the stored IPv4 UDP profile. The SAML
   flow opens a browser tab; the existing provider session may authenticate
   automatically without a prompt. Confirm `status: 3`, a `utun` route, and
   one protected ICMP reply from `10.20.0.1`.
2. For the early-loss run, turn `en0` Wi-Fi off for 75 seconds with the existing
   watchdog and EXIT restoration, then observe for at most five minutes after
   Wi-Fi returns. Success requires a *new* browser-open event, `status: 3`,
   `utun` route, and protected ICMP, without manually restarting the agent.
   Record nonsecret status, times, route, and browser-open count. Cleanly stop
   and remove OFTC's VPN configuration and agent after the result.
3. Start a fresh connection for the lifetime run with no deliberate network
   interruption. Sample protected ICMP and CHILD rekey counts near 20, 40,
   and 54 minutes; observe the scheduled 55-minute disconnect and for at most
   five minutes afterward. Success again requires a new browser-open event,
   automatic connected status, `utun` route, and protected ICMP. A provider
   prompt is not required when its session is still valid.

Stop either run on unexpected VPN/configuration state, failure to restore Wi-Fi,
or a route/DNS mismatch. Preserve only nonsecret evidence. After both runs,
uninstall the agent, stop and remove OFTC's configuration, and verify baseline
route/DNS and Tailscale state. Leave v12 installed and disconnected. Preserve
exact v11 in `/private/tmp/oftc-v12-recovery-build/IntegrationHost-v11-rollback.app`
without reinstalling it. Sleep/wake and IPv6 tethering remain separate gates.

The operator approved v12 installation, both separate live runs,
protected probes to `10.20.0.1`, and guarded Wi-Fi loss. Apple signing and
notarization were completed under standing authorization.

## Gate result

The loss run connected at 17:49:43 UTC on October 8, 2026 with `utun10` and
protected ICMP. Wi-Fi was off for 75 seconds and restored at 17:51:06 UTC.
The tunnel disconnected during the outage and was still down at 17:56:17 UTC,
more than five minutes after Wi-Fi returned. The only browser-open event was
the initial connection; the supervisor job remained loaded.

The independent lifetime run connected at 17:56:42 UTC with no deliberate
network interruption. Protected ICMP passed after two local CHILD rekeys and
again at 18:47:00 UTC. The five-second sampler saw `status: 3` on `utun10` at
18:51:39 UTC and `status: 1` on `en0` at 18:51:44 UTC. At 18:56:48 UTC, more
than five minutes later, it was still disconnected with one browser-open event
for the run and no recovery event. The supervisor job was still loaded.

Both runs ended with OFTC's agent and VPN configuration removed and route/DNS
back to baseline. Independent final checks found Wi-Fi on and Tailscale
Disabled/Disconnected. Exact v12 remains installed and disconnected; exact
v11 is retained only as a rollback copy. Automatic recovery is still unproven.
Nonsecret timestamps, status, route, rekey, and browser counts are in
`/private/tmp/oftc-issue13-v12-recovery-state/evidence.txt`.
