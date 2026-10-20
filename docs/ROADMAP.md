# Roadmap

The active implementation is the standalone macOS app in [`app/`](../app/).
The Fortinet-backed controller and the research gates are available in Git
commit `b9ade25`; they are no longer build inputs. OFTC 1.0.2 build 19 is a
signed, notarized package from pinned commit `6bebfa6`. Its extension
activation, short live IPv4 UDP canary, and explicit stop passed on the
development Mac. Build v15 has the longer recovery and renewal evidence.
The [1.0.3 build 20 colleague packet](evidence/v20-packaged-pilot.md) passed
package trust and offline Mac mini setup/uninstall checks; live connection and
fresh extension approval on that build remain open.
OFTC 1.0.4 build 22 passed the development Mac's bundled-agent label check.
The [build 23 menu bar candidate](evidence/v23-menu-bar-candidate.md) passes
offline build, state/counter checks, and native UI rendering. It is signed,
notarized, installed, and its provider is activated on the development Mac.
Live traffic/statistics on provider 23 and login-service lifecycle validation
remain separate gates.

The [signed/notarized build 24 host candidate](evidence/v24-traffic-sparklines.md)
adds recent traffic-rate sparklines using the same build 23 provider; it is
installed on the development Mac. Live sparkline and lifecycle validation
remain separate gates.

The [build 25 guided-install candidate](evidence/v25-guided-install-and-upgrades.md)
is signed, notarized, and packaged with an updated colleague guide. It adds
visible welcome guidance, provider-readiness checks, explicit app reopening,
and clearer Installer update prerequisites. Offline and native UI checks pass;
build 25 installation, actual login/reboot behaviour, and live traffic remain
separate gates.

The [build 26 follow-up](evidence/v26-menu-visibility-and-upgrade-recovery.md)
addresses separate colleague reports of an invisible disconnected icon,
inaccessible quit controls, first-menu connection failure, and disappearing
statistics. It adds concrete masks and an independent controls window,
keeps totals through missing samples, and improves safe helper error reporting.
The first-connect cause and colleague-side rendering still need confirmation.

## Next: pilot validation

1. On a colleague's Mac, validate fresh 1.0.5 build 26 welcome/setup approval
   and a separate 1.0.3/1.0.4-to-1.0.5 update. Check actual postinstall opening,
   native app closing, reopening, quiet login launch, first menu connection,
   browser SSO, protected traffic, idle statistics, menu rates
   and history, explicit stop/reconnect, and route/DNS cleanup. Then validate
   recovery and a longer connection. The earlier Mac mini 1.0.3 test had an
   existing provider record and did not prove fresh approval. See the
   [pilot guide](pilot-validation.md) and
   [build 26 record](evidence/v26-menu-visibility-and-upgrade-recovery.md).
2. Validate the [build 22 app-bundled agent](evidence/v22-bundled-agent-candidate.md)
   on a fresh Mac. Its upgrade on the development Mac displayed OFTC in
   Background App Activity without the old Developer ID row after refresh.
3. Make recovery after a host crash explicit. The current LaunchAgent uses
   `KeepAlive=false` because the host supervises connection recovery itself;
   launchd restart after a crash has not been validated.
4. Complete the [initial rollout gates](initial-rollout-gaps.md) on the target
   IPv4 UDP connection. Keep the old client recoverable from Git history until
   those gates pass.

## Wider network acceptance

Validate real sleep/wake, peer loss, Wi-Fi and tether roaming, TCP stalls,
peer-initiated or simultaneous rekey, and sustained IPv6-only/NAT64 during
initial rollout. Short IPv6 and TCP packet tests are evidence of capability,
not acceptance for those environments. The scheduled 20-hour IKE renewal
trigger also needs a live observation; explicit renewal passed.

See [Issue 13](../Issues/013-replace-fortinet-vpn-daemons.md) for the acceptance
ledger and [the v15 gate](evidence/v15-live-gate.md) for measured results.
