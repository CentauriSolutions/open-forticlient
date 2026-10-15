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
OFTC 1.0.4 build 22 is currently installed on the development Mac for the
bundled-agent label check; its provider has not been activated there.

## Next: pilot validation

1. On a new colleague's Mac, validate fresh 1.0.3 setup approval, browser SSO,
   protected traffic, explicit stop/reconnect, and route/DNS cleanup. Then
   validate recovery and a longer connection on the packaged build. The Mac
   mini's 1.0.3 offline setup/uninstall test had an earlier provider record,
   so it did not prove a fresh approval path. See the
   [pilot guide](pilot-validation.md) and
   [build 20 record](evidence/v20-packaged-pilot.md).
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
