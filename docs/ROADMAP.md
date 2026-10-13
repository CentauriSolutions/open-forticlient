# Roadmap

The active implementation is the standalone macOS app in [`app/`](../app/).
The Fortinet-backed controller and the research gates are available in Git
commit `b9ade25`; they are no longer build inputs. The source builds an
offline v16 candidate using the v15 development bundle ID; v15 is the
live-tested installation.

## Next: distributable client

1. Choose the final app name, bundle IDs, and version scheme. Provision matching
   host and provider Developer ID profiles and entitlements.
2. Package the app and `oftc` CLI with a supported install, update, and uninstall
   flow. Verify signing, notarization, stapling, extension activation, agent
   lifecycle, and migration on a clean Mac. Keep build output separate from the
   installed app.
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
