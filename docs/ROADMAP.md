# Roadmap

The active implementation is the standalone macOS app in [`app/`](../app/).
The Fortinet-backed controller and the research gates are available in Git
commit `b9ade25`; they are no longer build inputs. OFTC 1.0.1 build 18 is a
signed, notarized candidate installed on the development Mac. Its setup,
extension activation, and short live IPv4 UDP canary passed. Build v15 has
the longer recovery and renewal evidence.

## Next: distributable client

1. Pin the source revision and rebuild the signed, notarized package from it.
2. Validate fresh interactive SSO, recovery, and a longer connection on build
   18. Its short protected IPv4 traffic and explicit stop passed. On a
   separate canary Mac, exercise fresh guided setup, update, uninstall, and
   route/DNS cleanup. See the [pilot guide](pilot-validation.md).
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
