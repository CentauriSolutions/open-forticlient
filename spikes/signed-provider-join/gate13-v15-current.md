# V15 supervisor recovery and IKE renewal gate

The October 13 live gate started on the USB Ethernet `en9` path after the
operator disconnected the legacy VPN. The exact v15 app is
`/private/tmp/oftc-v15-supervisor-fix/IntegrationHost.app`. Its notarized
archive SHA-256 is
`ae58d05c823efa01506a1fc5a43fac4ac1f4a02d824e5adb7574671ca199b63a`;
Apple accepted submission `94709caf-a784-48df-b989-b35ab4c8981c`.
`codesign`, stapler, and Gatekeeper checks passed. The installed v14 app is
held as a verified rollback. The v15 gate scripts pin all host/provider/engine
hashes and the selected profile. No Fortinet or Tailscale service was changed.

The v14 run first proved explicit IKE SA renewal, then CHILD SA rekey on the
renewed IKE SA, with protected ICMP to `10.20.0.1` after each. A separate
75-second `en9` outage made NetworkExtension report disconnected, but the
supervisor neither logged a heartbeat nor retried. A process sample showed
its main dispatch queue blocked in `NSNotificationCenter` waiting for
`OperationQueue.main` during a VPN status notification. The observer had
registered with `queue: .main` while the command used `dispatchMain()`.
V15 registers for synchronous notification delivery and dispatches its state
check asynchronously to the main dispatch queue. The failed v14 run was
cleaned up with baseline route and DNS restored.

The v15 recovery run began at 19:43 UTC. Its first protected ICMP ran before
the tunnel could pass traffic; a subsequent observation at 19:44 UTC passed.
The gate now permits 30 seconds after connected status for that first packet.
V15 again passed explicit IKE renewal, subsequent CHILD rekey, and protected
traffic after each. The approved, separate `en9` loss ran from 19:44:24 to
19:45:39 UTC. The supervisor logged provider error 301, one recovery event,
and a second browser SSO attempt, then returned to connected status while
`en9` was still disabled. At 19:46:03 UTC, the target route was through
`utun10` and protected ICMP passed. The agent remained running. The recovery
run ended with OFTC agent/config absent and exact baseline route and DNS.

A fresh, uninterrupted lifecycle run started at 19:46:24 UTC with connected
status, `utun10`, and protected ICMP. It was independent of the link loss
test. Protected traffic passed after the full 55 minutes, and again at
20:42:51 UTC before stopping. It completed two automatic local CHILD rekeys
with one initial browser SSO attempt and no disconnect or recovery event.
Stop removed the agent and VPN configuration and restored exact baseline
route and DNS. The final gate left v15 installed and disconnected with an
exact verified v14 rollback copy. Nonsecret observations are in
`/private/tmp/oftc-issue13-v15-current-state/evidence.txt`.

At about 19:58 UTC the operator noticed an SSO prompt. The OFTC lifecycle log
contained only the initial browser-open event at 19:46:22 UTC; it had no
disconnect or recovery event, and protected ICMP still passed. The prompt's
source was not identified.

The 20:08:55 UTC sample showed the first automatic local CHILD rekey complete;
protected ICMP passed without a new SSO attempt or disconnect.
The 20:29:00 UTC sample showed a second automatic local CHILD rekey complete;
protected ICMP still passed with no reconnect.

This gate establishes recovery on the tested IPv4 Ethernet-to-Wi-Fi failover
and explicit IKE renewal. Genuine peer loss, an actual System Settings UI
stop, sleep/wake, TCP stalls, roaming, and sustained NAT64 remain rollout
gaps.

After the lifecycle gate, a separate macOS VPN-style stop through
`scutil --nc stop` disconnected a fresh v15 connection. The supervisor
recorded an unclassified disconnect, disabled its LaunchAgent, and made no
recovery SSO attempt. The tunnel stayed down for more than 90 seconds. Test
cleanup restored exact route/DNS baselines, removed OFTC agent/config, and
left Tailscale Disabled/Disconnected. A final fresh v15 connection then
passed protected ICMP over `utun10`; the supervisor and OFTC configuration
remain installed and active for the operator.
