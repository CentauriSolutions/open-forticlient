# Fortinet daemon replacement

OFTC's current app replaces the Fortinet VPN transport for a normal connection.
It runs IKEv2/EAP and ESP in its own NetworkExtension provider and applies the
authenticated route and DNS settings through macOS. It does not connect to
`fctctld`, `iked`, `fct_tunnel_ctl`, or the Fortinet PrivilegedHelper.

The host performs browser SAML, owns a nonsecret profile and a Keychain PSK,
and supervises recoverable tunnel failures. Importing a FortiClient profile
is an explicit, one-time migration command. See [architecture](architecture.md)
for the current code boundaries and [operations](operations.md) for setup.

The old controller that reused Fortinet's daemons is preserved in Git commit
`b9ade25`. Its DPD and IPv6/NAT64 defects motivated this replacement; see
[Issue 11](../Issues/011-survive-path-stalls-iked-dpd-bug.md) and
[Issue 12](../Issues/012-connect-over-ipv6-only-nat64-networks.md).

The signed v15 development app passed the measured IPv4 UDP
[live gate](evidence/v15-live-gate.md). The
[remaining rollout gaps](initial-rollout-gaps.md) and
[distribution work](ROADMAP.md) still prevent a general production claim.
