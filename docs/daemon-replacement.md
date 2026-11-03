# Fortinet daemon replacement

OFTC's current app replaces the Fortinet VPN transport for a normal connection.
It runs IKEv2/EAP and ESP in its own NetworkExtension provider and applies the
authenticated route and DNS settings through macOS. It does not connect to
`fctctld`, `iked`, `fct_tunnel_ctl`, or the Fortinet PrivilegedHelper.

The host performs browser SAML, owns a nonsecret profile and a Keychain PSK,
and supervises recoverable tunnel failures. Importing a FortiClient profile
is an explicit, one-time migration command. See [architecture](architecture.md)
for the current code boundaries and [operations](operations.md) for setup.

The old controller that reused Fortinet's daemons is preserved in Git history
(the `legacy-controller` tag). Its DPD and IPv6/NAT64 defects motivated this replacement; see
Issue 11 and
Issue 12.

The signed standalone app has passed IPv4 UDP and TCP connections, IKE and
CHILD SA rekeying, and recovery from network loss and sleep. The open work in
the [roadmap](ROADMAP.md) still stands between it and a general production
claim.
