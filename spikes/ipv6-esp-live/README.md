# IPv6-outer ESP live-proof runner

This isolated runner joins the authenticated IKEv2/SAML and CHILD_SA flow to
the existing ESP engine over an IPv6 outer socket. It selects an IPv6 gateway
address (native AAAA or DNS64 synthesis) and refuses an IPv4-only resolver
result. The IKE NAT detection hashes use the actual IPv6 local/remote socket
addresses. The explicit `--idi-v4` argument supplies the current CLAT IPv4
identity for FortiGate's existing IPv4 IDi contract; the IPv4 address is not
derived from the IPv6 socket. Recheck the CLAT address after each network
change. UDP 4500 is the default; TCP 4443 is an explicit fallback and does
not happen automatically.

`sh spikes/ipv6-esp-live/run.sh` builds the binary under
`/private/tmp/oftc-ipv6-esp-live/` and runs offline tests only. The script
does not contact the VPN, open SSO, or consume a token.

On a verified IPv6-only/NAT64 hotspot, no-token preflights are:

```
/private/tmp/oftc-ipv6-esp-live/ipv6-esp-live --idi-v4 192.0.0.2
/private/tmp/oftc-ipv6-esp-live/ipv6-esp-live --idi-v4 192.0.0.2 --transport tcp
```

Replace `192.0.0.2` with the current CLAT address. Both commands were run on
the IPv6-only hotspot and exited successfully after responder AUTH
verification and an EAP-MSCHAPv2 challenge, before SAML. The UDP preflight
also ran as part of the authorized probe below.
After **explicit operator authorization for one fresh token and one echo on
UDP**, the authenticated probe command used was:

```
/private/tmp/oftc-ipv6-esp-live/ipv6-esp-live --idi-v4 192.0.0.2 --authenticate --esp-target 10.20.0.1
```

For an independently authorized TCP fallback attempt, add `--transport tcp`.
The target is the operator-approved internal FortiGate ICMP address. Each
authenticated invocation first does a no-token preflight, then uses one fresh
SAML token for one IKE SA and one ESP-protected IPv4 ICMP echo inside the
IPv6/NAT64 outer transport. A reply counts only after ESP integrity, replay,
selector, IP/ICMP checksum, address, ID, sequence, and payload checks. The
probe waits at most 12 seconds for the reply. It installs no routes, DNS
settings, or packet tunnel. Output contains stages and packet counts, never
credentials, keys, or raw packets.

## Authenticated UDP result, 2026-10-07

On the IPv6-only phone hotspot with CLAT `192.0.0.2`, the operator authorized
one fresh SAML token and one protected echo to `10.20.0.1`. The UDP invocation
above exited successfully. It verified responder PSK AUTH, inner
EAP-MSCHAPv2 Success, outer EAP Success, final responder AUTH, and the
CHILD_SA. The gateway assigned one split route and no DNS servers. One ESP
echo was sent over the IPv6 outer UDP socket, and the matching reply was
authenticated and validated. No system route, DNS setting, or packet tunnel
was installed.

This passes the direct IPv6/NAT64 UDP data-plane subgate. The authenticated
IPv6 outer TCP fallback remains untested, as does the live signed-provider
join on IPv6. Network transitions and lock/wake recovery are separate gates.
