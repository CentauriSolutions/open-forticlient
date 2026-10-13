# Authenticated NetworkExtension settings probe

`SettingsMapper.swift` converts the plain `NetworkSettings` returned by
`provider-live-engine::Session::connect` into `NEPacketTunnelNetworkSettings`.
It is an offline mapping check; it does not call `setTunnelNetworkSettings`,
install a VPN, or change the host's routes or DNS.

```sh
zsh spikes/provider-settings/run.sh
```

The script typechecks against the installed macOS NetworkExtension framework
and executes 15 synthetic success/failure cases. It covers exact `/24`, `/32`,
and authenticated `/0` ranges, non-CIDR and reversed range rejection, no DNS,
split DNS, server-only DNS, IPv4 and IPv6 outer endpoints, IPv4-mapped IPv6,
invalid masks/domains/MTU, and the recursive endpoint guard.

## Provider integration

1. Only after `Session::connect` authenticates the final IKE AUTH and CHILD_SA,
   copy its plain settings to `AuthenticatedNetworkSettings`. Convert each
   `Ipv4Addr` to its canonical dotted decimal form and each `AddressRange` to
   its exact first and last addresses. Pass `outer_remote_ipv4` from the
   connected socket as `outerEndpoint`; never re-resolve the gateway hostname
   after starting the tunnel. The mapper rejects an invalid or non-CIDR range
   instead of rounding it to a wider route.
2. Call `SettingsMapper.make`, then `setTunnelNetworkSettings(settings)` and
   await its completion before reading or writing `packetFlow` packets or
   reporting tunnel startup success. On failure, close the Rust session and
   complete startup with an error. On stop, cancel packet work, close the
   session, and clear settings with `setTunnelNetworkSettings(nil)`.
3. The assigned address is set with a `/32` interface mask. A supplied CP mask
   is validated but is not allowed to create an additional on-link route.
   Only the authenticated split ranges become `includedRoutes`. The resolved
   outer IPv4 endpoint gets an `excludedRoutes` `/32` so a route that contains
   it cannot recursively capture IKE/ESP traffic. An IPv6 outer endpoint has
   no IPv4 exclusion because this provider currently installs IPv4 inner
   routes only. If IPv6 inner routes are added, add an exact IPv6 outer
   exclusion at the same time.
4. With no DNS servers, `dnsSettings` remains nil, matching the observed
   live Gate 3 configuration. Servers plus domains use those domains for
   split DNS matching and search. Servers without domains use an empty match
   domain for the system resolver. The 1280-byte inner MTU from the engine is
   applied directly. No proxy or IPv6 inner settings are created.

This probe verifies Swift API use and object contents. A signed live provider
must still confirm that macOS applies the intended route and DNS state and
removes it on stop. The signed synthetic packet tunnel checks framework
application separately; it does not yet use authenticated settings.
