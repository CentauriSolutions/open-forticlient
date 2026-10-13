# Ephemeral host-to-provider bootstrap probe

## Result

The macOS 27 Swift compiler accepts a host call to
`NEVPNConnection.startVPNTunnel(options:)` with one `NSData` value and a
`NEPacketTunnelProvider.startTunnel(options:completionHandler:)` override that
extracts it. `run.sh` typechecks those real NetworkExtension signatures and
runs eight synthetic envelope checks. This is an **offline API and codec
probe**. It does not prove that macOS delivered the options to a signed,
activated provider, and it has no real credential or network action.

```sh
zsh spikes/provider-ipc/run.sh
```

The envelope has a fixed version, 16-byte start ID, expiry, bounded opaque
payload (1–4096 bytes), and exact-length checks. The test rejects missing,
malformed, oversized, stale, and too-far-future data. The test payload spells
`SYNTHETIC`; it is never a login credential. The source deliberately prints
neither the opaque payload nor the options dictionary.

## Real handoff

1. Save a `NETunnelProviderManager` with only durable, nonsecret metadata in
   `NETunnelProviderProtocol`: provider bundle ID, display name, and server
   label. Never put a `tokenid`, PSK, IKE key, or ESP key in
   `providerConfiguration` or any preference value. The current signed
   synthetic host already creates this sort of minimal configuration.
2. The host obtains a fresh SAML callback, constructs a short-lived envelope
   containing its single-use token and the EAP identity/UID needed by the
   provider, and calls `startVPNTunnel(options:)` once. The prototype only
   carries an opaque synthetic value; production needs a versioned schema for
   identity plus token, strict size limits, and a fresh random start ID.
3. In `startTunnel`, reject nil, invalid, expired, or repeated start data with
   a generic error. Move the token to the Rust engine immediately. The **provider
   owns UDP/TCP transport and performs IKE_SA_INIT, EAP-MSCHAPv2, IKE_AUTH,
   CHILD_SA, and subsequent ESP itself**. This avoids transferring a live
   socket, IKE message counters, NAT mapping, and sequence numbers from the
   host to another process. Drop the token after authentication; retain only
   session keys in provider process memory for ESP/rekey.
4. Do not install tunnel routes before authenticated CHILD_SA and assigned
   configuration are validated. Call `setTunnelNetworkSettings` with the
   assigned addresses/routes/DNS, wait for its completion, start packet flow,
   then call the `startTunnel` completion handler with `nil`. On error, call
   completion with a generic `NSError` and close transport and state. The host
   observes connection status; `startVPNTunnel` itself returns before the
   connection completes.
5. On `stopTunnel`, cancel packet reads/timers, close transport, invalidate
   IKE/CHILD state and secret buffers, remove settings, then call its completion.
   For an unrecoverable error after establishment, use
   `cancelTunnelWithError`. A fresh start requires a **fresh token**; never
   reuse one after a crash, pause, or restart.

`sendProviderMessage` is available for later control/status messages, but its
API may launch a provider that is not running. A separate secret message would
require a start/message rendezvous and timeout. The start options path is the
smaller initial integration. Apple's docs say Connect On Demand starts pass
`nil` options, so automatic relaunch cannot reuse this flow. Keep On Demand off
until a fresh-auth trigger exists; a provider process that merely reconnects
its transport while alive can use its in-memory session under a deliberate
policy.

This keeps secrets out of **saved VPN preferences**. It is not a guarantee
that Foundation, NetworkExtension IPC, or a crash reporter leaves no transient
copy of the options bytes. Swift `Data` can be copied; the prototype does not
claim reliable zeroization. Avoid logging options, errors containing payloads,
crash dumps in a test, and persistent launch arguments. For stronger custody,
minimize copies and keep the credential lifetime short; use a Rust-owned buffer
once received, and test process/crash behavior on the real signed provider.

## Fit with the signed synthetic bundle

`../packet-tunnel-integration/Host/main.swift` currently calls the no-argument
`startVPNTunnel()`, while `Provider/PacketTunnelProvider.swift` ignores its
`options`. The bundle can adopt this interface by changing those two call
sites and adding the codec, without new NetworkExtension API entitlements. Its
current provider would still fail closed with synthetic data until an IKE
engine is integrated. Any modified bundle must be rebuilt, signed and
notarized again, then the system extension replaced through its established
activation flow. Reuse of the existing **synthetic** bundle IDs is appropriate
only for the spike, not the production app.

## Apple API references

- [`startVPNTunnel(options:)`](https://developer.apple.com/documentation/networkextension/nevpnconnection/startvpntunnel%28options%3A%29): per-start dictionary; call returns immediately.
- [`startTunnel(options:completionHandler:)`](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/starttunnel%28options%3Acompletionhandler%3A%29): receives start options, nil for On Demand, completion after settings.
- [`providerConfiguration`](https://developer.apple.com/documentation/networkextension/netunnelproviderprotocol/providerconfiguration): part of provider configuration, whose values must support secure coding/copying.
- [`sendProviderMessage`](https://developer.apple.com/documentation/networkextension/netunnelprovidersession/sendprovidermessage%28_%3Aresponsehandler%3A%29), [`stopTunnel`](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/stoptunnel%28with%3Acompletionhandler%3A%29), [`cancelTunnelWithError`](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/canceltunnelwitherror%28_%3A%29): later control and teardown.
