# Gate 0: packet-tunnel system-extension probe

This is an isolated packaging and packet-flow experiment. It does not contact a
VPN gateway, use SSO, or integrate with `client/oftc`. The only included route is
`198.51.100.254/32` (TEST-NET-2). The interface address is `192.0.2.2/32`, and
the DNS resolver `192.0.2.53` applies only to `gate0.invalid`. The provider
answers one ICMP echo locally through `packetFlow.readPackets` and
`packetFlow.writePackets`; it does not forward traffic.

## Gate 0 result on this Mac (2026-10-07)

The local packet-tunnel path worked. This is a **local IPv4** test with no outer
transport, gateway exchange, IKE proposal, or SSO token.

| Level | Evidence |
| --- | --- |
| Build | Xcode 27.0 compiled both executables; the provider was embedded in `Contents/Library/SystemExtensions`. |
| Sign and provision | Separate exact-ID Developer ID profiles authorized `packet-tunnel-provider-systemextension`; the host profile also authorized `system-extension.install`. Both bundles passed `codesign --verify --deep --strict` with the same team and secure timestamps. |
| Notarize | Apple accepted submission `f3f1db75-f833-4ed4-867f-12378643c6d6`; `stapler validate` succeeded and `spctl --assess` reported `Notarized Developer ID`. |
| Install and activate | The app installed in `/Applications`; after operator approval, `systemextensionsctl list` reported the provider version 2 as `activated enabled`. |
| Packet flow | `./smoke.sh test` connected, applied `192.0.2.2/32`, routed only `198.51.100.254/32` through `utun10`, set MTU 1280 and scoped `gate0.invalid` DNS to `192.0.2.53`. One ICMP request received one synthetic reply (0% loss), proving the local `packetFlow` read/write path. |
| Stop and cleanup | The VPN disconnected, its configuration was removed, the route returned to the default via `en0`, and the scoped resolver disappeared. The app was removed after system-extension deactivation. `systemextensionsctl list` still reports the inert provider as `terminated waiting to uninstall on reboot`; verify its disappearance after the next reboot. |

No VPN gateway, Fortinet process, or SSO flow was involved. The remaining
cleanup check is macOS's physical removal of the extension after reboot.

`build.sh` first uses an ad hoc signature to check bundle structure; the
Developer ID signing step replaces it with the profile-authorized signature.

## Apple account setup

Xcode Settings > Apple Accounts shows the operator's Developer Program team
and Admin role. A **Developer ID Application** certificate is installed with
its private key in this Mac's login keychain. Verify without displaying key
material:

```sh
security find-identity -v -p codesigning
```

Two explicit macOS App IDs are registered with the **Network Extensions**
capability. The host App ID also has **System Extensions**:

| Component | Bundle ID |
| --- | --- |
| Host app | `com.chris.openforticlient.gate0` |
| System extension | `com.chris.openforticlient.gate0.provider` |

There is a separate **Developer ID** provisioning profile for each App ID using
the same team and Developer ID Application certificate. Each profile must
authorize `packet-tunnel-provider-systemextension`; the host profile must also
authorize `com.apple.developer.system-extension.install`. If either ID is unavailable,
choose a unique host ID and run `BUNDLE_ID=<chosen-host-id> ./build.sh`; the
extension ID will be `<chosen-host-id>.provider`. Pass the same `BUNDLE_ID` to
`smoke.sh`. Keep profiles and certificate
private keys outside this repo. Profile paths are passed as environment
variables to the signing script; the profiles are copied only into ignored
`build/` output.

Apple's [deployment table](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
allows direct Developer ID distribution of a macOS packet-tunnel **system
extension**. Both host and extension need the Network Extensions entitlement;
Developer ID uses its `-systemextension` value and profiles for both bundles
([Apple DTS](https://developer.apple.com/forums/thread/737894),
[Apple entitlement reference](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)).
Xcode 27 reportedly fixes the older Direct Distribution export bug, but this
probe uses an explicit signing script so each asset can be inspected.

## Build and sign

From this directory:

```sh
./build.sh
DEVELOPER_ID_IDENTITY='Developer ID Application: ...' \
APP_PROFILE=/private/path/to/host.provisionprofile \
EXTENSION_PROFILE=/private/path/to/provider.provisionprofile \
./sign-developer-id.sh
codesign --verify --deep --strict --verbose=2 build/Gate0Host.app
```

`sign-developer-id.sh` validates the exact bundle IDs, common team, expiry,
and required entitlements in both profiles before copying them into the bundles
and signing the extension and app from the inside out. It never prints profile
contents or private-key material. The generated app is ignored by Git.

## Mac approval and narrowly scoped smoke test

Apple requires directly distributed system extensions to be notarized
([System Extensions](https://developer.apple.com/documentation/systemextensions)).
The `oftc-gate0` notary credential is stored in the local keychain. To recreate
it on another Mac, use `notarytool store-credentials` and enter an app-specific
password only at its secure prompt; never send it to the repo or chat:

```sh
xcrun notarytool store-credentials oftc-gate0 \
  --apple-id '<your Apple Developer email>' --team-id HU2S8957ZY
NOTARY_KEYCHAIN_PROFILE=oftc-gate0 ./notarize.sh
```

The script uploads a ZIP of the signed app, waits for Apple, staples the ticket,
then checks `codesign`, `stapler`, and `spctl`. If submission fails, retain the
submission ID from `notarytool` and inspect its log before changing code or
signing assets. The ZIP is ignored in `build/`.

After notarization, run the local install test below. `install` copies the
probe to `/Applications/OFTC Gate0 Probe.app` and asks macOS to activate the
system extension. macOS may ask for approval in System Settings. Activation may
also request a restart. The test then creates only its own VPN configuration;
macOS may separately ask to allow that configuration. These operations affect
system networking, so review the signed app and test route before running them.
Disconnect any active enterprise VPN first; Apple's `NETunnelProviderManager`
documentation says only one enterprise VPN configuration can be enabled at a
time. `smoke.sh test` refuses to start while another VPN is active. Tailscale
was disconnected for this test. Installing and activating
the extension does not start its VPN configuration; a separate test step does.

```sh
./smoke.sh install
systemextensionsctl list
./smoke.sh test
./smoke.sh cleanup
systemextensionsctl list
```

`test` waits for the tunnel to report connected, inspects the one host route,
scoped DNS, and MTU, sends one ICMP echo to `198.51.100.254`, and stops/removes its
VPN configuration even if an intermediate check fails. The reply from this
local-only provider is the packet-flow proof. Compare the post-stop
route and DNS output to ensure the probe's utun and resolver disappeared.
`cleanup` deactivates the extension and removes only the dedicated probe app.
macOS may retain the deactivated provider until reboot. Check
`systemextensionsctl list` afterward before claiming physical removal. No VPN,
SSO, gateway, or real internal route is involved.

The provider uses Apple's documented
[`NEProvider.startSystemExtensionMode()`](https://developer.apple.com/documentation/networkextension/neprovider/startsystemextensionmode%28%29),
[`NEPacketTunnelProvider`](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider),
and [system-extension activation](https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers).
