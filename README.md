# Open Forticlient (OFTC)

A macOS VPN client for **FortiGate IPsec IKEv2 gateways that use browser SAML
sign-in**. It lives in the menu bar, keeps more than one VPN connected at a time,
and reconnects after sleep, lock, and network changes. Every reconnect needs a fresh
browser sign-in (SAML tokens are single use), so you may see a sign-in window when the
tunnel comes back.

OFTC runs its own IKEv2 and ESP engine inside a NetworkExtension packet tunnel.
Normal connections do not run Fortinet's daemons or read FortiClient's files;
the app can import an existing FortiClient profile once, during setup.

> **Not affiliated with Fortinet.** "FortiGate" and "FortiClient" are trademarks
> of Fortinet, Inc., used here only to say which gateways this client talks to.
> OFTC performs the same authentication the official client does; it changes how
> reconnection behaves, not what you are allowed to reach.

## Features

- **Several tunnels at once.** Every VPN is a peer profile with its own macOS VPN
  entry, Keychain PSK, supervisor, and connect-at-login setting. Each reconnects
  independently, and each tunnel's routes go through its own interface. (Detecting
  *overlapping* routes between tunnels is not built yet; see the roadmap.)
- **Menu bar controls.** A row per VPN with its state, Connect/Disconnect,
  per-VPN "Connect at login", and live traffic rates and sparklines while connected.
- **Recovers from sleep, lock, and roaming.** When the gateway drops the session, a
  supervisor starts a new sign-in and reconnects once you complete it in your
  browser (each attempt needs a fresh single-use token); sign-ins are queued one at a
  time.
- **Share VPN setups.** `oftc export` (or *Settings → Export VPNs…*) writes your
  profiles to a `.oftc` file; opening that file on a colleague's Mac adds them.
- **Safe with self-signed gateways.** If a gateway's certificate is not trusted
  you are asked, with the fingerprint, and the choice is pinned; a later change
  is flagged.
- **Update notices.** The app can tell you a new release exists (it never installs
  anything itself).
- A small `oftc` command-line tool for everything above.

## Requirements

- macOS 15 or later on Apple silicon.
- A FortiGate IPsec IKEv2 VPN that signs in with SAML, and its pre-shared key.
  (The PSK is not the secret that protects access; your SAML sign-in is.)
- An administrator password to install, and approval of OFTC's system extension
  in *System Settings → General → Login Items & Extensions* the first time.

## Install

Download a release from the
[Releases page](https://github.com/CentauriSolutions/open-forticlient/releases):

- `Open-Forticlient-<version>.dmg`: open it and double-click **1 Install OFTC.pkg**.
- or `OFTC-<version>.pkg` directly.

Both are signed with a Developer ID and notarized. The installer puts
**Open Forticlient** in `/Applications`, the `oftc` command in `/usr/local/bin`,
and `man oftc`. An interactive install opens the app, so its icon appears in the
menu bar. On a fresh install it also starts at login; turn that off in *Settings*. Quit OFTC
and disconnect first if you are updating.

Then add a VPN: choose **Add VPN…** in the menu bar popover, run `oftc setup`, or
open a `.oftc` file someone sent you. You sign in to each VPN in your browser.

## Use

```sh
oftc setup --gateway vpn.example.com --saml-port 9443 --name "Office VPN"
oftc profiles                  # list VPNs
oftc connect                   # connect every VPN (or: oftc connect office-vpn)
oftc status
oftc autostart office-vpn on   # connect at login
oftc disconnect
oftc export -o vpns.oftc       # share your VPNs (the file contains each PSK)
oftc setup --from vpns.oftc    # import a shared file
oftc remove office-vpn
```

`oftc help` and `man oftc` list everything. More detail is in
[docs/operations.md](docs/operations.md); managed deployment is in
[docs/managed-deployment.md](docs/managed-deployment.md).

## How it works

`oftc` → host app → NetworkExtension provider → Rust IKE/ESP engine. The host owns
profiles, Keychain access, browser SAML, VPN configuration, and the reconnect
supervisor; the provider owns transport, IKEv2/EAP, ESP, routes, and DNS. SAML
tokens are handed to the provider for a single start and never written down. See
[docs/architecture.md](docs/architecture.md) and the protocol notes in
[docs/](docs/). If something fails, [docs/support.md](docs/support.md) says what to send.

## Build from source

You can build and check an unsigned development bundle and the CLI without
touching any installed VPN:

```sh
OFTC_BUILD_DIR=/private/tmp/oftc-build-local zsh app/build.sh
zsh scripts/test-rust.sh
```

`app/build.sh` writes only to the build directory and runs the offline checks. It
does not sign, install, activate, authenticate, or connect. A NetworkExtension
only runs when signed with a Developer ID and matching provisioning profiles;
the release scripts (`app/sign-developer-id.sh`, `notarize-app.sh`, `package.sh`,
`make-dmg.sh`) take those identities from the environment. [AGENTS.md](AGENTS.md)
has the working conventions.

## Status

Working: UDP and TCP outer transport, IKE and CHILD SA rekeying, concurrent
tunnels, recovery after sleep, SAML re-authentication, the menu bar app, `.oftc`
sharing, and signed installers. Still open: the live gate for the Rust provider,
overlapping-route detection and DNS policy across tunnels, IPv6-only/NAT64
acceptance, and an installer test on a clean Mac. See [docs/ROADMAP.md](docs/ROADMAP.md).

## Acknowledgements

OFTC was built at [The San Francisco Compute Company](https://sfcompute.com), where
people reach several private networks over FortiGate VPNs from laptops that sleep,
lock, and wander between Wi-Fi networks, and the stock client's habit of dropping
the tunnel every time got old. We wrote the client we wanted to use, and they were
kind enough to let it go out into the world as open source. Thank you to the team.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.
