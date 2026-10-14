# macOS app

This is the active OFTC host, NetworkExtension provider, and IKE/ESP engine.
[`build.sh`](build.sh) creates an unsigned development bundle and runs offline
checks. It writes `OFTC.app` to a fresh `OFTC_BUILD_DIR=/private/tmp/oftc-build-*`
or the ignored `app/build/` path and refuses an existing output directory.
It never changes the installed app or VPN state.

```sh
OFTC_BUILD_DIR=/private/tmp/oftc-build-local zsh app/build.sh
```

[`sign-developer-id.sh`](sign-developer-id.sh) is a separate, explicit signing
step for the final OFTC bundle IDs. It requires matching Developer ID profiles
and identity. [`notarize-app.sh`](notarize-app.sh) and
[`package.sh`](package.sh) prepare a stapled app and signed package containing
the CLI and man page; [`notarize-package.sh`](notarize-package.sh) notarizes
the package. Installation, extension activation, and live traffic require
separate validation. See the [roadmap](../docs/ROADMAP.md).

[`docs/architecture.md`](../docs/architecture.md) maps each source directory.
The previous `spikes/` builds and the Fortinet-backed CLI are in Git commit
`b9ade25`; no active build input points there.
