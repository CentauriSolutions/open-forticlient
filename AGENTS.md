# AGENTS.md

Guidance for anyone (human or agent) working in this repo.

## What this project is

OFTC (Open Forticlient) is a standalone macOS **FortiGate IPsec IKEv2 + SAML**
client. The active app, provider, engine, and CLI are in [app/](app/) and
[client/](client/). The former Fortinet-backed controller and experiment source
are preserved under the `legacy-controller` tag, not in the active source tree.
Start with [README.md](README.md), [docs/architecture.md](docs/architecture.md),
and [docs/ROADMAP.md](docs/ROADMAP.md).

## Issue tracking

Work is tracked in GitHub Issues for this repository. Code comments, docs, and
commit messages that say "Issue 13" mean GitHub issue #13.

- Reference the issue a change belongs to in its commit message.
- Keep an issue's task list current as work lands, and close it when its
  acceptance criteria are met.
- If scope shifts materially, open a new issue and link it rather than silently
  expanding an existing one.

## Working style for this repo

- **Build from active sources.** `app/build.sh` must use `app/` inputs only.
  Use a fresh build directory; do not point a build at an installed or
  notarized app.
- **Keep evidence levels distinct.** Offline build, Developer ID signing,
  notarization, installation, extension activation, and live traffic are
  separate claims; say which one a result supports.
- **Releases are local.** CI only builds, tests and makes an unsigned package;
  signing, notarization and the GitHub draft release run from `app/release.sh` on a
  maintainer's Mac ([docs/releasing.md](docs/releasing.md)). Never put signing
  identities, profiles or notary credentials in the repo or in CI.
- **Release dev assets when a test is done.** Every `OFTC.app` a build leaves
  under `/private/tmp` gets registered with Launch Services under the shipping
  bundle id, and stale copies keep old file-type declarations, icons and names
  alive for the installed app. After testing, run
  `zsh app/release-dev-assets.sh --keep <build you still need>`; also delete
  scratch exports (`.oftc` files carry PSKs) and fake apps made for experiments.
- **No secrets in the repo.** SAML `tokenid`s are single-use credentials; they and
  raw captures are covered by `.gitignore` and must never be committed. Large
  reverse-engineering dumps (`*.asm`, `strings`) are regenerable and also ignored.
  The former research tools are under the `legacy-controller` tag.
- **No private infrastructure in the repo.** Examples, tests, and docs use
  reserved names and addresses (`vpn.example.com`, `203.0.113.0/24`, RFC 1918
  ranges), never a real gateway, profile name, or network.
- **This is interoperability for the machine's own operator** (the legitimate VPN
  user and FortiGate admin). The replacement performs the same authentication the
  official client does; it changes reconnection behavior, not access control.
