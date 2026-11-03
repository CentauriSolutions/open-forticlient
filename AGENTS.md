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
- The repo lives at `CentauriSolutions/open-forticlient` and merges through a merge
  queue; CI must keep its `merge_group` trigger. One PR is one change, and PRs are squash-merged: the PR title is the commit
  subject (Conventional Commits) and the body is the commit body, with `Refs #N` /
  `Fixes #N`. For a series, stack PRs (each based on the previous branch) rather than
  one large PR; GitHub retargets a stacked PR to `main` when its base merges.
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
- **New CI checks are required by whoever adds them.** Tests added to an existing job
  are covered by that job's required check. A new workflow or job is not required
  until it is added to the `main` ruleset: after the PR that introduces it merges (so
  the check name has reported on `main`), run
  `scripts/require-check.sh --apply "<job name>"` and say so in the PR or issue.
  Do not add the check before its PR merges, or the merge queue waits on a check
  that never reports.
- **Every test earns its place.** A unit test is added or kept only if it pins a
  behaviour, branch or boundary that no other test already pins. Do not add a test to
  raise a count, to re-assert a constant, or to re-test a dependency beyond the
  known-answer vectors the code relies on. Two tests that exercise the same function
  with the same class of input are one test: delete one, or fold them into a
  table-driven test whose rows are distinct cases. A test that could not fail if the
  code were broken is vacuous; fix it or delete it. When a change ports or moves code,
  its tests move with it, and any that now duplicate another are dropped in the same
  change with a note saying what covers the behaviour instead. Reviewers check this.
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
