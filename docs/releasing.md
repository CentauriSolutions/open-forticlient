# Releasing

CI builds and tests every push and pull request; releases are built, signed and
notarized on a maintainer's Mac, because the signing identities and the
NetworkExtension provisioning profiles never leave it.

## CI

`.github/workflows/ci.yml` runs on `macos-15` for each push to `main`, each pull
request, and each merge-queue group (the repo merges through a queue, which needs the
`merge_group` trigger). Three jobs run in order, each a required check: `Rust lint`
(`scripts/lint-rust.sh`, clippy with warnings fatal, plus shell syntax), `Rust tests`
(`scripts/test-rust.sh`), and `Build, test, unsigned package`, which runs `app/build.sh`
(the unsigned bundle and the Swift checks) and then `OFTC_UNSIGNED_PACKAGE=1 zsh app/package.sh`, and uploads
`OFTC-<version>-<commit>-unsigned.pkg` plus `SHA256SUMS` as the `oftc-unsigned-pkg`
artifact (kept 14 days). The unsigned package is for inspecting the payload and
install scripts; macOS will not activate its extension, and it is not for users.

### Required checks

`main` is protected by a ruleset (squash only, merge queue, required checks). The
build job is required. Whoever adds a new CI job makes it required after their PR
merges, with `scripts/require-check.sh --apply "<job name>"` (run without `--apply`
to preview). That needs admin rights on the repo.

## Cutting a release

1. Bump the version in `app/Host/Info.plist` (`CFBundleShortVersionString`,
   `CFBundleVersion`) and, if the provider changed, `app/Provider/Info.plist`.
   Scripts read the version from there; nothing else needs editing.
2. Update `docs/` and the update-feed expectations if behaviour changed, commit, and
   merge to `main`.
3. Tag the commit: `git tag -s vX.Y.Z` (matching `CFBundleShortVersionString`).
4. On the release Mac, from a clean checkout of that tag:

   ```sh
   zsh app/release.sh            # build, sign, notarize, package, DMG into dist/X.Y.Z/
   zsh app/release.sh --publish  # same, then push the tag and create a DRAFT release
   ```

5. Install the package on a test Mac (upgrade and clean install), then publish the
   draft on GitHub. The app's update notice reads the latest published release, so
   publishing is what tells users about it.
6. `zsh app/release-dev-assets.sh` removes test builds from Launch Services.

The DMG attached to a release is the generic one. A DMG with a team's default VPNs
(`OFTC_VPNS_FILE=vpns.oftc zsh app/make-dmg.sh`) is for first installs and is not
published.

## Local signing setup

`app/release.sh` reads these from the environment or from `~/.config/oftc/release.env`
(a file of `NAME=value` lines; keep it outside the repo):

| Variable | What |
| --- | --- |
| `DEVELOPER_ID_IDENTITY` | SHA-1 of the Developer ID Application certificate |
| `DEVELOPER_ID_INSTALLER_IDENTITY` | Developer ID Installer identity |
| `NOTARY_PROFILE` | `notarytool store-credentials` profile name |
| `APP_PROFILE`, `EXTENSION_PROFILE` | paths to the host and provider Developer ID provisioning profiles for the exact bundle ids (all-devices, packet-tunnel entitlement) |

Each step is also a script (`sign-developer-id.sh`, `notarize-app.sh`, `package.sh`,
`notarize-package.sh`, `make-dmg.sh`) if you need to re-run one. A release build
uses a fresh `/private/tmp/oftc-build-release-*` directory every time.
