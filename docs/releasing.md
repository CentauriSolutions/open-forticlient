# Releasing

CI builds and tests every push and pull request; releases are built, signed and
notarized on a maintainer's Mac, because the signing identities and the
NetworkExtension provisioning profiles never leave it.

## CI

`.github/workflows/ci.yml` runs on `macos-15` for each push to `main`, each pull
request, and each merge-queue group (the repo merges through a queue, which needs the
`merge_group` trigger). Three jobs run in order, each a required check: `Rust lint`
(`scripts/lint-rust.sh`, clippy with warnings fatal, plus shell syntax), `Rust tests`
(`scripts/test-rust.sh -- --include-ignored`, which also runs the loopback-socket tests a
default local run skips), and `Build, test, unsigned package`, which runs `app/build.sh`
(the unsigned bundle and the Swift checks) and then `OFTC_UNSIGNED_PACKAGE=1 zsh app/package.sh`, and uploads
`OFTC-<version>-<commit>-unsigned.pkg` plus `SHA256SUMS` as the `oftc-unsigned-pkg`
artifact (kept 14 days). The unsigned package is for inspecting the payload and
install scripts; macOS will not activate its extension, and it is not for users.

### Required checks

`main` is protected by a ruleset (squash only, merge queue, required checks). The
build job is required. Whoever adds a new CI job makes it required after their PR
merges, with `scripts/require-check.sh --apply "<job name>"` (run without `--apply`
to preview). That needs admin rights on the repo.

## Gate build (Rust provider candidate)

The provider extension is the Rust `OFTCTunnel` binary (`app/core/tunnel`), built by
`app/build.sh` with the rest of the workspace. To produce a signed, notarized app for a
live gate check without cutting a release, from a clean checkout:

```sh
zsh app/gate-build.sh   # fresh /private/tmp/oftc-build-gate-*, sign, notarize; prints the app path
```

It uses the same environment as `release.sh` (`~/.config/oftc/release.env`), needs no
installer identity, and installs nothing. Afterwards run `zsh app/release-dev-assets.sh`.

## Version policy

macOS moves a system extension forward only. It will not replace an activated
provider with one whose version is not higher, and a rollback is not a downgrade: a
rollback build must be numbered **higher than the build it replaces**, which is higher
than every build ever activated.

- `app/Provider/Info.plist` (`CFBundleVersion`, and `CFBundleShortVersionString`)
  must be higher than every provider build activated on any maintained Mac.
  `app/provider-version-floor` records that highest build and version (36 / 1.0.13:
  the dev Mac's gate builds 1.0.8/31, 1.0.10/33 and 1.0.13/36 came from local
  uncommitted plist bumps, while `main` still said 1.0.5/29).
- `app/check-versions.sh` fails unless the provider is above that floor. `release.sh`
  runs it first and CI runs it in the lint job.
- Gate builds (`app/gate-build.sh`) do not bump anything. When a gate needs a newer
  provider than `main` has, bump `app/Provider/Info.plist` locally, uncommitted, to a
  build above everything activated so far. Once such a build is activated, raise
  `app/provider-version-floor` to it in a PR before the next release; the check then
  keeps `main` from shipping below it.
- The host (`app/Host/Info.plist`) is the product version: the tag, the package and the
  update notice use it. It is not subject to the extension rule.
- The first generally available release is 1.0.0, host build 44, provider 1.3.2 build 52.
  The host's display version restarts at 1.0.0 for the public release; its build number
  (`CFBundleVersion`) keeps rising from the private builds (1.2.2 was build 41), because
  the app compares builds, not display versions, to tell a stale host from a current one.
  The package does not version-check the bundle (`BundleIsVersionChecked` is false), so a
  lower display version still installs over an older private build. Builds shared before
  1.3.0 have no in-app update notice, so the first public release reaches those users by
  being handed to them. The provider is separate: it must stay above the activated floor
  (here 1.3.1 build 51, the highest activated on a maintained Mac), so it is 1.3.2/52.

## Cutting a release

1. Bump the version in `app/Host/Info.plist` (`CFBundleShortVersionString`,
   `CFBundleVersion`) and, if the provider changed, `app/Provider/Info.plist`, keeping
   the provider above `app/provider-version-floor` (see Version policy).
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

## How the package upgrades an installed app

`app/package.sh` builds the component package with `app/package-files/component.plist`:
the app bundle is replaced as a whole (`BundleOverwriteAction` `upgrade`, so files the
new bundle lacks, such as an old `Frameworks` directory, are deleted rather than merged
into), is not relocatable (Installer never updates a `/private/tmp` build in its
place), requires the identifier to match, and is installed even when the disk holds a
higher build. `postinstall` also removes `Contents/Frameworks` left in the installed
bundle by older builds, only inside `/Applications/Open Forticlient.app` and only if its
identifier is ours; `package.sh` refuses a bundle that ships any `Frameworks` directory.
`zsh app/check-package-scripts.sh` (CI, lint job) tests that cleanup and the installer's
active-VPN test offline. What offline cannot show is that Installer really replaces an
old bundle this way: see the checklist.

The distribution file still sets `allow-external-scripts` (its `checkUpdate` runs
`system.run`); `productbuild` warns that Apple will break this in a future macOS. The
preinstall script makes the same checks, so removing the distribution script loses only
the earlier, friendlier message.

## Live checklist before publishing a draft

Run on a Mac, with the signed, notarized pkg from `dist/<version>/`; these are the claims
CI and the offline checks cannot make.

1. **Clean install** (no OFTC, no `/Applications/Open Forticlient.app`): install; the
   app opens and the menu bar icon appears; `pkgutil --pkg-info com.chris.openforticlient.oftc.pkg`
   shows the version; `codesign --verify --deep --strict "/Applications/Open Forticlient.app"` and
   `spctl --assess --type execute` pass; approve the extension; connect a VPN.
   `systemextensionsctl list` shows the provider `activated enabled` at build 50 or higher.
2. **Upgrade over an old build** (a Swift-provider build installed, VPNs saved):
   disconnect every VPN, install; `ls "/Applications/Open Forticlient.app/Contents"` has
   no `Frameworks`; the codesign check passes; the saved VPNs are still listed; activate
   the new provider (Settings, Add VPN...); `systemextensionsctl list` shows the new
   version `activated enabled` with the old one `terminated`/removed and no error 8.
   Repeat once with a VPN connected: Installer must refuse and name the VPN.
3. **Uninstall**: `oftc uninstall`. Expect: VPNs stop; the system extension is
   deactivated (approve or reboot if macOS asks, then rerun); `/Applications/Open Forticlient.app`,
   `/usr/local/bin/oftc`, `/usr/local/libexec/oftc` and the receipt are gone;
   System Settings, General, Login Items & Extensions lists no OFTC item
   (no `...oftc.host`, no `...oftc.agent`, no OFTC app item); profiles, Keychain PSKs
   and `~/Library/Logs/OFTC` remain unless `--erase-profile`.

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
