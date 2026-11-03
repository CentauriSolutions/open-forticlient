#!/bin/zsh
# Build, sign, notarize and package a release on this Mac, then (optionally)
# attach it to a draft GitHub release. Nothing is published without --publish,
# and a published draft is still a draft until you click Publish on GitHub.
#
# Usage: app/release.sh [--publish]
#
# Run it from a clean checkout at the release tag (vX.Y.Z, matching the host
# CFBundleShortVersionString). Signing inputs come from the environment or from
# ~/.config/oftc/release.env (see docs/releasing.md); none are stored in the repo.
set -euo pipefail

root="${0:A:h}"
repo="${root:h}"
publish=0
[[ "${1:-}" == --publish ]] && { publish=1; shift; }
[[ $# -eq 0 ]] || { print -u2 'usage: app/release.sh [--publish]'; exit 2; }

[[ -f "$HOME/.config/oftc/release.env" ]] && source "$HOME/.config/oftc/release.env"
for name in DEVELOPER_ID_IDENTITY DEVELOPER_ID_INSTALLER_IDENTITY NOTARY_PROFILE APP_PROFILE EXTENSION_PROFILE; do
    [[ -n "${(P)name:-}" ]] || { print -u2 "Set $name (see docs/releasing.md)"; exit 2; }
done
export DEVELOPER_ID_IDENTITY DEVELOPER_ID_INSTALLER_IDENTITY NOTARY_PROFILE APP_PROFILE EXTENSION_PROFILE

version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$root/Host/Info.plist")
tag="v$version"
cd "$repo"
[[ -z "$(git status --porcelain)" ]] || { print -u2 'Working tree is not clean'; exit 2; }
[[ "$(git tag --points-at HEAD)" == *"$tag"* ]] || {
    print -u2 "HEAD is not tagged $tag. Bump the version, commit, then: git tag -s $tag"; exit 2
}

stamp=$(date +%Y%m%d%H%M%S)
export OFTC_BUILD_DIR="/private/tmp/oftc-build-release-$stamp"
dist="$repo/dist/$version"
[[ ! -e "$dist" ]] || { print -u2 "$dist already exists; remove it to rebuild"; exit 2; }

print "== build ($tag, $OFTC_BUILD_DIR)"
zsh "$root/../scripts/test-rust.sh"
zsh "$root/build.sh"
print '== sign';          zsh "$root/sign-developer-id.sh"
print '== notarize app';  zsh "$root/notarize-app.sh"
print '== package';       zsh "$root/package.sh"
print '== notarize pkg';  zsh "$root/notarize-package.sh"
print '== disk image';    OFTC_VPNS_FILE= zsh "$root/make-dmg.sh"

mkdir -p "$dist"
cp "$OFTC_BUILD_DIR/OFTC-$version.pkg" "$OFTC_BUILD_DIR/Open-Forticlient-$version.dmg" "$dist/"
(cd "$dist" && shasum -a 256 *.pkg *.dmg > SHA256SUMS)
print "Release files in $dist:"; ls -l "$dist"

if (( publish )); then
    print "== draft release $tag"
    git push origin "$tag"
    gh release create "$tag" --draft --verify-tag --title "Open Forticlient $version" \
        --generate-notes "$dist/OFTC-$version.pkg" "$dist/Open-Forticlient-$version.dmg" "$dist/SHA256SUMS"
    print 'Draft created. Review it on GitHub, then Publish.'
else
    print 'Not published. Re-run with --publish, or attach the files by hand.'
fi
print 'Test the package on a Mac, then: zsh app/release-dev-assets.sh'
