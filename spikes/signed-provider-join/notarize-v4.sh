#!/bin/zsh
set -euo pipefail

root="${0:A:h}"
app="$root/build/IntegrationHost.app"
archive="$root/build/IntegrationHost-v4-notary.zip"
expected_sha256='4174f0085a1478c9ab881045813680f12d262abcd59aef943a0dbde2e744d43a'
: "${NOTARY_KEYCHAIN_PROFILE:?Set the existing notarytool keychain profile}"

[[ -f "$archive" ]] || { print -u2 'Prepared archive is missing'; exit 2; }
actual_sha256=$(shasum -a 256 "$archive" | awk '{print $1}')
[[ "$actual_sha256" == "$expected_sha256" ]] || {
    print -u2 'Prepared archive differs from the reviewed signed candidate'; exit 2
}
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist") == 4 ]] || {
    print -u2 'Expected bundle version 4'; exit 2
}
codesign --verify --deep --strict "$app"
xcrun notarytool submit "$archive" --keychain-profile "$NOTARY_KEYCHAIN_PROFILE" --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
codesign --verify --deep --strict "$app"
spctl --assess --type execute --verbose=4 "$app"
print "Notarized and stapled version 4 candidate: $app"
