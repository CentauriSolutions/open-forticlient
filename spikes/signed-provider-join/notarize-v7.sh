#!/bin/zsh
set -euo pipefail

build='/private/tmp/oftc-v7-rekey-build'
app="$build/IntegrationHost.app"
archive="$build/IntegrationHost-v7-notary.zip"
expected_sha256='ea601e2512b309f0b838ad3a69f908dbe4ee773f67993c810cc6ac32cc1b7c34'
: "${NOTARY_KEYCHAIN_PROFILE:?Set the existing notarytool keychain profile}"

[[ -f "$archive" ]] || { print -u2 'Prepared archive is missing'; exit 2; }
actual_sha256=$(shasum -a 256 "$archive" | awk '{print $1}')
[[ "$actual_sha256" == "$expected_sha256" ]] || {
    print -u2 'Prepared archive differs from the signed v7 candidate'; exit 2
}
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist") == 7 ]] || {
    print -u2 'Expected host bundle version 7'; exit 2
}
extension="$app/Contents/Library/SystemExtensions/com.chris.openforticlient.gate0.provider.systemextension"
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$extension/Contents/Info.plist") == 7 ]] || {
    print -u2 'Expected provider bundle version 7'; exit 2
}
codesign --verify --deep --strict "$app"
xcrun notarytool submit "$archive" --keychain-profile "$NOTARY_KEYCHAIN_PROFILE" --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
codesign --verify --deep --strict "$app"
spctl --assess --type execute --verbose=4 "$app"
print "Notarized and stapled version 7 candidate: $app"
