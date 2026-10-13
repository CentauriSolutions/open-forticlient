#!/bin/zsh
# Submit only the frozen signed v12 recovery candidate. Does not install it.
set -euo pipefail

build='/private/tmp/oftc-v12-recovery-build'
app="$build/IntegrationHost.app"
archive="$build/IntegrationHost-v12-notary.zip"
extension="$app/Contents/Library/SystemExtensions/com.chris.openforticlient.gate0.provider.systemextension"
expected_sha256='1f48ffdcb2f62573b851af94dc05720031cd4e9d044500467af90886d3af602b'
: "${NOTARY_KEYCHAIN_PROFILE:?Set the existing notarytool keychain profile}"

[[ -f "$archive" && "$(shasum -a 256 "$archive" | awk '{print $1}')" == "$expected_sha256" ]] || {
    print -u2 'Frozen v12 archive is missing or changed'; exit 2
}
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist")" == 12 &&
   "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$extension/Contents/Info.plist")" == 12 ]] || {
    print -u2 'Expected v12 host and provider'; exit 2
}
codesign --verify --deep --strict "$app"
xcrun notarytool submit "$archive" --keychain-profile "$NOTARY_KEYCHAIN_PROFILE" --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
codesign --verify --deep --strict "$app"
spctl --assess --type execute "$app"
print "Notarized and stapled uninstalled v12 candidate: $app"
