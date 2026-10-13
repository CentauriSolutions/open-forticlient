#!/bin/zsh
set -euo pipefail

build='/private/tmp/oftc-gate5-unsigned-build'
app="$build/IntegrationHost.app"
archive="$build/IntegrationHost-v6-notary.zip"
expected_sha256='fa5b2cf8a6c19750b107c802e94741c3ff870bddff8e0ce0d680013c84182259'
: "${NOTARY_KEYCHAIN_PROFILE:?Set the existing notarytool keychain profile}"

[[ -f "$archive" ]] || { print -u2 'Prepared archive is missing'; exit 2; }
actual_sha256=$(shasum -a 256 "$archive" | awk '{print $1}')
[[ "$actual_sha256" == "$expected_sha256" ]] || {
    print -u2 'Prepared archive differs from the reviewed signed candidate'; exit 2
}
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist") == 6 ]] || {
    print -u2 'Expected host bundle version 6'; exit 2
}
extension="$app/Contents/Library/SystemExtensions/com.chris.openforticlient.gate0.provider.systemextension"
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$extension/Contents/Info.plist") == 6 ]] || {
    print -u2 'Expected provider bundle version 6'; exit 2
}
codesign --verify --deep --strict "$app"
xcrun notarytool submit "$archive" --keychain-profile "$NOTARY_KEYCHAIN_PROFILE" --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
codesign --verify --deep --strict "$app"
spctl --assess --type execute --verbose=4 "$app"
print "Notarized and stapled version 6 candidate: $app"
