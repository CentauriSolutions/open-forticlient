#!/bin/zsh
set -euo pipefail

build='/private/tmp/oftc-v9-group14-build'
app="$build/IntegrationHost.app"
archive="$build/IntegrationHost-v9-notary.zip"
expected_sha256='beb5287f842f709912239c210e03b06a264f9b26757c28ab7e50418d573ec994'
: "${NOTARY_KEYCHAIN_PROFILE:?Set the existing notarytool keychain profile}"

[[ -f "$archive" ]] || { print -u2 'Prepared archive is missing'; exit 2; }
actual_sha256=$(shasum -a 256 "$archive" | awk '{print $1}')
[[ "$actual_sha256" == "$expected_sha256" ]] || {
    print -u2 'Prepared archive differs from the signed v9 candidate'; exit 2
}
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist") == 9 ]] || {
    print -u2 'Expected host bundle version 9'; exit 2
}
extension="$app/Contents/Library/SystemExtensions/com.chris.openforticlient.gate0.provider.systemextension"
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$extension/Contents/Info.plist") == 9 ]] || {
    print -u2 'Expected provider bundle version 9'; exit 2
}
codesign --verify --deep --strict "$app"
xcrun notarytool submit "$archive" --keychain-profile "$NOTARY_KEYCHAIN_PROFILE" --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
codesign --verify --deep --strict "$app"
spctl --assess --type execute --verbose=4 "$app"
print "Notarized and stapled version 9 candidate: $app"
