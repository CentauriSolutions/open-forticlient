#!/bin/zsh
# Submit only the frozen signed v13 supervisor diagnostic candidate. Does not install it.
set -euo pipefail

build='/private/tmp/oftc-v13-supervisor-build'
app="$build/IntegrationHost.app"
archive="$build/IntegrationHost-v13-notary.zip"
extension="$app/Contents/Library/SystemExtensions/com.chris.openforticlient.gate0.provider.systemextension"
expected_sha256='cd91dd01b0b20433f91ecd977da2fb84eb95c4f532cdc16eafbf9a701bcce9d1'
: "${NOTARY_KEYCHAIN_PROFILE:?Set the existing notarytool keychain profile}"

[[ -f "$archive" && "$(shasum -a 256 "$archive" | awk '{print $1}')" == "$expected_sha256" ]] || {
    print -u2 'Frozen v13 archive is missing or changed'; exit 2
}
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist")" == 13 &&
   "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$extension/Contents/Info.plist")" == 13 ]] || {
    print -u2 'Expected v13 host and provider'; exit 2
}
codesign --verify --deep --strict "$app"
xcrun notarytool submit "$archive" --keychain-profile "$NOTARY_KEYCHAIN_PROFILE" --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
codesign --verify --deep --strict "$app"
spctl --assess --type execute "$app"
print "Notarized and stapled uninstalled v13 candidate: $app"
