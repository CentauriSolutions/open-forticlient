#!/bin/zsh
set -euo pipefail

root="${0:A:h}"
app="$root/build/IntegrationHost.app"
archive="$root/build/IntegrationHost-notarization.zip"
: "${NOTARY_KEYCHAIN_PROFILE:?Set NOTARY_KEYCHAIN_PROFILE to an existing notarytool keychain profile}"

codesign --verify --deep --strict --verbose=2 "$app"
details=$(codesign -dv --verbose=4 "$app" 2>&1)
[[ "$details" == *'Authority=Developer ID Application:'* ]] || {
    print -u2 'The app is not Developer ID signed'; exit 1;
}
rm -f "$archive"
ditto -c -k --sequesterRsrc --keepParent "$app" "$archive"
xcrun notarytool submit "$archive" --keychain-profile "$NOTARY_KEYCHAIN_PROFILE" --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
codesign --verify --deep --strict --verbose=2 "$app"
spctl --assess --type execute --verbose=4 "$app"
print "Notarized and stapled integration bundle: $app"
