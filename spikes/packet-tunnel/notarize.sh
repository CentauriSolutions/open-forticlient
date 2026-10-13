#!/bin/zsh
set -euo pipefail

root="${0:A:h}"
app="$root/build/Gate0Host.app"
archive="$root/build/Gate0Host-notarization.zip"
: "${NOTARY_KEYCHAIN_PROFILE:?Set NOTARY_KEYCHAIN_PROFILE to a profile stored with xcrun notarytool store-credentials}"

codesign --verify --deep --strict --verbose=2 "$app"
signature_details=$(codesign -dv --verbose=4 "$app" 2>&1)
[[ "$signature_details" == *'Authority=Developer ID Application:'* ]] || {
    print -u2 'The app is not Developer ID signed'; exit 1;
}

rm -f "$archive"
ditto -c -k --sequesterRsrc --keepParent "$app" "$archive"
xcrun notarytool submit "$archive" --keychain-profile "$NOTARY_KEYCHAIN_PROFILE" --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
codesign --verify --deep --strict --verbose=2 "$app"
spctl --assess --type execute --verbose=4 "$app"
print "Notarized and stapled: $app"
