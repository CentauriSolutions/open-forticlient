#!/bin/zsh
# Notarize the signed release app before it is placed in a distribution package.
set -euo pipefail

root="${0:A:h}"
build="${OFTC_BUILD_DIR:-$root/build}"
if [[ "$build" != "$root/build" && ! "$build" =~ '^/private/tmp/oftc-build-[A-Za-z0-9-]+$' ]]; then
    print -u2 'OFTC_BUILD_DIR must be app/build or a /private/tmp/oftc-build-* path'
    exit 2
fi
app="$build/OFTC.app"
archive="$build/OFTC-app-notary.zip"
: "${NOTARY_PROFILE:?Set NOTARY_PROFILE to a notarytool keychain profile name}"
[[ -d "$app" && ! -e "$archive" ]] || {
    print -u2 'Signed app must exist and notary archive must be fresh'; exit 2
}
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist") == com.chris.openforticlient.oftc ]] || {
    print -u2 'Unexpected app bundle ID'; exit 2
}
codesign --verify --deep --strict --verbose=2 "$app"
ditto -c -k --keepParent "$app" "$archive"
xcrun notarytool submit "$archive" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=2 "$app"
print "Notarized and stapled app: $app"
print 'The app was not installed or activated.'
