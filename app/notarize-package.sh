#!/bin/zsh
set -euo pipefail

root="${0:A:h}"
build="${OFTC_BUILD_DIR:-$root/build}"
if [[ "$build" != "$root/build" && ! "$build" =~ '^/private/tmp/oftc-build-[A-Za-z0-9-]+$' ]]; then
    print -u2 'OFTC_BUILD_DIR must be app/build or a /private/tmp/oftc-build-* path'
    exit 2
fi
package="$build/OFTC-1.0.6.pkg"
: "${NOTARY_PROFILE:?Set NOTARY_PROFILE to a notarytool keychain profile name}"
[[ -f "$package" ]] || { print -u2 'Signed package missing'; exit 2; }
pkgutil --check-signature "$package"
xcrun notarytool submit "$package" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$package"
xcrun stapler validate "$package"
spctl --assess --type install --verbose=2 "$package"
print "Notarized and stapled package: $package"
print 'The package was not installed.'
