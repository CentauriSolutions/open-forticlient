#!/bin/zsh
# Assemble a signed flat package from a notarized app and its signed CLI.
set -euo pipefail

root="${0:A:h}"
build="${OFTC_BUILD_DIR:-$root/build}"
if [[ "$build" != "$root/build" && ! "$build" =~ '^/private/tmp/oftc-build-[A-Za-z0-9-]+$' ]]; then
    print -u2 'OFTC_BUILD_DIR must be app/build or a /private/tmp/oftc-build-* path'
    exit 2
fi
app="$build/OFTC.app"
cli="$build/oftc"
stage="$build/package-root"
unsigned="$build/OFTC-unsigned.pkg"
component="$build/OFTC-component.pkg"
package="$build/OFTC-1.2.2.pkg"
: "${DEVELOPER_ID_INSTALLER_IDENTITY:?Set DEVELOPER_ID_INSTALLER_IDENTITY to a Developer ID Installer identity}"
[[ -d "$app" && -f "$cli" && ! -e "$stage" && ! -e "$unsigned" && ! -e "$package" && ! -e "$component" ]] || {
    print -u2 'Need a signed app and CLI in a fresh packaging output path'; exit 2
}
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist") == com.chris.openforticlient.oftc \
   && $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist") == 41 ]] || {
    print -u2 'Unexpected app identity or build number'; exit 2
}
codesign --verify --deep --strict --verbose=2 "$app"
codesign --verify --strict --verbose=2 "$cli"
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=2 "$app"
mkdir -p "$stage/Applications" "$stage/usr/local/bin" "$stage/usr/local/libexec/oftc" \
    "$stage/usr/local/share/man/man1"
ditto "$app" "$stage/Applications/Open Forticlient.app"
cp "$cli" "$stage/usr/local/bin/oftc"
cp "$root/package-files/remove-package" "$stage/usr/local/libexec/oftc/remove-package"
cp "$root/../client/man/oftc.1" "$stage/usr/local/share/man/man1/oftc.1"
pkgbuild --root "$stage" --install-location / --ownership recommended \
    --identifier com.chris.openforticlient.oftc.pkg --version 1.2.2 \
    --scripts "$root/package-scripts" "$component"
productbuild --distribution "$root/package-resources/Distribution.xml" \
    --resources "$root/package-resources" --package-path "$build" "$unsigned"
productsign --sign "$DEVELOPER_ID_INSTALLER_IDENTITY" "$unsigned" "$package"
pkgutil --check-signature "$package"
print "Developer ID signed package: $package"
print 'Notarize and staple this package before distribution.'
