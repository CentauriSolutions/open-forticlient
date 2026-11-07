#!/bin/zsh
# Assemble a signed flat package from a notarized app and its signed CLI.
# With OFTC_UNSIGNED_PACKAGE=1 (CI), package an unsigned build instead and skip
# every signature check; that package cannot activate the extension.
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
unsigned_only="${OFTC_UNSIGNED_PACKAGE:-}"
version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist")
package="$build/OFTC-$version.pkg"
[[ -n "$unsigned_only" ]] && package="$build/OFTC-$version-unsigned.pkg"
[[ "$version" =~ '^[0-9]+(\.[0-9]+){1,2}$' ]] || { print -u2 "Unexpected app version: $version"; exit 2; }
[[ -n "$unsigned_only" ]] || : "${DEVELOPER_ID_INSTALLER_IDENTITY:?Set DEVELOPER_ID_INSTALLER_IDENTITY to a Developer ID Installer identity}"
[[ -d "$app" && -f "$cli" && ! -e "$stage" && ! -e "$unsigned" && ! -e "$package" && ! -e "$component" ]] || {
    print -u2 'Need a signed app and CLI in a fresh packaging output path'; exit 2
}
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist") == com.chris.openforticlient.oftc ]] || {
    print -u2 'Unexpected app identity'; exit 2
}
if [[ -z "$unsigned_only" ]]; then
    codesign --verify --deep --strict --verbose=2 "$app"
    codesign --verify --strict --verbose=2 "$cli"
    xcrun stapler validate "$app"
    spctl --assess --type execute --verbose=2 "$app"
fi
mkdir -p "$stage/Applications" "$stage/usr/local/bin" "$stage/usr/local/libexec/oftc" \
    "$stage/usr/local/share/man/man1"
ditto "$app" "$stage/Applications/Open Forticlient.app"
# An installed profile must be readable by every user, or codesign --verify --deep
# fails for a non-root user (the signing script installs them 0644).
if [[ -n "$(find "$stage/Applications" -name embedded.provisionprofile ! -perm -004 -print -quit)" ]]; then
    print -u2 'An embedded.provisionprofile in the bundle is not world-readable'; exit 2
fi
# The postinstall script deletes any Contents/Frameworks it finds in the installed
# bundle (leftovers of older builds); the current bundle must therefore ship none.
if [[ -n "$(find "$stage/Applications" -type d -name Frameworks -print -quit)" ]]; then
    print -u2 'The app must not contain a Frameworks directory (postinstall removes stale ones)'; exit 2
fi
cp "$cli" "$stage/usr/local/bin/oftc"
cp "$root/package-files/remove-package" "$stage/usr/local/libexec/oftc/remove-package"
# The source man page and Distribution.xml carry @OFTC_VERSION@; the product version is the app's plist.
sed "s/@OFTC_VERSION@/$version/g" "$root/../client/man/oftc.1" > "$stage/usr/local/share/man/man1/oftc.1"
pkgbuild --root "$stage" --install-location / --ownership recommended \
    --identifier com.chris.openforticlient.oftc.pkg --version "$version" \
    --component-plist "$root/package-files/component.plist" --scripts "$root/package-scripts" "$component"
# The component version comes from the app, so a version bump is one edit.
mkdir -p "$build/package-resources"
ditto "$root/package-resources" "$build/package-resources"
sed -i '' "s/@OFTC_VERSION@/$version/g" \
    "$build/package-resources/Distribution.xml"
productbuild --distribution "$build/package-resources/Distribution.xml" \
    --resources "$build/package-resources" --package-path "$build" "$unsigned"
if [[ -n "$unsigned_only" ]]; then
    mv "$unsigned" "$package"
    print "UNSIGNED package (CI artifact, not for distribution): $package"
    exit 0
fi
productsign --sign "$DEVELOPER_ID_INSTALLER_IDENTITY" "$unsigned" "$package"
pkgutil --check-signature "$package"
print "Developer ID signed package: $package"
print 'Notarize and staple this package before distribution.'
