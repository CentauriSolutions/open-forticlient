#!/bin/zsh
set -euo pipefail

root="${0:A:h}"
bundle_id="${BUNDLE_ID:-com.chris.openforticlient.gate0}"
app="$root/build/Gate0Host.app"
extension="$app/Contents/Library/SystemExtensions/${bundle_id}.provider.systemextension"

if [[ ! "$bundle_id" =~ '^[A-Za-z0-9][A-Za-z0-9.-]*$' ]]; then
    print -u2 'BUNDLE_ID must be a valid reverse-DNS bundle identifier'
    exit 2
fi

rm -rf "$root/build"
mkdir -p "$app/Contents/MacOS" "$extension/Contents/MacOS" "$root/build/module-cache"
cp "$root/Host/Info.plist" "$app/Contents/Info.plist"
cp "$root/Provider/Info.plist" "$extension/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $bundle_id" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier ${bundle_id}.provider" "$extension/Contents/Info.plist"

export CLANG_MODULE_CACHE_PATH="$root/build/module-cache"
export SWIFT_MODULECACHE_PATH="$root/build/module-cache"
target="$(uname -m)-apple-macosx13.0"
xcrun swiftc -swift-version 5 -target "$target" -module-name Gate0Host \
    -framework Foundation -framework NetworkExtension -framework SystemExtensions \
    "$root/Host/main.swift" -o "$app/Contents/MacOS/Gate0Host"
xcrun swiftc -swift-version 5 -target "$target" -module-name Gate0Provider \
    -framework Foundation -framework NetworkExtension \
    "$root/Provider/main.swift" "$root/Provider/PacketTunnelProvider.swift" \
    -o "$extension/Contents/MacOS/Gate0Provider"

# Ad hoc signatures verify bundle structure only. They cannot authorize the
# restricted entitlement or activate the system extension.
codesign --force --sign - --options runtime --entitlements "$root/Provider/DeveloperID.entitlements" "$extension"
codesign --force --sign - --options runtime --entitlements "$root/Host/DeveloperID.entitlements" "$app"
codesign --verify --deep --strict --verbose=2 "$app"
print "Built ad hoc probe: $app"
print 'Gate 0 remains unproved until Developer ID profiles, signing, installation, and packet I/O.'
