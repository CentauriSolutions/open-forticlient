#!/bin/zsh
set -euo pipefail

root="${0:A:h}"
bundle_id="${BUNDLE_ID:-com.chris.openforticlient.integration}"
[[ "$bundle_id" =~ '^[A-Za-z0-9][A-Za-z0-9.-]*$' ]] || {
    print -u2 'BUNDLE_ID must be a reverse-DNS bundle identifier'; exit 2;
}
app="$root/build/IntegrationHost.app"
extension="$app/Contents/Library/SystemExtensions/${bundle_id}.provider.systemextension"
frameworks="$extension/Contents/Frameworks"
bin="$extension/Contents/MacOS"
target="$(uname -m)-apple-macosx13.0"

rm -rf "$root/build"
mkdir -p "$app/Contents/MacOS" "$bin" "$frameworks" "$root/build/module-cache"
cp "$root/Host/Info.plist" "$app/Contents/Info.plist"
cp "$root/Provider/Info.plist" "$extension/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $bundle_id" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier ${bundle_id}.provider" "$extension/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist" "$extension/Contents/Info.plist"

export CLANG_MODULE_CACHE_PATH="$root/build/module-cache"
export SWIFT_MODULECACHE_PATH="$root/build/module-cache"
xcrun swiftc -swift-version 5 -target "$target" -O -emit-library \
    -Xlinker -install_name -Xlinker '@rpath/libcrypto_swift.dylib' \
    "$root/../crypto/swift-bridge.swift" -o "$frameworks/libcrypto_swift.dylib"
rustc --edition=2021 --crate-type cdylib -C opt-level=z -C strip=symbols \
    "$root/Core/packet.rs" -L native="$frameworks" -l dylib=crypto_swift \
    -C 'link-arg=-Wl,-install_name,@rpath/liboftc_core.dylib' \
    -C 'link-arg=-Wl,-rpath,@loader_path' -o "$frameworks/liboftc_core.dylib"
xcrun swiftc -swift-version 5 -target "$target" -O -module-name IntegrationHost \
    -framework Foundation -framework NetworkExtension -framework SystemExtensions \
    "$root/IPC/Bootstrap.swift" "$root/Host/main.swift" -o "$app/Contents/MacOS/IntegrationHost"
xcrun swiftc -swift-version 5 -target "$target" -O -module-name IntegrationProvider \
    -framework Foundation -framework NetworkExtension -L "$frameworks" -l oftc_core \
    -Xlinker -rpath -Xlinker '@executable_path/../Frameworks' \
    "$root/IPC/Bootstrap.swift" "$root/Provider/main.swift" "$root/Provider/PacketTunnelProvider.swift" \
    -o "$bin/IntegrationProvider"

# Run the same two dylibs from the provider's executable directory before signing.
xcrun swiftc -swift-version 5 -target "$target" -O -L "$frameworks" -l oftc_core \
    -Xlinker -rpath -Xlinker '@executable_path/../Frameworks' \
    "$root/check.swift" -o "$bin/IntegrationCheck"
"$bin/IntegrationCheck"
rm "$bin/IntegrationCheck"

# Nested code must be signed before its containing system extension and app.
codesign --force --sign - --options runtime "$frameworks/libcrypto_swift.dylib"
codesign --force --sign - --options runtime "$frameworks/liboftc_core.dylib"
codesign --force --sign - --options runtime \
    --entitlements "$root/Provider/DeveloperID.entitlements" "$extension"
codesign --force --sign - --options runtime \
    --entitlements "$root/Host/DeveloperID.entitlements" "$app"
codesign --verify --strict --verbose=2 "$frameworks/libcrypto_swift.dylib"
codesign --verify --strict --verbose=2 "$frameworks/liboftc_core.dylib"
codesign --verify --deep --strict --verbose=2 "$app"

python3 "$root/check_bundle.py" "$app" "$extension"
print "Ad hoc integration bundle: $app"
print 'Ad hoc signatures validate local structure only; this script never activates the extension.'
