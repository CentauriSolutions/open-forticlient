#!/bin/zsh
set -euo pipefail

root="${0:A:h}"
repo="${root:h:h}"
bundle_id="${BUNDLE_ID:-com.chris.openforticlient.gate0}"
[[ "$bundle_id" =~ '^[A-Za-z0-9][A-Za-z0-9.-]*$' ]] || {
    print -u2 'BUNDLE_ID must be a reverse-DNS bundle identifier'; exit 2
}
build="${OFTC_SIGNED_JOIN_BUILD_DIR:-$root/build}"
case "$build" in
    "$root/build"|/private/tmp/oftc-*) ;;
    *) print -u2 'OFTC_SIGNED_JOIN_BUILD_DIR must be an /private/tmp/oftc-* path'; exit 2 ;;
esac
app="$build/IntegrationHost.app"
extension="$app/Contents/Library/SystemExtensions/${bundle_id}.provider.systemextension"
app_frameworks="$app/Contents/Frameworks"
provider_frameworks="$extension/Contents/Frameworks"
target="$(uname -m)-apple-macosx13.0"

# This directory is private to this spike. The installed v3 app and its build
# tree are never modified, signed, or replaced by this script.
rm -rf "$build"
mkdir -p "$app/Contents/MacOS" "$app_frameworks" \
    "$extension/Contents/MacOS" "$provider_frameworks" "$build/module-cache"
export CLANG_MODULE_CACHE_PATH="$build/module-cache"
export SWIFT_MODULECACHE_PATH="$build/module-cache"
cp "$root/Host/Info.plist" "$app/Contents/Info.plist"
cp "$root/Provider/Info.plist" "$extension/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $bundle_id" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier ${bundle_id}.provider" "$extension/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist" "$extension/Contents/Info.plist"

xcrun swiftc -swift-version 5 -target "$target" -O -emit-library \
    -Xlinker -install_name -Xlinker '@rpath/libcrypto_swift.dylib' \
    "$repo/spikes/crypto/swift-bridge.swift" -o "$provider_frameworks/libcrypto_swift.dylib"
CARGO_TARGET_DIR="$build/modp14-target" cargo build --offline --locked --release \
    --manifest-path "$repo/spikes/modp14/Cargo.toml"
rustc --edition=2021 --crate-name oftc_session --crate-type rlib \
    "$repo/spikes/provider-live-engine/session.rs" \
    --extern oftc_modp14="$build/modp14-target/release/liboftc_modp14.rlib" \
    -L "dependency=$build/modp14-target/release/deps" \
    -o "$build/liboftc_session.rlib"
rustc --edition=2021 --crate-type cdylib -C opt-level=z \
    "$repo/spikes/provider-ffi/ffi.rs" \
    --extern oftc_session="$build/liboftc_session.rlib" \
    -L "dependency=$build/modp14-target/release/deps" \
    -L "$provider_frameworks" -l dylib=crypto_swift \
    -C 'link-arg=-Wl,-install_name,@rpath/liboftc_provider_ffi.dylib' \
    -C 'link-arg=-Wl,-rpath,@loader_path' \
    -o "$provider_frameworks/liboftc_provider_ffi.dylib"
rustc --edition=2021 --crate-type cdylib -C opt-level=z \
    "$root/Provider/preflight.rs" \
    -L "$provider_frameworks" -l dylib=crypto_swift \
    -C 'link-arg=-Wl,-install_name,@rpath/liboftc_preflight.dylib' \
    -C 'link-arg=-Wl,-rpath,@loader_path' \
    -o "$provider_frameworks/liboftc_preflight.dylib"
rustc --edition=2021 --test "$root/Provider/preflight.rs" \
    -L "$provider_frameworks" -l dylib=crypto_swift \
    -C 'link-arg=-Wl,-rpath,@loader_path' -o "$build/preflight-tests"
DYLD_LIBRARY_PATH="$provider_frameworks" "$build/preflight-tests"

rustc --edition=2021 --crate-type cdylib -C opt-level=z \
    "$repo/spikes/host-bootstrap/lib.rs" \
    -C 'link-arg=-Wl,-install_name,@rpath/liboftc_host_bootstrap.dylib' \
    -o "$app_frameworks/liboftc_host_bootstrap.dylib"
rustc --edition=2021 --crate-type staticlib -C opt-level=z \
    "$root/Host/migration.rs" \
    -o "$build/liboftc_migration.a"
rustc --edition=2021 --test "$root/Host/migration.rs" -o "$build/migration-tests"
"$build/migration-tests"
xcrun swiftc -swift-version 5 -target "$target" -O -module-name IntegrationHost \
    -framework Foundation -framework NetworkExtension -framework Security -framework SystemExtensions \
    -L "$app_frameworks" -l oftc_host_bootstrap \
    "$build/liboftc_migration.a" \
    -Xlinker -rpath -Xlinker '@executable_path/../Frameworks' \
    "$repo/spikes/provider-ipc/Bootstrap.swift" \
    "$root/Host/CandidateHostBridge.swift" \
    "$root/Host/MigrationBridge.swift" \
    "$root/Host/OFTCProfile.swift" \
    "$root/Host/ReconnectSupervisor.swift" \
    "$root/Provider/BootstrapInput.swift" "$root/Host/main.swift" \
    -o "$app/Contents/MacOS/IntegrationHost"
xcrun swiftc -swift-version 5 -target "$target" -O -module-name IntegrationProvider \
    -framework Foundation -framework NetworkExtension \
    -import-objc-header "$repo/spikes/provider-ffi/oftc_ffi.h" \
    -L "$provider_frameworks" -l oftc_provider_ffi -l oftc_preflight \
    -Xlinker -rpath -Xlinker '@executable_path/../Frameworks' \
    "$repo/spikes/provider-ipc/Bootstrap.swift" \
    "$repo/spikes/provider-settings/SettingsMapper.swift" \
    "$root/Provider/BootstrapInput.swift" "$root/Provider/FFISettings.swift" \
    "$repo/spikes/packet-tunnel-integration/Provider/main.swift" \
    "$root/Provider/PacketTunnelProvider.swift" \
    -o "$extension/Contents/MacOS/IntegrationProvider"

xcrun swiftc -swift-version 5 -target "$target" \
    -framework Foundation -framework NetworkExtension \
    -L "$app_frameworks" -l oftc_host_bootstrap \
    -Xlinker -rpath -Xlinker "$app_frameworks" \
    "$repo/spikes/provider-ipc/Bootstrap.swift" \
    "$root/Host/CandidateHostBridge.swift" \
    "$root/Provider/BootstrapInput.swift" "$root/Provider/check.swift" \
    -o "$build/bootstrap-check"
"$build/bootstrap-check"
xcrun swiftc -swift-version 5 -target "$target" \
    -framework Foundation -framework NetworkExtension \
    -L "$app_frameworks" -l oftc_host_bootstrap \
    -Xlinker -rpath -Xlinker "$app_frameworks" \
    "$repo/spikes/provider-ipc/Bootstrap.swift" \
    "$root/Host/CandidateHostBridge.swift" \
    "$root/Provider/BootstrapInput.swift" \
    "$root/Host/ReconnectSupervisor.swift" \
    "$root/Host/check-supervisor.swift" \
    -o "$build/supervisor-check"
"$build/supervisor-check"
xcrun swiftc -swift-version 5 -target "$target" \
    "$root/Host/OFTCProfile.swift" "$root/Host/check-profile.swift" \
    -o "$build/profile-check"
"$build/profile-check"
otool -L "$app/Contents/MacOS/IntegrationHost" \
    "$extension/Contents/MacOS/IntegrationProvider" | \
    grep -E 'liboftc_host_bootstrap|liboftc_provider_ffi|liboftc_preflight'
print "Offline unsigned bundle built: $app"
print 'No SAML flow, VPN start, extension activation, Developer ID signing, or notarization occurred.'
