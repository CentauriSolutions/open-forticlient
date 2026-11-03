#!/bin/zsh
set -euo pipefail

root="${0:A:h}"
bundle_id="com.chris.openforticlient.oftc"
[[ "$bundle_id" =~ '^[A-Za-z0-9][A-Za-z0-9.-]*$' ]] || {
    print -u2 'BUNDLE_ID must be a reverse-DNS bundle identifier'; exit 2
}
build="${OFTC_BUILD_DIR:-$root/build}"
if [[ "$build" != "$root/build" && ! "$build" =~ '^/private/tmp/oftc-build-[A-Za-z0-9-]+$' ]]; then
    print -u2 'OFTC_BUILD_DIR must be app/build or a /private/tmp/oftc-build-* path'
    exit 2
fi
if [[ -e "$build" || -L "$build" ]]; then
    print -u2 "Build directory already exists; choose a fresh path: $build"
    exit 2
fi
app="$build/OFTC.app"
extension="$app/Contents/Library/SystemExtensions/${bundle_id}.provider.systemextension"
app_frameworks="$app/Contents/Frameworks"
agent_plist="$app/Contents/Library/LaunchAgents/${bundle_id}.agent.plist"
provider_frameworks="$extension/Contents/Frameworks"
target="$(uname -m)-apple-macosx13.0"

# A fresh output path protects installed and notarized artifacts.
mkdir -p "$app/Contents/MacOS" "$app/Contents/Helpers" "$app/Contents/Resources" "$app_frameworks" \
    "${agent_plist:h}" \
    "$extension/Contents/MacOS" "$provider_frameworks" "$build/module-cache"
export CLANG_MODULE_CACHE_PATH="$build/module-cache"
export SWIFT_MODULECACHE_PATH="$build/module-cache"
cp "$root/Host/Info.plist" "$app/Contents/Info.plist"
cp "$root/Provider/Info.plist" "$extension/Contents/Info.plist"
cp "$root/Host/LaunchAgent.plist" "$agent_plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $bundle_id" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier ${bundle_id}.provider" "$extension/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist" "$extension/Contents/Info.plist" "$agent_plist"

cp "$root/assets/OFTC.icns" "$app/Contents/Resources/OFTC.icns"
cp "$root/assets/OFTCDocument.icns" "$app/Contents/Resources/OFTCDocument.icns"
mkdir -p "$app/Contents/Resources/en.lproj"
cp "$root/Host/en.lproj/InfoPlist.strings" "$app/Contents/Resources/en.lproj/InfoPlist.strings"

export CARGO_TARGET_DIR="$build/rust-target"
cargo test --locked --workspace --manifest-path "$root/Cargo.toml"
cargo build --locked --release --workspace --manifest-path "$root/Cargo.toml"
cp "$CARGO_TARGET_DIR/release/liboftc_provider_ffi.dylib" "$CARGO_TARGET_DIR/release/liboftc_preflight.dylib" \
    "$provider_frameworks/"
cp "$CARGO_TARGET_DIR/release/liboftc_host_bootstrap.dylib" "$app_frameworks/"
cp "$CARGO_TARGET_DIR/release/liboftc_migration.a" "$build/liboftc_migration.a"
unset CARGO_TARGET_DIR

xcrun swiftc -swift-version 5 -target "$target" -O -module-name OFTCAgent \
    -framework AppKit -framework Foundation -framework NetworkExtension -framework Security \
    -framework SecurityInterface -framework ServiceManagement -framework SystemExtensions \
    -L "$app_frameworks" -l oftc_host_bootstrap \
    "$build/liboftc_migration.a" \
    -Xlinker -rpath -Xlinker '@executable_path/../Frameworks' \
    "$root/support/Bootstrap.swift" \
    "$root/Host/CandidateHostBridge.swift" \
    "$root/Host/MigrationBridge.swift" \
    "$root/Host/OFTCProfile.swift" \
    "$root/Host/ProfileScope.swift" \
    "$root/Host/ProfileBundle.swift" \
    "$root/Host/LauncherAlias.swift" \
    "$root/Host/UpdateCheck.swift" \
    "$root/Host/GatewayTrust.swift" \
    "$root/Host/GatewayTrustPrompt.swift" \
    "$root/Host/Onboarding.swift" \
    "$root/Host/LaunchExperience.swift" \
    "$root/Host/ProviderReadiness.swift" \
    "$root/Host/Welcome.swift" \
    "$root/Host/ControlsWindow.swift" \
    "$root/Host/MenuCommand.swift" \
    "$root/Host/AgentService.swift" \
    "$root/Host/AgentIntent.swift" \
    "$root/Host/SupervisorStatus.swift" \
    "$root/Host/MenuModel.swift" \
    "$root/Host/TrafficHistory.swift" \
    "$root/Host/RateSparklineView.swift" \
    "$root/Host/MenuBar.swift" \
    "$root/support/TrafficStatistics.swift" \
    "$root/Host/ReconnectSupervisor.swift" \
    "$root/Provider/BootstrapInput.swift" "$root/Host/main.swift" \
    -o "$app/Contents/MacOS/OFTCAgent"
xcrun swiftc -swift-version 5 -target "$target" -O -module-name OFTCTunnel \
    -framework Foundation -framework NetworkExtension \
    -import-objc-header "$root/core/provider-ffi/oftc_ffi.h" \
    -L "$provider_frameworks" -l oftc_provider_ffi -l oftc_preflight \
    -Xlinker -rpath -Xlinker '@executable_path/../Frameworks' \
    "$root/support/Bootstrap.swift" \
    "$root/support/SettingsMapper.swift" \
    "$root/support/TrafficStatistics.swift" \
    "$root/Provider/BootstrapInput.swift" "$root/Provider/FFISettings.swift" \
    "$root/Provider/main.swift" \
    "$root/Provider/PacketTunnelProvider.swift" \
    -o "$extension/Contents/MacOS/OFTCTunnel"

xcrun swiftc -swift-version 5 -target "$target" \
    -framework Foundation -framework NetworkExtension \
    -L "$app_frameworks" -l oftc_host_bootstrap \
    -Xlinker -rpath -Xlinker "$app_frameworks" \
    "$root/support/Bootstrap.swift" \
    "$root/Host/CandidateHostBridge.swift" \
    "$root/Provider/BootstrapInput.swift" "$root/Provider/check.swift" \
    -o "$build/bootstrap-check"
"$build/bootstrap-check"
xcrun swiftc -swift-version 5 -target "$target" \
    -framework Foundation -framework NetworkExtension \
    -L "$app_frameworks" -l oftc_host_bootstrap \
    -Xlinker -rpath -Xlinker "$app_frameworks" \
    "$root/support/Bootstrap.swift" \
    "$root/Host/CandidateHostBridge.swift" \
    "$root/Provider/BootstrapInput.swift" \
    "$root/Host/ReconnectSupervisor.swift" \
    "$root/Host/SupervisorStatus.swift" \
    "$root/Host/OFTCProfile.swift" "$root/Host/ProfileScope.swift" \
    "$root/Host/AgentIntent.swift" \
    "$root/Host/ProfileBundle.swift" \
    "$root/Host/LauncherAlias.swift" \
    "$root/Host/UpdateCheck.swift" \
    "$root/Host/GatewayTrust.swift" \
    "$root/Host/check-supervisor.swift" \
    -o "$build/supervisor-check"
"$build/supervisor-check"
xcrun swiftc -swift-version 5 -target "$target" \
    "$root/Host/OFTCProfile.swift" "$root/Host/check-profile.swift" \
    -o "$build/profile-check"
"$build/profile-check"
xcrun swiftc -swift-version 5 -target "$target" \
    -framework Foundation -framework NetworkExtension \
    "$root/Host/MenuModel.swift" "$root/Host/AgentIntent.swift" \
    "$root/Host/TrafficHistory.swift" \
    "$root/Host/OFTCProfile.swift" "$root/Host/ProfileScope.swift" \
    "$root/Host/SupervisorStatus.swift" "$root/support/TrafficStatistics.swift" \
    "$root/Host/check-menu.swift" -o "$build/menu-check"
"$build/menu-check"
xcrun swiftc -swift-version 5 -target "$target" \
    "$root/Host/LaunchExperience.swift" "$root/Host/check-experience.swift" \
    -o "$build/experience-check"
"$build/experience-check"
xcrun swiftc -swift-version 5 -target "$target" \
    "$root/Host/MenuCommand.swift" "$root/Host/check-menu-command.swift" \
    -o "$build/menu-command-check"
"$build/menu-command-check"
CARGO_TARGET_DIR="$build/client-target" cargo test --locked \
    --manifest-path "$root/../client/Cargo.toml"
CARGO_TARGET_DIR="$build/client-target" cargo build --locked --release \
    --manifest-path "$root/../client/Cargo.toml"
cp "$build/client-target/release/oftc" "$build/oftc"
cp "$build/oftc" "$app/Contents/Helpers/oftc"
otool -L "$app/Contents/MacOS/OFTCAgent" \
    "$extension/Contents/MacOS/OFTCTunnel" | \
    grep -E 'liboftc_host_bootstrap|liboftc_provider_ffi|liboftc_preflight'
print "Offline unsigned bundle built: $app"
print 'No SAML flow, VPN start, extension activation, Developer ID signing, or notarization occurred.'
