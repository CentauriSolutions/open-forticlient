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
agent_plist="$app/Contents/Library/LaunchAgents/${bundle_id}.agent.plist"
host_plist="$app/Contents/Library/LaunchAgents/${bundle_id}.host.plist"
target="$(uname -m)-apple-macosx13.0"

# A fresh output path protects installed and notarized artifacts.
mkdir -p "$app/Contents/MacOS" "$app/Contents/Helpers" "$app/Contents/Resources" \
    "${agent_plist:h}" \
    "$extension/Contents/MacOS" "$build/module-cache"
export CLANG_MODULE_CACHE_PATH="$build/module-cache"
export SWIFT_MODULECACHE_PATH="$build/module-cache"
cp "$root/Host/Info.plist" "$app/Contents/Info.plist"
cp "$root/Provider/Info.plist" "$extension/Contents/Info.plist"
cp "$root/Host/LaunchAgent.plist" "$agent_plist"
cp "$root/Host/HostAgent.plist" "$host_plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $bundle_id" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier ${bundle_id}.provider" "$extension/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist" "$extension/Contents/Info.plist" "$agent_plist" "$host_plist"
# The host service plist is static and bundled (SMAppService.agent): its file name is
# its label, it runs the entitled main executable as `host serve`, restarts after a failed exit and
# lets supervisors outlive it, and names no per-user path.
plist_value() { /usr/libexec/PlistBuddy -c "Print :$1" "$host_plist"; }
[[ $(plist_value Label) == "${bundle_id}.host" ]] || { print -u2 'Host plist Label must be <bundle id>.host'; exit 1; }
[[ $(plist_value BundleProgram) == Contents/MacOS/OFTCAgent ]] || { print -u2 'Host plist must run Contents/MacOS/OFTCAgent'; exit 1; }
[[ $(plist_value ProgramArguments:0) == OFTCAgent && $(plist_value ProgramArguments:1) == host \
   && $(plist_value ProgramArguments:2) == serve ]] \
   && ! plist_value ProgramArguments:3 >/dev/null 2>&1 || {
    print -u2 'Host plist ProgramArguments must be exactly: OFTCAgent host serve'; exit 1
}
# Restart only after a failure: `host serve` exits 0 on SIGTERM or when another host
# holds the socket, and neither should respawn it.
[[ $(plist_value KeepAlive:SuccessfulExit) == false ]] || {
    print -u2 'Host plist must set KeepAlive to {SuccessfulExit: false}'; exit 1
}
for key in RunAtLoad AbandonProcessGroup; do
    [[ $(plist_value $key) == true ]] || { print -u2 "Host plist must set $key true"; exit 1; }
done
for key in StandardOutPath StandardErrorPath WorkingDirectory Program Sockets; do
    if plist_value $key >/dev/null 2>&1; then print -u2 "Host plist must not set $key"; exit 1; fi
done

cp "$root/assets/OFTC.icns" "$app/Contents/Resources/OFTC.icns"
cp "$root/assets/OFTCDocument.icns" "$app/Contents/Resources/OFTCDocument.icns"
mkdir -p "$app/Contents/Resources/en.lproj"
cp "$root/Host/en.lproj/InfoPlist.strings" "$app/Contents/Resources/en.lproj/InfoPlist.strings"

# The UI reaches the host only through Host/HostEdge.swift (docs/ui-edge.md, section 10): the
# ratchet fails on any new reach around it, and its own test pins that it can fail.
zsh "$root/check-ui-edge-test.sh"
zsh "$root/check-ui-edge.sh"

export CARGO_TARGET_DIR="$build/rust-target"
cargo build --locked --release --workspace --manifest-path "$root/Cargo.toml"
# The provider is the Rust OFTCTunnel executable from this workspace build; it
# statically links the engine, provider logic and preflight.
cp "$CARGO_TARGET_DIR/release/OFTCTunnel" "$extension/Contents/MacOS/OFTCTunnel"
cp "$CARGO_TARGET_DIR/release/liboftc_hostlib.a" "$build/liboftc_hostlib.a"
unset CARGO_TARGET_DIR

xcrun swiftc -swift-version 5 -target "$target" -O -module-name OFTCAgent \
    -framework AppKit -framework Foundation -framework NetworkExtension -framework Security \
    -framework SecurityInterface -framework ServiceManagement -framework SystemExtensions \
    "$build/liboftc_hostlib.a" \
    "$root/Host/MigrationBridge.swift" \
    "$root/Host/OFTCProfile.swift" \
    "$root/Host/ProfileScope.swift" \
    "$root/Host/LauncherAlias.swift" \
    "$root/Host/UpdateCheck.swift" \
    "$root/Host/GatewayTrust.swift" \
    "$root/Host/GatewayTrustPrompt.swift" \
    "$root/Host/Onboarding.swift" \
    "$root/Host/LaunchExperience.swift" \
    "$root/Host/SetupPlan.swift" \
    "$root/Host/SetupRepair.swift" \
    "$root/Host/Welcome.swift" \
    "$root/Host/ControlsWindow.swift" \
    "$root/Host/HostEdge.swift" \
    "$root/Host/MenuCommand.swift" \
    "$root/Host/MenuModel.swift" \
    "$root/Host/TrafficHistory.swift" \
    "$root/Host/RateSparklineView.swift" \
    "$root/Host/MenuBar.swift" \
    "$root/Host/main.swift" \
    -o "$app/Contents/MacOS/OFTCAgent"
xcrun swiftc -swift-version 5 -target "$target" \
    "$root/Host/OFTCProfile.swift" "$root/Host/ProfileScope.swift" "$root/Host/LauncherAlias.swift" \
    "$root/Host/UpdateCheck.swift" "$root/Host/check-misc.swift" -o "$build/misc-check"
"$build/misc-check"
xcrun swiftc -swift-version 5 -target "$target" \
    "$root/Host/OFTCProfile.swift" "$root/Host/check-profile.swift" \
    -o "$build/profile-check"
"$build/profile-check"
# The setup window still reads the profiles the Rust host writes; it must accept them.
# This goes with that reader when the window moves onto the host's add_profile.
xcrun swiftc -swift-version 5 -target "$target" \
    -framework Foundation -framework NetworkExtension \
    "$root/Host/OFTCProfile.swift" "$root/Host/ProfileScope.swift" "$root/Host/check-host-compat.swift" \
    -o "$build/host-compat-check"
"$build/host-compat-check" "$root/core/host/tests/fixtures/rust"
xcrun swiftc -swift-version 5 -target "$target" \
    "$root/Host/GatewayTrust.swift" "$root/Host/check-trust-compat.swift" \
    -o "$build/trust-compat-check"
"$build/trust-compat-check" "$root/core/host/tests/fixtures"
xcrun swiftc -swift-version 5 -target "$target" -framework Foundation \
    "$root/Host/MenuModel.swift" "$root/Host/TrafficHistory.swift" "$root/Host/HostEdge.swift" \
    "$root/Host/LaunchExperience.swift" "$root/Host/check-menu.swift" -o "$build/menu-check"
"$build/menu-check"
xcrun swiftc -swift-version 5 -target "$target" \
    "$root/Host/LaunchExperience.swift" "$root/Host/check-experience.swift" \
    -o "$build/experience-check"
"$build/experience-check"
xcrun swiftc -swift-version 5 -target "$target" \
    "$root/Host/MenuCommand.swift" "$root/Host/HostEdge.swift" "$root/Host/check-menu-command.swift" \
    -o "$build/menu-command-check"
"$build/menu-command-check"
# HostEdge against the golden documents core/ui-edge pins and a scripted host on a temporary
# unix socket (no real host, launchd or Network Extension).
xcrun swiftc -swift-version 5 -target "$target" \
    "$root/Host/HostEdge.swift" "$root/Host/check-host-edge.swift" -o "$build/host-edge-check"
"$build/host-edge-check" "$root/core/ui-edge/tests/golden"
xcrun swiftc -swift-version 5 -target "$target" \
    "$root/Host/LaunchExperience.swift" "$root/Host/MenuCommand.swift" "$root/Host/HostEdge.swift" \
    "$root/Host/SetupPlan.swift" "$root/Host/check-setup-plan.swift" \
    -o "$build/setup-plan-check"
"$build/setup-plan-check"
CARGO_TARGET_DIR="$build/client-target" cargo build --locked --release \
    --manifest-path "$root/../client/Cargo.toml"
cp "$build/client-target/release/oftc" "$build/oftc"
cp "$build/oftc" "$app/Contents/Helpers/oftc"
# The host links no OFTC dylib: the Rust host is static in the executable.
if otool -L "$app/Contents/MacOS/OFTCAgent" | grep -E '@rpath|liboftc'; then
    print -u2 'OFTCAgent must not depend on an OFTC dylib or an @rpath library'; exit 1
fi
# The provider carries no OFTC dylib and no unresolved @rpath dependency.
if otool -L "$extension/Contents/MacOS/OFTCTunnel" | grep -E '@rpath|liboftc'; then
    print -u2 'The provider must not depend on an OFTC dylib or an @rpath library'; exit 1
fi
print "Offline unsigned bundle built: $app"
print 'No SAML flow, VPN start, extension activation, Developer ID signing, or notarization occurred.'
