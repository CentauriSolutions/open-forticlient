#!/bin/zsh
# Turn an app/build.sh bundle into a hello-Rust-provider bundle for the early smoke
# test: replace the Swift provider executable with this spike and point
# NEProviderClasses at the plain class name. Run before signing. Touches only the
# given fresh build directory; it never installs or activates anything.
set -euo pipefail
build="${1:?usage: swap-provider.sh /private/tmp/oftc-build-<name>}"
[[ "$build" =~ '^/private/tmp/oftc-build-[A-Za-z0-9-]+$' ]] || { print -u2 'build dir must be /private/tmp/oftc-build-*'; exit 2; }
here="${0:A:h}"
ext=("$build"/OFTC.app/Contents/Library/SystemExtensions/*.systemextension(N))
(( $#ext == 1 )) || { print -u2 'expected exactly one system extension in the bundle'; exit 2; }
(cd "$here" && cargo build --release --locked)
cp "$here/target/release/oftc-ne-spike" "$ext[1]/Contents/MacOS/OFTCTunnel"
/usr/libexec/PlistBuddy \
    -c "Set :NetworkExtension:NEProviderClasses:com.apple.networkextension.packet-tunnel OFTCPacketTunnelProvider" \
    "$ext[1]/Contents/Info.plist"
plutil -lint "$ext[1]/Contents/Info.plist"
print "Swapped provider in $ext[1]; sign it with app/sign-developer-id.sh before activating."
