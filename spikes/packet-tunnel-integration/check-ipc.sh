#!/bin/zsh
set -euo pipefail
root="${0:A:h}"
target="$(uname -m)-apple-macosx13.0"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/module-cache"
export CLANG_MODULE_CACHE_PATH="$tmp/module-cache"
export SWIFT_MODULECACHE_PATH="$tmp/module-cache"

# Typecheck the real host and provider source files without linking, signing,
# installing, or starting either executable.
xcrun swiftc -swift-version 5 -target "$target" -typecheck \
    -module-name IntegrationHost -framework Foundation \
    -framework NetworkExtension -framework SystemExtensions \
    "$root/IPC/Bootstrap.swift" "$root/Host/main.swift"
xcrun swiftc -swift-version 5 -target "$target" -typecheck \
    -module-name IntegrationProvider -framework Foundation \
    -framework NetworkExtension \
    "$root/IPC/Bootstrap.swift" "$root/Provider/main.swift" \
    "$root/Provider/PacketTunnelProvider.swift"
xcrun swiftc -swift-version 5 -target "$target" -O \
    "$root/IPC/Bootstrap.swift" "$root/IPC/check.swift" -o "$tmp/check"
"$tmp/check"
