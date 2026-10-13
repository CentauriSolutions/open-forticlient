#!/bin/zsh
set -euo pipefail
root="${0:A:h}"
target="$(uname -m)-apple-macosx13.0"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/module-cache"
export CLANG_MODULE_CACHE_PATH="$tmp/module-cache"
export SWIFT_MODULECACHE_PATH="$tmp/module-cache"
xcrun swiftc -swift-version 5 -target "$target" -typecheck \
    -framework Foundation -framework NetworkExtension \
    "$root/SettingsMapper.swift" "$root/check.swift"
xcrun swiftc -swift-version 5 -target "$target" -O \
    -framework Foundation -framework NetworkExtension \
    "$root/SettingsMapper.swift" "$root/check.swift" -o "$tmp/check"
"$tmp/check"
