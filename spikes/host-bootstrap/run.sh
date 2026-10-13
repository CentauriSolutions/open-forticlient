#!/bin/zsh
set -euo pipefail
root="${0:A:h}"
repo="${root:h:h}"
target="$(uname -m)-apple-macosx13.0"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/module-cache"
export CLANG_MODULE_CACHE_PATH="$tmp/module-cache"
export SWIFT_MODULECACHE_PATH="$tmp/module-cache"

rustc --edition=2021 --test "$root/lib.rs" -o "$tmp/rust-tests"
"$tmp/rust-tests"
rustc --edition=2021 --crate-type cdylib --cfg oftc_synthetic \
    "$root/lib.rs" -o "$tmp/liboftc_host_bootstrap.dylib"
xcrun swiftc -swift-version 5 -target "$target" -D OFTC_SYNTHETIC -typecheck \
    -framework Foundation -framework NetworkExtension \
    "$repo/spikes/provider-ipc/Bootstrap.swift" \
    "$root/HostBridge.swift" "$root/check.swift"
xcrun swiftc -swift-version 5 -target "$target" -D OFTC_SYNTHETIC \
    -framework Foundation -framework NetworkExtension \
    -L "$tmp" -loftc_host_bootstrap \
    "$repo/spikes/provider-ipc/Bootstrap.swift" \
    "$root/HostBridge.swift" "$root/check.swift" -o "$tmp/check"
DYLD_LIBRARY_PATH="$tmp" "$tmp/check"
