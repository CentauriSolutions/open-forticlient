#!/bin/sh
set -eu
cd "$(dirname "$0")"

build_dir=$(mktemp -d "${TMPDIR:-/private/tmp}/oftc-packet-flow-bridge.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT
cache=${OFTC_SWIFT_CACHE:-/private/tmp/oftc-crypto-swift-cache}
target="$(uname -m)-apple-macos11.0"

xcrun swiftc -module-cache-path "$cache" -target "$target" -O \
  -emit-library ../crypto/swift-bridge.swift -o "$build_dir/libcrypto_swift.dylib"
rustc --edition 2021 -O -A dead_code --crate-type cdylib bridge.rs -L "$build_dir" \
  -l dylib=crypto_swift -C 'link-arg=-Wl,-rpath,@loader_path' \
  -o "$build_dir/libpacket_flow_bridge.dylib"
xcrun swiftc -module-cache-path "$cache" -target "$target" check.swift \
  -L "$build_dir" -lpacket_flow_bridge \
  -Xlinker -rpath -Xlinker @executable_path \
  -o "$build_dir/check"
"$build_dir/check"
