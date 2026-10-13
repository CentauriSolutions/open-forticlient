#!/bin/sh
set -eu
cd "$(dirname "$0")"

cache=${OFTC_SWIFT_CACHE:-/private/tmp/oftc-crypto-swift-cache}
target="$(uname -m)-apple-macos11.0"
tmp_dir=$(mktemp -d "${TMPDIR:-/private/tmp}/oftc-child-sa.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT
xcrun swiftc -module-cache-path "$cache" -target "$target" -O \
  -emit-library ../crypto/swift-bridge.swift -o "$tmp_dir/libcrypto_swift.dylib"
rustc --edition 2021 --test main.rs -L "$tmp_dir" -l dylib=crypto_swift \
  -C 'link-arg=-Wl,-rpath,@loader_path' -o "$tmp_dir/child-sa-test"
"$tmp_dir/child-sa-test"
