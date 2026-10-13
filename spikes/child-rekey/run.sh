#!/bin/sh
set -eu
cd "$(dirname "$0")"
cache=${OFTC_SWIFT_CACHE:-/private/tmp/oftc-crypto-swift-cache}
target="$(uname -m)-apple-macos11.0"
tmp_dir=$(mktemp -d "${TMPDIR:-/private/tmp}/oftc-child-rekey.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT
xcrun swiftc -module-cache-path "$cache" -target "$target" -O \
  -emit-library ../crypto/swift-bridge.swift -o "$tmp_dir/libcrypto_swift.dylib"
CARGO_TARGET_DIR="$tmp_dir/modp14-target" cargo build --offline --locked --release \
  --manifest-path ../modp14/Cargo.toml
rustc --edition 2021 --test main.rs -L "$tmp_dir" -l dylib=crypto_swift \
  --extern oftc_modp14="$tmp_dir/modp14-target/release/liboftc_modp14.rlib" \
  -L "dependency=$tmp_dir/modp14-target/release/deps" \
  -C 'link-arg=-Wl,-rpath,@loader_path' -o "$tmp_dir/child-rekey-test"
"$tmp_dir/child-rekey-test"
