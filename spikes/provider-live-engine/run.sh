#!/bin/sh
set -eu
cd "$(dirname "$0")"
cache=${OFTC_SWIFT_CACHE:-/private/tmp/oftc-crypto-swift-cache}
build_dir=${OFTC_BUILD_DIR:-${TMPDIR:-/private/tmp}/oftc-provider-live-engine}
mkdir -p "$build_dir"
target="$(uname -m)-apple-macos11.0"
xcrun swiftc -module-cache-path "$cache" -target "$target" -O \
  -emit-library ../crypto/swift-bridge.swift \
  -Xlinker -install_name -Xlinker @rpath/libcrypto_swift.dylib \
  -o "$build_dir/libcrypto_swift.dylib"
CARGO_TARGET_DIR="$build_dir/modp14-target" cargo build --offline --locked --release \
  --manifest-path ../modp14/Cargo.toml
rustc --edition 2021 --test session.rs -L "$build_dir" -l dylib=crypto_swift \
  --extern oftc_modp14="$build_dir/modp14-target/release/liboftc_modp14.rlib" \
  -L "dependency=$build_dir/modp14-target/release/deps" \
  -C 'link-arg=-Wl,-rpath,@loader_path' -o "$build_dir/provider-live-engine-test"
"$build_dir/provider-live-engine-test"
rustc --edition 2021 --crate-type rlib session.rs \
  --extern oftc_modp14="$build_dir/modp14-target/release/liboftc_modp14.rlib" \
  -L "dependency=$build_dir/modp14-target/release/deps" \
  -o "$build_dir/libprovider_live_engine.rlib"
echo 'Built provider-owned session rlib; no network request was sent.'
