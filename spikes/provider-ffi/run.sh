#!/bin/sh
set -eu
cd "$(dirname "$0")"
cache=${OFTC_SWIFT_CACHE:-/private/tmp/oftc-crypto-swift-cache}
build_dir=${OFTC_BUILD_DIR:-${TMPDIR:-/private/tmp}/oftc-provider-ffi}
mkdir -p "$build_dir"
mkdir -p "$build_dir/module-cache"
export CLANG_MODULE_CACHE_PATH="$build_dir/module-cache"
export SWIFT_MODULECACHE_PATH="$build_dir/module-cache"
target="$(uname -m)-apple-macos11.0"
xcrun swiftc -module-cache-path "$cache" -target "$target" -O \
  -emit-library ../crypto/swift-bridge.swift \
  -Xlinker -install_name -Xlinker @rpath/libcrypto_swift.dylib \
  -o "$build_dir/libcrypto_swift.dylib"
CARGO_TARGET_DIR="$build_dir/modp14-target" cargo build --offline --locked --release \
  --manifest-path ../modp14/Cargo.toml
rustc --edition 2021 --crate-name oftc_session --crate-type rlib \
  ../provider-live-engine/session.rs \
  --extern oftc_modp14="$build_dir/modp14-target/release/liboftc_modp14.rlib" \
  -L "dependency=$build_dir/modp14-target/release/deps" \
  -o "$build_dir/liboftc_session.rlib"
rustc --edition 2021 --test ffi.rs --extern oftc_session="$build_dir/liboftc_session.rlib" \
  -L "dependency=$build_dir/modp14-target/release/deps" \
  -L "$build_dir" -l dylib=crypto_swift \
  -C 'link-arg=-Wl,-rpath,@loader_path' -o "$build_dir/provider-ffi-test"
"$build_dir/provider-ffi-test"
rustc --edition 2021 --crate-type cdylib -C opt-level=z ffi.rs \
  --extern oftc_session="$build_dir/liboftc_session.rlib" \
  -L "dependency=$build_dir/modp14-target/release/deps" \
  -L "$build_dir" -l dylib=crypto_swift \
  -C 'link-arg=-Wl,-install_name,@rpath/liboftc_provider_ffi.dylib' \
  -C 'link-arg=-Wl,-rpath,@loader_path' -o "$build_dir/liboftc_provider_ffi.dylib"
xcrun swiftc -swift-version 5 -target "$(uname -m)-apple-macosx13.0" \
  -typecheck -import-objc-header oftc_ffi.h check.swift
echo 'Offline C ABI, Rust tests, cdylib, and Swift typecheck passed; no network request was sent.'
