#!/bin/sh
set -eu
cd "$(dirname "$0")"
out=${OFTC_TCP_LIVE_BUILD_DIR:-/private/tmp/oftc-tcp-live-probe}
mkdir -p "$out"
cache=${OFTC_SWIFT_CACHE:-/private/tmp/oftc-crypto-swift-cache}
target="$(uname -m)-apple-macos11.0"
xcrun swiftc -module-cache-path "$cache" -target "$target" -O \
  -emit-library ../crypto/swift-bridge.swift \
  -Xlinker -install_name -Xlinker @rpath/libcrypto_swift.dylib \
  -o "$out/libcrypto_swift.dylib"
rustc --edition 2021 --test main.rs -L "$out" -l dylib=crypto_swift \
  -C 'link-arg=-Wl,-rpath,@loader_path' -o "$out/tcp-live-probe-test"
"$out/tcp-live-probe-test"
rustc --edition 2021 -C opt-level=2 main.rs -L "$out" -l dylib=crypto_swift \
  -C 'link-arg=-Wl,-rpath,@loader_path' -o "$out/tcp-live-probe"
echo "Built $out/tcp-live-probe; no network request or SAML attempt was made."
