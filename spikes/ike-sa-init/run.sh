#!/bin/sh
set -eu
cd "$(dirname "$0")"

cache=${OFTC_SWIFT_CACHE:-/private/tmp/oftc-crypto-swift-cache}
target="$(uname -m)-apple-macos11.0"

xcrun swiftc -module-cache-path "$cache" -target "$target" -O \
  -emit-library ../crypto/swift-bridge.swift -o libcrypto_swift.dylib
rustc --edition 2021 --test protocol.rs -o protocol-test
./protocol-test
rustc --edition 2021 -C opt-level=2 main.rs -L . -l dylib=crypto_swift \
  -C 'link-arg=-Wl,-rpath,@loader_path' -o probe
echo "Built ./probe (no network probe run)."
