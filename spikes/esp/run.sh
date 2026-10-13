#!/bin/sh
set -eu
cd "$(dirname "$0")"

cache=${OFTC_SWIFT_CACHE:-/private/tmp/oftc-crypto-swift-cache}
target="$(uname -m)-apple-macos11.0"

xcrun swiftc -module-cache-path "$cache" -target "$target" -O \
  -emit-library ../crypto/swift-bridge.swift -o libcrypto_swift.dylib
rustc --edition 2021 --test esp.rs -L . -l dylib=crypto_swift \
  -C 'link-arg=-Wl,-rpath,@loader_path' -o esp-test
./esp-test
rustc --edition 2021 -C opt-level=z -C strip=symbols main.rs \
  -L . -l dylib=crypto_swift \
  -C 'link-arg=-Wl,-rpath,@loader_path' -o esp-release
./esp-release
