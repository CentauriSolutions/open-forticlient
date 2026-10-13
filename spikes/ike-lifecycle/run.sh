#!/bin/sh
set -eu
cd "$(dirname "$0")"
cache=${OFTC_SWIFT_CACHE:-/private/tmp/oftc-crypto-swift-cache}
target="$(uname -m)-apple-macos11.0"
xcrun swiftc -module-cache-path "$cache" -target "$target" -O \
  -emit-library ../crypto/swift-bridge.swift \
  -Xlinker -install_name -Xlinker @rpath/libcrypto_swift.dylib \
  -o libcrypto_swift.dylib
rustc --edition 2021 --test test.rs -L . -l dylib=crypto_swift \
  -C 'link-arg=-Wl,-rpath,@loader_path' -o lifecycle-test
./lifecycle-test
