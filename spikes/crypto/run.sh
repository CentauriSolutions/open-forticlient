#!/bin/sh
set -eu
cd "$(dirname "$0")"

cache=${OFTC_SWIFT_CACHE:-/private/tmp/oftc-crypto-swift-cache}
target="$(uname -m)-apple-macos11.0"

xcrun clang -std=c11 -Wall -Wextra -Werror -O2 \
  -mmacosx-version-min=11.0 crypto.c test.c \
  -framework Security -framework CoreFoundation -o crypto-test
./crypto-test

xcrun swiftc -module-cache-path "$cache" -target "$target" -O \
  swift-test.swift -o swift-test
./swift-test

xcrun swiftc -module-cache-path "$cache" -target "$target" -O \
  -emit-library swift-bridge.swift -o libcrypto_swift.dylib
rustc --edition 2021 -C opt-level=z -C strip=symbols rust-test.rs \
  -L . -l dylib=crypto_swift \
  -C 'link-arg=-Wl,-rpath,@loader_path' -o rust-test
./rust-test
