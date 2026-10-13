#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
build="${TMPDIR:-/private/tmp}/oftc-provider-transport-preflight"
mkdir -p "$build" "$build/module-cache"
target="$(uname -m)-apple-macos11.0"
xcrun swiftc -module-cache-path "$build/module-cache" -target "$target" -O \
  -emit-library "$root/../crypto/swift-bridge.swift" \
  -Xlinker -install_name -Xlinker @rpath/libcrypto_swift.dylib \
  -o "$build/libcrypto_swift.dylib"
rustc --edition=2021 --test "$root/preflight.rs" -L "$build" -l dylib=crypto_swift \
  -C "link-arg=-Wl,-rpath,$build" -o "$build/preflight-tests"
"$build/preflight-tests"
rustc --edition=2021 --crate-type cdylib -C opt-level=z "$root/preflight.rs" \
  -L "$build" -l dylib=crypto_swift \
  -C 'link-arg=-Wl,-install_name,@rpath/liboftc_transport_preflight.dylib' \
  -C 'link-arg=-Wl,-rpath,@loader_path' \
  -o "$build/liboftc_transport_preflight.dylib"
nm -gU "$build/liboftc_transport_preflight.dylib" | grep ' _oftc_provider_preflight_ipv6$'
clang -x c -fsyntax-only "$root/oftc_transport_preflight.h"
echo 'Offline tests and C ABI build passed; no gateway traffic was sent.'
