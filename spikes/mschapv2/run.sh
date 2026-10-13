#!/bin/sh
set -eu
cd "$(dirname "$0")"
build_dir=$(mktemp -d "${TMPDIR:-/private/tmp}/oftc-mschapv2.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT
rustc --edition 2021 -D warnings --test mschapv2.rs -o "$build_dir/mschapv2-test"
"$build_dir/mschapv2-test"
rustc --edition 2021 -D warnings -C opt-level=2 --crate-type rlib \
  --crate-name mschapv2 mschapv2.rs -o "$build_dir/libmschapv2.rlib"
printf 'Optimized rlib bytes: '
stat -f '%z' "$build_dir/libmschapv2.rlib"
