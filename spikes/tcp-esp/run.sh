#!/bin/sh
set -eu
cd "$(dirname "$0")"
rustc --edition 2021 --test lib.rs -o /private/tmp/oftc-tcp-esp-test
/private/tmp/oftc-tcp-esp-test
