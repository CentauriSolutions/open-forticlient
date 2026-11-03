#!/bin/zsh
# Clippy over every Rust package, warnings fatal. CI's "Rust lint" job runs this.
set -euo pipefail
root="${0:A:h:h}"
cargo clippy --locked --manifest-path "$root/app/Cargo.toml" --workspace --all-targets -- -D warnings
cargo clippy --locked --manifest-path "$root/client/Cargo.toml" --all-targets -- -D warnings
