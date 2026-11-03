#!/bin/zsh
# Unit tests for every Rust package. CI's "Rust tests" job runs this; it needs no
# Swift, signing, or Apple frameworks beyond what the crates link themselves.
set -euo pipefail
root="${0:A:h:h}"
cargo test --locked --manifest-path "$root/app/Cargo.toml" --workspace
cargo test --locked --manifest-path "$root/client/Cargo.toml"
