#!/bin/zsh
# Unit tests for every Rust package. CI's "Rust tests" job runs this; it needs no
# Swift, signing, or Apple frameworks beyond what the crates link themselves.
#
# Extra arguments go to cargo test for the app workspace, e.g.
#   zsh scripts/test-rust.sh -- --include-ignored
# CI passes that: the #[ignore]d tests are loopback-only (UDP/TCP on 127.0.0.1) and are
# skipped by default only because sandboxed agent environments deny local-network
# access. They are the only coverage of the Session ESP, DPD and teardown wiring.
# The client has no ignored tests, so it always runs with defaults.
set -euo pipefail
root="${0:A:h:h}"
cargo test --locked --manifest-path "$root/app/Cargo.toml" --workspace "$@"
cargo test --locked --manifest-path "$root/client/Cargo.toml"
