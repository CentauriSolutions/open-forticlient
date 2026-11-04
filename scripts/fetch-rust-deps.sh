#!/bin/zsh
# Fetch every locked Rust dependency, retrying a stalled download.
#
# Hosted macOS runners sometimes stall on the crates download ("transfer too slow"),
# and a stalled `cargo fetch` then holds the job until its timeout. Each attempt is
# bounded with an alarm, so a stall costs minutes and is retried rather than
# burning the whole job. Cargo's own retry and timeout settings come from the
# environment (see .github/workflows/ci.yml).
set -euo pipefail

root="${0:A:h:h}"
attempts=3
limit=90    # seconds per attempt; worst case 2 manifests x 3 x 90 s = 9 min, inside the 15-minute lint timeout

fetch() {
    perl -e 'alarm shift; exec @ARGV' "$limit" \
        cargo fetch --locked --manifest-path "$1"
}

for manifest in "$root/app/Cargo.toml" "$root/client/Cargo.toml"; do
    n=1
    until fetch "$manifest"; do
        (( n < attempts )) || { print -u2 "cargo fetch failed $attempts times for $manifest"; exit 1; }
        print -u2 "cargo fetch attempt $n failed for $manifest; retrying"
        (( n++ ))
        sleep 5
    done
done
