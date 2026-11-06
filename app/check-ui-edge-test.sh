#!/bin/zsh
# Covers check-ui-edge.sh against ui-edge-fixture/ and mutated copies of it: the ratchet must
# pass the fixture and fail on a new violation, a higher count, a stale baseline, a forbidden
# import in HostEdge.swift and a baseline that grew.
set -euo pipefail
here="${0:A:h}"
check="$here/check-ui-edge.sh"
work="$(mktemp -d /private/tmp/oftc-ui-edge-test.XXXXXX)"
trap 'rm -rf "$work"' EXIT
n=0

fresh() { rm -rf "$work/t"; cp -R "$here/ui-edge-fixture" "$work/t"; }
passes() { n=$((n + 1)); zsh "$check" --root "$work/t" >/dev/null 2>"$work/err" || { print -u2 "expected pass: $1"; cat "$work/err" >&2; exit 1; }; }
fails() { n=$((n + 1)); if zsh "$check" --root "$work/t" >/dev/null 2>"$work/err"; then print -u2 "expected failure: $1"; exit 1; fi; grep -q -- "$2" "$work/err" || { print -u2 "wrong failure for $1:"; cat "$work/err" >&2; exit 1; }; }

fresh; passes "the fixture as shipped (a deleted file's baseline row is ignored)"

fresh; print 'import Security' >> "$work/t/Host/Clean.swift"
fails "a new import in a clean file" "Clean.swift matches 'import Security'"

fresh; print 'import Security // reviewed' >> "$work/t/Host/Clean.swift"
fails "an import followed by a comment" "'import Security'"

fresh; print '@_exported import NetworkExtension;' >> "$work/t/Host/Clean.swift"
fails "an attributed import followed by a semicolon" "'import NetworkExtension'"

fresh; print 'func run() { _ = Process() }' >> "$work/t/Host/Clean.swift"
fails "a child process outside the edge" "'Process('"

fresh; print 'import Foundation' > "$work/t/Host/New.swift"
fails "a UI file that is neither listed nor exempt" "New.swift is in neither"

fresh; print 'func again() { _ = SecItemAdd }' >> "$work/t/Host/Violating.swift"
fails "a second match in a file the baseline allows one in" "allows 1"

fresh; print -- 'func other() { _ = NETunnelProviderManager.self }' >> "$work/t/Host/Violating.swift"
fails "a different pattern in a baselined file" "NETunnelProviderManager"

fresh; : > "$work/t/Host/Violating.swift"
fails "a baseline that lists more than remains" "lower it"

fresh; print 'let manager = NEVPNManager.shared()' >> "$work/t/Host/Clean.swift"
fails "the older VPN manager API" "NEVPNManager"

fresh; print 'import NetworkExtension' >> "$work/t/Host/HostEdge.swift"
fails "HostEdge.swift importing NetworkExtension" "HostEdge.swift may not use 'import NetworkExtension'"

# The baseline guard for pull requests, against a throwaway repository.
repo="$work/repo"
mkdir -p "$repo/app"; cp -R "$here/ui-edge-fixture/." "$repo/app/"
git -C "$repo" init -q
git -C "$repo" add -A >/dev/null
git -C "$repo" -c user.name=t -c user.email=t@example.com commit -q -m base
grew() { zsh "$check" --root "$repo/app" --grew-since HEAD >/dev/null 2>"$work/err"; }

n=$((n + 1)); grew || { print -u2 "expected an unchanged baseline to pass"; exit 1; }
printf 'Host/Violating.swift\tSecItem\t2\nHost/Gone.swift\tSecItem\t5\n' > "$repo/app/ui-edge-baseline.txt"
n=$((n + 1)); if grew; then print -u2 "expected a higher baseline count to fail"; exit 1; fi
printf 'Host/Violating.swift\tSecItem\t1\nHost/Gone.swift\tSecItem\t5\nHost/Clean.swift\tKeychain\t1\n' > "$repo/app/ui-edge-baseline.txt"
n=$((n + 1)); if grew; then print -u2 "expected a new baseline row to fail"; exit 1; fi
printf 'Host/Violating.swift\tSecItem\t1\n' > "$repo/app/ui-edge-baseline.txt"
n=$((n + 1)); grew || { print -u2 "expected a shrunk baseline to pass"; exit 1; }

print "UI edge ratchet checks passed ($n cases)."
