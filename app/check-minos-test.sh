#!/bin/zsh
# Proves app/check-minos.sh passes on minos 15.0 and fails on 13.0, 27.0 and a mismatch
# warning in a link log. Builds tiny C binaries in a temp dir; offline.
set -euo pipefail
root="${0:A:h}"
tmp=$(mktemp -d /private/tmp/oftc-build-minos-test.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
print 'int main(void) { return 0; }' > "$tmp/m.c"
for v in 13.0 15.0 27.0; do
    xcrun clang -mmacosx-version-min=$v "$tmp/m.c" -o "$tmp/bin-$v"
done
zsh "$root/check-minos.sh" 15.0 "$tmp/bin-15.0" >/dev/null
for v in 13.0 27.0; do
    if zsh "$root/check-minos.sh" 15.0 "$tmp/bin-15.0" "$tmp/bin-$v" 2>/dev/null; then
        print -u2 "check-minos accepted minos $v"; exit 1
    fi
done
print "ld: warning: object file x.o was built for newer 'macOS' version (15.5) than being linked (13.0)" > "$tmp/link.log"
if zsh "$root/check-minos.sh" 15.0 --log "$tmp/link.log" "$tmp/bin-15.0" 2>/dev/null; then
    print -u2 'check-minos accepted a link log with a version mismatch'; exit 1
fi
print 'minos checks passed'
