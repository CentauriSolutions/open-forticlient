#!/bin/zsh
# Fail unless every given Mach-O is built for macOS with minos exactly equal to the
# minimum, and (with --log) the link log has no "built for newer" warning.
# Offline; reads files only.
#
# Usage: app/check-minos.sh <min-version> [--log <file>] <macho>...
set -euo pipefail

min="$1"; shift
log=""
if [[ "${1:-}" == --log ]]; then log="$2"; shift 2; fi
rc=0
for f in "$@"; do
    # Universal files list one build block per slice; every slice must match.
    info=$(vtool -show-build "$f" 2>&1) || { print -u2 "$f: not a Mach-O ($info)"; rc=1; continue; }
    platforms=("${(@f)$(print -r -- "$info" | awk '$1 == "platform" { print $2 }')}")
    versions=("${(@f)$(print -r -- "$info" | awk '$1 == "minos" { print $2 }')}")
    [[ ${#platforms} -ge 1 && -n "${platforms[1]}" && ${#platforms} == ${#versions} ]] || {
        print -u2 "$f: no LC_BUILD_VERSION"; rc=1; continue
    }
    for p in $platforms; do
        [[ "$p" == MACOS ]] || { print -u2 "$f: platform $p, expected MACOS"; rc=1; }
    done
    for v in $versions; do
        [[ "$v" == "$min" ]] || { print -u2 "$f: minos $v, expected $min"; rc=1; }
    done
    (( rc )) || print "minos $min: ${f:t}"
done
if [[ -n "$log" ]] && grep -q "built for newer" "$log"; then
    print -u2 "Link log has a deployment-target mismatch:"; grep "built for newer" "$log" >&2
    rc=1
fi
exit $rc
