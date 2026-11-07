#!/bin/zsh
# Fail unless every version the build shows is the app's Info.plist version: `oftc --version`
# (built from that plist by client/build.rs) against the packaged bundle's CFBundleShortVersionString
# and CFBundleVersion, and the man page footer and Distribution.xml (both rendered from @OFTC_VERSION@) and docs/releasing.md against the same version. Builds nothing.
#
# Usage: app/check-version-parity.sh <OFTC.app> [oftc-binary [man-page]]
set -euo pipefail

root="${0:A:h}"
app="${1:?usage: check-version-parity.sh <OFTC.app> [oftc-binary [man-page]]}"
oftc="${2:-$app/Contents/Helpers/oftc}"
man="${3:-$root/../client/man/oftc.1}"
plist="$app/Contents/Info.plist"

read_plist() { /usr/libexec/PlistBuddy -c "Print :$1" "$plist" 2>/dev/null || { print -u2 "Cannot read $1 from $plist"; exit 2; } }
version=$(read_plist CFBundleShortVersionString)
build=$(read_plist CFBundleVersion)

rc=0
shown=$("$oftc" --version)
expected="oftc $version (build $build)"
[[ "$shown" == "$expected" ]] || { print -u2 "oftc --version printed '$shown'; the app is '$expected'"; rc=1; }
# Every tracked file that carries the product version holds @OFTC_VERSION@ and is rendered from the plist
# at package time (app/package.sh does the same sed), so none can drift; check the placeholders are there
# and the rendered copies name the version.
dist="${root}/package-resources/Distribution.xml"
for f in "$man" "$dist"; do
    grep -q '@OFTC_VERSION@' "$f" || { print -u2 "$f has no @OFTC_VERSION@ placeholder (a hand-written version can drift from $version)"; rc=1; }
    grep -qE '(^|[^0-9.])[0-9]+\.[0-9]+\.[0-9]+([^0-9]|$)' <(grep -E '^\.TH |oftc\.pkg' "$f") && { print -u2 "$f carries a literal version on its version line; use @OFTC_VERSION@"; rc=1; }
done
footer=$(sed "s/@OFTC_VERSION@/$version/g" "$man" | awk '/^\.TH / { print }')
[[ "$footer" == *"\"OFTC $version\""* ]] || { print -u2 "$man rendered footer '$footer' does not name OFTC $version"; rc=1; }
# docs/releasing.md states the pre-release numbering; it must not contradict the plist.
stated=$(grep -oE 'the host is numbered [0-9.]+, build [0-9]+' "$root/../docs/releasing.md" || true)
[[ -z "$stated" || "$stated" == "the host is numbered $version, build $build" ]] || { print -u2 "docs/releasing.md says '$stated'; the app is $version, build $build"; rc=1; }
(( rc == 0 )) && print "Version parity: oftc and the man page both say $version (build $build), as the app's Info.plist does."
exit $rc
