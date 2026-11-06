#!/bin/zsh
# Fail unless every version the build shows is the app's Info.plist version: `oftc --version`
# (built from that plist by client/build.rs) against the packaged bundle's CFBundleShortVersionString
# and CFBundleVersion, and the man page's footer against the same version. Builds nothing.
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
footer=$(awk '/^\.TH / { print }' "$man")
[[ "$footer" == *"\"OFTC $version\""* ]] || { print -u2 "$man footer '$footer' does not name OFTC $version"; rc=1; }
(( rc == 0 )) && print "Version parity: oftc and the man page both say $version (build $build), as the app's Info.plist does."
exit $rc
