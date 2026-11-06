#!/bin/zsh
# Fail unless the provider's CFBundleVersion and CFBundleShortVersionString are
# strictly higher than the floor in app/provider-version-floor (the highest
# provider build known to be activated anywhere). Offline; no secrets.
#
# Usage: app/check-versions.sh [provider-info.plist [floor-file]]
set -euo pipefail

root="${0:A:h}"
plist="${1:-$root/Provider/Info.plist}"
floor_file="${2:-$root/provider-version-floor}"

read_plist() { /usr/libexec/PlistBuddy -c "Print :$1" "$plist" 2>/dev/null; }
floor_value() { awk -v k="$1" '$1 == k { print $2 }' "$floor_file"; }

build=$(read_plist CFBundleVersion) || { print -u2 "Cannot read CFBundleVersion from $plist"; exit 2; }
version=$(read_plist CFBundleShortVersionString) || { print -u2 "Cannot read CFBundleShortVersionString from $plist"; exit 2; }
floor_build=$(floor_value build)
floor_version=$(floor_value version)
[[ "$build" =~ '^[0-9]+$' && "$floor_build" =~ '^[0-9]+$' ]] || {
    print -u2 "Provider build ($build) and floor build ($floor_build) must be integers"; exit 2
}
[[ "$version" =~ '^[0-9]+(\.[0-9]+){1,2}$' && "$floor_version" =~ '^[0-9]+(\.[0-9]+){1,2}$' ]] || {
    print -u2 "Provider version ($version) and floor version ($floor_version) must be dotted numbers"; exit 2
}
# Compare dotted versions numerically: the highest of the pair under a version sort.
newer() { [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)" == "$1" ]]; }

if (( build <= floor_build )); then
    print -u2 "Provider build $build is not above the highest activated build $floor_build ($floor_file). macOS refuses a provider downgrade; bump app/Provider/Info.plist."
    exit 1
fi
newer "$version" "$floor_version" || {
    print -u2 "Provider version $version is not above the highest activated version $floor_version ($floor_file)."
    exit 1
}
print "Provider $version ($build) is above the activated floor $floor_version ($floor_build)."
