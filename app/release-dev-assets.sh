#!/bin/zsh
# Release what test builds leave behind: Launch Services registrations of
# OFTC.app copies, their build directories, mounted images, and sandbox data of
# throwaway bundle ids. Usage: release-dev-assets.sh [--keep NAME]...
# (NAME is the part after /private/tmp/oftc-build-). Never touches
# /Applications/OFTC.app or real profiles.
set -euo pipefail

lsregister=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
keep=()
while (( $# )); do
    [[ "$1" == --keep && -n "${2:-}" ]] || { print -u2 'usage: release-dev-assets.sh [--keep NAME]...'; exit 2; }
    keep+=("$2"); shift 2
done

for volume in /Volumes/Open\ Forticlient*(N); do
    hdiutil detach "$volume" >/dev/null 2>&1 && print "ejected $volume" || true
done
for dir in /private/tmp/oftc-build-*(N/) /private/tmp/oftctest-*(N/); do
    name=${dir:t}; name=${name#oftc-build-}
    (( ${keep[(Ie)$name]} )) && { print "kept $dir"; continue; }
    # lsregister -u exits nonzero for a bundle that was never registered; under set -e
    # that would stop the cleanup at the first such build directory.
    [[ -d "$dir/OFTC.app" ]] && { "$lsregister" -u "$dir/OFTC.app" >/dev/null 2>&1 || true; }
    rm -rf -- "$dir" && print "removed $dir"
done
for data in "$HOME"/Library/Application\ Support/com.example.oftctest(N/); do
    rm -rf -- "$data" && print "removed $data"
done
security delete-generic-password -s com.example.oftctest.psk >/dev/null 2>&1 || true
