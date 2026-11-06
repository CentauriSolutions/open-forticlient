#!/bin/zsh
# Offline checks of the installer scripts against a temporary tree.
# It never touches /Applications, the user session, launchd or the real system:
# OFTC_POSTINSTALL_ROOT makes the script stop after the cleanup.
set -euo pipefail

root="${0:A:h}"
script="$root/package-scripts/postinstall"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail() { print -u2 "FAIL: $1"; exit 1; }
fake_bundle() { # <path> <bundle id>
    mkdir -p "$1/Contents/MacOS" "$1/Contents/Library/SystemExtensions/p.systemextension/Contents/MacOS"
    /usr/libexec/PlistBuddy -c 'Clear dict' -c "Add :CFBundleIdentifier string $2" "$1/Contents/Info.plist" >/dev/null
    : > "$1/Contents/MacOS/OFTCAgent"
}
run() { OFTC_POSTINSTALL_ROOT="$1" sh "$script" || fail "postinstall exited non-zero"; }

# 1. An old build's Frameworks (app and extension) go; the rest of the bundle stays.
r="$tmp/stale"; app="$r/Applications/Open Forticlient.app"
fake_bundle "$app" com.chris.openforticlient.oftc
mkdir -p "$app/Contents/Frameworks" "$app/Contents/Library/SystemExtensions/p.systemextension/Contents/Frameworks"
: > "$app/Contents/Frameworks/liboftc_host_bootstrap.dylib"
: > "$app/Contents/Library/SystemExtensions/p.systemextension/Contents/Frameworks/libcrypto_swift.dylib"
run "$r"
[[ ! -e "$app/Contents/Frameworks" && ! -e "$app/Contents/Library/SystemExtensions/p.systemextension/Contents/Frameworks" ]] \
    || fail 'stale Frameworks remained'
[[ -f "$app/Contents/MacOS/OFTCAgent" && -f "$app/Contents/Info.plist" ]] || fail 'cleanup removed more than Frameworks'

# 2. A bundle with another identifier, or a symlinked bundle, is never touched.
r="$tmp/foreign"; app="$r/Applications/Open Forticlient.app"
fake_bundle "$app" com.example.other
mkdir -p "$app/Contents/Frameworks"
run "$r"
[[ -d "$app/Contents/Frameworks" ]] || fail 'removed Frameworks of a bundle that is not ours'
r="$tmp/linked"; mkdir -p "$r/Applications" "$tmp/elsewhere"
fake_bundle "$tmp/elsewhere/App.app" com.chris.openforticlient.oftc
mkdir -p "$tmp/elsewhere/App.app/Contents/Frameworks" "$tmp/elsewhere/OFTC.app"
ln -s "$tmp/elsewhere/App.app" "$r/Applications/Open Forticlient.app"
ln -s "$tmp/elsewhere/App.app" "$r/Applications/OFTC.app"
run "$r"
[[ -d "$tmp/elsewhere/App.app/Contents/Frameworks" && -L "$r/Applications/OFTC.app" ]] \
    || fail 'followed a symlinked bundle'

# 3. A Frameworks symlink is removed as a link; its target is left alone.
r="$tmp/frameworks-link"; app="$r/Applications/Open Forticlient.app"
fake_bundle "$app" com.chris.openforticlient.oftc
mkdir -p "$tmp/target"; : > "$tmp/target/keep"
ln -s "$tmp/target" "$app/Contents/Frameworks"
run "$r"
[[ ! -e "$app/Contents/Frameworks" && ! -L "$app/Contents/Frameworks" && -f "$tmp/target/keep" ]] \
    || fail 'did not unlink a Frameworks symlink safely'

# 4. A clean current bundle, and an absent app, are untouched / fine.
r="$tmp/clean"; fake_bundle "$r/Applications/Open Forticlient.app" com.chris.openforticlient.oftc
run "$r"; [[ -f "$r/Applications/Open Forticlient.app/Contents/MacOS/OFTCAgent" ]] || fail 'clean bundle changed'
run "$tmp/nothing"

# 5. The pre-rename OFTC.app goes only when it is our bundle.
r="$tmp/renamed"; fake_bundle "$r/Applications/OFTC.app" com.chris.openforticlient.oftc
run "$r"; [[ ! -e "$r/Applications/OFTC.app" ]] || fail 'old OFTC.app remained'
r="$tmp/oftc-foreign"; fake_bundle "$r/Applications/OFTC.app" com.example.other
run "$r"; [[ -d "$r/Applications/OFTC.app" ]] || fail 'removed an OFTC.app that is not ours'

print 'postinstall cleanup checks passed'
