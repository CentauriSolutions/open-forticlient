#!/bin/zsh
# Gate-day build: build the app in a fresh /private/tmp/oftc-build-gate-* directory,
# Developer ID sign it and notarize it, then print the app path. One command:
#
#   zsh app/gate-build.sh
#
# It does not install or activate anything. Signing inputs come from the
# environment or ~/.config/oftc/release.env (see docs/releasing.md); none are
# stored in the repo. NOTARY_PROFILE is the name of a notarytool keychain
# profile (a name, not a credential) and defaults to the gate profile.
set -euo pipefail

root="${0:A:h}"
[[ -f "$HOME/.config/oftc/release.env" ]] && source "$HOME/.config/oftc/release.env"
: "${NOTARY_PROFILE:=oftc-gate0}"
for name in DEVELOPER_ID_IDENTITY NOTARY_PROFILE APP_PROFILE EXTENSION_PROFILE; do
    [[ -n "${(P)name:-}" ]] || { print -u2 "Set $name (see docs/releasing.md)"; exit 2; }
done
export DEVELOPER_ID_IDENTITY NOTARY_PROFILE APP_PROFILE EXTENSION_PROFILE

export OFTC_BUILD_DIR="/private/tmp/oftc-build-gate-$(date +%Y%m%d%H%M%S)"
print "== build ($OFTC_BUILD_DIR)"
zsh "$root/build.sh"
print '== sign';          zsh "$root/sign-developer-id.sh"
print '== notarize app';  zsh "$root/notarize-app.sh"
print "Gate app (signed, notarized, not installed): $OFTC_BUILD_DIR/OFTC.app"
print 'When the gate is done: zsh app/release-dev-assets.sh'
