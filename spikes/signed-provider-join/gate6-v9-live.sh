#!/bin/zsh
# Install the pinned v9 diagnostic candidate for one approved rekey attempt.
# A failed attempt restores the exact installed v7 app; the inner smoke script
# stops/removes OFTC and compares route/DNS before this wrapper rolls back.
set -euo pipefail

root="${0:A:h}"
candidate='/private/tmp/oftc-v9-group14-build/IntegrationHost.app'
archive='/private/tmp/oftc-v9-group14-build/IntegrationHost-v9-notary.zip'
rollback='/private/tmp/oftc-v9-group14-build/IntegrationHost-v7-rollback.app'
app='/Applications/OFTC development probe.app'
staging='/Applications/.OFTC development probe.v9-staging.app'
held='/Applications/.OFTC development probe.v7-held.app'
provider_id='com.chris.openforticlient.gate0.provider'
v9_archive_sha='beb5287f842f709912239c210e03b06a264f9b26757c28ab7e50418d573ec994'
v9_host_sha='00d1e9c74b18b33c658c07b0adb05e38f509cd75dd5bf6ec5ad4e21bb59bae36'
v9_provider_sha='b15771bc49d63786406813c861bd20110931a1347a16ad459c46d3b9229bcfdb'
v9_engine_sha='f902160c4728c04cc9d9de0e89d8a4c65697e85f74f27c03846c125830ae4a94'
v7_host_sha='835ed4118a58bc16829a5905332bd17157ab8448269b249d9fe3b060ca772960'
v7_provider_sha='4fd7d73308ce8a0e40c6508b8d56058f333b984637469a590dfdecb7b590fa0f'
v7_engine_sha='340df9724d86494181d41ced77b00b7af88abae403cb371228a111498fcd19f2'

fail() { print -u2 -- "$*"; exit 1; }
sha() { shasum -a 256 "$1" | awk '{ print $1 }'; }
version() { /usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$1/Contents/Info.plist"; }
provider() { print -r -- "$1/Contents/Library/SystemExtensions/${provider_id}.systemextension"; }
exact_bundle() {
    local bundle="$1" expected_version="$2" host_sha="$3" provider_sha="$4" engine_sha="$5"
    local extension="$(provider "$bundle")"
    [[ -d "$bundle" && -d "$extension" ]] || return 1
    [[ "$(version "$bundle")" == "$expected_version" &&
       "$(version "$extension")" == "$expected_version" ]] || return 1
    [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$bundle/Contents/Info.plist")" ==
       'com.chris.openforticlient.gate0' ]] || return 1
    [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$extension/Contents/Info.plist")" ==
       "$provider_id" ]] || return 1
    [[ "$(sha "$bundle/Contents/MacOS/IntegrationHost")" == "$host_sha" &&
       "$(sha "$extension/Contents/MacOS/IntegrationProvider")" == "$provider_sha" &&
       "$(sha "$extension/Contents/Frameworks/liboftc_provider_ffi.dylib")" == "$engine_sha" ]]
}
v7_exact() { exact_bundle "$1" 7 "$v7_host_sha" "$v7_provider_sha" "$v7_engine_sha"; }
v9_exact() { exact_bundle "$1" 9 "$v9_host_sha" "$v9_provider_sha" "$v9_engine_sha"; }
signed_and_notarized() {
    codesign --verify --deep --strict "$1" >/dev/null 2>&1 &&
        xcrun stapler validate "$1" >/dev/null 2>&1 &&
        spctl --assess --type execute "$1" >/dev/null 2>&1
}
tailscale_inactive() {
    [[ "$(networksetup -getnetworkserviceenabled Tailscale 2>/dev/null)" == Disabled &&
       "$(scutil --nc status Tailscale 2>/dev/null | head -1 | tr -d '\r')" == Disconnected ]]
}
extension_active() {
    systemextensionsctl list | rg -F "$provider_id" |
        rg "\\([^)]*/$1\\).*\\[activated enabled\\]" >/dev/null
}

[[ $# -ge 1 ]] || fail 'Usage: gate6-v9-live.sh --plan | --execute <IKESamlPort>'
mode="$1"; shift
case "$mode" in
--plan)
    (( $# == 0 )) || fail 'Plan takes no arguments'
    cat <<'EOF'
Pinned v9 live gate; no action has been taken.
Requires separate approval to replace the installed v7 OFTC test app and to
use ONE fresh SAML token for an IPv4 UDP 4500 CHILD_SA rekey probe. Tailscale
must remain Disabled/Disconnected. No other VPN may be active.
The script verifies v7 and the signed/notarized v9 candidate, saves the exact
v7 app, installs/activates v9, then runs one SAML start, one local rekey, and
one post-rekey ICMP echo to 10.20.0.1. The inner gate always stops/removes OFTC
and compares route/DNS. A failed gate restores and reactivates v7. A passing
gate leaves v9 installed with no OFTC VPN configuration and keeps the v7
rollback copy at /private/tmp/oftc-v9-group14-build/IntegrationHost-v7-rollback.app.
Use the selected profile's exact IKESamlPort with --execute, not the IKE port.
EOF
    exit 0
    ;;
--execute)
    (( $# == 1 )) || fail 'Execute requires the exact IKESamlPort'
    saml_port="$1"
    [[ "$saml_port" =~ '^[0-9]{1,5}$' ]] &&
        (( saml_port >= 1 && saml_port <= 65535 )) || fail 'Invalid IKESamlPort'
    ;;
*) fail 'Usage: gate6-v9-live.sh --plan | --execute <IKESamlPort>' ;;
esac

[[ -f "$archive" && "$(sha "$archive")" == "$v9_archive_sha" ]] ||
    fail 'Pinned signed v9 archive is missing or changed'
v9_exact "$candidate" && signed_and_notarized "$candidate" ||
    fail 'Pinned v9 candidate failed version, hash, signature, or notarization checks'
v7_exact "$app" && signed_and_notarized "$app" ||
    fail 'Installed v7 rollback baseline failed version, hash, signature, or notarization checks'
[[ ! -e "$staging" && ! -e "$held" ]] ||
    fail 'A staging path already exists; inspect it before proceeding'
if [[ -e "$rollback" ]]; then
    v7_exact "$rollback" && signed_and_notarized "$rollback" ||
        fail 'Existing v7 rollback copy differs from the pinned signed bundle'
fi
[[ "$("$app/Contents/MacOS/IntegrationHost" status)" == *'configuration absent'* ]] ||
    fail 'OFTC configuration is present; refusing to replace the app'
tailscale_inactive || fail 'Tailscale must already be Disabled and Disconnected'
if scutil --nc list | rg '\((Connected|Connecting|Reasserting)\)' >/dev/null; then
    fail 'Another VPN is active'
fi

typeset -i moved_v7=0 installed_v9=0
cleanup() {
    local result="${1:-$?}" v9_host="$app/Contents/MacOS/IntegrationHost" state
    trap - EXIT INT TERM
    set +e
    if (( result != 0 )); then
        if (( installed_v9 )) && v9_exact "$app"; then
            state=$("$v9_host" status 2>/dev/null)
            if [[ "$state" != *'configuration absent'* ]]; then
                "$v9_host" stop >/dev/null 2>&1
                "$v9_host" remove-config >/dev/null 2>&1
            fi
            rm -rf "$app"
        fi
        if (( moved_v7 )) && [[ ! -e "$app" && -d "$held" ]]; then
            mv "$held" "$app"
            if "$app/Contents/MacOS/IntegrationHost" activate >/dev/null 2>&1; then
                local -i restored=0
                for _ in {1..60}; do
                    if extension_active 7; then restored=1; break; fi
                    sleep 1
                done
                (( restored )) || print -u2 'v7 app restored; extension activation needs inspection'
            else
                print -u2 'v7 app restored; extension reactivation needs inspection'
            fi
        fi
        v7_exact "$app" && signed_and_notarized "$app" ||
            print -u2 'v7 rollback verification failed; inspect the saved rollback copy'
        print -u2 'v9 gate failed; inspect OFTC configuration, route, DNS, and extension state.'
    else
        rm -rf "$held"
        print 'v9 rekey and cleanup passed; v9 remains installed, with v7 rollback saved.'
    fi
    [[ ! -e "$staging" ]] || rm -rf "$staging"
    tailscale_inactive || { print -u2 'Tailscale state changed'; result=1; }
    exit "$result"
}
trap 'cleanup $?' EXIT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

[[ -e "$rollback" ]] || ditto "$app" "$rollback"
v7_exact "$rollback" && signed_and_notarized "$rollback" ||
    fail 'Saved v7 rollback copy failed verification'
ditto "$candidate" "$staging"
v9_exact "$staging" && signed_and_notarized "$staging" ||
    fail 'Staged v9 copy failed verification'
mv "$app" "$held"
moved_v7=1
mv "$staging" "$app"
installed_v9=1
"$app/Contents/MacOS/IntegrationHost" activate
typeset -i active=0
for _ in {1..60}; do
    if extension_active 9; then active=1; break; fi
    sleep 1
done
(( active )) || fail 'Version 9 extension did not activate within 60 seconds'
zsh "$root/gate6-v9-rekey-smoke.sh" --execute "$saml_port"
[[ "$("$app/Contents/MacOS/IntegrationHost" status)" == *'configuration absent'* ]] ||
    fail 'OFTC configuration remains after the smoke gate'
