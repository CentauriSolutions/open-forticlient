#!/bin/zsh
# Install the pinned v8 diagnostic candidate for one approved rekey attempt.
# A failed attempt restores the exact installed v7 app; the inner smoke script
# stops/removes OFTC and compares route/DNS before this wrapper rolls back.
set -euo pipefail

root="${0:A:h}"
candidate='/private/tmp/oftc-v8-rekey-build/IntegrationHost.app'
archive='/private/tmp/oftc-v8-rekey-build/IntegrationHost-v8-notary.zip'
rollback='/private/tmp/oftc-v8-rekey-build/IntegrationHost-v7-rollback.app'
app='/Applications/OFTC development probe.app'
staging='/Applications/.OFTC development probe.v8-staging.app'
held='/Applications/.OFTC development probe.v7-held.app'
provider_id='com.chris.openforticlient.gate0.provider'
v8_archive_sha='908933d1ee0750c95cdb5bcd6e90ce625d68b9d181e3310e92dcdb8318922d9e'
v8_host_sha='23ff420db46d9852b8f135296d1d551322fd12c4b2a39871c157177fe933c118'
v8_provider_sha='15dda3a4a3437bf614a3cf89c296ba2d3860a3efcec3f3e229837268678c6723'
v8_engine_sha='d4b055ddfa01911f20ff89dc640512c0a8f06ca10a9bff52e28fe5c8e8943d6e'
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
v8_exact() { exact_bundle "$1" 8 "$v8_host_sha" "$v8_provider_sha" "$v8_engine_sha"; }
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

[[ $# -ge 1 ]] || fail 'Usage: gate6-v8-live.sh --plan | --execute <IKESamlPort>'
mode="$1"; shift
case "$mode" in
--plan)
    (( $# == 0 )) || fail 'Plan takes no arguments'
    cat <<'EOF'
Pinned v8 live gate; no action has been taken.
Requires separate approval to replace the installed v7 OFTC test app and to
use ONE fresh SAML token for an IPv4 UDP 4500 CHILD_SA rekey probe. Tailscale
must remain Disabled/Disconnected. No other VPN may be active.
The script verifies v7 and the signed/notarized v8 candidate, saves the exact
v7 app, installs/activates v8, then runs one SAML start, one local rekey, and
one post-rekey ICMP echo to 10.20.0.1. The inner gate always stops/removes OFTC
and compares route/DNS. A failed gate restores and reactivates v7. A passing
gate leaves v8 installed with no OFTC VPN configuration and keeps the v7
rollback copy at /private/tmp/oftc-v8-rekey-build/IntegrationHost-v7-rollback.app.
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
*) fail 'Usage: gate6-v8-live.sh --plan | --execute <IKESamlPort>' ;;
esac

[[ -f "$archive" && "$(sha "$archive")" == "$v8_archive_sha" ]] ||
    fail 'Pinned signed v8 archive is missing or changed'
v8_exact "$candidate" && signed_and_notarized "$candidate" ||
    fail 'Pinned v8 candidate failed version, hash, signature, or notarization checks'
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

typeset -i moved_v7=0 installed_v8=0
cleanup() {
    local result="${1:-$?}" v8_host="$app/Contents/MacOS/IntegrationHost" state
    trap - EXIT INT TERM
    set +e
    if (( result != 0 )); then
        if (( installed_v8 )) && v8_exact "$app"; then
            state=$("$v8_host" status 2>/dev/null)
            if [[ "$state" != *'configuration absent'* ]]; then
                "$v8_host" stop >/dev/null 2>&1
                "$v8_host" remove-config >/dev/null 2>&1
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
        print -u2 'v8 gate failed; inspect OFTC configuration, route, DNS, and extension state.'
    else
        rm -rf "$held"
        print 'v8 rekey and cleanup passed; v8 remains installed, with v7 rollback saved.'
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
v8_exact "$staging" && signed_and_notarized "$staging" ||
    fail 'Staged v8 copy failed verification'
mv "$app" "$held"
moved_v7=1
mv "$staging" "$app"
installed_v8=1
"$app/Contents/MacOS/IntegrationHost" activate
typeset -i active=0
for _ in {1..60}; do
    if extension_active 8; then active=1; break; fi
    sleep 1
done
(( active )) || fail 'Version 8 extension did not activate within 60 seconds'
zsh "$root/gate6-v8-rekey-smoke.sh" --execute "$saml_port"
[[ "$("$app/Contents/MacOS/IntegrationHost" status)" == *'configuration absent'* ]] ||
    fail 'OFTC configuration remains after the smoke gate'
