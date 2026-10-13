#!/bin/zsh
# Reviewed, opt-in IPv4 sustained gate. --plan is read-only; --start requires
# separate operator approval. --finish and --rollback clean up the gate.
set -euo pipefail

root="${0:A:h}"
build='/private/tmp/oftc-v11-sustained-build'
candidate="$build/IntegrationHost.app"
archive="$build/IntegrationHost-v11-notary.zip"
rollback="$build/IntegrationHost-v9-rollback.app"
baseline_route="$build/gate7-baseline.route"
baseline_dns="$build/gate7-baseline.dns-sha256"
started="$build/gate7-started"
app='/Applications/OFTC development probe.app'
staging='/Applications/.OFTC development probe.v11-staging.app'
held='/Applications/.OFTC development probe.v9-held.app'
provider_id='com.chris.openforticlient.gate0.provider'
cli="$root/../../client/target/release/oftc"
agent="$HOME/Library/LaunchAgents/com.open-forticlient.oftc.standalone.plist"
target='10.20.0.1'
profile='Office VPN'
gateway='vpn.example.com'
port='9443'
v11_archive_sha='c1285f64d613cd2ed2dedb035dc4c399d06af051eaca1a769f4c597aa363a071'
v11_host_sha='53f97b89eb6c3ea98eac5aa3edae195e6f710a245aaa28c11d3e0d1222849917'
v11_provider_sha='d75937123867b80cc6bd310b0762f5e2251699f3eef7dd9aa33a618c65f80785'
v11_engine_sha='9865cd1a017f5f0ab041b5c49466001b7d7741590cb94b697710f68d2f471eb2'
v9_host_sha='00d1e9c74b18b33c658c07b0adb05e38f509cd75dd5bf6ec5ad4e21bb59bae36'
v9_provider_sha='b15771bc49d63786406813c861bd20110931a1347a16ad459c46d3b9229bcfdb'
v9_engine_sha='f902160c4728c04cc9d9de0e89d8a4c65697e85f74f27c03846c125830ae4a94'
cli_sha='29951026d73de6a50da1b6e11a3d635307e7a91f6816969ae779ce6676e492f9'

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
v11_exact() { exact_bundle "$1" 11 "$v11_host_sha" "$v11_provider_sha" "$v11_engine_sha"; }
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
route_snapshot() {
    route -n get -inet "$target" 2>/dev/null |
        awk '$1 == "gateway:" || $1 == "interface:" || $1 == "ifscope:" || $1 == "mtu:" { print $1, $2 }'
}
route_interface() { route_snapshot | awk '$1 == "interface:" { print $2; exit }'; }
dns_digest() { scutil --dns | shasum -a 256 | awk '{ print $1 }'; }
extension_active() {
    systemextensionsctl list | rg -F "$provider_id" |
        rg "\\([^)]*/$1\\).*\\[activated enabled\\]" >/dev/null
}
host() { "$app/Contents/MacOS/IntegrationHost" "$@"; }
wait_disconnected() {
    local state
    for _ in {1..45}; do
        state=$(host status 2>/dev/null || true)
        [[ "$state" == *'status: 1'* || "$state" == *'configuration absent'* ]] && return 0
        sleep 1
    done
    return 1
}
cleanup_vpn() {
    local state result=0
    if [[ -f "$agent" ]]; then
        "$cli" standalone uninstall-agent || result=1
    fi
    if v11_exact "$app"; then
        state=$(host status 2>/dev/null || true)
        if [[ "$state" != *'configuration absent'* ]]; then
            host stop || result=1
            wait_disconnected || result=1
            host remove-config || result=1
        fi
        [[ "$(host status 2>/dev/null || true)" == *'configuration absent'* ]] || result=1
    fi
    tailscale_inactive || result=1
    return "$result"
}
check_baseline() {
    [[ -f "$baseline_route" && -f "$baseline_dns" ]] || return 1
    [[ "$(route_snapshot)" == "$(cat "$baseline_route")" &&
       "$(dns_digest)" == "$(cat "$baseline_dns")" ]] && tailscale_inactive
}
restore_v9() {
    local result=0
    if [[ -d "$held" ]]; then
        cleanup_vpn || result=1
        if v11_exact "$app" && [[ "$(host status 2>/dev/null || true)" == *'configuration absent'* ]]; then
            rm -rf "$app"
        fi
        if [[ ! -e "$app" ]]; then
            mv "$held" "$app" || result=1
            host activate || result=1
            local active=0
            for _ in {1..60}; do
                if extension_active 9; then active=1; break; fi
                sleep 1
            done
            (( active )) || result=1
        fi
    fi
    [[ ! -e "$staging" ]] || rm -rf "$staging"
    v9_exact "$app" && signed_and_notarized "$app" || result=1
    [[ ! -f "$baseline_route" ]] || check_baseline || result=1
    rm -f "$started"
    return "$result"
}

[[ $# == 1 ]] || fail 'Usage: gate7-v11-sustained.sh --plan|--start|--finish|--rollback'
case "$1" in
--plan)
    cat <<'EOF'
Pinned v11 IPv4 sustained gate; this command changes nothing.
Separate approval is required before --start. It replaces the installed v9
development app with signed/notarized v11, activates its system extension,
imports only the local "Office VPN" profile and PSK into OFTC's profile/Keychain,
adds OFTC's macOS VPN configuration, and starts OFTC's per-user LaunchAgent.
If import rejects the saved FortiClient credential, it saves the nonsecret
profile and uses the previously migrated exact-gateway OFTC Keychain PSK.
The agent starts verified-TLS SAML to vpn.example.com:9443
and UDP 4500 IKE/ESP (bounded TCP fallback before token use). It can acquire
fresh SAML tokens on recoverable drops, under its three-per-ten-minute policy.
The approved protected traffic target is 10.20.0.1. No Fortinet VPN or Tailscale
service is started, stopped, or changed. Tailscale must be Disabled/Disconnected.
The operator may lock/unlock during the supervised run. Check rekey-counts after
at least 23 minutes and protected traffic before --finish. --finish stops the
agent, removes OFTC's VPN configuration, and verifies route/DNS restoration.
--rollback does the same and reinstalls the pinned signed v9 app. The imported
OFTC profile and Keychain PSK remain as intentional persistent setup data.
EOF
    exit 0 ;;
--start|--finish|--rollback) mode="$1" ;;
*) fail 'Usage: gate7-v11-sustained.sh --plan|--start|--finish|--rollback' ;;
esac

[[ -x "$cli" && "$(sha "$cli")" == "$cli_sha" ]] || fail 'Pinned OFTC CLI is missing or changed'
if [[ "$mode" == --finish || "$mode" == --rollback ]]; then
    [[ -f "$started" || -d "$held" ]] || fail 'No v11 gate state to finish or roll back'
    if [[ "$mode" == --rollback ]]; then
        restore_v9 || fail 'Rollback incomplete; inspect OFTC, route, DNS, and extension state'
        print 'OFTC stopped; exact v9 app and extension restored. Tailscale remains off.'
    else
        v11_exact "$app" || fail 'Installed v11 app differs from pinned candidate'
        cleanup_vpn || fail 'VPN cleanup incomplete; run --rollback after inspection'
        check_baseline || fail 'Route or DNS did not return to baseline; inspect before rollback'
        rm -rf "$held"
        rm -f "$started"
        print 'OFTC stopped and config removed; route/DNS restored. v11 remains installed.'
    fi
    exit 0
fi

[[ -f "$archive" && "$(sha "$archive")" == "$v11_archive_sha" ]] ||
    fail 'Pinned v11 signed archive is missing or changed'
v11_exact "$candidate" && signed_and_notarized "$candidate" ||
    fail 'Pinned v11 candidate failed version, hash, signature, or notarization checks'
v9_exact "$app" && signed_and_notarized "$app" ||
    fail 'Installed v9 rollback baseline differs from the verified app'
[[ ! -e "$staging" && ! -e "$held" && ! -e "$started" && ! -e "$agent" ]] ||
    fail 'A prior staging path or agent exists; inspect it before starting'
[[ "$(host status)" == *'configuration absent'* ]] || fail 'OFTC VPN configuration already exists'
[[ ! -e "$HOME/Library/Application Support/com.chris.openforticlient.gate0/profile.json" ]] ||
    fail 'An OFTC profile already exists; refusing to overwrite it'
[[ "$(plutil -extract 'Profiles.Office VPN.Server' raw -o - \
    '/Library/Application Support/Fortinet/FortiClient/conf/vpn.plist')" == "$gateway" &&
   "$(plutil -extract 'Profiles.Office VPN.IKESamlPort' raw -o - \
    '/Library/Application Support/Fortinet/FortiClient/conf/vpn.plist')" == "$port" ]] ||
    fail 'Selected FortiClient profile gateway or SAML port changed'
tailscale_inactive || fail 'Tailscale must already be Disabled and Disconnected'
if scutil --nc list | rg '\((Connected|Connecting|Reasserting)\)' >/dev/null; then
    fail 'Another VPN is active'
fi
[[ "$(route_interface)" == en0 ]] || fail 'Target has no safe en0 baseline route'
umask 077
route_snapshot > "$baseline_route"
dns_digest > "$baseline_dns"
[[ -s "$baseline_route" && -s "$baseline_dns" ]] || fail 'Could not capture route/DNS baseline'

on_start_exit() {
    local result="$1"
    trap - EXIT INT TERM
    if (( result != 0 )); then
        set +e
        restore_v9 || print -u2 'Automatic v9 rollback incomplete; inspect installed app, VPN, route, and DNS.'
    fi
    exit "$result"
}
trap 'on_start_exit $?' EXIT
trap 'on_start_exit 130' INT
trap 'on_start_exit 143' TERM
[[ -e "$rollback" ]] || ditto "$app" "$rollback"
v9_exact "$rollback" && signed_and_notarized "$rollback" || fail 'v9 rollback copy failed verification'
ditto "$candidate" "$staging"
v11_exact "$staging" && signed_and_notarized "$staging" || fail 'Staged v11 app failed verification'
mv "$app" "$held"
mv "$staging" "$app"
host activate
active=0
for _ in {1..60}; do
    if extension_active 11; then active=1; break; fi
    sleep 1
done
(( active )) || fail 'v11 system extension did not activate within 60 seconds'
if ! "$cli" standalone import-profile "$profile"; then
    security find-generic-password -s 'com.chris.openforticlient.gate0.psk' \
        -a "$gateway" >/dev/null 2>&1 ||
        fail 'Profile import failed and no exact-gateway OFTC Keychain PSK exists'
    print 'Profile import rejected the saved credential; using existing OFTC Keychain PSK.'
    host save-profile "$gateway" "$port"
fi
[[ "$(host show-profile)" == "OFTC profile: gateway=$gateway saml-port=$port transport=udp" ]] ||
    fail 'Imported OFTC profile did not match selected gateway, port, and UDP mode'
host install-config
"$cli" standalone install-agent
"$cli" standalone start-agent
connected=0
for _ in {1..390}; do
    if [[ "$(host status 2>/dev/null || true)" == *'status: 3'* ]]; then
        connected=1; break
    fi
    sleep 1
done
(( connected )) || fail 'OFTC did not reach Connected within the SAML/NE start deadline'
interface="$(route_interface)"
[[ "$interface" == utun* ]] || fail 'Protected target did not route over OFTC utun'
assigned=$(ifconfig "$interface" | awk '$1 == "inet" { print $2; exit }')
[[ -n "$assigned" ]] || fail 'OFTC utun lacks an assigned IPv4 address'
ping -c 1 -W 5000 "$target"
print -r -- "v11 connected: $target via $interface, assigned IPv4 $assigned"
host rekey-counts
print -r -- "$(date -u '+%Y-%m-%d %H:%M:%S UTC')" > "$started"
print 'Leave the supervised VPN running for lock/unlock and 23-minute automatic rekey checks.'
print "After testing, run: zsh $root/gate7-v11-sustained.sh --finish"
