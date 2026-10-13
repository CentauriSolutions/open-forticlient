#!/bin/zsh
# Opt-in v12 IPv4 recovery gate. No shell tracing or secret-bearing logs.
set -euo pipefail
setopt NO_BG_NICE

root="${0:A:h}"
build='/private/tmp/oftc-v12-recovery-build'
candidate="$build/IntegrationHost.app"
archive="$build/IntegrationHost-v12-notary.zip"
state='/private/tmp/oftc-issue13-v12-recovery-state'
app='/Applications/OFTC development probe.app'
staging='/Applications/.OFTC development probe.v12-staging.app'
held='/Applications/.OFTC development probe.v11-held.app'
v11_backup="$build/IntegrationHost-v11-rollback.app"
provider_id='com.chris.openforticlient.gate0.provider'
cli='/private/tmp/oftc-issue13-cli-verify-target/release/oftc'
agent="$HOME/Library/LaunchAgents/com.open-forticlient.oftc.standalone.plist"
log="$HOME/Library/Logs/open-forticlient/standalone.log"
gateway='vpn.example.com'
target='10.20.0.1'
archive_sha='1f48ffdcb2f62573b851af94dc05720031cd4e9d044500467af90886d3af602b'
v12_host_sha='8e220fe5fca23c644f1fe5bd750219e8006ca4e1bdb3a0edd6b8eba30da43b5e'
v12_provider_sha='137728030341381e9e5ef3fbbcc30ac9a607399bc83cc9104aa657030222de0a'
v12_engine_sha='e62b2a7f96affe6eed429fae2ecbc12dbbe0e7b195b694c77bbedc188d54bc90'
v11_host_sha='53f97b89eb6c3ea98eac5aa3edae195e6f710a245aaa28c11d3e0d1222849917'
v11_provider_sha='d75937123867b80cc6bd310b0762f5e2251699f3eef7dd9aa33a618c65f80785'
v11_engine_sha='9865cd1a017f5f0ab041b5c49466001b7d7741590cb94b697710f68d2f471eb2'
cli_sha='549d4e6a86859033560c3c8895a9891d95585246cf9085283e3a74253a812d96'

fail() { print -u2 -- "$*"; exit 1; }
sha() { shasum -a 256 "$1" | awk '{print $1}'; }
host() { "$app/Contents/MacOS/IntegrationHost" "$@"; }
extension() { print -r -- "$1/Contents/Library/SystemExtensions/$provider_id.systemextension"; }
exact_bundle() {
    local bundle="$1" expected_version="$2" host_sha="$3" provider_sha="$4" engine_sha="$5"
    local ext="$(extension "$bundle")"
    [[ -d "$ext" &&
       "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$bundle/Contents/Info.plist")" == "$expected_version" &&
       "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$ext/Contents/Info.plist")" == "$expected_version" &&
       "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$bundle/Contents/Info.plist")" == 'com.chris.openforticlient.gate0' &&
       "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$ext/Contents/Info.plist")" == "$provider_id" &&
       "$(sha "$bundle/Contents/MacOS/IntegrationHost")" == "$host_sha" &&
       "$(sha "$ext/Contents/MacOS/IntegrationProvider")" == "$provider_sha" &&
       "$(sha "$ext/Contents/Frameworks/liboftc_provider_ffi.dylib")" == "$engine_sha" ]]
}
exact_v12() { exact_bundle "$1" 12 "$v12_host_sha" "$v12_provider_sha" "$v12_engine_sha"; }
exact_v11() { exact_bundle "$1" 11 "$v11_host_sha" "$v11_provider_sha" "$v11_engine_sha"; }
verified() {
    codesign --verify --deep --strict "$1" >/dev/null 2>&1 &&
        xcrun stapler validate "$1" >/dev/null 2>&1 &&
        spctl --assess --type execute "$1" >/dev/null 2>&1
}
active_version() {
    systemextensionsctl list | rg -F "$provider_id" |
        rg "\\([^)]*/$1\\).*\\[activated enabled\\]" >/dev/null
}
loaded() { launchctl print "gui/$(id -u)/com.open-forticlient.oftc.standalone" >/dev/null 2>&1; }
tailscale_inactive() {
    [[ "$(networksetup -getnetworkserviceenabled Tailscale 2>/dev/null)" == Disabled &&
       "$(scutil --nc status Tailscale 2>/dev/null | head -1 | tr -d '\r')" == Disconnected ]]
}
route_snapshot() {
    route -n get -inet "$target" 2>/dev/null |
        awk '$1 == "gateway:" || $1 == "interface:" || $1 == "ifscope:" || $1 == "mtu:" {print $1, $2}'
}
route_interface() { route_snapshot | awk '$1 == "interface:" {print $2; exit}'; }
dns_digest() { scutil --dns | shasum -a 256 | awk '{print $1}'; }
append_evidence() {
    [[ -d "$state" ]] && print -r -- "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*" >> "$state/evidence.txt"
}
baseline_matches() {
    [[ -s "$state/baseline.route" && -s "$state/baseline.dns-sha256" &&
       "$(route_snapshot)" == "$(cat "$state/baseline.route")" &&
       "$(dns_digest)" == "$(cat "$state/baseline.dns-sha256")" ]] && tailscale_inactive
}
wait_disconnected() {
    local vpn_state
    for _ in {1..45}; do
        vpn_state=$(host status 2>/dev/null || true)
        [[ "$vpn_state" == *'status: 1'* || "$vpn_state" == *'configuration absent'* ]] && return 0
        sleep 1
    done
    return 1
}
cleanup_vpn() {
    local result=0 vpn_state
    if [[ -e "$agent" ]] || loaded; then
        "$cli" standalone uninstall-agent || result=1
    fi
    if [[ -x "$app/Contents/MacOS/IntegrationHost" ]]; then
        vpn_state=$(host status 2>/dev/null || true)
        if [[ "$vpn_state" != *'configuration absent'* ]]; then
            host stop || result=1
            wait_disconnected || result=1
            host remove-config || result=1
        fi
        [[ "$(host status 2>/dev/null || true)" == *'configuration absent'* ]] || result=1
    fi
    [[ ! -e "$agent" ]] && ! loaded || result=1
    tailscale_inactive || result=1
    return "$result"
}
restore_v11() {
    local result=0 active=0
    cleanup_vpn || result=1
    if [[ -d "$held" ]]; then
        exact_v11 "$held" && verified "$held" || return 1
        if [[ -e "$app" ]]; then
            exact_v12 "$app" || return 1
            rm -rf "$app" || return 1
        fi
        mv "$held" "$app" || return 1
        host activate || result=1
        for _ in {1..60}; do
            if active_version 11; then active=1; break; fi
            sleep 1
        done
        (( active )) || result=1
    fi
    [[ ! -e "$staging" ]] || rm -rf "$staging"
    exact_v11 "$app" && verified "$app" || result=1
    [[ ! -d "$state" ]] || baseline_matches || result=1
    rm -f "$state/active" "$state/installed"
    append_evidence "stage=restore_v11 result=$result agent=absent config=absent"
    return "$result"
}
on_install_failure() {
    local result="$1"
    trap - EXIT INT TERM
    if (( result != 0 )); then
        set +e
        append_evidence "stage=mutation_failure exit=$result"
        restore_v11 || print -u2 'Automatic v11 restore incomplete; inspect app, extension, agent, route, and DNS.'
    fi
    exit "$result"
}
on_run_failure() {
    local result="$1"
    trap - EXIT INT TERM
    if (( result != 0 )); then
        set +e
        append_evidence "stage=run_failure exit=$result"
        cleanup_vpn || print -u2 'OFTC cleanup incomplete; inspect agent, config, and route.'
        baseline_matches || print -u2 'Route or DNS differs from baseline; inspect network.'
        rm -f "$state/active"
    fi
    exit "$result"
}
preflight() {
    [[ ! -e "$state" && ! -e "$staging" && ! -e "$held" ]] || fail 'Prior gate state or staging exists'
    [[ -x "$cli" && "$(sha "$cli")" == "$cli_sha" ]] || fail 'Pinned CLI is missing or changed'
    [[ -f "$archive" && "$(sha "$archive")" == "$archive_sha" ]] || fail 'Frozen v12 archive changed'
    exact_v12 "$candidate" && verified "$candidate" || fail 'V12 candidate failed hash or notarization checks'
    exact_v11 "$app" && verified "$app" && active_version 11 || fail 'Installed v11 baseline changed'
    [[ "$(host show-profile)" == "OFTC profile: gateway=$gateway saml-port=9443 transport=udp" ]] ||
        fail 'Stored OFTC profile differs from selected IPv4 UDP profile'
    security find-generic-password -s 'com.chris.openforticlient.gate0.psk' -a "$gateway" \
        >/dev/null 2>&1 || fail 'Exact-gateway OFTC Keychain item is absent'
    [[ "$(host status)" == *'configuration absent'* ]] || fail 'OFTC VPN config already exists'
    [[ ! -e "$agent" ]] && ! loaded || fail 'OFTC LaunchAgent already exists'
    tailscale_inactive || fail 'Tailscale must remain Disabled/Disconnected'
    if scutil --nc list | rg '\((Connected|Connecting|Reasserting)\)' >/dev/null; then
        fail 'Another VPN is active'
    fi
    [[ "$(route_interface)" == en0 ]] || fail 'Target lacks an en0 baseline route'
    print 'Preflight passed: exact notarized v12 candidate, installed v11 rollback, stored profile, inactive VPN/agent/Tailscale, en0 route.'
}
run_preflight() {
    [[ -f "$state/installed" && ! -e "$state/active" ]] || fail 'V12 gate is not ready for a fresh run'
    exact_v12 "$app" && verified "$app" && active_version 12 || fail 'Installed v12 candidate changed'
    exact_v11 "$held" && verified "$held" || fail 'Held v11 rollback changed'
    [[ "$(host status)" == *'configuration absent'* ]] || fail 'OFTC VPN config already exists'
    [[ ! -e "$agent" ]] && ! loaded || fail 'OFTC LaunchAgent already exists'
    tailscale_inactive && [[ "$(route_interface)" == en0 ]] || fail 'Network baseline changed'
    baseline_matches || fail 'Route or DNS differs from pre-install baseline'
}
observe() {
    [[ -f "$state/active" ]] || fail 'No active v12 run'
    local run="$(cat "$state/active")" vpn_state interface counts ping_result='skipped'
    local browser_attempts=0 recovery_events=0 bytes offset
    vpn_state=$(host status 2>/dev/null || true)
    interface=$(route_interface)
    counts=$(host rekey-counts 2>/dev/null || true)
    if [[ "$vpn_state" == *'status: 3'* && "$interface" == utun* ]]; then
        ping -c 1 -W 5000 "$target" >/dev/null 2>&1 && ping_result=pass || ping_result=fail
    fi
    offset=$(cat "$state/$run/log-offset")
    bytes=$(stat -f %z "$log" 2>/dev/null || print 0)
    if (( bytes >= offset )); then
        browser_attempts=$(tail -c +$((offset + 1)) "$log" 2>/dev/null |
            rg -c 'Opening browser for SSO' || print 0)
        recovery_events=$(tail -c +$((offset + 1)) "$log" 2>/dev/null |
            rg -c 'OFTC supervisor: starting fresh SSO recovery' || print 0)
    fi
    append_evidence "run=$run status=${vpn_state// /_} route=$interface ping=$ping_result counts=${counts// /_} browser_attempts=$browser_attempts recovery_events=$recovery_events agent_loaded=$(loaded && print yes || print no)"
    tail -n 1 "$state/evidence.txt"
    [[ "$vpn_state" == *'status: 3'* && "$interface" == utun* && "$ping_result" == pass ]]
}

case "$1" in
--plan)
    [[ $# == 1 ]] || fail 'Usage: gate9-v12-recovery.sh --plan|--check|--install|--start loss|lifetime|--observe|--stop-run|--finish'
    print 'Exact signed/notarized v12 IPv4 recovery gate; see gate9-v12-recovery.md.'
    print -r -- '--check changes nothing. --install saves installed v11 and activates v12.'
    print -r -- '--start loss and --start lifetime are separate fresh SSO connections.'
    print -r -- '--observe records nonsecret status/route/rekey/browser counts and protected ICMP.'
    print -r -- '--stop-run removes OFTC agent/config and checks baseline. --finish leaves v12 installed.'
    print 'Tailscale and Fortinet services are read-only. Wi-Fi loss requires its separate guarded script.'
    ;;
--check)
    [[ $# == 1 ]] || fail 'Usage: --check'
    preflight
    ;;
--install)
    [[ $# == 1 ]] || fail 'Usage: --install'
    preflight
    umask 077
    mkdir -m 700 "$state"
    route_snapshot > "$state/baseline.route"
    dns_digest > "$state/baseline.dns-sha256"
    [[ -s "$state/baseline.route" && -s "$state/baseline.dns-sha256" ]] || fail 'Could not save network baseline'
    trap 'on_install_failure $?' EXIT
    trap 'on_install_failure 130' INT
    trap 'on_install_failure 143' TERM
    ditto "$candidate" "$staging"
    exact_v12 "$staging" && verified "$staging" || fail 'Staged v12 failed verification'
    mv "$app" "$held"
    mv "$staging" "$app"
    host activate
    active=0
    for _ in {1..60}; do
        if active_version 12; then active=1; break; fi
        sleep 1
    done
    (( active )) || fail 'V12 extension did not activate within 60 seconds'
    print -r -- installed > "$state/installed"
    append_evidence 'stage=install v12=exact v11=held'
    trap - EXIT INT TERM
    print 'V12 installed. Start one approved run with --start loss or --start lifetime.'
    ;;
--start)
    [[ $# == 2 && ( "$2" == loss || "$2" == lifetime ) ]] || fail 'Usage: --start loss|lifetime'
    run="$2"
    run_preflight
    [[ ! -e "$state/$run" ]] || fail 'That run already has evidence; refusing to repeat it'
    mkdir -m 700 "$state/$run"
    stat -f %z "$log" > "$state/$run/log-offset" 2>/dev/null || print 0 > "$state/$run/log-offset"
    print -r -- "$run" > "$state/active"
    append_evidence "run=$run stage=start"
    trap 'on_run_failure $?' EXIT
    trap 'on_run_failure 130' INT
    trap 'on_run_failure 143' TERM
    host install-config
    "$cli" standalone install-agent
    "$cli" standalone start-agent
    connected=0
    for _ in {1..390}; do
        if [[ "$(host status 2>/dev/null || true)" == *'status: 3'* ]]; then connected=1; break; fi
        sleep 1
    done
    (( connected )) || fail 'OFTC did not connect within the SAML/NE start deadline'
    observe
    trap - EXIT INT TERM
    print 'Initial protected traffic passed. Use --observe, then --stop-run.'
    ;;
--observe)
    [[ $# == 1 ]] || fail 'Usage: --observe'
    observe
    ;;
--stop-run)
    [[ $# == 1 && -f "$state/active" ]] || fail 'No active run to stop'
    run="$(cat "$state/active")"
    cleanup_vpn || fail 'OFTC agent/config cleanup incomplete; inspect before continuing'
    baseline_matches || fail 'Route or DNS differs from baseline; inspect network before the next run'
    append_evidence "run=$run stage=stopped agent=absent config=absent route=baseline dns=baseline"
    rm "$state/active"
    print "Run stopped; nonsecret evidence: $state/evidence.txt"
    ;;
--finish)
    [[ $# == 1 && -f "$state/installed" && ! -e "$state/active" ]] ||
        fail 'No completed v12 gate state to finish'
    cleanup_vpn || fail 'OFTC agent/config cleanup incomplete'
    baseline_matches || fail 'Route or DNS differs from baseline; inspect network'
    exact_v12 "$app" && verified "$app" && active_version 12 || fail 'Installed v12 changed'
    exact_v11 "$held" && verified "$held" || fail 'Held v11 rollback changed'
    [[ ! -e "$v11_backup" ]] || fail 'Existing v11 backup path needs inspection'
    mv "$held" "$v11_backup"
    exact_v11 "$v11_backup" && verified "$v11_backup" ||
        fail 'V11 rollback copy failed verification after move'
    rm "$state/installed"
    append_evidence 'stage=finished v12=installed agent=absent config=absent route=baseline dns=baseline v11=backed_up'
    print "V12 remains installed and disconnected; exact v11 backup retained at $v11_backup"
    print "Nonsecret evidence: $state/evidence.txt"
    ;;
*) fail 'Usage: gate9-v12-recovery.sh --plan|--check|--install|--start loss|lifetime|--observe|--stop-run|--finish' ;;
esac
