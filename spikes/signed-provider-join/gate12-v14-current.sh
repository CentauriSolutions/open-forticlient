#!/bin/zsh
# Opt-in v14 IPv4 IKE renewal gate from current v12 on USB Ethernet.
set -euo pipefail
setopt NO_BG_NICE

root="${0:A:h}"
build='/private/tmp/oftc-v14-ike-final'
candidate="$build/IntegrationHost.app"
archive="$build/IntegrationHost-v14-notary.zip"
state='/private/tmp/oftc-issue13-v14-current-state'
app='/Applications/OFTC development probe.app'
staging='/Applications/.OFTC development probe.v14-staging.app'
held='/Applications/.OFTC development probe.v12-held.app'
v12_backup='/private/tmp/oftc-v14-ike-final/IntegrationHost-v12-rollback.app'
provider_id='com.chris.openforticlient.gate0.provider'
cli='/private/tmp/oftc-v13-cli-target/release/oftc'
agent="$HOME/Library/LaunchAgents/com.open-forticlient.oftc.standalone.plist"
log="$HOME/Library/Logs/open-forticlient/standalone.log"
gateway='vpn.example.com'
target='10.20.0.1'
archive_sha='2af1d67ae54fe972e6807c52080021bff7cce5771501f23803a7689612451a92'
v14_host_sha='9e7dce0472be846fa031cd03c0c4ab687cfd46f837c39ea553c301f2b95119bc'
v14_provider_sha='1755eb7e33f41ad054152cfde648a4580de0ebbf5648435c3e15ec6a26515889'
v14_engine_sha='27071fcc776860b3569d6a4af7db019d436848095aeb36152ec144a7b31d4c9c'
v12_host_sha='8e220fe5fca23c644f1fe5bd750219e8006ca4e1bdb3a0edd6b8eba30da43b5e'
v12_provider_sha='137728030341381e9e5ef3fbbcc30ac9a607399bc83cc9104aa657030222de0a'
v12_engine_sha='e62b2a7f96affe6eed429fae2ecbc12dbbe0e7b195b694c77bbedc188d54bc90'
cli_sha='b50a8cdd756ef6fd78568daff37bd5e189127345f9333020b45e01a9801b542e'

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
exact_v14() { exact_bundle "$1" 14 "$v14_host_sha" "$v14_provider_sha" "$v14_engine_sha"; }
exact_v12() { exact_bundle "$1" 12 "$v12_host_sha" "$v12_provider_sha" "$v12_engine_sha"; }
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
running() {
    launchctl print "gui/$(id -u)/com.open-forticlient.oftc.standalone" 2>/dev/null |
        rg -q '^[[:space:]]*pid = [0-9]+$'
}
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
restore_v12() {
    local result=0 active=0
    cleanup_vpn || result=1
    if [[ -d "$held" ]]; then
        exact_v12 "$held" && verified "$held" || return 1
        if [[ -e "$app" ]]; then
            exact_v14 "$app" || return 1
            rm -rf "$app" || return 1
        fi
        mv "$held" "$app" || return 1
        host activate || result=1
        for _ in {1..60}; do
            if active_version 12; then active=1; break; fi
            sleep 1
        done
        (( active )) || result=1
    fi
    [[ ! -e "$staging" ]] || rm -rf "$staging"
    exact_v12 "$app" && verified "$app" || result=1
    [[ ! -d "$state" ]] || baseline_matches || result=1
    rm -f "$state/active" "$state/installed"
    append_evidence "stage=restore_v12 result=$result agent=absent config=absent"
    return "$result"
}
on_install_failure() {
    local result="$1"
    trap - EXIT INT TERM
    if (( result != 0 )); then
        set +e
        append_evidence "stage=mutation_failure exit=$result"
        restore_v12 || print -u2 'Automatic v12 restore incomplete; inspect app, extension, agent, route, and DNS.'
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
    [[ -f "$archive" && "$(sha "$archive")" == "$archive_sha" ]] || fail 'Frozen v14 archive changed'
    exact_v14 "$candidate" && verified "$candidate" || fail 'V14 candidate failed hash or notarization checks'
    exact_v12 "$app" && verified "$app" && active_version 12 || fail 'Installed v12 baseline changed'
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
    [[ "$(route_interface)" == en9 && "$(ifconfig en9 | awk '/status:/{print $2; exit}')" == active ]] || fail 'Target lacks an active en9 baseline route'
    print 'Preflight passed: exact notarized v14 candidate, installed v12 rollback, stored profile, inactive VPN/agent/Tailscale, en9 route.'
}
run_preflight() {
    [[ -f "$state/installed" && ! -e "$state/active" ]] || fail 'V14 gate is not ready for a fresh run'
    exact_v14 "$app" && verified "$app" && active_version 14 || fail 'Installed v14 candidate changed'
    exact_v12 "$held" && verified "$held" || fail 'Held v12 rollback changed'
    [[ "$(host status)" == *'configuration absent'* ]] || fail 'OFTC VPN config already exists'
    [[ ! -e "$agent" ]] && ! loaded || fail 'OFTC LaunchAgent already exists'
    tailscale_inactive && [[ "$(route_interface)" == en9 ]] || fail 'Network baseline changed'
    baseline_matches || fail 'Route or DNS differs from pre-install baseline'
}
observe() {
    [[ -f "$state/active" ]] || fail 'No active v14 run'
    local run="$(cat "$state/active")" vpn_state interface counts ping_result='skipped'
    local browser_attempts=0 recovery_events=0 heartbeats=0 disconnect_events=0
    local refresh_timeouts=0 pause_events=0 bytes offset recent
    local last_heartbeat='none' last_fresh_status='none'
    vpn_state=$(host status 2>/dev/null || true)
    interface=$(route_interface)
    counts=$(host rekey-counts 2>/dev/null || true)
    if [[ "$vpn_state" == *'status: 3'* && "$interface" == utun* ]]; then
        ping -c 1 -W 5000 "$target" >/dev/null 2>&1 && ping_result=pass || ping_result=fail
    fi
    offset=$(cat "$state/$run/log-offset")
    bytes=$(stat -f %z "$log" 2>/dev/null || print 0)
    if (( bytes >= offset )); then
        recent=$(tail -c +$((offset + 1)) "$log" 2>/dev/null || true)
        browser_attempts=$(print -r -- "$recent" | rg -c 'Opening browser for SSO' || print 0)
        recovery_events=$(print -r -- "$recent" | rg -c 'OFTC supervisor: starting fresh SSO recovery' || print 0)
        heartbeats=$(print -r -- "$recent" | rg -c 'OFTC supervisor: heartbeat' || print 0)
        disconnect_events=$(print -r -- "$recent" | rg -c 'OFTC supervisor: VPN disconnected; fetching error' || print 0)
        refresh_timeouts=$(print -r -- "$recent" | rg -c 'OFTC supervisor: preference refresh timed out' || print 0)
        pause_events=$(print -r -- "$recent" | rg -c 'OFTC supervisor: automatic start paused' || print 0)
        last_heartbeat=$(print -r -- "$recent" |
            rg '^OFTC supervisor: heartbeat status=[0-9]+ established=[01] current=[01] refresh=[01] error_fetch=[01]$' |
            tail -1 | tr ' ' '_' || true)
        last_fresh_status=$(print -r -- "$recent" |
            rg '^OFTC supervisor: fresh status=[0-9]+$' | tail -1 | tr ' ' '_' || true)
        [[ -n "$last_heartbeat" ]] || last_heartbeat='none'
        [[ -n "$last_fresh_status" ]] || last_fresh_status='none'
    fi
    append_evidence "run=$run status=${vpn_state// /_} route=$interface ping=$ping_result counts=${counts// /_} browser_attempts=$browser_attempts recovery_events=$recovery_events heartbeats=$heartbeats last_heartbeat=$last_heartbeat last_fresh_status=$last_fresh_status disconnect_events=$disconnect_events refresh_timeouts=$refresh_timeouts pause_events=$pause_events agent_loaded=$(loaded && print yes || print no) agent_running=$(running && print yes || print no)"
    tail -n 1 "$state/evidence.txt"
    [[ "$vpn_state" == *'status: 3'* && "$interface" == utun* && "$ping_result" == pass ]]
}

case "$1" in
--plan)
    [[ $# == 1 ]] || fail 'Usage: gate12-v14-current.sh --plan|--check|--install|--start renewal|lifecycle|--probe|--observe|--stop-run|--finish'
    print 'Exact signed/notarized v14 IPv4 IKE renewal gate from installed v12 on en9.'
    print -r -- '--check changes nothing. --install saves installed v12 and activates v14.'
    print -r -- '--start renewal|lifecycle opens one fresh SSO connection using the stored profile.'
    print -r -- '--probe runs one explicit IKE renewal in the renewal run.'
    print -r -- '--observe records nonsecret status/route/rekey counts and protected ICMP.'
    print -r -- '--stop-run removes OFTC agent/config and checks baseline. --finish leaves v14 installed.'
    print 'Tailscale and Fortinet services are read-only. The 55-minute lifecycle is a separate run.'
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
    exact_v14 "$staging" && verified "$staging" || fail 'Staged v14 failed verification'
    mv "$app" "$held"
    mv "$staging" "$app"
    host activate
    active=0
    for _ in {1..60}; do
        if active_version 14; then active=1; break; fi
        sleep 1
    done
    (( active )) || fail 'V14 extension did not activate within 60 seconds'
    print -r -- installed > "$state/installed"
    append_evidence 'stage=install v14=exact v12=held'
    trap - EXIT INT TERM
    print 'V14 installed. Start the independent runs with --start renewal or --start lifecycle.'
    ;;
--start)
    [[ $# == 2 && ( "$2" == renewal || "$2" == lifecycle ) ]] ||
        fail 'Usage: --start renewal|lifecycle'
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
    date +%s > "$state/$run/connected-at"
    trap - EXIT INT TERM
    print 'Initial protected traffic passed. For renewal use --probe, then --observe and --stop-run.'
    ;;
--probe)
    [[ $# == 1 && -f "$state/active" && "$(cat "$state/active")" == renewal ]] ||
        fail 'The explicit IKE renewal probe requires an active renewal run'
    [[ ! -e "$state/renewal/probed" ]] || fail 'IKE renewal probe already attempted'
    print -r -- attempted > "$state/renewal/probed"
    host rekey-ike-once || fail 'IKE renewal probe failed; stop and inspect the run'
    append_evidence 'run=renewal stage=ike_rekey_probe result=passed'
    observe || fail 'Protected traffic failed after IKE renewal'
    host rekey-once || fail 'CHILD rekey on the renewed IKE SA failed; stop and inspect the run'
    append_evidence 'run=renewal stage=child_rekey_after_ike result=passed'
    observe || fail 'Protected traffic failed after CHILD rekey on renewed IKE SA'
    print -r -- passed > "$state/renewal/probe-passed"
    ;;
--observe)
    [[ $# == 1 ]] || fail 'Usage: --observe'
    observe
    ;;
--stop-run)
    [[ $# == 1 && -f "$state/active" ]] || fail 'No active run to stop'
    run="$(cat "$state/active")"
    passed=1
    if [[ "$run" == lifecycle ]]; then
        [[ -s "$state/lifecycle/connected-at" ]] || fail 'Missing lifecycle connection timestamp'
        elapsed=$(( $(date +%s) - $(cat "$state/lifecycle/connected-at") ))
        (( elapsed >= 55 * 60 )) && observe || passed=0
        append_evidence "run=lifecycle elapsed_seconds=$elapsed post_limit_traffic=$passed"
    elif [[ ! -f "$state/renewal/probe-passed" ]]; then
        passed=0
    fi
    if [[ "$run" == renewal ]] && rg -q 'stage=en9_loss' "$state/evidence.txt"; then
        observe || passed=0
    fi
    cleanup_vpn || fail 'OFTC agent/config cleanup incomplete; inspect before continuing'
    baseline_matches || fail 'Route or DNS differs from baseline; inspect network before the next run'
    append_evidence "run=$run stage=stopped agent=absent config=absent route=baseline dns=baseline"
    rm "$state/active"
    if (( passed )); then print -r -- passed > "$state/$run/stopped"; fi
    (( passed )) || fail 'Run cleaned up but did not pass its renewal or lifecycle check'
    print "Run stopped; nonsecret evidence: $state/evidence.txt"
    ;;
--finish)
    [[ $# == 1 && -f "$state/installed" && ! -e "$state/active" ]] ||
        fail 'No completed v14 gate state to finish'
    [[ -f "$state/renewal/stopped" && -f "$state/lifecycle/stopped" ]] ||
        fail 'Independent renewal and 55-minute lifecycle runs have not both passed'
    cleanup_vpn || fail 'OFTC agent/config cleanup incomplete'
    baseline_matches || fail 'Route or DNS differs from baseline; inspect network'
    exact_v14 "$app" && verified "$app" && active_version 14 || fail 'Installed v14 changed'
    exact_v12 "$held" && verified "$held" || fail 'Held v12 rollback changed'
    [[ ! -e "$v12_backup" ]] || fail 'Existing v12 backup path needs inspection'
    mv "$held" "$v12_backup"
    exact_v12 "$v12_backup" && verified "$v12_backup" ||
        fail 'V12 rollback copy failed verification after move'
    rm "$state/installed"
    append_evidence 'stage=finished v14=installed agent=absent config=absent route=baseline dns=baseline v12=backed_up'
    print "V14 remains installed and disconnected; exact v12 backup retained at $v12_backup"
    print "Nonsecret evidence: $state/evidence.txt"
    ;;
*) fail 'Usage: gate12-v14-current.sh --plan|--check|--install|--start renewal|lifecycle|--probe|--observe|--stop-run|--finish' ;;
esac
