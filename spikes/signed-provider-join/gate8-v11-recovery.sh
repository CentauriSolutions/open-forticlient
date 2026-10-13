#!/bin/zsh
# Staged Issue 13 IPv4 recovery/lifetime gate. Read --plan before live use.
# No shell tracing: SAML tokens and the imported PSK must never enter a log.
set -euo pipefail

root="${0:A:h}"
app='/Applications/OFTC development probe.app'
provider_id='com.chris.openforticlient.gate0.provider'
cli='/private/tmp/oftc-issue13-cli-verify-target/release/oftc'
agent="$HOME/Library/LaunchAgents/com.open-forticlient.oftc.standalone.plist"
log="$HOME/Library/Logs/open-forticlient/standalone.log"
state='/private/tmp/oftc-issue13-v11-recovery-state'
target='10.20.0.1'
gateway='vpn.example.com'
port='9443'
cli_sha='549d4e6a86859033560c3c8895a9891d95585246cf9085283e3a74253a812d96'
host_sha='53f97b89eb6c3ea98eac5aa3edae195e6f710a245aaa28c11d3e0d1222849917'
provider_sha='d75937123867b80cc6bd310b0762f5e2251699f3eef7dd9aa33a618c65f80785'
engine_sha='9865cd1a017f5f0ab041b5c49466001b7d7741590cb94b697710f68d2f471eb2'

fail() { print -u2 -- "$*"; exit 1; }
sha() { shasum -a 256 "$1" | awk '{print $1}'; }
host() { "$app/Contents/MacOS/IntegrationHost" "$@"; }
route_snapshot() {
    route -n get -inet "$target" 2>/dev/null |
        awk '$1 == "gateway:" || $1 == "interface:" || $1 == "ifscope:" || $1 == "mtu:" {print $1, $2}'
}
route_interface() { route_snapshot | awk '$1 == "interface:" {print $2; exit}'; }
dns_digest() { scutil --dns | shasum -a 256 | awk '{print $1}'; }
tailscale_inactive() {
    [[ "$(networksetup -getnetworkserviceenabled Tailscale 2>/dev/null)" == Disabled &&
       "$(scutil --nc status Tailscale 2>/dev/null | head -1 | tr -d '\r')" == Disconnected ]]
}
loaded() { launchctl print "gui/$(id -u)/com.open-forticlient.oftc.standalone" >/dev/null 2>&1; }
active_v11() {
    systemextensionsctl list | rg -F "$provider_id" |
        rg '\([^)]*/11\).*\[activated enabled\]' >/dev/null
}
exact_v11() {
    local extension="$app/Contents/Library/SystemExtensions/$provider_id.systemextension"
    [[ -d "$extension" &&
       "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist")" == 11 &&
       "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$extension/Contents/Info.plist")" == 11 &&
       "$(sha "$app/Contents/MacOS/IntegrationHost")" == "$host_sha" &&
       "$(sha "$extension/Contents/MacOS/IntegrationProvider")" == "$provider_sha" &&
       "$(sha "$extension/Contents/Frameworks/liboftc_provider_ffi.dylib")" == "$engine_sha" ]]
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
append_evidence() { print -r -- "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*" >> "$state/evidence.txt"; }

preflight() {
    [[ -x "$cli" && "$(sha "$cli")" == "$cli_sha" ]] || fail 'Pinned rebuilt CLI is missing or changed'
    exact_v11 || fail 'Installed v11 app does not match the approved signed bundle'
    codesign --verify --deep --strict "$app" >/dev/null 2>&1 || fail 'Installed app signature failed'
    xcrun stapler validate "$app" >/dev/null 2>&1 || fail 'Installed app ticket failed'
    spctl --assess --type execute "$app" >/dev/null 2>&1 || fail 'Installed app Gatekeeper check failed'
    active_v11 || fail 'Installed v11 provider is not active'
    [[ "$(host show-profile)" == "OFTC profile: gateway=$gateway saml-port=$port transport=udp" ]] ||
        fail 'OFTC-owned profile differs from the selected IPv4 UDP profile'
    security find-generic-password -s 'com.chris.openforticlient.gate0.psk' \
        -a "$gateway" >/dev/null 2>&1 || fail 'OFTC-owned exact-gateway Keychain PSK is absent'
    [[ "$(host status)" == *'configuration absent'* ]] || fail 'OFTC VPN config already exists'
    [[ ! -e "$agent" ]] && ! loaded || fail 'Standalone agent already exists or is loaded'
    tailscale_inactive || fail 'Tailscale must already be Disabled and Disconnected'
    if scutil --nc list | rg '\((Connected|Connecting|Reasserting)\)' >/dev/null; then
        fail 'Another VPN is active'
    fi
    [[ "$(route_interface)" == en0 ]] || fail 'Target has no en0 baseline route'
    print 'Preflight passed: exact signed v11, rebuilt CLI, stored profile/PSK, inactive VPN/agent/Tailscale, en0 route.'
}

cleanup() {
    local result=0 vpn_state
    if [[ -e "$agent" ]]; then
        "$cli" standalone uninstall-agent || result=1
    fi
    if loaded || [[ -e "$agent" ]]; then result=1; fi
    vpn_state=$(host status 2>/dev/null || true)
    if [[ "$vpn_state" != *'configuration absent'* ]]; then
        host stop || result=1
        wait_disconnected || result=1
        host remove-config || result=1
    fi
    [[ "$(host status 2>/dev/null || true)" == *'configuration absent'* ]] || result=1
    tailscale_inactive || result=1
    return "$result"
}

observe() {
    [[ -d "$state" && -f "$state/started" ]] || fail 'No active gate state'
    local vpn_state interface counts ping_result='skipped' supervisor_events=0 recovery_events=0 browser_attempts=0 bytes offset
    vpn_state=$(host status 2>/dev/null || true)
    interface=$(route_interface)
    counts=$(host rekey-counts 2>/dev/null || true)
    if [[ "$vpn_state" == *'status: 3'* && "$interface" == utun* ]]; then
        if ping -c 1 -W 5000 "$target" >/dev/null 2>&1; then
            ping_result=pass
        else
            ping_result=fail
        fi
    fi
    offset=$(cat "$state/log-offset")
    bytes=$(stat -f %z "$log" 2>/dev/null || print 0)
    if (( bytes >= offset )); then
        supervisor_events=$(tail -c +$((offset + 1)) "$log" 2>/dev/null |
            rg -c '^OFTC supervised VPN connected$' || print 0)
        recovery_events=$(tail -c +$((offset + 1)) "$log" 2>/dev/null |
            rg -c '^OFTC tunnel lost; acquiring fresh SAML for recovery$' || print 0)
        browser_attempts=$(tail -c +$((offset + 1)) "$log" 2>/dev/null |
            rg -c 'Opening browser for SSO' || print 0)
    fi
    append_evidence "status=${vpn_state// /_} route=$interface ping=$ping_result counts=${counts// /_} connected_events=$supervisor_events recovery_events=$recovery_events browser_attempts=$browser_attempts agent_loaded=$(loaded && print yes || print no)"
    tail -n 1 "$state/evidence.txt"
    [[ "$vpn_state" == *'status: 3'* && "$interface" == utun* && "$ping_result" == pass ]]
}

[[ $# == 1 ]] || fail 'Usage: gate8-v11-recovery.sh --plan|--check|--start|--observe|--finish|--rollback'
case "$1" in
--plan)
    cat <<'EOF'
Issue 13 staged IPv4 gate for the already installed, signed/notarized v11 app.
No app or extension installation, Fortinet change, or Tailscale change is planned.
--check is read-only and requires no SAML. --start adds only OFTC's VPN config,
stages/starts its per-user LaunchAgent, and starts verified-TLS SAML to
vpn.example.com:9443 plus UDP 4500 IKE/ESP (bounded TCP
fallback before EAP). Supervised recovery may request fresh SAML tokens, at
most three times per ten minutes. Protected probes target only 10.20.0.1.

Approval is required before --start or any live probe. First verify one start,
then --observe. For a separate approved real-loss stage, the operator turns
Wi-Fi off for about 75 seconds and back on; run --observe before and after.
Do this early: a failed SAML acquisition during the outage may stop the v11
supervisor, which this gate will record rather than retry automatically.
For an independent lifetime run, skip the loss stage and leave the first SA
up through 55 minutes. Recovery should open a new browser tab; an existing
provider session may authenticate without a prompt. Then --observe. A separate
approved sleep/wake stage is optional if local access is practical.

--finish and --rollback both stop/uninstall the agent, remove OFTC's VPN config,
and compare route/DNS to their pre-test baselines. The signed v11 app, OFTC
profile/Keychain PSK, and existing v9 rollback copy remain. Tailscale must
stay Disabled/Disconnected. Evidence contains UTC times, status, route,
nonsecret rekey counts, and counts of fixed supervisor messages, never raw logs.
EOF
    ;;
--check)
    [[ ! -e "$state" ]] || fail 'Prior gate state exists; inspect and finish it first'
    preflight
    ;;
--start)
    [[ ! -e "$state" ]] || fail 'Prior gate state exists; inspect and finish it first'
    preflight
    umask 077
    mkdir -m 700 "$state"
    route_snapshot > "$state/baseline.route"
    dns_digest > "$state/baseline.dns-sha256"
    stat -f %z "$log" > "$state/log-offset" 2>/dev/null || print 0 > "$state/log-offset"
    [[ -s "$state/baseline.route" && -s "$state/baseline.dns-sha256" ]] ||
        fail 'Could not save baseline route and DNS'
    append_evidence 'stage=start preflight=pass'
    on_start_exit() {
        local result="$1"
        trap - EXIT INT TERM
        if (( result != 0 )); then
            set +e
            cleanup
            append_evidence "stage=start_failure cleanup_exit=$?"
        fi
        exit "$result"
    }
    trap 'on_start_exit $?' EXIT
    trap 'on_start_exit 130' INT
    trap 'on_start_exit 143' TERM
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
    (( connected )) || fail 'OFTC did not connect within the SAML/NE start deadline'
    print -r -- "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$state/started"
    observe
    trap - EXIT INT TERM
    print 'Initial gate passed. Keep the VPN up; use --observe for each approved stage.'
    ;;
--observe)
    observe
    ;;
--finish|--rollback)
    [[ -d "$state" ]] || fail 'No gate state exists'
    cleanup || fail 'Cleanup incomplete; inspect agent, config, and VPN before retrying --rollback'
    [[ "$(route_snapshot)" == "$(cat "$state/baseline.route")" ]] ||
        fail 'Route differs from baseline after cleanup; inspect current network path'
    [[ "$(dns_digest)" == "$(cat "$state/baseline.dns-sha256")" ]] ||
        fail 'DNS differs from baseline after cleanup; inspect current network path'
    append_evidence 'stage=finished config=absent agent=absent route=baseline dns=baseline tailscale=inactive'
    print "Cleanup passed; evidence: $state/evidence.txt"
    ;;
*) fail 'Usage: gate8-v11-recovery.sh --plan|--check|--start|--observe|--finish|--rollback' ;;
esac
