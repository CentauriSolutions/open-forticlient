#!/bin/zsh
# One explicitly approved, token-bearing UDP provider smoke test. Default is
# read-only plan output. Never auto-retries SAML or ICMP.
set -euo pipefail

app='/Applications/OFTC development probe.app'
host="$app/Contents/MacOS/IntegrationHost"
bundle_id='com.chris.openforticlient.gate0'
provider_id="${bundle_id}.provider"
gateway='vpn.example.com'
target='10.20.0.1'
tailscale_service='Tailscale'
expected_version='5'

usage() {
    print -u2 'Usage: gate4-smoke.sh --plan [--leave-tailscale-off] | --execute <saml-port> <32-hex-UID> [--insecure-saml] [--leave-tailscale-off]'
    exit 2
}

if [[ "${1:-}" == '--plan' ]]; then
    [[ $# == 1 || ( $# == 2 && "$2" == '--leave-tailscale-off' ) ]] || usage
    cat <<EOF
Gate 4 live provider smoke plan; nothing has been changed.
Required before --execute: explicit approval for ONE fresh SAML token to
${gateway} over UDP 4500 and ONE encrypted ICMP echo to ${target}.
Pass the profile's exact IKESamlPort as <saml-port>; do not guess a default.
Installed app/provider must have exact ${bundle_id} IDs and version ${expected_version},
valid Developer ID/notarization, and activated enabled extension.
Tailscale must start Enabled, Connected, OnDemandEnabled TRUE. The script
disables its network service before either OFTC probe.
OFTC must start without a saved VPN config. It installs only its own config,
runs one no-token provider preflight and requires its authenticated EAP stage
with no route/DNS change. Only then it starts live SAML once, waits for
Connected, requires ${target} to route over
the OFTC utun, sends ping -c 1 once, stops/removes OFTC, and checks route/DNS
cleanup. Any failure stops; no fresh-token retry.
EOF
    if [[ "${2:-}" == '--leave-tailscale-off' ]]; then
        print 'Selected cleanup: leave Tailscale Disabled/inactive (Disconnected or Invalid). No networksetup on or scutil --nc start.'
    else
        print 'Selected cleanup: re-enable Tailscale, request scutil --nc start, verify original state.'
    fi
    exit 0
fi

[[ "${1:-}" == '--execute' && $# -ge 3 && $# -le 5 ]] || usage
saml_port="$2"
[[ "$saml_port" =~ '^[0-9]{1,5}$' ]] && (( saml_port >= 1 && saml_port <= 65535 )) || usage
uid="$3"
[[ "$uid" =~ '^[0-9A-Fa-f]{32}$' ]] || usage
insecure_flag=()
typeset -i leave_tailscale_off=0
shift 3
for option in "$@"; do
    case "$option" in
    --insecure-saml)
        (( ${#insecure_flag[@]} == 0 )) || usage
        insecure_flag=(--insecure-saml)
        ;;
    --leave-tailscale-off)
        (( leave_tailscale_off == 0 )) || usage
        leave_tailscale_off=1
        ;;
    *) usage ;;
    esac
done

fail() { print -u2 -- "$*"; exit 1; }
service_state() { networksetup -getnetworkserviceenabled "$tailscale_service" 2>/dev/null; }
vpn_state() { scutil --nc status "$tailscale_service" 2>/dev/null | head -1 | tr -d '\r'; }
on_demand_state() {
    scutil --nc show "$tailscale_service" 2>/dev/null |
        awk '$1 == "OnDemandEnabled" { print $3; exit }'
}
tailscale_inactive() {
    [[ "$(service_state)" == 'Disabled' ]] || return 1
    local state
    state=$(vpn_state)
    [[ "$state" == 'Disconnected' || "$state" == 'Invalid' ]]
}
route_interface() {
    route -n get -inet "$target" 2>/dev/null |
        awk '$1 == "interface:" { print $2; exit }'
}
dns_digest() { scutil --dns | shasum -a 256 | awk '{ print $1 }'; }

wait_oftc_disconnected() {
    local host_status
    for _ in {1..45}; do
        host_status=$("$host" status 2>/dev/null || true)
        [[ "$host_status" == *'status: 1'* || "$host_status" == *'configuration absent'* ]] && return 0
        sleep 1
    done
    return 1
}

wait_tailscale() {
    for _ in {1..60}; do
        [[ "$(service_state)" == 'Enabled' && "$(vpn_state)" == 'Connected' &&
           "$(on_demand_state)" == 'TRUE' ]] && return 0
        sleep 1
    done
    return 1
}

[[ -x "$host" ]] || fail "Installed OFTC host is missing: $host"
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist")" == "$bundle_id" ]] ||
    fail 'Installed host bundle ID mismatch'
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist")" == "$expected_version" ]] ||
    fail 'This smoke test requires the reviewed version 5 host; version 4 is preflight-only'
extension="$app/Contents/Library/SystemExtensions/${provider_id}.systemextension"
[[ -d "$extension" ]] || fail 'Expected provider system extension is missing from the installed app'
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$extension/Contents/Info.plist")" == "$provider_id" ]] ||
    fail 'Installed provider bundle ID mismatch'
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$extension/Contents/Info.plist")" == "$expected_version" ]] ||
    fail 'Installed provider version mismatch'
systemextensionsctl list | rg -F "$provider_id" | rg '\([^)]*/5\).*\[activated enabled\]' >/dev/null ||
    fail 'Reviewed version 5 provider is not activated and enabled'
codesign --verify --deep --strict "$app" >/dev/null || fail 'Installed app signature failed verification'
xcrun stapler validate "$app" >/dev/null || fail 'Installed app notarization staple is invalid'
spctl --assess --type execute "$app" >/dev/null || fail 'Gatekeeper rejected installed app'
[[ "$("$host" status)" == *'configuration absent'* ]] ||
    fail 'OFTC configuration already exists; refusing to replace it'
[[ "$(service_state)" == 'Enabled' && "$(vpn_state)" == 'Connected' &&
   "$(on_demand_state)" == 'TRUE' ]] ||
    fail 'Tailscale is not initially Enabled, Connected, and OnDemandEnabled TRUE'

typeset -i tailscale_toggle_attempted=0
typeset -i oftc_config_attempted=0
baseline_interface=''
baseline_dns=''
tunnel_interface=''

cleanup() {
    local result="${1:-$?}"
    trap - EXIT INT TERM
    # Cleanup must run to completion even if a route/DNS read or VPN command
    # fails. Record each failure and restore Tailscale before exiting.
    set +e
    if (( oftc_config_attempted )); then
        local host_status
        host_status=$("$host" status 2>/dev/null || true)
        if [[ "$host_status" != *'configuration absent'* ]]; then
            "$host" stop >/dev/null || result=1
            wait_oftc_disconnected || { print -u2 'OFTC did not reach Disconnected'; result=1; }
            "$host" remove-config >/dev/null || { print -u2 'Could not remove OFTC test config'; result=1; }
        fi
        local restored_interface restored_dns
        restored_interface=$(route_interface) || {
            print -u2 'Could not read post-stop route'
            restored_interface=''
            result=1
        }
        restored_dns=$(dns_digest) || {
            print -u2 'Could not read post-stop DNS'
            restored_dns=''
            result=1
        }
        if [[ -n "$baseline_interface" && "$restored_interface" != "$baseline_interface" ]]; then
            print -u2 "Route cleanup mismatch: expected $baseline_interface, got $restored_interface"
            result=1
        fi
        if [[ -n "$baseline_dns" && "$restored_dns" != "$baseline_dns" ]]; then
            print -u2 'DNS did not return to the post-Tailscale-disable baseline'
            result=1
        fi
    fi
    if (( tailscale_toggle_attempted )); then
        if (( leave_tailscale_off )); then
            if ! tailscale_inactive; then
                print -u2 'Tailscale was not left Disabled and inactive as requested'
                result=1
            else
                print 'Tailscale remains Disabled and inactive as requested.'
            fi
        else
            networksetup -setnetworkserviceenabled "$tailscale_service" on || {
                print -u2 'Could not re-enable Tailscale network service'; result=1
            }
            # A start request is required to restore the original On Demand
            # state even when re-enabling appears to connect the service.
            scutil --nc start "$tailscale_service" >/dev/null ||
                print -u2 'Tailscale start returned nonzero; verifying final state'
            wait_tailscale || {
                print -u2 'Tailscale did not restore Enabled/Connected/OnDemandEnabled TRUE'
                result=1
            }
        fi
    fi
    if (( result == 0 )); then
        print 'Gate 4 smoke and selected cleanup passed.'
    fi
    exit "$result"
}
trap 'cleanup $?' EXIT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

# Mutation begins only after every installed-bundle and original-state guard.
tailscale_toggle_attempted=1
networksetup -setnetworkserviceenabled "$tailscale_service" off
for _ in {1..30}; do
    tailscale_inactive && break
    sleep 1
done
tailscale_inactive || fail 'Tailscale did not become inactive after disable'
if scutil --nc list | rg '^\* \((Connected|Connecting|Reasserting)\)' >/dev/null; then
    fail 'Another VPN is active after Tailscale disable'
fi
baseline_interface=$(route_interface)
[[ "$baseline_interface" == 'en0' ]] ||
    fail "This IPv4 Wi-Fi smoke requires $target to use en0 before OFTC (got $baseline_interface)"
baseline_dns=$(dns_digest)

oftc_config_attempted=1
"$host" install-config
print 'Running installed version 5 provider preflight without a SAML token.'
preflight_result=$("$host" preflight "$gateway" "$uid")
[[ "$preflight_result" == *'preflight_passed responder_auth_and_eap_challenge'* ]] ||
    fail 'No-token provider preflight lacked the authenticated EAP challenge stage'
wait_oftc_disconnected || fail 'No-token preflight did not return to Disconnected'
[[ "$(route_interface)" == "$baseline_interface" ]] ||
    fail 'No-token preflight changed the internal target route'
[[ "$(dns_digest)" == "$baseline_dns" ]] ||
    fail 'No-token preflight changed DNS'
print 'No-token provider preflight passed; route and DNS stayed at baseline.'
print "One SAML start to $gateway on UDP 4500; no automatic retry."
"$host" start-live "$gateway" "$saml_port" "${insecure_flag[@]}"
connected=0
for _ in {1..90}; do
    host_status=$("$host" status 2>/dev/null || true)
    if [[ "$host_status" == *'status: 3'* ]]; then connected=1; break; fi
    sleep 1
done
(( connected )) || fail 'OFTC did not reach Connected; no retry will be made'

tunnel_interface=$(route_interface)
[[ "$tunnel_interface" == utun* && "$tunnel_interface" != "$baseline_interface" ]] ||
    fail "Protected target did not route over the new OFTC utun: $tunnel_interface"
assigned_ip=$(ifconfig "$tunnel_interface" |
    awk '$1 == "inet" { print $2; exit }')
[[ -n "$assigned_ip" ]] || fail 'OFTC utun has no assigned IPv4 address'
print "Authenticated tunnel route: $target via $tunnel_interface; assigned IPv4 $assigned_ip"
connected_dns=$(dns_digest)
[[ "$connected_dns" == "$baseline_dns" ]] && print 'DNS unchanged (gateway supplied no DNS in prior direct probes).' ||
    print 'DNS changed while connected; inspect gateway-assigned settings before claiming DNS behavior.'

print "Sending exactly one ICMP echo to $target through $tunnel_interface."
ping -c 1 -W 5000 "$target"
[[ "$(route_interface)" == "$tunnel_interface" ]] ||
    fail 'Target route changed during the single echo'
print 'One ICMP reply received through the OFTC tunnel; cleanup will now run.'
