#!/bin/zsh
# One explicitly approved, token-bearing Gate 6 provider rekey probe. The
# installed version 7 bundle and transport mode are checked before mutation.
# Tailscale is read-only here: it must already be Disabled and Disconnected.
set -euo pipefail

app='/Applications/OFTC development probe.app'
host="$app/Contents/MacOS/IntegrationHost"
bundle_id='com.chris.openforticlient.gate0'
provider_id="${bundle_id}.provider"
gateway='vpn.example.com'
target='10.20.0.1'
tailscale_service='Tailscale'
expected_version='7'
expected_host_sha256='835ed4118a58bc16829a5905332bd17157ab8448269b249d9fe3b060ca772960'
expected_provider_sha256='4fd7d73308ce8a0e40c6508b8d56058f333b984637469a590dfdecb7b590fa0f'
expected_engine_sha256='340df9724d86494181d41ced77b00b7af88abae403cb371228a111498fcd19f2'

usage() {
    print -u2 'Usage: gate6-rekey-smoke.sh --plan [--tcp] [--ipv6-outer <CLAT-IPv4>] | --execute <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]'
    exit 2
}

[[ $# -ge 1 ]] || usage
mode="$1"
shift
[[ "$mode" == '--plan' || "$mode" == '--execute' ]] || usage
saml_port=''
if [[ "$mode" == '--execute' ]]; then
    [[ $# -ge 1 ]] || usage
    saml_port="$1"
    shift
    [[ "$saml_port" =~ '^[0-9]{1,5}$' ]] &&
        (( saml_port >= 1 && saml_port <= 65535 )) || usage
fi

typeset -i tcp=0 ipv6_outer=0 insecure_saml=0
clat_v4=''
while (( $# )); do
    case "$1" in
    --tcp)
        (( tcp == 0 )) || usage
        tcp=1
        shift
        ;;
    --ipv6-outer)
        (( ipv6_outer == 0 && $# >= 2 )) || usage
        ipv6_outer=1
        clat_v4="$2"
        shift 2
        ;;
    --insecure-saml)
        [[ "$mode" == '--execute' ]] && (( insecure_saml == 0 )) || usage
        insecure_saml=1
        shift
        ;;
    *) usage ;;
    esac
done

valid_ipv4() {
    local value="$1" octet
    local -a parts
    parts=("${(@s:.:)value}")
    (( ${#parts[@]} == 4 )) || return 1
    for octet in "${parts[@]}"; do
        [[ "$octet" =~ '^[0-9]{1,3}$' ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}
(( ! ipv6_outer )) || valid_ipv4 "$clat_v4" || usage

transport='UDP 4500 with IPv4 outer'
(( ipv6_outer )) && transport='UDP 4500 with native IPv6 outer'
(( tcp )) && transport='TCP 4443 with IPv4 outer'
(( tcp && ipv6_outer )) && transport='TCP 4443 with native IPv6 outer'
if [[ "$mode" == '--plan' ]]; then
    cat <<EOF
Gate 6 signed-provider rekey plan; nothing has been changed.
Mode: ${transport}. Gateway: ${gateway}. One ICMP echo target: ${target}.
Required before --execute: explicit approval for ONE fresh SAML token, ONE
local CHILD_SA rekey, and ONE encrypted ICMP echo after rekey. Use the profile's exact
IKESamlPort; it is not inferred from the IKE transport port.
The exact version ${expected_version} Developer ID signed and notarized host/provider
must be installed, with its extension activated and enabled. OFTC must have
no saved VPN configuration. Tailscale must already be Disabled/Disconnected
and is never changed by this script. No other VPN may be active.
Capture the target route and DNS baseline, install OFTC config, acquire SAML
once, connect, verify the target routes over the OFTC utun, request one
bounded authenticated CHILD_SA rekey without another token, send ping -c 1
once, then stop/remove OFTC and compare route/DNS with the baseline.
The installed-host no-token preflight is a separate diagnostic and is not
needed for this already proven IPv4 UDP transport.
On any failure, cleanup still runs. There is no SAML, rekey, or echo retry.
EOF
    exit 0
fi

fail() { print -u2 -- "$*"; exit 1; }
service_state() { networksetup -getnetworkserviceenabled "$tailscale_service" 2>/dev/null; }
vpn_state() { scutil --nc status "$tailscale_service" 2>/dev/null | head -1 | tr -d '\r'; }
tailscale_inactive() {
    [[ "$(service_state)" == 'Disabled' && "$(vpn_state)" == 'Disconnected' ]]
}
route_snapshot() {
    route -n get -inet "$target" 2>/dev/null |
        awk '$1 == "gateway:" || $1 == "interface:" || $1 == "ifscope:" || $1 == "mtu:" { print $1, $2 }'
}
route_interface() {
    route_snapshot | awk '$1 == "interface:" { print $2; exit }'
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

[[ -x "$host" ]] || fail "Installed OFTC host is missing: $host"
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist")" == "$bundle_id" ]] ||
    fail 'Installed host bundle ID mismatch'
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist")" == "$expected_version" ]] ||
    fail 'This smoke test requires the reviewed version 6 host'
extension="$app/Contents/Library/SystemExtensions/${provider_id}.systemextension"
[[ -d "$extension" ]] || fail 'Expected provider system extension is missing'
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$extension/Contents/Info.plist")" == "$provider_id" ]] ||
    fail 'Installed provider bundle ID mismatch'
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$extension/Contents/Info.plist")" == "$expected_version" ]] ||
    fail 'Installed provider version mismatch'
[[ "$(shasum -a 256 "$host" | awk '{print $1}')" == "$expected_host_sha256" ]] ||
    fail 'Installed host differs from the pinned v7 candidate'
[[ "$(shasum -a 256 "$extension/Contents/MacOS/IntegrationProvider" | awk '{print $1}')" == "$expected_provider_sha256" ]] ||
    fail 'Installed provider differs from the pinned v7 candidate'
[[ "$(shasum -a 256 "$extension/Contents/Frameworks/liboftc_provider_ffi.dylib" | awk '{print $1}')" == "$expected_engine_sha256" ]] ||
    fail 'Installed engine differs from the pinned v7 candidate'
systemextensionsctl list | rg -F "$provider_id" | rg '\([^)]*/7\).*\[activated enabled\]' >/dev/null ||
    fail 'Version 7 provider is not activated and enabled'
codesign --verify --deep --strict "$app" >/dev/null || fail 'Installed app signature failed verification'
xcrun stapler validate "$app" >/dev/null || fail 'Installed app notarization staple is invalid'
spctl --assess --type execute "$app" >/dev/null || fail 'Gatekeeper rejected installed app'
[[ "$("$host" status)" == *'configuration absent'* ]] ||
    fail 'OFTC configuration already exists; refusing to replace it'
tailscale_inactive || fail 'Tailscale must already be Disabled and Disconnected'
if scutil --nc list | rg '\((Connected|Connecting|Reasserting)\)' >/dev/null; then
    fail 'Another VPN is active'
fi
if (( ipv6_outer )); then
    ifconfig en0 | awk -v expected="$clat_v4" '$1 == "inet" && $2 == expected { found=1 } END { exit !found }' ||
        fail 'Requested CLAT IDi is not currently assigned to en0'
    ifconfig en0 | awk '$1 == "inet6" && $2 !~ /^fe80:/ { found=1 } END { exit !found }' ||
        fail 'en0 has no native non-link-local IPv6 address'
fi

baseline_route=$(route_snapshot)
baseline_interface=$(print -r -- "$baseline_route" | awk '$1 == "interface:" { print $2; exit }')
[[ -n "$baseline_interface" && "$baseline_interface" != utun* ]] ||
    fail 'Target route has no safe non-VPN baseline'
baseline_dns=$(dns_digest)
[[ -n "$baseline_dns" ]] || fail 'Could not capture DNS baseline'

typeset -i oftc_config_attempted=0
cleanup() {
    local result="${1:-$?}" host_status restored_route restored_dns
    trap - EXIT INT TERM
    set +e
    if (( oftc_config_attempted )); then
        host_status=$("$host" status 2>/dev/null || true)
        if [[ "$host_status" != *'configuration absent'* ]]; then
            "$host" stop >/dev/null || { print -u2 'Could not stop OFTC'; result=1; }
            wait_oftc_disconnected || { print -u2 'OFTC did not reach Disconnected'; result=1; }
            "$host" remove-config >/dev/null || { print -u2 'Could not remove OFTC test config'; result=1; }
        fi
        [[ "$("$host" status 2>/dev/null || true)" == *'configuration absent'* ]] || {
            print -u2 'OFTC configuration remains after cleanup'; result=1
        }
        restored_route=$(route_snapshot) || {
            print -u2 'Could not read post-stop target route'; restored_route=''; result=1
        }
        restored_dns=$(dns_digest) || {
            print -u2 'Could not read post-stop DNS'; restored_dns=''; result=1
        }
        [[ "$restored_route" == "$baseline_route" ]] || {
            print -u2 'Target route did not return to baseline'; result=1
        }
        [[ "$restored_dns" == "$baseline_dns" ]] || {
            print -u2 'DNS did not return to baseline'; result=1
        }
    fi
    if ! tailscale_inactive; then
        print -u2 'Tailscale is no longer Disabled and Disconnected'; result=1
    fi
    if (( result == 0 )); then
        print 'Gate 6 rekey, packet flow, and cleanup passed; Tailscale remains Disabled/Disconnected.'
    fi
    exit "$result"
}
trap 'cleanup $?' EXIT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

oftc_config_attempted=1
"$host" install-config
live_args=()
(( tcp )) && live_args+=(--tcp)
(( ipv6_outer )) && live_args+=(--ipv6-outer "$clat_v4")
(( insecure_saml )) && live_args+=(--insecure-saml)
print "One SAML start to $gateway using $transport; no automatic retry."
"$host" start-live "$gateway" "$saml_port" "${live_args[@]}"
typeset -i connected=0
for _ in {1..90}; do
    host_status=$("$host" status 2>/dev/null || true)
    if [[ "$host_status" == *'status: 3'* ]]; then connected=1; break; fi
    sleep 1
done
(( connected )) || fail 'OFTC did not reach Connected; no retry will be made'

tunnel_interface=$(route_interface)
[[ "$tunnel_interface" == utun* && "$tunnel_interface" != "$baseline_interface" ]] ||
    fail 'Protected target did not route over a new OFTC utun'
assigned_ip=$(ifconfig "$tunnel_interface" | awk '$1 == "inet" { print $2; exit }')
[[ -n "$assigned_ip" ]] || fail 'OFTC utun has no assigned IPv4 address'
print "Authenticated tunnel route: $target via $tunnel_interface; assigned IPv4 $assigned_ip"
print 'Requesting exactly one bounded local CHILD_SA rekey; no new SAML token.'
"$host" rekey-once
[[ "$(route_interface)" == "$tunnel_interface" ]] ||
    fail 'Target route changed during rekey'
print "Sending exactly one post-rekey ICMP echo to $target through $tunnel_interface."
ping -c 1 -W 5000 "$target"
[[ "$(route_interface)" == "$tunnel_interface" ]] ||
    fail 'Target route changed during the single echo'
print 'One post-rekey ICMP reply received through OFTC; cleanup will now run.'
