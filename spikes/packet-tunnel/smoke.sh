#!/bin/zsh
set -euo pipefail

root="${0:A:h}"
source_app="$root/build/Gate0Host.app"
installed_app="/Applications/OFTC Gate0 Probe.app"
host="$installed_app/Contents/MacOS/Gate0Host"
probe_ip="198.51.100.254"
expected_bundle_id="${BUNDLE_ID:-com.chris.openforticlient.gate0}"

usage() {
    print -u2 'Usage: smoke.sh install|test|cleanup'
    exit 2
}

check_installed() {
    [[ -x "$host" ]] || { print -u2 "Probe is not installed at $installed_app"; exit 1; }
    [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$installed_app/Contents/Info.plist")" == "$expected_bundle_id" ]] || {
        print -u2 "Refusing to operate an app with a different bundle ID at $installed_app"; exit 1;
    }
}

wait_status() {
    local expected="$1"
    local vpn_state
    for _ in {1..30}; do
        vpn_state=$("$host" status)
        # NEVPNStatus: 0 invalid, 1 disconnected, 2 connecting, 3 connected,
        # 4 reasserting, 5 disconnecting. Compare the numeric API value.
        [[ "$vpn_state" == *"status: $expected" ]] && return 0
        sleep 1
    done
    print -u2 "Timed out waiting for VPN status $expected; last result: $vpn_state"
    return 1
}

case "${1:-}" in
install)
    [[ -d "$source_app" ]] || { print -u2 'Build and Developer ID sign the probe first'; exit 1; }
    [[ ! -e "$installed_app" ]] || { print -u2 "Refusing to replace $installed_app"; exit 1; }
    [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$source_app/Contents/Info.plist")" == "$expected_bundle_id" ]] || {
        print -u2 'BUNDLE_ID does not match the built app'; exit 1;
    }
    codesign --verify --deep --strict "$source_app"
    signature_details=$(codesign -dv --verbose=4 "$source_app" 2>&1)
    [[ "$signature_details" == *'Authority=Developer ID Application:'* ]] || {
        print -u2 'The host app is not Developer ID signed'; exit 1;
    }
    [[ -f "$source_app/Contents/embedded.provisionprofile" ]] || {
        print -u2 'Host app provisioning profile is missing'; exit 1;
    }
    if [[ -w /Applications ]]; then
        ditto "$source_app" "$installed_app"
    else
        sudo ditto "$source_app" "$installed_app"
    fi
    print "Installed $installed_app"
    print 'Submitting system-extension activation; macOS may require approval in System Settings.'
    "$host" activate
    ;;
test)
    check_installed
    if scutil --nc list | rg '^\* \((Connected|Connecting|Reasserting)\).*VPN' >/dev/null; then
        print -u2 'Another VPN is active; disconnect it before the packet-flow test'
        exit 1
    fi
    if scutil --dns | rg 'gate0\.invalid' >/dev/null; then
        print -u2 'gate0.invalid DNS is already present; refusing to overwrite an existing test state'
        exit 1
    fi
    baseline_route=$(route -n get -inet "$probe_ip")
    print -r -- "$baseline_route" | rg '^[[:space:]]*destination: default$' >/dev/null || {
        print -u2 'The TEST-NET host already has a non-default route; refusing to override it'
        exit 1
    }
    baseline_interface=$(print -r -- "$baseline_route" | awk '$1 == "interface:" { print $2 }')
    probe_interface=''
    # Always request stop and remove only our own VPN configuration on exit.
    cleanup_test() {
        local result=$?
        trap - EXIT
        "$host" stop || result=1
        wait_status 1 || result=1
        "$host" remove-config || result=1
        print 'Post-stop route (must not point to the probe utun):'
        post_route=$(route -n get -inet "$probe_ip" || true)
        print -r -- "$post_route"
        post_interface=$(print -r -- "$post_route" | awk '$1 == "interface:" { print $2 }')
        if [[ -n "$probe_interface" && "$post_interface" == "$probe_interface" ]]; then
            print -u2 'Probe route still uses its utun after stop'
            result=1
        elif [[ "$post_interface" != "$baseline_interface" ]]; then
            print -u2 'Post-stop route differs from baseline; inspect before claiming cleanup'
            result=1
        fi
        print 'Post-stop scoped DNS (must have no gate0.invalid resolver):'
        if scutil --dns | rg -C 3 'gate0\.invalid'; then
            print -u2 'Probe DNS resolver remains after stop'
            result=1
        fi
        exit "$result"
    }
    trap cleanup_test EXIT
    "$host" install-config
    "$host" start
    wait_status 3
    print 'Connected route (must use the probe utun and a /32 host route):'
    connected_route=$(route -n get -inet "$probe_ip")
    print -r -- "$connected_route"
    probe_interface=$(print -r -- "$connected_route" | awk '$1 == "interface:" { print $2 }')
    [[ "$probe_interface" == utun* ]] || { print -u2 'Probe route is not on a utun'; exit 1; }
    print -r -- "$connected_route" | rg 'mask: 255\.255\.255\.255' >/dev/null || {
        print -u2 'Probe route is not a /32 host route'; exit 1;
    }
    print 'Probe interface and MTU (must show mtu 1280):'
    ifconfig "$probe_interface" | rg 'mtu 1280'
    print 'Scoped DNS (must show gate0.invalid and 192.0.2.53):'
    scutil --dns | rg -C 3 'gate0\.invalid'
    scutil --dns | rg '192\.0\.2\.53' >/dev/null || { print -u2 'Probe DNS server is missing'; exit 1; }
    print 'One ICMP echo to the TEST-NET-2 host; a reply proves packetFlow read and write:'
    ping -c 1 -W 1000 "$probe_ip"
    print 'Packet-flow round trip succeeded. Provider logs should also report reply write accepted=1.'
    ;;
cleanup)
    check_installed
    vpn_state=$("$host" status)
    if [[ "$vpn_state" != *'configuration absent'* ]]; then
        "$host" stop || true
        wait_status 1 || true
        "$host" remove-config || true
    fi
    "$host" deactivate
    if [[ -w "$installed_app" ]]; then
        rm -rf "$installed_app"
    else
        sudo rm -rf "$installed_app"
    fi
    print 'Removed only the Gate 0 probe app. Verify systemextensionsctl list and route/DNS state.'
    ;;
*) usage ;;
esac
