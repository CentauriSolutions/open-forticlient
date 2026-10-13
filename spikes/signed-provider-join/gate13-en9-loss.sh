#!/bin/zsh
# Approved 75-second loss of the active en9 service during a v15 run.
# Independent watchdog and EXIT trap restore the service.
set -euo pipefail
setopt NO_BG_NICE

state='/private/tmp/oftc-issue13-v15-current-state'
app='/Applications/OFTC development probe.app'
service='USB 10/100/1G/2.5G LAN'
target='10.20.0.1'
watchdog_pid=0
restore_needed=0

fail() { print -u2 -- "$*"; exit 1; }
service_state() { /usr/sbin/networksetup -getnetworkserviceenabled "$service"; }
route_interface() {
    route -n get -inet "$target" 2>/dev/null |
        awk '$1 == "interface:" {print $2; exit}'
}
tailscale_inactive() {
    [[ "$(/usr/sbin/networksetup -getnetworkserviceenabled Tailscale 2>/dev/null)" == Disabled &&
       "$(scutil --nc status Tailscale 2>/dev/null | head -1 | tr -d '\r')" == Disconnected ]]
}
mark() {
    local vpn_state
    vpn_state=$("$app/Contents/MacOS/IntegrationHost" status 2>/dev/null || true)
    print -r -- "$(date -u '+%Y-%m-%dT%H:%M:%SZ') stage=en9_loss $* service=$(service_state) route=$(route_interface) vpn=${vpn_state// /_}" >> "$state/evidence.txt"
}
restore() {
    local result=0
    if (( restore_needed )); then
        /usr/sbin/networksetup -setnetworkserviceenabled "$service" on || result=1
        [[ "$(service_state)" == Enabled ]] || result=1
    fi
    if (( result == 0 && watchdog_pid > 0 )); then
        kill "$watchdog_pid" 2>/dev/null || true
    fi
    return "$result"
}

[[ $# == 1 ]] || fail 'Usage: gate13-en9-loss.sh --plan|--execute'
case "$1" in
--plan)
    print 'During an active v15 renewal run, disables the en9 USB Ethernet service for 75 seconds.'
    print 'Records nonsecret status at 0, 45, and 75 seconds. An independent 95-second watchdog restores it.'
    print 'Wi-Fi and Tailscale settings and Fortinet services are untouched.'
    exit 0 ;;
--execute) ;;
*) fail 'Usage: gate13-en9-loss.sh --plan|--execute' ;;
esac

[[ -f "$state/active" && "$(cat "$state/active")" == renewal ]] || fail 'V14 renewal run is not active'
[[ "$(service_state)" == Enabled && "$(ifconfig en9 | awk '/status:/{print $2; exit}')" == active ]] ||
    fail 'USB Ethernet en9 is not active and enabled'
[[ "$(route_interface)" == utun* ]] || fail 'Approved target is not routed over OFTC'
[[ "$("$app/Contents/MacOS/IntegrationHost" status)" == *'status: 3'* ]] ||
    fail 'OFTC is not connected'
[[ "$(/usr/sbin/networksetup -getairportpower en0)" == *'On' ]] || fail 'Wi-Fi fallback is off'
tailscale_inactive || fail 'Tailscale is not Disabled/Disconnected'

umask 077
nohup /bin/zsh -c '/bin/sleep 95; /usr/sbin/networksetup -setnetworkserviceenabled "USB 10/100/1G/2.5G LAN" on' \
    >/dev/null 2>&1 </dev/null &
watchdog_pid=$!
kill -0 "$watchdog_pid" || fail 'USB Ethernet restore watchdog did not start'
restore_needed=1
trap 'restore' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
/usr/sbin/networksetup -setnetworkserviceenabled "$service" off
[[ "$(service_state)" == Disabled ]] || fail 'USB Ethernet did not turn off'
mark 'elapsed=0'
/bin/sleep 45
mark 'elapsed=45'
/bin/sleep 30
/usr/sbin/networksetup -setnetworkserviceenabled "$service" on
[[ "$(service_state)" == Enabled ]] || fail 'USB Ethernet did not turn back on'
restore_needed=0
kill "$watchdog_pid" 2>/dev/null || true
watchdog_pid=0
mark 'elapsed=75 restored=yes'
trap - EXIT INT TERM
print 'USB Ethernet service restored. Observe OFTC recovery without restarting its agent.'
