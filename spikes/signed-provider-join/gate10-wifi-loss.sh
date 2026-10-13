#!/bin/zsh
# Exact, approved 75-second Wi-Fi loss for the active v13 loss run.
# A detached watchdog and an EXIT trap both restore Wi-Fi power.
set -euo pipefail
setopt NO_BG_NICE

root="${0:A:h}"
state='/private/tmp/oftc-issue13-v13-diagnostic-state'
app='/Applications/OFTC development probe.app'
target='10.20.0.1'
watchdog_pid=0
restore_needed=0

fail() { print -u2 -- "$*"; exit 1; }
wifi_power() { /usr/sbin/networksetup -getairportpower en0; }
tailscale_inactive() {
    [[ "$(/usr/sbin/networksetup -getnetworkserviceenabled Tailscale 2>/dev/null)" == Disabled &&
       "$(scutil --nc status Tailscale 2>/dev/null | head -1 | tr -d '\r')" == Disconnected ]]
}
mark() {
    local vpn_state
    vpn_state=$("$app/Contents/MacOS/IntegrationHost" status 2>/dev/null || true)
    print -r -- "$(date -u '+%Y-%m-%dT%H:%M:%SZ') stage=wifi_loss $* wifi=$(wifi_power | awk '{print $NF}') vpn=${vpn_state// /_}" >> "$state/evidence.txt"
}
restore() {
    local result=0
    if (( restore_needed )); then
        /usr/sbin/networksetup -setairportpower en0 on || result=1
        [[ "$(wifi_power)" == *'On' ]] || result=1
    fi
    if (( result == 0 && watchdog_pid > 0 )); then
        kill "$watchdog_pid" 2>/dev/null || true
    fi
    return "$result"
}

[[ $# == 1 ]] || fail 'Usage: gate10-wifi-loss.sh --plan|--execute'
case "$1" in
--plan)
    print 'For the separately approved v13 diagnostic loss run, --execute turns Wi-Fi en0 off for 75 seconds,'
    print 'records nonsecret VPN status at 0 and 45 seconds, then turns it on.'
    print 'An EXIT trap and a detached 95-second watchdog both restore Wi-Fi power.'
    print 'It changes no Tailscale setting, VPN configuration, or Fortinet process.'
    exit 0 ;;
--execute) ;;
*) fail 'Usage: gate10-wifi-loss.sh --plan|--execute' ;;
esac

[[ -f "$state/active" && "$(cat "$state/active")" == loss ]] ||
    fail 'V13 loss run has not started'
[[ "$(wifi_power)" == *'On' ]] || fail 'Wi-Fi en0 is not already on'
[[ "$(route -n get -inet "$target" | awk '$1 == "interface:" {print $2; exit}')" == utun* ]] ||
    fail 'Approved target is not routed over OFTC'
[[ "$("$app/Contents/MacOS/IntegrationHost" status)" == *'status: 3'* ]] ||
    fail 'OFTC is not connected'
tailscale_inactive || fail 'Tailscale is not Disabled/Disconnected'

umask 077
# If the controlling process disappears during network loss, this independent
# local process still restores Wi-Fi. Do not log its environment or shell trace.
nohup /bin/zsh -c '/bin/sleep 95; /usr/sbin/networksetup -setairportpower en0 on' \
    >/dev/null 2>&1 </dev/null &
watchdog_pid=$!
kill -0 "$watchdog_pid" || fail 'Wi-Fi restore watchdog did not start'
restore_needed=1
trap 'restore' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
/usr/sbin/networksetup -setairportpower en0 off
[[ "$(wifi_power)" == *'Off' ]] || fail 'Wi-Fi did not turn off'
mark 'elapsed=0'
/bin/sleep 45
mark 'elapsed=45'
/bin/sleep 30
/usr/sbin/networksetup -setairportpower en0 on
[[ "$(wifi_power)" == *'On' ]] || fail 'Wi-Fi did not turn back on'
restore_needed=0
kill "$watchdog_pid" 2>/dev/null || true
watchdog_pid=0
mark 'elapsed=75 restored=yes'
trap - EXIT INT TERM
print 'Wi-Fi power restored. Observe OFTC recovery without a manual agent restart.'
