#!/bin/bash
# Capture one OFTC tunnel session: outer IKE/ESP packets, inner tunnel packets,
# app logs, and a once-a-second timeline of curl results to a gateway address.
#
#   scripts/capture-tunnel.sh <inside-ip> [seconds] [curl-interval]
#
# <inside-ip>  an address reachable only through the tunnel (e.g. the FortiGate
#              web UI); the script curls it and uses it to find the utun.
# [seconds]    how long to run the test after the tunnel is up (default 90).
# [curl-interval]  seconds between curls (default 1). Use a large value such as
#              20 to leave the tunnel mostly idle, which is when keepalives
#              (ours or the official client's) show up on the wire.
#
# Works with the official FortiClient too: disconnect OFTC first, connect
# FortiClient when prompted. The log file then holds iked/FortiClient lines.
#
# Output goes to ~/oftc-capture-<time>/. Nothing here is committed; pcaps stay
# local (see AGENTS.md on captures).
set -u

target="${1:-}"
duration="${2:-90}"
interval="${3:-1}"
[[ -n "$target" ]] || { echo "usage: $0 <inside-ip> [seconds]" >&2; exit 2; }

out="$HOME/oftc-capture-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$out"
timeline="$out/timeline.txt"
stamp() { date '+%H:%M:%S'; }
note()  { echo "$(stamp) $*" | tee -a "$timeline"; }

wan_if="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
[[ -n "$wan_if" ]] || { echo "no default interface" >&2; exit 1; }

sudo -v || exit 1
# Keep sudo warm for the duration.
( while true; do sudo -n true; sleep 30; kill -0 "$$" 2>/dev/null || exit; done ) 2>/dev/null &
keepsudo=$!

cleanup() {
    note "stopping captures"
    sudo pkill -INT -f "tcpdump.*$out" 2>/dev/null
    kill "$logpid" "$keepsudo" 2>/dev/null
    sleep 1
    sudo chown "$USER" "$out"/* 2>/dev/null
    echo
    echo "Done. Files in $out:"
    ls -l "$out"
}
trap cleanup EXIT INT TERM

note "outer capture on $wan_if"
sudo tcpdump -ni "$wan_if" -s 0 -w "$out/outer.pcap" \
    'udp port 4500 or udp port 500 or tcp port 4443' 2>"$out/outer.err" &

/usr/bin/log stream --style compact \
    --predicate 'process CONTAINS[c] "oftc" OR process CONTAINS[c] "forti" OR process == "iked" OR process == "nesessionmanager"' \
    >"$out/log.txt" 2>&1 &
logpid=$!

echo
echo "Start the VPN now. Waiting up to 120s for a tunnel route to $target..."
utun=""
for _ in $(seq 1 240); do
    iface="$(route -n get "$target" 2>/dev/null | awk '/interface:/{print $2}')"
    if [[ "$iface" == utun* ]]; then utun="$iface"; break; fi
    sleep 0.5
done
[[ -n "$utun" ]] || { note "no utun route to $target appeared"; exit 1; }

note "tunnel up on $utun; starting inner capture"
sudo tcpdump -ni "$utun" -s 0 -w "$out/inner.pcap" 2>"$out/inner.err" &

end=$((SECONDS + duration))
while (( SECONDS < end )); do
    iface="$(route -n get "$target" 2>/dev/null | awk '/interface:/{print $2}')"
    result="$(curl -sk --max-time 3 -o /dev/null \
        -w 'http=%{http_code} connect=%{time_connect}s total=%{time_total}s' \
        "https://$target/" 2>&1)"
    note "route=${iface:-none} curl: ${result:-failed}"
    sleep "$interval"
done
