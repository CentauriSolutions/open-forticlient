#!/bin/bash
# Sample mach port counts and memory for OFTCAgent and the OFTCTunnel provider
# on an interval, to see whether either grows while the VPN stays connected.
# lsmp needs root, so run this with sudo:
#
#   sudo scripts/sample-agent-ports.sh [interval-seconds] [logfile]
#
# Defaults: every 120 s, appended to ~/oftc-ports.log. Stop with Ctrl-C.
# caffeinate keeps the Mac from idle-sleeping while it runs (closing the lid
# still sleeps it, and a sleeping Mac drops the tunnel).
set -u

interval="${1:-120}"
log="${2:-$HOME/oftc-ports.log}"

if [[ "${CAFFEINATED:-}" != 1 ]]; then
    CAFFEINATED=1 exec caffeinate -ims "$0" "$@"
fi

ports() { lsmp -p "$1" 2>/dev/null | awk 'NR>2' | wc -l | tr -d ' '; }
rss()   { ps -o rss= -p "$1" 2>/dev/null | tr -d ' '; }

echo "# sampling every ${interval}s into $log" | tee -a "$log"
while true; do
    line="$(date '+%Y-%m-%d %H:%M:%S')"
    for name in OFTCAgent OFTCTunnel; do
        pid="$(pgrep -x "$name" | head -1)"
        if [[ -n "$pid" ]]; then
            line+=" $name pid=$pid ports=$(ports "$pid") rss_kb=$(rss "$pid")"
        else
            line+=" $name none"
        fi
    done
    # Connected means the route to the tunnel's own address uses a utun.
    line+=" route=$(route -n get 10.20.0.1 2>/dev/null | awk '/interface:/{print $2}')"
    echo "$line" | tee -a "$log"
    sleep "$interval"
done
