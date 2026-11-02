#!/bin/bash
# Like sample-agent-ports.sh, but samples every OFTCAgent process separately
# (the menu bar app and the supervise-profile agent are different processes)
# plus the OFTCTunnel provider. lsmp needs root:
#
#   sudo scripts/sample-oftc-ports.sh [interval-seconds] [logfile]
#
# Defaults: every 60 s, appended to ~/oftc-ports2.log. Stop with Ctrl-C.
# The route check uses 10.20.0.1; set OFTC_TARGET to change it.
set -u

interval="${1:-60}"
log="${2:-$HOME/oftc-ports2.log}"
target="${OFTC_TARGET:-10.20.0.1}"

if [[ "${CAFFEINATED:-}" != 1 ]]; then
    CAFFEINATED=1 exec caffeinate -ims "$0" "$@"
fi

ports() { lsmp -p "$1" 2>/dev/null | awk 'NR>2' | wc -l | tr -d ' '; }
rss()   { ps -o rss= -p "$1" 2>/dev/null | tr -d ' '; }

echo "# sampling every ${interval}s into $log" | tee -a "$log"
while true; do
    line="$(date '+%Y-%m-%d %H:%M:%S')"
    for pid in $(pgrep -x OFTCAgent) $(pgrep -x OFTCTunnel); do
        cmd="$(ps -o command= -p "$pid" 2>/dev/null)"
        case "$cmd" in
            *supervise-profile*) role=supervisor ;;
            *OFTCTunnel*)        role=provider ;;
            *)                   role=menu ;;
        esac
        line+=" $role[$pid]=ports:$(ports "$pid"),rss_kb:$(rss "$pid")"
    done
    line+=" route=$(route -n get "$target" 2>/dev/null | awk '/interface:/{print $2}')"
    echo "$line" | tee -a "$log"
    sleep "$interval"
done
