#!/bin/zsh
# Read-only five-minute sampler around the v11 55-minute IKE hard deadline.
set -euo pipefail

state='/private/tmp/oftc-issue13-v11-recovery-state'
app='/Applications/OFTC development probe.app'
target='10.20.0.1'

[[ $# == 1 ]] || { print -u2 'Usage: gate8-lifetime-watch.sh --plan|--watch'; exit 2; }
case "$1" in
--plan)
    print 'Read-only status/route sampling every five seconds for five minutes.'
    print 'Records changes and 30-second heartbeats; sends no protected traffic.'
    exit 0 ;;
--watch) ;;
*) print -u2 'Usage: gate8-lifetime-watch.sh --plan|--watch'; exit 2 ;;
esac
[[ -f "$state/started" ]] || { print -u2 'No active Gate 8 session'; exit 1; }

previous=''
for i in {1..61}; do
    vpn_state=$("$app/Contents/MacOS/IntegrationHost" status 2>/dev/null || print unavailable)
    route_interface=$(route -n get -inet "$target" 2>/dev/null |
        awk '$1 == "interface:" {print $2; exit}')
    sample="vpn=${vpn_state// /_} route=${route_interface:-absent}"
    if [[ "$sample" != "$previous" ]] || (( i % 6 == 1 )); then
        print -r -- "$(date -u '+%Y-%m-%dT%H:%M:%SZ') stage=lifetime_watch $sample" >> "$state/evidence.txt"
        previous="$sample"
    fi
    (( i == 61 )) || /bin/sleep 5
done
print 'Five-minute read-only lifetime watch complete.'
