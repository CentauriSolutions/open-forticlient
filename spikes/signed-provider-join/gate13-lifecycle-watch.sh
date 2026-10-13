#!/bin/zsh
# Read-only status watch with protected ICMP to the one approved target.
set -euo pipefail

root="${0:A:h}"
state='/private/tmp/oftc-issue13-v15-current-state'
app='/Applications/OFTC development probe.app'
target='10.20.0.1'

[[ $# == 1 && "$1" == --watch ]] || {
    print -u2 'Usage: gate13-lifecycle-watch.sh --watch'; exit 2
}
[[ -f "$state/active" && "$(cat "$state/active")" == lifecycle &&
   -s "$state/lifecycle/connected-at" ]] || {
    print -u2 'No active v15 lifecycle run'; exit 1
}

connected_at=$(cat "$state/lifecycle/connected-at")
deadline=$((connected_at + 55 * 60))
last_report=0
previous=''
had_failure=0
print "Lifecycle watch started; protected-traffic deadline is $(date -u -r "$deadline" '+%Y-%m-%dT%H:%M:%SZ')."
while true; do
    now=$(date +%s)
    vpn_state=$("$app/Contents/MacOS/IntegrationHost" status 2>/dev/null || print unavailable)
    route_interface=$(route -n get -inet "$target" 2>/dev/null |
        awk '$1 == "interface:" {print $2; exit}')
    sample="vpn=${vpn_state// /_} route=${route_interface:-absent}"
    if [[ "$sample" != "$previous" ]] || (( now - last_report >= 300 )); then
        print -r -- "$(date -u '+%Y-%m-%dT%H:%M:%SZ') stage=lifecycle_watch $sample" >> "$state/evidence.txt"
        print -r -- "$sample"
        previous="$sample"
        last_report=$now
        if ! zsh "$root/gate13-v15-current.sh" --observe; then had_failure=1; fi
    fi
    [[ "$vpn_state" == *'status: 3'* && "$route_interface" == utun* ]] || had_failure=1
    (( now >= deadline )) && break
    /bin/sleep 30
done
(( had_failure == 0 )) || { print -u2 'Lifecycle watch saw a status, route, or protected-traffic failure.'; exit 1; }
print 'Lifecycle watch passed its 55-minute protected-traffic observation.'
