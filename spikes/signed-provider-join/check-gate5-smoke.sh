#!/bin/zsh
# Offline validation only. Extract the EXIT cleanup with mocked VPN commands.
set -euo pipefail

root="${0:A:h}"
script="$root/gate5-smoke.sh"
zsh -n "$script"
zsh "$script" --plan --tcp >/dev/null
zsh "$script" --plan --ipv6-outer 192.0.0.2 >/dev/null
zsh "$script" --plan --tcp --ipv6-outer 192.0.0.2 >/dev/null
for args in '--plan' '--plan --tcp --tcp' '--plan --ipv6-outer 999.0.0.2'; do
    local -a words
    words=(${=args})
    if zsh "$script" "${words[@]}" >/dev/null 2>&1; then
        print -u2 "Unexpectedly accepted invalid arguments: $args"
        exit 1
    fi
done
if rg 'networksetup -setnetworkserviceenabled|scutil --nc start' "$script" >/dev/null; then
    print -u2 'Gate 5 script contains a Tailscale mutation command'
    exit 1
fi

temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
cat > "$temp/host" <<'EOF'
#!/bin/sh
case "$1" in
status)
    if [ -f "$OFTC_REMOVED_MARKER" ]; then
        printf '%s\n' 'OFTC configuration absent'
    else
        printf '%s\n' 'OFTC VPN status: 3'
    fi
    ;;
stop) printf '%s\n' stop >> "$OFTC_CALLS_MARKER" ;;
remove-config)
    printf '%s\n' remove-config >> "$OFTC_CALLS_MARKER"
    : > "$OFTC_REMOVED_MARKER"
    ;;
*) exit 2 ;;
esac
EOF
chmod +x "$temp/host"

for scenario in success route_failure dns_failure tailscale_changed; do
    marker="$temp/$scenario.calls"
    removed="$temp/$scenario.removed"
    output="$temp/$scenario.out"
    : > "$marker"
    set +e
    OFTC_CALLS_MARKER="$marker" OFTC_REMOVED_MARKER="$removed" zsh -c '
        set -euo pipefail
        source <(sed -n "/^cleanup() {/,/^}$/p" "$1")
        host="$2"
        scenario="$3"
        oftc_config_attempted=1
        baseline_route="gateway: baseline\ninterface: en0"
        baseline_dns=baseline
        route_snapshot() {
            [[ "$scenario" == route_failure ]] && return 1
            print -r -- "$baseline_route"
        }
        dns_digest() {
            [[ "$scenario" == dns_failure ]] && return 1
            print baseline
        }
        tailscale_inactive() { [[ "$scenario" != tailscale_changed ]]; }
        wait_oftc_disconnected() { return 0; }
        cleanup 0
    ' zsh "$script" "$temp/host" "$scenario" > "$output" 2>&1
    result=$?
    set -e
    [[ "$(cat "$marker")" == $'stop\nremove-config' ]] || {
        cat "$output"
        print -u2 "OFTC cleanup calls missing in $scenario"
        exit 1
    }
    if [[ "$scenario" == success ]]; then
        [[ "$result" == 0 ]] || { cat "$output"; exit 1; }
    else
        [[ "$result" != 0 ]] || {
            print -u2 "Cleanup unexpectedly succeeded in $scenario"
            exit 1
        }
        case "$scenario" in
        route_failure) rg -F 'Could not read post-stop target route' "$output" >/dev/null ;;
        dns_failure) rg -F 'Could not read post-stop DNS' "$output" >/dev/null ;;
        tailscale_changed) rg -F 'Tailscale is no longer Disabled and Disconnected' "$output" >/dev/null ;;
        esac
    fi
done
print 'Gate 5 syntax, plans, argument guards, and mocked cleanup paths passed; no VPN command was run.'
