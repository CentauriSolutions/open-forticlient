#!/bin/zsh
# Offline regression for the smoke EXIT trap. All VPN commands are mocked.
set -euo pipefail

root="${0:A:h}"
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
cat > "$temp/host" <<'EOF'
#!/bin/sh
case "$1" in
status) printf '%s\n' 'OFTC VPN status: 1' ;;
stop|remove-config) exit 0 ;;
*) exit 2 ;;
esac
EOF
chmod +x "$temp/host"

for mode in leave restore; do
    marker="$temp/$mode.calls"
    : > "$marker"
    set +e
    zsh -c '
        set -euo pipefail
        source <(sed -n "/^cleanup() {/,/^}$/p" "$1")
        host="$2"
        marker="$3"
        tailscale_service=Tailscale
        tailscale_toggle_attempted=1
        oftc_config_attempted=1
        baseline_interface=en0
        baseline_dns=baseline
        leave_tailscale_off="$4"
        route_interface() { return 1; }
        dns_digest() { return 1; }
        service_state() { print Disabled; }
        vpn_state() { print Disconnected; }
        tailscale_inactive() { return 0; }
        networksetup() { print -r -- "networksetup $*" >> "$marker"; }
        scutil() { print -r -- "scutil $*" >> "$marker"; }
        wait_oftc_disconnected() { return 0; }
        wait_tailscale() { return 0; }
        cleanup 7
    ' zsh "$root/gate4-smoke.sh" "$temp/host" "$marker" "$([[ "$mode" == leave ]] && print 1 || print 0)" \
        > "$temp/$mode.out" 2>&1
    result=$?
    set -e
    [[ "$result" -ne 0 ]] || { print -u2 "Cleanup unexpectedly succeeded in $mode mode"; exit 1; }
    if ! rg -F 'Could not read post-stop route' "$temp/$mode.out" >/dev/null ||
       ! rg -F 'Could not read post-stop DNS' "$temp/$mode.out" >/dev/null; then
        cat "$temp/$mode.out"
        print -u2 "Cleanup skipped failed reads in $mode mode"
        exit 1
    fi
    if [[ "$mode" == leave ]]; then
        [[ ! -s "$marker" ]] || { print -u2 'Leave-off cleanup touched Tailscale'; exit 1; }
    else
        rg -F 'networksetup -setnetworkserviceenabled Tailscale on' "$marker" >/dev/null
        rg -F 'scutil --nc start Tailscale' "$marker" >/dev/null
    fi
done
print 'Smoke cleanup synthetic failure paths passed; no VPN command was run.'
