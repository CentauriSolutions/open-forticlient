#!/bin/zsh
# Offline guard and mocked rollback check. Never runs a VPN command.
set -euo pipefail
root="${0:A:h}"
script="$root/gate7-v11-sustained.sh"
zsh -n "$script"
zsh "$script" --plan >/dev/null
for args in '' '--plan extra' '--start extra' '--finish extra' '--rollback extra' '--execute'; do
    local -a words
    words=(${=args})
    if zsh "$script" "${words[@]}" >/dev/null 2>&1; then
        print -u2 "Unexpectedly accepted invalid arguments: $args"
        exit 1
    fi
done

temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
mkdir -p "$temp/app" "$temp/held" "$temp/staging"
print v11 > "$temp/app/version"
print v9 > "$temp/held/version"
print started > "$temp/started"
zsh -c '
    set -euo pipefail
    source <(sed -n "/^restore_v9() {/,/^}/p" "$1")
    marker_root="$2"
    app="$2/app"; held="$2/held"; staging="$2/staging"
    started="$2/started"; baseline_route="$2/baseline.route"
    v11_exact() { [[ "$(cat "$1/version")" == v11 ]]; }
    v9_exact() { [[ "$(cat "$1/version")" == v9 ]]; }
    signed_and_notarized() { return 0; }
    cleanup_vpn() { print cleaned > "$marker_root/cleaned"; }
    host() {
        case "$1" in
        status) print "OFTC configuration absent" ;;
        activate) print activated > "$marker_root/activated" ;;
        *) return 1 ;;
        esac
    }
    extension_active() { [[ "$1" == 9 ]]; }
    restore_v9
' zsh "$script" "$temp"
[[ "$(cat "$temp/app/version")" == v9 && -f "$temp/cleaned" &&
   -f "$temp/activated" && ! -e "$temp/held" && ! -e "$temp/staging" &&
   ! -e "$temp/started" ]] || { print -u2 'Mocked v9 rollback did not restore the app'; exit 1; }
print 'v11 gate syntax, argument guards, and mocked v9 rollback passed; no VPN command ran.'
