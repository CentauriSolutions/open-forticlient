#!/bin/zsh
# Offline syntax, argument, and rollback cleanup check. No VPN is started.
set -euo pipefail

root="${0:A:h}"
script="$root/gate6-v9-live.sh"
zsh -n "$script"
zsh "$script" --plan >/dev/null
for args in '--plan extra' '--execute' '--execute 0' '--execute 65536' '--execute 443 extra'; do
    local -a words
    words=(${=args})
    if zsh "$script" "${words[@]}" >/dev/null 2>&1; then
        print -u2 "Unexpectedly accepted invalid arguments: $args"
        exit 1
    fi
done

temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
mkdir -p "$temp/app/Contents/MacOS" "$temp/held/Contents/MacOS" "$temp/staging"
print v9 > "$temp/app/version"
print v7 > "$temp/held/version"
cat > "$temp/app/Contents/MacOS/IntegrationHost" <<'EOF'
#!/bin/sh
test "$1" = status && printf '%s\n' 'configuration absent'
EOF
chmod +x "$temp/app/Contents/MacOS/IntegrationHost"
cat > "$temp/held/Contents/MacOS/IntegrationHost" <<'EOF'
#!/bin/sh
test "$1" = activate && : > "$OFTC_V7_ACTIVATED_MARKER"
EOF
chmod +x "$temp/held/Contents/MacOS/IntegrationHost"

set +e
OFTC_V7_ACTIVATED_MARKER="$temp/activated" zsh -c '
    set -euo pipefail
    source <(sed -n "/^cleanup() {/,/^}$/p" "$1")
    app="$2/app"; held="$2/held"; staging="$2/staging"
    moved_v7=1; installed_v9=1
    v9_exact() { [[ "$(cat "$1/version")" == v9 ]]; }
    v7_exact() { [[ "$(cat "$1/version")" == v7 ]]; }
    signed_and_notarized() { return 0; }
    tailscale_inactive() { return 0; }
    extension_active() { [[ "$1" == 7 ]]; }
    cleanup 1
' zsh "$script" "$temp" > "$temp/out" 2>&1
result=$?
set -e
[[ "$result" == 1 && -f "$temp/activated" && "$(cat "$temp/app/version")" == v7 &&
   ! -e "$temp/held" && ! -e "$temp/staging" ]] || {
    cat "$temp/out"
    print -u2 'Mocked v7 rollback did not restore the installed app'
    exit 1
}
print 'v9 live gate syntax, argument guards, and mocked v7 rollback passed; no VPN command was run.'
