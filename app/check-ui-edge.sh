#!/bin/zsh
# The UI edge ratchet (docs/ui-edge.md, section 10).
#
# The Swift UI may reach the host only through Host/HostEdge.swift. This lists, for every
# file in ui-files.txt, how often it matches each forbidden pattern, and fails when a file
# other than HostEdge.swift matches more often than ui-edge-baseline.txt allows (the
# baseline records what is left to remove, so it can only shrink) or when HostEdge.swift
# uses what it may not.
#
#   check-ui-edge.sh                       check (build.sh runs this before compiling)
#   check-ui-edge.sh --print               print the current counts in baseline format
#   check-ui-edge.sh --grew-since <ref>    also fail if the baseline has a row or a count
#                                          that <ref>'s baseline does not (CI, on pull requests)
#   check-ui-edge.sh --root <dir>          use another tree (the self-test's fixtures)
set -euo pipefail

root="${0:A:h}"
mode=check
since=""
while (( $# )); do
    case "$1" in
        --root) root="${2:?--root needs a directory}"; shift 2 ;;
        --print) mode=print; shift ;;
        --grew-since) since="${2:?--grew-since needs a ref}"; mode=grew; shift 2 ;;
        *) print -u2 "usage: check-ui-edge.sh [--root <dir>] [--print] [--grew-since <ref>]"; exit 2 ;;
    esac
done
list="$root/ui-files.txt"
baseline="$root/ui-edge-baseline.txt"
[[ -f "$list" ]] || { print -u2 "missing $list"; exit 2 }

# label<TAB>extended regex. A label is what the baseline names; a regex is matched per line.
# `Keychain` matches an identifier, not the word in a user-facing sentence.
# HostEdge.swift is exempt from the five that name what it exists to use.
patterns=(
    $'import Security\t^[[:space:]]*(@[A-Za-z_]+[[:space:]]+)*import[[:space:]]+Security([^A-Za-z0-9_]|$)'
    $'import CryptoKit\t^[[:space:]]*(@[A-Za-z_]+[[:space:]]+)*import[[:space:]]+CryptoKit([^A-Za-z0-9_]|$)'
    $'import SystemExtensions\t^[[:space:]]*(@[A-Za-z_]+[[:space:]]+)*import[[:space:]]+SystemExtensions([^A-Za-z0-9_]|$)'
    $'import ServiceManagement\t^[[:space:]]*(@[A-Za-z_]+[[:space:]]+)*import[[:space:]]+ServiceManagement([^A-Za-z0-9_]|$)'
    $'import NetworkExtension\t^[[:space:]]*(@[A-Za-z_]+[[:space:]]+)*import[[:space:]]+NetworkExtension([^A-Za-z0-9_]|$)'
    $'import Network\t^[[:space:]]*(@[A-Za-z_]+[[:space:]]+)*import[[:space:]]+Network([^A-Za-z0-9_]|$)'
    $'SecItem\tSecItem'
    $'kSec\tkSec'
    $'Keychain\t[A-Za-z_.]Keychain|Keychain[A-Za-z_(.]'
    $'NETunnelProviderManager\tNETunnelProviderManager'
    $'NEVPNManager\tNEVPNManager'
    $'saveToPreferences\tsaveToPreferences'
    $'loadAllFromPreferences\tloadAllFromPreferences'
    $'SMAppService\tSMAppService'
    $'OSSystemExtension\tOSSystemExtension'
    $'URLSession\tURLSession'
    $'NWConnection\tNWConnection'
    $'socket(\tsocket\\('
    $'connect(\tconnect\\('
    $'Process(\t(^|[^A-Za-z0-9_])Process\\('
    $'profile.json\tprofile\\.json'
    $'supervisor.lock\tsupervisor\\.lock'
    $'supervisor-status\tsupervisor-status'
    $'oftc_ffi\toftc_ffi'
    $'oftc_engine\toftc_engine'
    $'oftc_provider\toftc_provider'
    $'oftc_host\toftc_host'
)
edge_may_use=("import Network" "NWConnection" "socket(" "connect(" "Process(")

# Current counts as "file<TAB>label<TAB>count" lines, nonzero only.
counts() {
    local file entry label regex n
    while IFS= read -r file; do
        [[ -z "$file" || "$file" == \#* || "$file" == exempt:* ]] && continue
        [[ -f "$root/$file" ]] || continue
        for entry in "${patterns[@]}"; do
            label="${entry%%$'\t'*}"
            regex="${entry#*$'\t'}"
            n=$(grep -cE -- "$regex" "$root/$file" || true)
            if (( n > 0 )); then print -r -- "$file"$'\t'"$label"$'\t'"$n"; fi
        done
    done < "$list"
}

# What the baseline allows for "file<TAB>label": its count, else 0.
allowed() {
    [[ -f "$baseline" ]] || { print 0; return }
    awk -F'\t' -v f="$1" -v l="$2" '$0 !~ /^#/ && $1 == f && $2 == l { print $3; found = 1 } END { if (!found) print 0 }' "$baseline"
}

case "$mode" in
print) counts; exit 0 ;;
grew)
    prefix=$(git -C "$root" rev-parse --show-prefix)
    old=$(git -C "$root" show "$since:${prefix}ui-edge-baseline.txt" 2>/dev/null) || {
        print "No baseline at $since; nothing to compare."; exit 0
    }
    rc=0
    [[ -f "$baseline" ]] || exit 0
    while IFS=$'\t' read -r file label n; do
        [[ -z "$file" || "$file" == \#* ]] && continue
        before=$(print -r -- "$old" | awk -F'\t' -v f="$file" -v l="$label" '$0 !~ /^#/ && $1 == f && $2 == l { print $3; found = 1 } END { if (!found) print 0 }')
        if (( n > before )); then
            print -u2 "ui-edge-baseline.txt grew: $file $label $before -> $n"
            rc=1
        fi
    done < "$baseline"
    if (( rc == 0 )); then print "ui-edge baseline did not grow since $since"; fi
    exit $rc ;;
esac

rc=0
# Every Swift file in Host/ (but the checks) is either watched or named as exempt, so a new UI
# file cannot escape the scan by never being listed.
known=()
while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    known+=("${line#exempt: }")
done < "$list"
for swiftfile in "$root"/Host/*.swift(N); do
    rel="Host/${swiftfile:t}"
    [[ "${swiftfile:t}" == check-*.swift ]] && continue
    if (( ${known[(Ie)$rel]} == 0 )); then
        print -u2 "$rel is in neither ui-files.txt nor its exempt list: list it, or exempt it with 'exempt: $rel' and say why"
        rc=1
    fi
done
current=$(counts)
while IFS=$'\t' read -r file label n; do
    [[ -z "$file" ]] && continue
    if [[ "$file" == "Host/HostEdge.swift" && ${edge_may_use[(Ie)$label]} -gt 0 ]]; then
        continue
    fi
    if [[ "$file" == "Host/HostEdge.swift" ]]; then
        print -u2 "$file may not use '$label' ($n lines): only Network and Process reach the host"
        rc=1
        continue
    fi
    allow=$(allowed "$file" "$label")
    if (( n > allow )); then
        print -u2 "$file matches '$label' on $n lines; the baseline allows $allow. The UI reaches the host only through HostEdge.swift."
        rc=1
    fi
done <<< "$current"
# A baseline that records more than exists is stale: lower it, so it only ever shrinks.
if [[ -f "$baseline" ]]; then
    while IFS=$'\t' read -r file label n; do
        [[ -z "$file" || "$file" == \#* ]] && continue
        [[ -f "$root/$file" ]] || continue
        have=$(print -r -- "$current" | awk -F'\t' -v f="$file" -v l="$label" '$1 == f && $2 == l { print $3; found = 1 } END { if (!found) print 0 }')
        if (( have < n )); then
            print -u2 "ui-edge-baseline.txt lists $file '$label' $n times but only $have remain: lower it"
            rc=1
        fi
    done < "$baseline"
fi
if (( rc == 0 )); then print "UI edge ratchet passed: no new reach around HostEdge.swift ($(grep -cv '^#' "$baseline" 2>/dev/null || print 0) baseline rows left to remove)."; fi
exit $rc
