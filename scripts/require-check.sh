#!/bin/bash
# Make a GitHub Actions check required on main (adds it to the "main" ruleset).
# Usage: scripts/require-check.sh [--apply] "<check name>"
# The check name is the job name as it appears in the PR checks list. Without
# --apply it only prints what would change. Needs `gh` logged in with admin rights
# on the repo (use GH_TOKEN=$(gh auth token --user <account>) to pick the account).
set -euo pipefail
apply=0
[[ "${1:-}" == --apply ]] && { apply=1; shift; }
check="${1:?usage: require-check.sh [--apply] \"<check name>\"}"
repo="${OFTC_REPO:-CentauriSolutions/open-forticlient}"
actions_app_id=15368

id=$(gh api "repos/$repo/rulesets" --jq '.[] | select(.name=="main") | .id')
[[ -n "$id" ]] || { echo 'no ruleset named "main"' >&2; exit 1; }
current=$(gh api "repos/$repo/rulesets/$id")
updated=$(jq --arg c "$check" --argjson app "$actions_app_id" '
  {name, target, enforcement, bypass_actors, conditions,
   rules: (.rules | map(
     if .type == "required_status_checks" and (.parameters.required_status_checks | map(.context) | index($c) | not)
     then .parameters.required_status_checks += [{context: $c, integration_id: $app}]
     else . end))}' <<<"$current")
if [[ "$(jq -S . <<<"$updated")" == "$(jq -S '{name,target,enforcement,bypass_actors,conditions,rules}' <<<"$current")" ]]; then
    echo "\"$check\" is already required"; exit 0
fi
echo "Required checks after the change:"
jq -r '.rules[] | select(.type=="required_status_checks") | .parameters.required_status_checks[].context' <<<"$updated" | sed 's/^/  - /'
if (( apply )); then
    gh api -X PUT "repos/$repo/rulesets/$id" --input - <<<"$updated" >/dev/null
    echo "Applied."
else
    echo "Dry run; re-run with --apply."
fi
