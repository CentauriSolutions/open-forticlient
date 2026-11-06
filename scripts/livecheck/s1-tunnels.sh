#!/bin/zsh
# S1 tunnel checks on the installed build, for each configured profile: connected, pings
# at 0% loss, both rekey probes pass and the counters move, traffic continues, then a soak
# with periodic probes. Needs the tunnels up (or --connect, which asks for the SSO).
set -u
setopt pipefail
source "${${(%):-%x}:A:h}/lib.sh"
LC_STAGE_SCRIPT=s1-tunnels.sh
LC_STAGE_USAGE='[--connect] [--soak-minutes N]'
LC_STAGE_FLAGS=(--connect)
LC_STAGE_OPTS=(--soak-minutes)
lc_init S1 "$@" || exit $?
trap lc_finish EXIT; trap 'exit 130' INT TERM
do_connect=0
[[ ${LC_ARGS[(Ie)--connect]} != 0 ]] && do_connect=1
if (( ${LC_ARGS[(Ie)--soak-minutes]} )); then SOAK_MINUTES=${LC_ARGS[$(( ${LC_ARGS[(Ie)--soak-minutes]} + 1 ))]}; fi
cli=$(lc_cli); agent=$(lc_agent)
[[ -n $PROFILES ]] || { lc_fail "PROFILES is not configured (see docs/livecheck.md)"; exit 1; }

# Sum of every number on the provider's child_rekeys line (local and remote counters).
rekey_total() {
  local out
  out=$("$agent" --profile "$1" rekey-counts 2>&1) || { print -- -1; return; }
  print -r -- "$out" | grep -o '[0-9][0-9]*' | awk '{s+=$1} END {print s+0}'
}
sup_list() { lc_supervisors | tr '\n' ' '; }

lc_snapshot start
snap_start=$LC_SNAP

lc_step "connect (only with --connect)"
if (( do_connect )); then
  lc_run -q "$cli" connect ${=PROFILES}
  for id in ${=PROFILES}; do
    human "complete the browser sign-in for profile $id when it opens" "profile $id reports connected" "$SSO_TIMEOUT" lc_is_connected "$id"
  done
else
  lc_info "not connecting: S1 expects the tunnels to be up already"
fi

sup_before=''
lc_live && sup_before=$(sup_list)
lc_info "supervisors (pid:pgid) before: ${sup_before:-none}"

for id in ${=PROFILES}; do
  lc_step "profile $id: connected and reachable"
  if lc_live; then
    lc_refresh_status
    expect_eq "profile $id state" "$(lc_pfield "$id" state)" connected
    addr=$(lc_target_for "$id" PING_TARGETS) || { lc_fail "no PING_TARGETS entry for $id"; continue; }
    lc_run ping -c 10 -t 20 "$addr"
    expect_contains "ping through $id at 0% loss" "$LC_OUT" " 0.0% packet loss"
    if tcp=$(lc_target_for "$id" TCP_TARGETS); then
      lc_run nc -z -G 5 "${tcp%%:*}" "${tcp##*:}"
      expect_rc "TCP connect through $id" "$LC_RC" 0
    fi
  else
    lc_dry "would assert profile $id connected and ping its PING_TARGETS address at 0% loss"
  fi

  lc_step "profile $id: rekey probes"
  before=$(lc_live && rekey_total "$id" || print 0)
  lc_run "$agent" --profile "$id" rekey-once
  expect_contains "CHILD_SA rekey probe $id" "$LC_OUT" "CHILD_SA rekey probe passed"
  lc_run "$agent" --profile "$id" rekey-ike-once
  expect_contains "IKE_SA rekey probe $id" "$LC_OUT" "IKE_SA rekey probe passed"
  after=$(lc_live && rekey_total "$id" || print 0)
  if lc_live; then
    if [[ $before == -1 || $after == -1 ]]; then lc_fail "rekey counters unavailable for $id (before=$before after=$after)"
    elif (( after > before )); then lc_pass "rekey counters increased for $id ($before -> $after)"
    else lc_fail "rekey counters did not increase for $id ($before -> $after)"; fi
  else lc_dry "would assert the rekey-counts total increases"; fi
  if lc_live; then
    lc_run ping -c 10 -t 20 "$(lc_target_for "$id" PING_TARGETS)"
    expect_contains "protected traffic continues after rekeys ($id)" "$LC_OUT" " 0.0% packet loss"
    lc_refresh_status
    expect_eq "profile $id still connected after rekeys" "$(lc_pfield "$id" state)" connected
  fi

  lc_step "profile $id: transport"
  lc_run -q "$agent" --profile "$id" show-profile
  lc_info "configured: $(print -r -- "$LC_OUT" | grep -o 'transport=[a-z]*')"
  lc_run -q netstat -an
  if lc_live; then
    if print -r -- "$LC_OUT" | grep -q 'ESTABLISHED' && print -r -- "$LC_OUT" | grep -E '\.4443 +ESTABLISHED' >/dev/null; then
      lc_info "in use (inferred from sockets, not per profile): a TCP connection to port 4443 is established"
    else
      lc_info "in use (inferred): no TCP 4443 connection; UDP presumed. The CLI does not report the transport in use."
    fi
  fi
done

lc_step "soak"
if lc_live; then
  typeset -i ticks
  ticks=$(( SOAK_MINUTES * 60 / SOAK_INTERVAL ))
  (( ticks < 1 )) && ticks=1
  lc_info "soaking $SOAK_MINUTES min: $ticks probes every ${SOAK_INTERVAL}s"
  broke=0
  for (( t = 1; t <= ticks && ! broke; t++ )); do
    lc_sleep "$SOAK_INTERVAL"
    lc_refresh_status
    for id in ${=PROFILES}; do
      st=$(lc_pfield "$id" state)
      if [[ $st != connected ]]; then lc_fail "soak probe $t: profile $id is '$st', not connected"; broke=1; continue; fi
      lc_ping_clean "$(lc_target_for "$id" PING_TARGETS)" 3 || { lc_fail "soak probe $t: ping through $id lost packets"; broke=1; }
    done
  done
  (( broke )) || lc_pass "soak: $ticks probes, every profile connected and pinging clean"
  expect_eq "supervisors unchanged across S1" "$(sup_list)" "$sup_before"
else
  lc_dry "would soak for $SOAK_MINUTES minutes, probing every ${SOAK_INTERVAL}s, asserting no disconnect"
fi

lc_snapshot end
lc_snapdiff "$snap_start" "$LC_SNAP"
