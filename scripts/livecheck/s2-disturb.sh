#!/bin/zsh
# S2 disturbance tests: network drop, sleep and wake, deliberate stop. Needs the tunnels up
# (run S1 first). Each test ends by asserting recovery and traffic, then restoring state.
#   (disturbs the network and sleeps the Mac: needs --yes)
#   zsh s2-disturb.sh --yes [--only drop|sleep|stop] [--no-restore]
set -u
setopt pipefail
source "${${(%):-%x}:A:h}/lib.sh"
LC_STAGE_SCRIPT=s2-disturb.sh
LC_STAGE_USAGE='--yes [--only drop|sleep|stop] [--no-restore]'
LC_STAGE_FLAGS=(--no-restore)
LC_STAGE_OPTS=(--only)
lc_init S2 "$@" || exit $?
trap lc_finish EXIT; trap 'exit 130' INT TERM
lc_need_yes
only=''
(( ${LC_ARGS[(Ie)--only]} )) && only=${LC_ARGS[$(( ${LC_ARGS[(Ie)--only]} + 1 ))]}
restore=1
(( ${LC_ARGS[(Ie)--no-restore]} )) && restore=0
cli=$(lc_cli)
[[ -n $PROFILES ]] || { lc_fail "PROFILES is not configured (see docs/livecheck.md)"; exit 1; }
want() { [[ -z $only || $only == "$1" ]]; }

dropped_how=''
s2_restore_network() {
  [[ -n $dropped_how ]] || return 0
  local manual=''
  case $dropped_how in
    service) manual="sudo networksetup -setnetworkserviceenabled \"$NETWORK_SERVICE\" on"; lc_run sudo -n networksetup -setnetworkserviceenabled "$NETWORK_SERVICE" on ;;
    wifi) manual="networksetup -setairportpower $WIFI_DEVICE on"; lc_run networksetup -setairportpower "$WIFI_DEVICE" on ;;
  esac
  if (( LC_RC != 0 )); then
    lc_fail "could not restore the network (exit $LC_RC)"
    lc_emit "RESTORE" "MANUALLY: $manual"
  else
    dropped_how=''
  fi
}
lc_on_exit s2_restore_network

all_connected() { local i; lc_refresh_status; for i in ${=PROFILES}; do [[ $(lc_pfield "$i" state) == connected ]] || return 1; done; }
any_not_connected() { ! all_connected; }
no_supervisors() { [[ -z $(lc_supervisors) ]]; }
all_stopped() {
  local i s; lc_refresh_status
  for i in ${=PROFILES}; do s=$(lc_pfield "$i" state); [[ $s == disconnected || $s == setup ]] || return 1; done
}

# Everything that must hold when a tunnel is back: connected, clean ping, supervisor alive.
assert_back() {   # label
  local id
  if lc_live; then
    for id in ${=PROFILES}; do
      lc_run ping -c 10 -t 20 "$(lc_target_for "$id" PING_TARGETS)"
      expect_contains "$1: traffic through $id at 0% loss" "$LC_OUT" " 0.0% packet loss"
    done
    expect_eq "$1: supervisor processes running" "$([[ -n $(lc_supervisors) ]] && print yes || print no)" yes
  else
    lc_dry "would assert every profile connected, pinging clean, supervisors running ($1)"
  fi
}

# After a disturbance a recovery may need a browser sign-in. Give it time to come back by
# itself first; only then ask a human, once per profile that is still down.
reconnect_with_sso() {
  local id
  if (( LC_DRY )); then
    lc_dry "would wait up to 90s for recovery, then ask a human for the browser sign-in per profile still down"
    (( LC_HUMANS++ )); LC_HUMAN_LOG+=("$LC_STAGE: browser sign-in after recovery")
    return 0
  fi
  lc_poll 90 5 all_connected && { lc_info "recovered without a prompt"; return 0; }
  for id in ${=PROFILES}; do
    lc_is_connected "$id" || human "complete the browser sign-in for $id (the recovery opened it)" "profile $id reports connected" "$SSO_TIMEOUT" lc_is_connected "$id"
  done
  all_connected && lc_pass "all profiles connected after sign-in" || lc_fail "not all profiles connected after sign-in"
}

lc_snapshot start
snap_start=$LC_SNAP
lc_sudo_prime
lc_live && { all_connected && lc_pass "precondition: every profile connected" || { lc_fail "precondition: every profile must be connected (run S1 --connect)"; exit 1; } }

if want drop; then
  lc_step "network drop"
  first=${${=PROFILES}[1]}
  mark=$(lc_log_lines "$first")
  rc=1
  if [[ -n $NETWORK_SERVICE ]]; then
    lc_run sudo -n networksetup -setnetworkserviceenabled "$NETWORK_SERVICE" off; rc=$LC_RC; [[ $rc == 0 ]] && dropped_how=service
  elif [[ -n $WIFI_DEVICE ]]; then
    lc_run networksetup -setairportpower "$WIFI_DEVICE" off; rc=$LC_RC; [[ $rc == 0 ]] && dropped_how=wifi
  fi
  if lc_live && [[ $rc != 0 ]]; then
    lc_info "scripted network drop unavailable (rc=$rc); asking a human"
    human "turn Wi-Fi off from the menu bar (or unplug Ethernet)" "profile $first leaves 'connected'" 180 lc_is_not_connected "$first"
    human_dropped=1
  else
    human_dropped=0
    wait_for "profile $first leaves 'connected' after the network drop" 180 5 lc_is_not_connected "$first"
  fi
  lc_info "network down; holding 20s so the supervisor sees the disconnect"
  lc_sleep 20
  if (( human_dropped )) && lc_live; then
    human "turn Wi-Fi back on" "profile $first has a route again (state changes or ping resolves)" 180 lc_has_network
  else
    s2_restore_network
  fi
  reconnect_with_sso
  if lc_live; then
    newlog=$(lc_log_since "$first" "$mark")
    expect_contains "supervisor log shows the disconnect" "$newlog" "OFTC supervisor: VPN disconnected; fetching error"
    expect_contains "supervisor log shows fresh sign-in recovery" "$newlog" "OFTC supervisor: starting fresh SSO recovery"
    expect_contains "supervisor log shows reconnection" "$newlog" "OFTC supervisor: VPN connected"
  fi
  assert_back "after network drop"
fi

if want sleep; then
  lc_step "sleep and wake"
  wake_at=$(date -v+$(( SLEEP_SECONDS + 15 ))S '+%m/%d/%y %H:%M:%S')
  lc_sudo pmset schedule wake "$wake_at"
  expect_rc "scheduled wake" "$LC_RC" 0
  lc_run pmset sleepnow
  # pmset returns before the Mac suspends and the script freezes with it: a jump in the
  # wall clock between one-second ticks is the evidence that it really slept.
  if lc_live; then
    if lc_detect_sleep $(( SLEEP_SECONDS + 180 )); then
      (( LC_SLEPT >= SLEEP_SECONDS - 5 )) && lc_pass "Mac slept (clock jumped ${LC_SLEPT}s, wanted >= $(( SLEEP_SECONDS - 5 ))s)" || lc_fail "Mac slept only ${LC_SLEPT}s, wanted >= $(( SLEEP_SECONDS - 5 ))s"
    else lc_fail "no sleep detected within $(( SLEEP_SECONDS + 180 ))s of pmset sleepnow"; fi
  else lc_dry "would watch for a wall-clock jump of at least $(( SLEEP_SECONDS - 5 ))s"; fi
  lc_sudo pmset schedule cancel wake "$wake_at"
  lc_run -q pmset -g log
  lc_live && lc_info "last wake lines: $(print -r -- "$LC_OUT" | grep -E ' Wake ' | tail -2 | tr '\n' ';' | cut -c1-200)"
  reconnect_with_sso
  assert_back "after wake"
fi

if want stop; then
  lc_step "deliberate stop"
  mark=$(lc_log_lines "${${=PROFILES}[1]}")
  lc_run -q "$cli" disconnect ${=PROFILES}
  wait_for "every profile reports disconnected" 60 3 all_stopped
  lc_info "holding ${DISCONNECT_WAIT}s: nothing may reconnect and no supervisor may remain"
  if lc_live; then
    ticks=$(( DISCONNECT_WAIT / 10 )); stayed=1
    for (( t = 1; t <= ticks; t++ )); do
      lc_sleep 10
      all_stopped || { lc_fail "a profile left 'disconnected' during the hold (tick $t)"; stayed=0; break; }
    done
    (( stayed )) && lc_pass "no reconnect during ${DISCONNECT_WAIT}s"
    expect_eq "supervisor processes after the hold" "$(lc_supervisors | tr -d '\n')" ""
    newlog=$(lc_log_since "${${=PROFILES}[1]}" "$mark")
    expect_not_contains "no new connection attempt after the stop" "$newlog" "begin attempt"
  else
    lc_dry "would hold ${DISCONNECT_WAIT}s asserting disconnected, no supervisor, no new attempt"
  fi
  if (( restore )); then
    lc_run -q "$cli" connect ${=PROFILES}
    for id in ${=PROFILES}; do
      human "complete the browser sign-in for $id" "profile $id reports connected" "$SSO_TIMEOUT" lc_is_connected "$id"
    done
  else
    lc_info "--no-restore: leaving the tunnels down"
  fi
fi

lc_snapshot end
lc_snapdiff "$snap_start" "$LC_SNAP"
