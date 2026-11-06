#!/bin/zsh
# S3 host service: supervisors and tunnels survive a kickstart of the host service, the
# service is loaded once, and `host register` / `host restart` behave. Needs tunnels up.
set -u
setopt pipefail
source "${${(%):-%x}:A:h}/lib.sh"
LC_STAGE_SCRIPT=s3-host.sh
lc_init S3 "$@" || exit $?
trap lc_finish EXIT
agent=$(lc_agent)
label="$LC_BUNDLE_ID.host"
target="gui/$(id -u)/$label"
[[ -n $PROFILES ]] || { lc_fail "PROFILES is not configured (see docs/livecheck.md)"; exit 1; }

host_pids() { ps -axo pid,command 2>/dev/null | awk '/OFTCAgent host serve/ && !/awk/ {print $1}' | sort | tr '\n' ' '; }
host_pid_changed() { local now; now=$(host_pids); [[ -n $now && $now != "$1" ]]; }
status_answers() { "$(lc_cli)" status --json >/dev/null 2>&1; }

lc_snapshot start
snap_start=$LC_SNAP

lc_step "before: host service and supervisors"
if lc_live; then
  sup_before=$(lc_supervisors | tr '\n' ' ')
  hp_before=$(host_pids)
  lc_info "supervisors (pid:pgid): ${sup_before:-none}"
  lc_info "host service pid(s): ${hp_before:-none}"
  [[ -n $sup_before ]] && lc_pass "supervisors are running" || lc_fail "no supervisor is running: connect the tunnels first"
  expect_eq "exactly one 'host serve' process" "$(print -r -- "$hp_before" | wc -w | tr -d ' ')" 1
  for pair in ${=sup_before}; do
    expect_eq "supervisor ${pair%%:*} leads its own process group" "${pair%%:*}" "${pair##*:}"
  done
  lc_refresh_status
  for id in ${=PROFILES}; do expect_eq "profile $id state before" "$(lc_pfield "$id" state)" connected; done
else
  lc_dry "would record supervisor pid:pgid pairs and the host pid, assert one host, own process groups, tunnels connected"
fi

lc_step "registration"
lc_run launchctl print "$target"
expect_rc "host service is loaded in the gui domain" "$LC_RC" 0
lc_run launchctl list
lc_live && expect_eq "host label listed once by launchctl list" "$(print -r -- "$LC_OUT" | grep -c "$label")" 1
lc_run launchctl print-disabled "gui/$(id -u)"
lc_live && expect_not_contains "host label is not disabled" "$(print -r -- "$LC_OUT" | grep "$label")" "disabled"
lc_run sudo -n sfltool dumpbtm
if lc_live; then
  if (( LC_RC == 0 )); then
    expect_eq "Login Items / BTM entries for the host label" "$(print -r -- "$LC_OUT" | grep -c "$label")" 1
  else
    lc_info "Login Items/BTM count not observable here (sfltool dumpbtm needs root and the sudo credential); count in System Settings > Login Items if it matters"
  fi
fi

lc_step "kickstart"
lc_run launchctl kickstart -k "$target"
expect_rc "kickstart" "$LC_RC" 0
if lc_live; then
  wait_for "host service restarted under a new pid" 60 2 host_pid_changed "$hp_before"
  wait_for "host socket answers 'oftc status --json'" 60 2 status_answers
  expect_eq "exactly one 'host serve' process after" "$(host_pids | wc -w | tr -d ' ')" 1
  expect_eq "supervisors (pid:pgid) unchanged" "$(lc_supervisors | tr '\n' ' ')" "$sup_before"
  lc_refresh_status
  for id in ${=PROFILES}; do
    expect_eq "profile $id state after kickstart" "$(lc_pfield "$id" state)" connected
    lc_run ping -c 10 -t 20 "$(lc_target_for "$id" PING_TARGETS)"
    expect_contains "ping through $id after kickstart" "$LC_OUT" " 0.0% packet loss"
  done
else
  lc_dry "would assert a new host pid, one host, supervisors unchanged, tunnels connected and pinging"
fi

lc_step "host register and host restart"
lc_run "$agent" host register
reg_rc=$LC_RC; reg_out=$LC_OUT
if lc_live; then
  if [[ $reg_out == *usage* || $reg_out == *Usage* ]]; then
    lc_info "this build has no 'host register' verb (usage printed); registration is by the launch agent plist only"
  else
    expect_rc "host register (idempotent)" "$reg_rc" 0
    lc_info "host register said: ${reg_out:0:200}"
  fi
fi
lc_run "$agent" host restart
expect_contains "host restart" "$LC_OUT" "OFTC host restarted"
if lc_live; then
  wait_for "host socket answers after restart" 60 2 status_answers
  expect_eq "exactly one 'host serve' process after register/restart" "$(host_pids | wc -w | tr -d ' ')" 1
  expect_eq "supervisors (pid:pgid) still unchanged" "$(lc_supervisors | tr '\n' ' ')" "$sup_before"
fi

lc_snapshot end
lc_snapdiff "$snap_start" "$LC_SNAP"
