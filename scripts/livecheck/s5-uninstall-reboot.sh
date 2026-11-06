#!/bin/zsh
# S5 uninstall and reboot. CHANGES THIS MAC: needs --yes.
#   Phase "pre" (default): `oftc uninstall`, assert it left no extension, launch agent or
#   Login Item and kept the profiles; reinstall from the DMG (so connect-at-login has an
#   app to start), turn auto-start on for PROFILES, leave a marker and a one-shot user
#   LaunchAgent, and schedule a reboot.
#   Phase "post": run by that LaunchAgent after login. It deletes the plist first, asserts
#   the stale extension entries are gone, the tunnels came up (after your SSO) and the host
#   service runs, then deletes the marker. A marker left behind means a half-run.
#   zsh s5-uninstall-reboot.sh --yes [--no-reinstall] [--no-reboot] [--dmg PATH] [--force]
set -u
setopt pipefail
source "${${(%):-%x}:A:h}/lib.sh"
LC_STAGE_SCRIPT=s5-uninstall-reboot.sh
LC_STAGE_USAGE='--yes [--phase pre|post] [--no-reinstall] [--no-reboot] [--dmg PATH] [--force]'
LC_STAGE_FLAGS=(--no-reinstall --no-reboot --force)
LC_STAGE_OPTS=(--phase --dmg)
# The resume agent must never run twice: the post phase removes its own plist before
# anything else can fail. The run directory is persistent so it survives the reboot.
state_dir="$HOME/Library/Application Support/oftc-livecheck"
label=local.oftc-livecheck.s5-resume
plist="$HOME/Library/LaunchAgents/$label.plist"
[[ " $* " == *" --phase post "* && " $* " != *" --dry-run "* ]] && rm -f "$plist"
[[ -n ${LIVECHECK_RUN_DIR:-} ]] || LIVECHECK_RUN_DIR="$state_dir/runs/$(date +%Y%m%d-%H%M%S)"
lc_init S5 "$@" || exit $?
trap lc_finish EXIT; trap 'exit 130' INT TERM
lc_need_yes
phase=pre
(( ${LC_ARGS[(Ie)--phase]} )) && phase=${LC_ARGS[$(( ${LC_ARGS[(Ie)--phase]} + 1 ))]}
dmg=$DMG_PATH
(( ${LC_ARGS[(Ie)--dmg]} )) && dmg=${LC_ARGS[$(( ${LC_ARGS[(Ie)--dmg]} + 1 ))]}
reinstall=$(( ${LC_ARGS[(Ie)--no-reinstall]} ? 0 : 1 ))
do_reboot=$(( ${LC_ARGS[(Ie)--no-reboot]} ? 0 : 1 ))
force=$(( ${LC_ARGS[(Ie)--force]} ? 1 : 0 ))
cli=$(lc_cli); agent=$(lc_agent)
marker="$state_dir/s5.marker"
sup="$HOME/Library/Application Support/$LC_BUNDLE_ID"
ext_lines() { systemextensionsctl list 2>/dev/null | grep -i oftc; }
no_ext() { [[ -z $(ext_lines) ]]; }
no_stale() { local e; e=$(ext_lines); [[ $e != *'terminated waiting'* ]]; }
host_pids() { ps -axo pid,command 2>/dev/null | awk '/OFTCAgent host serve/ && !/awk/ {print $1}' | sort | tr '\n' ' '; }
host_up() { [[ -n $(host_pids) ]]; }
profile_dirs() { ls "$sup/profiles" 2>/dev/null | wc -l | tr -d ' '; }

if [[ $phase == pre ]]; then
  lc_step "half-run check"
  if (( LC_DRY )); then lc_dry "would refuse to start if $marker exists (a previous half-run)"
  elif [[ -e $marker ]]; then
    if (( force )) && lc_live; then lc_info "--force: removing our own marker $marker"; rm -f "$marker" "$plist"
    else lc_fail "found $marker: a previous S5 did not finish ($(head -1 "$marker" 2>/dev/null)). Look at its run directory, then re-run with --force"; exit 1; fi
  else lc_pass "no S5 marker present"; fi
  [[ -n $PROFILES ]] || { lc_fail "PROFILES is not configured"; exit 1; }
  (( reinstall )) && { [[ -n $dmg ]] || { lc_fail "reinstall needs DMG_PATH or --dmg (or pass --no-reinstall)"; exit 1; }; }

  lc_snapshot before
  snap_before=$LC_SNAP
  lc_sudo_prime
  dirs_before=$(lc_live && profile_dirs || print 0)

  # Verify the package BEFORE uninstalling anything: a bad DMG must not leave this Mac
  # with no app.
  if (( reinstall )); then
    lc_step "mount and verify the package before touching the installed app"
    lc_live && [[ ! -f $dmg ]] && { lc_fail "DMG not found: $dmg"; exit 1; }
    lc_attach_dmg "$dmg" || exit 1
    lc_verify_pkg "$LC_PKG"
    if lc_live && (( LC_FAIL )); then lc_info "package verification failed: nothing was uninstalled"; exit 1; fi
  fi

  lc_step "oftc uninstall"
  lc_info "this may ask for the admin password again (in this terminal or a dialog): that is the same one act as S0"
  lc_run_tty "$cli" uninstall
  expect_rc "oftc uninstall" "$LC_RC" 0
  if lc_live && [[ $LC_RC != 0 ]]; then lc_info "uninstall failed: not reinstalling, not rebooting"; exit 1; fi
  lc_snapshot uninstalled
  if lc_live; then
    [[ ! -d $APP ]] && lc_pass "app bundle removed" || lc_fail "app bundle still present"
    [[ ! -e $OFTC_CLI ]] && lc_pass "$OFTC_CLI removed" || lc_fail "$OFTC_CLI still present"
    lc_run -q pkgutil --pkgs
    expect_not_contains "installer receipts" "$LC_OUT" openforticlient
    lc_run -q launchctl list
    expect_not_contains "launchctl list" "$(print -r -- "$LC_OUT" | grep -i oftc || true)" oftc
    for l in agent host; do
      lc_run -q launchctl print "gui/$(id -u)/$LC_BUNDLE_ID.$l"
      expect_eq "launch agent $l is gone" "$([[ $LC_RC == 0 ]] && print loaded || print absent)" absent
    done
    lc_sudoq sfltool dumpbtm
    (( LC_RC == 0 )) && expect_not_contains "Login Items / BTM entries" "$LC_OUT" "$LC_BUNDLE_ID" || lc_info "Login Items/BTM not observable without root; check System Settings > Login Items shows no OFTC entry"
    exts=$(ext_lines)
    expect_not_contains "extension is not left activated" "$exts" "activated enabled"
    if [[ $exts == *"terminated waiting"* ]]; then lc_info "extension removal deferred ('terminated waiting to uninstall'): expected until reboot; the post phase asserts it clears"; else lc_pass "no OFTC extension entries remain"; fi
    expect_eq "profile directories retained" "$(profile_dirs)" "$dirs_before"
    lc_info "Keychain PSK retention is not read here; S4/S0 snapshots show psk=available once the app is back"
  fi

  if (( reinstall )); then
    lc_step "reinstall so connect-at-login has an app"
    lc_install_pkg "$LC_PKG"
    expect_rc "installer exit status" "$LC_RC" 0
    (( LC_RC == 0 )) && lc_open_app_after_install
    lc_detach_dmg
    ext_active() { systemextensionsctl list 2>/dev/null | grep -i oftc | grep -q 'activated enabled'; }
    lc_activate
    if (( LC_APPROVAL )); then
      lc_info "approval requested: yes"
      human "approve the OFTC Network Extension in System Settings > General > Login Items & Extensions > Network Extensions" "an OFTC extension is 'activated enabled'" 300 ext_active
    fi
    lc_activate_finish
    for id in ${=PROFILES}; do lc_run "$cli" autostart "$id" on; expect_rc "autostart on for $id" "$LC_RC" 0; done
  else
    lc_info "--no-reinstall: the post phase checks extension cleanup only"
  fi
  lc_snapshot pre-reboot

  lc_step "marker, resume agent, reboot"
  if lc_live && (( LC_FAIL )); then
    lc_info "failures above: not arming the resume agent and not rebooting"
    exit 1
  fi
  args=(--phase post --yes --run-dir "$LC_RUN")
  [[ -n ${LIVECHECK_CONFIG:-} ]] && args+=(--config "$LIVECHECK_CONFIG")
  (( reinstall )) || args+=(--no-reinstall)
  if lc_live; then
    mkdir -p "$state_dir" "${plist:h}"
    { print "s5 pre-reboot done $(date '+%F %T') run=$LC_RUN"; print "reinstall=$reinstall"; } > "$marker"
    {
      print '<?xml version="1.0" encoding="UTF-8"?>'
      print '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
      print "<plist version=\"1.0\"><dict><key>Label</key><string>$label</string>"
      print '<key>ProgramArguments</key><array><string>/bin/zsh</string>'
      print "<string>$LC_HERE/s5-uninstall-reboot.sh</string>"
      for a in "${args[@]}"; do print "<string>${a//&/&amp;}</string>"; done
      print '</array><key>RunAtLoad</key><true/>'
      print '<key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin</string></dict>'
      print "<key>StandardOutPath</key><string>$LC_RUN/s5-resume.out</string><key>StandardErrorPath</key><string>$LC_RUN/s5-resume.out</string>"
      print '</dict></plist>'
    } > "$plist"
    plutil -lint "$plist" >/dev/null && lc_pass "resume LaunchAgent written: $plist (runs once at next login, deletes itself)" || lc_fail "resume plist is not valid"
    lc_info "marker: $marker (present until the post phase finishes)"
  else
    lc_dry "would write $marker and $plist (RunAtLoad: zsh s5-uninstall-reboot.sh ${args[*]})"
  fi
  lc_snapshot pre-reboot-final
  if (( do_reboot )); then
    lc_info "rebooting in one minute (to abort: sudo pkill shutdown, then re-run with --force). After the reboot, LOG IN: the resume agent then runs the post phase and writes $LC_RUN/summary.txt"
    lc_sudo shutdown -r +1
    expect_rc "reboot scheduled" "$LC_RC" 0
  else
    lc_info "--no-reboot: reboot this Mac yourself, then log in; the post phase runs from the LaunchAgent"
  fi
  exit 0
fi

# ---- phase post (after reboot and login, started by the LaunchAgent) ------------------------------
[[ $phase == post ]] || { print -u2 "unknown phase $phase"; exit 2; }
lc_step "post-reboot: resume"
if lc_live; then
  rm -f "$plist" && lc_info "resume agent plist removed first, so it cannot run twice"
  if [[ -e $marker ]]; then lc_pass "marker found; this is the resumed S5"; else lc_fail "no S5 marker: this is not a resumed run"; fi
fi
lc_snapshot post-reboot
wait_for "host service running after login" 120 5 host_up
if lc_live; then
  expect_eq "exactly one 'host serve' process" "$(host_pids | wc -w | tr -d ' ')" 1
  wait_for "extension list has no stale 'terminated waiting' entries" 60 5 no_stale
  if (( reinstall )); then
    expect_eq "one activated enabled extension" "$(ext_lines | grep -c 'activated enabled')" 1
    lc_poll 90 5 lc_any_connected && lc_info "connect-at-login connected without a prompt" || lc_info "no tunnel yet: connect-at-login should have opened the browser sign-in"
    for id in ${=PROFILES}; do
      lc_is_connected "$id" || human "complete the browser sign-in that connect-at-login opened for $id" "profile $id reports connected" "$SSO_TIMEOUT" lc_is_connected "$id"
      lc_refresh_status
      expect_eq "profile $id state after reboot" "$(lc_pfield "$id" state)" connected
      lc_run ping -c 10 -t 20 "$(lc_target_for "$id" PING_TARGETS)"
      expect_contains "traffic through $id after reboot" "$LC_OUT" " 0.0% packet loss"
    done
  else
    wait_for "no OFTC extension entries remain" 60 5 no_ext
  fi
  lc_snapdiff "$LC_RUN/S5-pre-reboot-final.snap" "$LC_RUN/S5-post-reboot.snap"
  if (( LC_FAIL == 0 )); then rm -f "$marker"; lc_info "marker removed: the run finished"; else lc_info "marker left in place because checks failed: $marker"; fi
  osascript -e 'display notification "S5 post-reboot checks finished; see the run directory summary" with title "OFTC livecheck"' >/dev/null 2>&1
fi
