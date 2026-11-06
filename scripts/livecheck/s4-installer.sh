#!/bin/zsh
# S4 installer: verify the DMG's package, prove the installer refuses while a tunnel is up,
# install it, and assert the bundle, extension, receipts, profiles, PSK presence, pins,
# auto-start and host service all came through. CHANGES THIS MAC: needs --yes.
#   zsh s4-installer.sh --yes [--dmg PATH] [--skip-guard] [--reconnect]
set -u
setopt pipefail
source "${${(%):-%x}:A:h}/lib.sh"
LC_STAGE_SCRIPT=s4-installer.sh
LC_STAGE_USAGE='[--dmg PATH] [--skip-guard] [--reconnect]'
lc_init S4 "$@" || exit $?
trap lc_finish EXIT
lc_need_yes
dmg=$DMG_PATH
(( ${LC_ARGS[(Ie)--dmg]} )) && dmg=${LC_ARGS[$(( ${LC_ARGS[(Ie)--dmg]} + 1 ))]}
skip_guard=$(( ${LC_ARGS[(Ie)--skip-guard]} ? 1 : 0 ))
reconnect=$(( ${LC_ARGS[(Ie)--reconnect]} ? 1 : 0 ))
[[ -n $dmg ]] || { lc_fail "no DMG: set DMG_PATH or pass --dmg"; exit 1; }
cli=$(lc_cli); agent=$(lc_agent)
guard_re='^/Applications/(OFTC|Open Forticlient)\.app/Contents/MacOS/OFTCAgent([[:space:]]|$)'

host_pids() { ps -axo pid,command 2>/dev/null | awk '/OFTCAgent host serve/ && !/awk/ {print $1}' | sort | tr '\n' ' '; }
host_pid_changed() { local now; now=$(host_pids); [[ -n $now && $now != "$1" ]]; }
app_version() { /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist" 2>/dev/null; }
app_build() { /usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP/Contents/Info.plist" 2>/dev/null; }
none_matches_guard() { ! pgrep -f "$guard_re" >/dev/null 2>&1; }
user_lines() { grep -E '^(profile#|profile dirs:|pins:|logs:)' "$1" | sed -E 's/logs: [0-9]+ files/logs/'; }

lc_snapshot before
snap_before=$LC_SNAP
lc_step "plan"
lc_info "the only commands this stage runs as root: installer -pkg <pkg from the DMG> -target / (once to prove the refusal, once to install)"
lc_sudo_prime

lc_step "mount and verify the package"
ver_before=''; build_before=''; hp_before=''
if lc_live; then ver_before=$(app_version); build_before=$(app_build); hp_before=$(host_pids); fi
lc_info "installed before: ${ver_before:-none} build ${build_before:-none}; host pid(s) before: ${hp_before:-none}"
lc_attach_dmg "$dmg" || exit 1
lc_verify_pkg "$LC_PKG"

lc_step "installer guard with a tunnel connected"
if (( skip_guard )); then
  lc_info "--skip-guard: not testing the refusal"
elif lc_live && lc_none_connected; then
  lc_fail "guard test needs a connected tunnel (run S1 --connect first, or pass --skip-guard)"
else
  lc_install_pkg "$LC_PKG"
  if lc_live; then
    expect_eq "installer exit status is nonzero (refused)" "$([[ $LC_RC != 0 ]] && print refused || print ran)" refused
    expect_eq "bundle version unchanged by the refused install" "$(app_version)" "$ver_before"
    lc_run tail -n 400 "$INSTALL_LOG"
    reason=$(print -r -- "$LC_OUT" | grep -oE 'OFTC is running|An OFTC VPN is active' | tail -1)
    [[ -n $reason ]] && lc_pass "preinstall refusal recorded in install.log: $reason" || lc_fail "no OFTC refusal message found in install.log"
    lc_run pgrep -fl "$guard_re"
    lc_info "processes the preinstall guard matches (any OFTCAgent: menu, supervisors and the host service all match): ${LC_OUT//$'\n'/; }"
  fi
fi

lc_step "get out of the way: disconnect, quit the menu app"
lc_run "$cli" disconnect
wait_for "no OFTC VPN connected" 60 3 lc_none_connected
lc_run "$agent" quit-menu
if lc_live; then
  if lc_poll 30 2 none_matches_guard; then lc_pass "no process matches the preinstall guard"
  else
    lc_fail "a process still matches the preinstall guard, so a real install will be refused as 'OFTC is running'"
    lc_run pgrep -fl "$guard_re"
    lc_info "matching processes: ${LC_OUT//$'\n'/; }"
  fi
fi

lc_step "install"
lc_install_pkg "$LC_PKG"
installed=0
if lc_live; then
  expect_rc "installer exit status" "$LC_RC" 0
  expect_contains "installer says it succeeded" "$LC_OUT" "The install was successful"
  (( LC_RC == 0 )) && installed=1
fi
if (( installed )) || (( LC_DRY )); then
  lc_step "bundle after install"
  if lc_live; then
    ver_after=$(app_version); build_after=$(app_build)
    lc_info "installed after: $ver_after build $build_after"
    [[ -n $EXPECT_VERSION ]] && expect_eq "installed version is the DMG's" "$ver_after" "$EXPECT_VERSION"
    [[ $build_after != "$build_before" ]] && lc_pass "bundle replaced (build $build_before -> $build_after)" || lc_info "same build as before: a reinstall, not an upgrade"
    expect_eq "Frameworks directories in the bundle" "$(find "$APP" -name Frameworks -maxdepth 6 2>/dev/null | wc -l | tr -d ' ')" 0
    [[ ! -e $OLD_APP ]] && lc_pass "no old OFTC.app left" || lc_fail "$OLD_APP still exists"
  else
    lc_dry "would assert version, build change, no Frameworks directory, no old OFTC.app"
  fi
  lc_run codesign --verify --deep --strict "$APP"
  expect_rc "codesign verify" "$LC_RC" 0
  lc_run spctl --assess --type execute "$APP"
  expect_rc "Gatekeeper accepts the app" "$LC_RC" 0
  lc_run pkgutil --pkgs
  if lc_live; then
    rcpt=$(print -r -- "$LC_OUT" | grep -i openforticlient || true)
    [[ -n $rcpt ]] && lc_pass "installer receipt present: $rcpt" || lc_fail "no OFTC installer receipt"
    for r in ${=rcpt}; do lc_run pkgutil --pkg-info "$r"; lc_info "receipt $r: $(print -r -- "$LC_OUT" | grep '^version' | tr '\n' ' ')"; done
  fi

  lc_step "system extension replaced"
  lc_run systemextensionsctl list
  if lc_live; then
    ext_active() { systemextensionsctl list 2>/dev/null | grep -i oftc | grep "$build_after" | grep -q 'activated enabled'; }
    if ext_active; then
      lc_info "approval requested: no (the new build's extension is already activated enabled)"
    else
      lc_run "$agent" activate
      if [[ $LC_OUT == *"approval required"* ]]; then
        lc_info "approval requested: yes (OFTCAgent activate reported macOS approval required)"
        human "approve the OFTC Network Extension in System Settings > General > Login Items & Extensions > Network Extensions" "extension build $build_after is 'activated enabled'" 300 ext_active
      elif [[ $LC_RC == 3 ]]; then
        lc_info "extension replacement accepted but a reboot is required (activate exit 3); S5 finishes the cleanup"
      else
        wait_for "extension build $build_after is 'activated enabled'" 60 3 ext_active
      fi
    fi
    lc_run systemextensionsctl list
    lc_info "extension entries now: $(print -r -- "$LC_OUT" | grep -i oftc | sed -E 's/[[:space:]]+/ /g' | tr '\n' ';')"
  fi

  lc_step "profiles, PSK presence, pins, auto-start, host service survived"
  lc_snapshot after
  if lc_live; then
    expect_eq "profiles, PSK presence, auto-start, transport and pins" "$(user_lines "$LC_SNAP")" "$(user_lines "$snap_before")"
    [[ -z $hp_before ]] && lc_info "host service was not running before: cannot assert it was kickstarted" || wait_for "postinstall kickstarted the host service (new pid)" 60 2 host_pid_changed "$hp_before"
  else
    lc_dry "would compare profiles, PSK presence, auto-start, pins before/after and assert the host pid changed"
  fi
  if (( reconnect )); then
    lc_step "reconnect (--reconnect)"
    lc_run "$cli" connect
    for id in ${=PROFILES}; do
      human "complete the browser sign-in for $id" "profile $id reports connected" "$SSO_TIMEOUT" lc_is_connected "$id"
      lc_live && { lc_run ping -c 5 -t 15 "$(lc_target_for "$id" PING_TARGETS)"; expect_contains "traffic through $id after the upgrade" "$LC_OUT" " 0.0% packet loss"; }
    done
  fi
else
  lc_info "install did not succeed; the after-install assertions are skipped"
  lc_snapshot after
fi
lc_snapdiff "$snap_before" "$LC_SNAP"
