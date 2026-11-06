#!/bin/zsh
# S0 preflight: sudo, disk, versions, install state, extensions, nothing connected
# (or, with --expect-connected, everything configured connected). Read-only apart from
# `sudo -v`. Run by name:  zsh scripts/livecheck/s0-preflight.sh [--dry-run]
set -u
setopt pipefail
source "${${(%):-%x}:A:h}/lib.sh"
LC_STAGE_SCRIPT=s0-preflight.sh
LC_STAGE_USAGE='[--expect-connected]'
lc_init S0 "$@" || exit $?
trap lc_finish EXIT
expect_connected=0
[[ ${LC_ARGS[(Ie)--expect-connected]} != 0 ]] && expect_connected=1

lc_step "admin credential"
lc_sudo_prime

lc_step "machine"
lc_run sw_vers -productVersion; lc_info "macOS $LC_OUT"
lc_run uname -m; lc_info "arch $LC_OUT"
lc_run df -k /
avail_gb=$(print -r -- "$LC_OUT" | awk 'NR==2 {printf "%d", $4/1048576}')
expect_num_ge "free disk on / in GB" "${avail_gb:-0}" 5

lc_step "installed build"
if lc_live && [[ -d $APP ]]; then
  ver=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist" 2>/dev/null)
  bld=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP/Contents/Info.plist" 2>/dev/null)
  lc_info "app installed: version $ver build $bld"
  pver=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP"/Contents/Library/SystemExtensions/*/Contents/Info.plist(N[1]) 2>/dev/null)
  lc_info "bundled provider build: ${pver:-unknown}"
  lc_run "$(lc_cli)" --version; lc_info "cli: $LC_OUT"
elif lc_live; then
  lc_info "app not installed at $APP (expected for a clean-install run of S4)"
else
  lc_dry "would read the installed app version, provider build and oftc --version"
fi

lc_step "system extension"
lc_run systemextensionsctl list
if lc_live; then
  oftc_ext=$(print -r -- "$LC_OUT" | grep -i oftc || true)
  lc_info "oftc extension entries: $(print -r -- "$oftc_ext" | grep -c . || true)"
  expect_not_contains "no stale 'terminated waiting to uninstall' extension" "$oftc_ext" "terminated waiting"
fi

lc_step "connection state"
lc_run scutil --nc list
if lc_live; then
  nconn=$(print -r -- "$LC_OUT" | grep "$LC_BUNDLE_ID" | grep -c '(Connected)' || true)
  if (( expect_connected )); then
    expect_num_ge "OFTC VPNs connected" "$nconn" 1
  else
    expect_eq "OFTC VPNs connected (stage wants none)" "$nconn" 0
  fi
fi

lc_step "host service"
lc_run launchctl print "gui/$(id -u)/$LC_BUNDLE_ID.host"
if lc_live; then
  (( LC_RC == 0 )) && lc_info "host service is loaded in the gui domain" || lc_info "host service is not loaded (not registered, or an old build)"
fi

lc_step "configuration"
if lc_live; then
  [[ -n $PROFILES ]] && lc_pass "PROFILES configured: ${#${=PROFILES}} profile(s)" || lc_info "PROFILES empty: S1, S2, S3 and S6 need it"
  for id in ${=PROFILES}; do
    lc_target_for "$id" PING_TARGETS >/dev/null && lc_pass "ping target set for profile $id" || lc_fail "no PING_TARGETS entry for profile $id"
  done
  [[ -z $DMG_PATH || -f $DMG_PATH ]] && lc_pass "DMG_PATH ok or unset" || lc_fail "DMG_PATH does not exist"
else
  lc_dry "would check PROFILES, PING_TARGETS and DMG_PATH"
fi

lc_snapshot start
lc_snapshot end
lc_snapdiff "$LC_RUN/S0-start.snap" "$LC_RUN/S0-end.snap"
