#!/bin/zsh
# S7 screenshots at named moments, into <run-dir>/shots, for a reviewer to look at. Needs
# Screen Recording permission for the terminal. One human act: open the menu popover.
set -u
setopt pipefail
source "${${(%):-%x}:A:h}/lib.sh"
LC_STAGE_SCRIPT=s7-screenshots.sh
lc_init S7 "$@" || exit $?
trap lc_finish EXIT
cli=$(lc_cli)
[[ -n $PROFILES ]] || { lc_fail "PROFILES is not configured"; exit 1; }

# A hash of the strip below the menu bar where the popover opens. The popover changing it
# is the observable result of the human's click.
region_hash() {
  local b w f
  b=$(osascript -e 'tell application "Finder" to get bounds of window of desktop' 2>/dev/null) || return 1
  w=${${(s:, :)b}[3]}
  [[ $w == <-> ]] || return 1
  f=$(mktemp "$LC_RUN/region.XXXXXX") || return 1
  screencapture -x -R "$(( w - 420 )),30,420,520" -t png "$f" 2>/dev/null || { rm -f "$f"; return 1; }
  shasum "$f" | awk '{print $1}'
  rm -f "$f"
}
popover_open() { [[ $(region_hash) != "$baseline" ]]; }
all_up() { local i; lc_refresh_status; for i in ${=PROFILES}; do [[ $(lc_pfield "$i" state) == connected ]] || return 1; done; }
all_down() { local i s; lc_refresh_status; for i in ${=PROFILES}; do s=$(lc_pfield "$i" state); [[ $s == disconnected ]] || return 1; done; }

lc_step "baseline"
baseline=''
lc_live && baseline=$(region_hash)
lc_shot desktop-baseline
lc_step "popover, connected"
human "click the OFTC icon in the menu bar so the popover is open, and leave it open" "the screen region under the menu bar changes" 120 popover_open
lc_sleep 3
lc_shot popover-connected
lc_step "popover, disconnected"
lc_run "$cli" disconnect
wait_for "every profile disconnected" 60 3 all_down
lc_sleep 3
lc_shot popover-disconnected
lc_step "popover, reconnected"
lc_run "$cli" connect
for id in ${=PROFILES}; do
  human "complete the browser sign-in for $id" "profile $id reports connected" "$SSO_TIMEOUT" lc_is_connected "$id"
done
lc_sleep 5
lc_shot popover-reconnected
lc_info "review the images in $LC_RUN/shots; close the popover when done"
