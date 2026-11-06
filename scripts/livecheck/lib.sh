# Shared helpers for the livecheck stages. Source this from a stage script; never run it.
# See docs/livecheck.md. zsh, macOS only, nothing beyond what ships with macOS.
#
# Every external command is called by bare name (so the selftest's PATH shims stand in
# for the real tools) and every command that executes goes through lc_run, which prints
# it first. Nothing here reads, prints or logs a PSK or token.

setopt extendedglob
LC_HERE=${${(%):-%x}:A:h}
LC_DRY=0
LC_YES=0
LC_PASS=0
LC_FAIL=0
LC_INFO=0
LC_HUMANS=0
LC_OUT=''
LC_RC=0
LC_STAGE=''
LC_RUN=''
LC_LOG=''
LC_STATUS=''
typeset -ga LC_ARGS LC_FAILS LC_HUMAN_LOG LC_SCRUB
typeset -g LC_BUNDLE_ID=com.chris.openforticlient.oftc
# Seconds per poll tick are multiplied by this; the selftest sets 0 so no real time passes.
: "${LC_SLEEP_SCALE:=1}"

# ---- config ---------------------------------------------------------------------

# Defaults, overridden by the LIVECHECK_CONFIG file (NAME=value lines, never in the repo).
: "${APP:=/Applications/Open Forticlient.app}"
# Paths the selftest redirects (environment only, not config).
: "${OFTC_CLI:=/usr/local/bin/oftc}"
: "${OLD_APP:=/Applications/OFTC.app}"
: "${INSTALL_LOG:=/var/log/install.log}"
export OFTC_CLI
PROFILES=''          # space-separated profile ids the live stages exercise
PING_TARGETS=''      # id=address pairs: an address that only answers through that tunnel
TCP_TARGETS=''       # id=address:port pairs for a TCP check through the tunnel (optional)
SOAK_MINUTES=10
SOAK_INTERVAL=30     # seconds between soak probes
SSO_TIMEOUT=300      # seconds to wait for the human to finish a browser sign-in
NETWORK_SERVICE=''   # networksetup service name for the network-drop test; empty = ask a human
WIFI_DEVICE=''       # Wi-Fi device (en0 ...) for -setairportpower; empty = use NETWORK_SERVICE
DMG_PATH=''          # S4: the release DMG to install
EXPECT_VERSION=''    # S4: version the DMG should install (optional)
FAIL_PROFILE=''      # S6: id of a profile that cannot connect
FAIL_EXPECT_CODE='network_blocked'
FAIL_EXPECT_DETAIL='did not answer'   # substring of profiles[].error.detail
SLEEP_SECONDS=60     # S2: how long the Mac sleeps
DISCONNECT_WAIT=120  # S2: seconds a deliberate stop must stay stopped

LC_CONFIG_KEYS=(APP PROFILES PING_TARGETS TCP_TARGETS SOAK_MINUTES SOAK_INTERVAL SSO_TIMEOUT
  NETWORK_SERVICE WIFI_DEVICE DMG_PATH EXPECT_VERSION FAIL_PROFILE FAIL_EXPECT_CODE
  FAIL_EXPECT_DETAIL SLEEP_SECONDS DISCONNECT_WAIT)

# Parsed, never sourced: only the keys above are accepted, values are literal text.
lc_load_config() {
  local file=${LIVECHECK_CONFIG:-$HOME/.config/oftc/livecheck.env} line key val
  if [[ ! -f $file ]]; then
    lc_info "no config file at $file; using defaults"
    return 0
  fi
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z ${line//[[:space:]]/} || $line == [[:space:]]#'#'* ]] && continue
    key=${line%%=*}
    val=${line#*=}
    key=${key//[[:space:]]/}
    val=${val%%[[:space:]]#}
    val=${val##[[:space:]]#}
    if [[ $val == \"*\" || $val == \'*\' ]]; then val=${val[2,-2]}; fi
    if (( ${LC_CONFIG_KEYS[(Ie)$key]} )); then
      typeset -g "$key=$val"
    else
      lc_info "config: ignoring unknown key '$key'"
    fi
  done < "$file"
  export APP
  # Anything configured as an address or a profile id is scrubbed from the log.
  local pair
  LC_SCRUB=()
  for pair in ${=PING_TARGETS} ${=TCP_TARGETS}; do
    val=${pair#*=}; val=${val%%:*}
    [[ -n $val ]] && LC_SCRUB+=("$val")
  done
}

# ---- output and log ---------------------------------------------------------------

lc_scrub() {
  local s=$1 a
  s=${s//(#m)gateway=[^[:space:]]##/gateway=<gateway>}
  for a in "${LC_SCRUB[@]}"; do s=${s//$a/<addr>}; done
  print -r -- "$s"
}

lc_emit() {
  local tag=$1; shift
  local line
  line=$(lc_scrub "$tag $*")
  print -r -- "$line"
  [[ -n $LC_LOG ]] && print -r -- "$(date +%T) $line" >> "$LC_LOG"
  return 0
}

lc_step() { print; lc_emit "STEP" "$*"; }
lc_info() { (( LC_INFO++ )); lc_emit "INFO" "$*"; }
lc_pass() { (( LC_PASS++ )); lc_emit "PASS" "$*"; }
lc_fail() { (( LC_FAIL++ )); LC_FAILS+=("$*"); lc_emit "FAIL" "$*"; }
lc_dry()  { lc_emit "DRY " "$*"; }

lc_live() { (( ! LC_DRY )); }

# ---- running commands ---------------------------------------------------------------

# Prints the exact command, then runs it and captures stdout+stderr in LC_OUT and the
# exit status in LC_RC. In --dry-run it only prints. Always returns 0: callers assert.
lc_run() {
  if (( LC_DRY )); then lc_emit "DRY " "would run: $*"; LC_OUT=''; LC_RC=0; return 0; fi
  lc_emit "RUN " "$*"
  LC_OUT=$("$@" 2>&1)
  LC_RC=$?
  if [[ -n $LC_OUT ]]; then
    local l
    while IFS= read -r l; do lc_log_only "  | $l"; done <<< "${LC_OUT:0:4000}"
  fi
  lc_log_only "  = exit $LC_RC"
  return 0
}

lc_log_only() {
  [[ -n $LC_LOG ]] && print -r -- "$(date +%T) $(lc_scrub "$*")" >> "$LC_LOG"
  return 0
}

# Like lc_run, but through sudo. Needs the credential cached by S0 (`sudo -v`), so it
# never prompts mid-stage: -n fails instead of waiting for a password nobody sees.
lc_sudo() { lc_run sudo -n "$@"; }

lc_sleep() {
  # $1 seconds; scaled so the selftest does not wait.
  (( LC_SLEEP_SCALE == 0 )) && return 0
  sleep $(( $1 * LC_SLEEP_SCALE ))
}

# ---- assertions ---------------------------------------------------------------------

expect_eq() {   # desc actual expected
  if (( LC_DRY )); then lc_dry "would assert: $1 == '$3'"; return 0; fi
  if [[ $2 == "$3" ]]; then lc_pass "$1 (= $2)"; else lc_fail "$1: got '$2', expected '$3'"; fi
}

expect_contains() {   # desc haystack needle
  if (( LC_DRY )); then lc_dry "would assert: $1 contains '$3'"; return 0; fi
  if [[ $2 == *"$3"* ]]; then lc_pass "$1 (contains '$3')"; else lc_fail "$1: '$3' not found in: ${2:0:300}"; fi
}

expect_not_contains() {
  if (( LC_DRY )); then lc_dry "would assert: $1 lacks '$3'"; return 0; fi
  if [[ $2 != *"$3"* ]]; then lc_pass "$1 (no '$3')"; else lc_fail "$1: unexpected '$3' in: ${2:0:300}"; fi
}

expect_rc() {   # desc actual-rc expected-rc
  if (( LC_DRY )); then lc_dry "would assert: $1 exits $3"; return 0; fi
  if [[ $2 == "$3" ]]; then lc_pass "$1 (exit $2)"; else lc_fail "$1: exit $2, expected $3"; fi
}

expect_num_ge() {   # desc actual minimum
  if (( LC_DRY )); then lc_dry "would assert: $1 >= $3"; return 0; fi
  if [[ $2 == <-> ]] && (( $2 >= $3 )); then lc_pass "$1 ($2 >= $3)"; else lc_fail "$1: '$2' is not a number >= $3"; fi
}

# Polls "$@" every interval seconds until it succeeds or timeout seconds pass.
# Usage: wait_for "desc" timeout interval cmd [args...]. PASS/FAIL line either way.
wait_for() {
  local desc=$1 timeout=$2 interval=$3; shift 3
  if (( LC_DRY )); then lc_dry "would poll up to ${timeout}s (every ${interval}s) for: $desc"; return 0; fi
  lc_poll "$timeout" "$interval" "$@"
  if (( $? == 0 )); then lc_pass "$desc (after ${LC_POLLED}s)"; return 0; fi
  lc_fail "$desc: not observed within ${timeout}s"
  return 1
}

# Silent poll. Time is counted in ticks so a scaled-down selftest is deterministic.
lc_poll() {
  local timeout=$1 interval=$2; shift 2
  local ticks=$(( timeout / interval )) i=0
  (( ticks < 1 )) && ticks=1
  LC_POLLED=0
  while :; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    (( i >= ticks )) && return 1
    lc_sleep "$interval"
    (( i++ )); LC_POLLED=$(( i * interval ))
  done
}

# One clearly marked atomic request for a person, then poll for its observable result.
# The script never asks the person to report anything it can observe itself.
# Usage: human "what to do" "what the script will watch for" timeout cmd [args...]
human() {
  local ask=$1 observe=$2 timeout=$3; shift 3
  (( LC_HUMANS++ ))
  LC_HUMAN_LOG+=("$LC_STAGE: $ask")
  if (( LC_DRY )); then lc_dry "would ask a human (one act): $ask; then poll up to ${timeout}s for: $observe"; return 0; fi
  print -n '\a'
  lc_emit "HUMAN" ">>> ACTION REQUIRED (one act): $ask"
  lc_emit "HUMAN" "    The script is watching for: $observe (waits up to ${timeout}s). Nothing to report back."
  lc_poll "$timeout" 5 "$@"
  if (( $? == 0 )); then lc_pass "human act observed: $observe (after ${LC_POLLED}s)"; return 0; fi
  lc_fail "human act not observed within ${timeout}s: $observe"
  return 1
}

# ---- profiles and status ---------------------------------------------------------------

lc_cli() {
  if [[ -x $OFTC_CLI ]]; then print -r -- "$OFTC_CLI"
  elif [[ -x $APP/Contents/Helpers/oftc ]]; then print -r -- "$APP/Contents/Helpers/oftc"
  else print -r -- oftc; fi
}
lc_agent() { print -r -- "$APP/Contents/MacOS/OFTCAgent"; }

# Reads a key path from JSON on stdin. plutil ships with macOS and parses JSON.
lc_json() { plutil -extract "$1" raw -o - - 2>/dev/null; }

lc_refresh_status() {
  LC_STATUS=$("$(lc_cli)" status --json 2>/dev/null) || LC_STATUS=''
}

# Echoes one field of the profile with this id, from the last lc_refresh_status.
lc_pfield() {   # id keypath-under-profile
  local n i
  n=$(lc_json profiles <<< "$LC_STATUS") || return 1
  for (( i = 0; i < n; i++ )); do
    if [[ $(lc_json "profiles.$i.id" <<< "$LC_STATUS") == "$1" ]]; then
      lc_json "profiles.$i.$2" <<< "$LC_STATUS"
      return
    fi
  done
  return 1
}

lc_pstate() { lc_refresh_status; lc_pfield "$1" state; }
lc_is_connected() { [[ $(lc_pstate "$1") == connected ]]; }
lc_is_not_connected() { [[ $(lc_pstate "$1") != connected ]]; }
lc_any_connected() {
  local id
  lc_refresh_status
  for id in ${=PROFILES}; do [[ $(lc_pfield "$id" state) == connected ]] && return 0; done
  return 1
}
lc_none_connected() { ! lc_any_connected; }

lc_target_for() {   # id list-name(PING_TARGETS|TCP_TARGETS)
  local pair
  for pair in ${=${(P)2}}; do
    [[ ${pair%%=*} == "$1" ]] && { print -r -- "${pair#*=}"; return 0; }
  done
  return 1
}

# Succeeds when a ping through the tunnel shows 0% loss.
lc_ping_clean() {   # address [count]
  local out
  out=$(ping -c "${2:-5}" -t 15 "$1" 2>&1) || return 1
  [[ $out == *" 0.0% packet loss"* ]]
}

# Supervisor processes as "pid:pgid" pairs for the profiles' supervisors, sorted.
lc_supervisors() {
  ps -axo pid,ppid,pgid,command 2>/dev/null | awk '/supervise-profile/ && !/awk/ {print $1":"$3}' | sort
}

lc_log_lines() { local f="$HOME/Library/Logs/OFTC/$1.log"; [[ -f $f ]] && wc -l < "$f" | tr -d ' ' || print 0; }
lc_log_since() { local f="$HOME/Library/Logs/OFTC/$1.log"; [[ -f $f ]] && tail -n "+$(( $2 + 1 ))" "$f"; }

# ---- snapshots -------------------------------------------------------------------------

# Writes a snapshot to $LC_RUN/<stage>-<label>.snap and leaves its path in LC_SNAP.
lc_snapshot() {
  LC_SNAP="$LC_RUN/$LC_STAGE-$1.snap"
  lc_step "snapshot $1"
  if (( LC_DRY )); then lc_dry "would write $LC_SNAP"; return 0; fi
  zsh "$LC_HERE/snapshot.sh" "$LC_STAGE-$1" > "$LC_SNAP" 2>&1
  lc_info "snapshot written: $LC_SNAP ($(wc -l < "$LC_SNAP" | tr -d ' ') lines)"
}

# Shows what changed between two snapshots (compare.sh marks the lines that matter).
lc_snapdiff() {   # before after
  (( LC_DRY )) && { lc_dry "would compare $1 with $2"; return 0; }
  local out
  out=$(zsh "$LC_HERE/compare.sh" "$1" "$2" 2>&1)
  lc_info "snapshot diff $(basename "$1") -> $(basename "$2"):"
  while IFS= read -r l; do lc_emit "    " "$l"; done <<< "$out"
  LC_DIFF=$out
}

# ---- stage lifecycle ------------------------------------------------------------------------

lc_usage() {
  print -r -- "usage: $LC_STAGE_SCRIPT [--dry-run] [--yes] [--config FILE] [--run-dir DIR] ${LC_STAGE_USAGE:-}"
  print -r -- "  --dry-run  print what the stage would do; run nothing, touch nothing"
  print -r -- "  --yes      required by stages that change the system (S4, S5)"
}

# lc_init <stage-name> "$@" : guard against sourcing, parse common flags, open the log.
# Remaining arguments are left in LC_ARGS for the stage.
lc_init() {
  LC_STAGE=$1; shift
  if [[ $ZSH_EVAL_CONTEXT == *:file:* ]]; then
    print -u2 "livecheck stages are run by name, never sourced"; return 3
  fi
  LC_ARGS=()
  while (( $# )); do
    case $1 in
      --dry-run) LC_DRY=1 ;;
      --yes) LC_YES=1 ;;
      --config) LIVECHECK_CONFIG=$2; shift ;;
      --run-dir) LIVECHECK_RUN_DIR=$2; shift ;;
      -h|--help) lc_usage; exit 0 ;;
      *) LC_ARGS+=("$1") ;;
    esac
    shift
  done
  [[ $(uname -s) == Darwin ]] || { print -u2 "livecheck is macOS only"; exit 2; }
  if (( LC_DRY )); then
    LC_RUN=${LIVECHECK_RUN_DIR:-}
  else
    LC_RUN=${LIVECHECK_RUN_DIR:-${TMPDIR:-/tmp}/oftc-livecheck/$(date +%Y%m%d-%H%M%S)}
    (umask 077; mkdir -p "$LC_RUN") || { print -u2 "cannot create $LC_RUN"; exit 2; }
    chmod 700 "$LC_RUN"
    LC_LOG="$LC_RUN/$LC_STAGE.log"
  fi
  lc_emit "STAGE" "$LC_STAGE$( (( LC_DRY )) && print ' (dry run: nothing executes)')"
  lc_load_config
  if (( LC_DRY )); then   # a plan needs names to talk about; these are placeholders
    [[ -n $PROFILES ]] || { PROFILES='profile-a profile-b'; PING_TARGETS='profile-a=192.0.2.1 profile-b=198.51.100.1'; lc_info "dry run: placeholder profile ids"; }
    [[ -n $FAIL_PROFILE ]] || FAIL_PROFILE=profile-x
    [[ -n $DMG_PATH ]] || DMG_PATH=/path/to/OFTC.dmg
  fi
}

# Stages that change the system refuse to run without --yes (a dry run needs none).
lc_need_yes() {
  if (( ! LC_YES && ! LC_DRY )); then
    print -u2 "$LC_STAGE changes this Mac (installer / uninstall / reboot). Re-run with --yes, or --dry-run to see the plan."
    trap - EXIT
    exit 3
  fi
}

lc_finish() {
  local rc=$?
  trap - EXIT
  lc_run_cleanups
  print
  if (( LC_DRY )); then
    lc_emit "SUMMARY" "$LC_STAGE dry run: $LC_HUMANS human act(s) would be requested"
    exit 0
  fi
  local line="$LC_STAGE PASS=$LC_PASS FAIL=$LC_FAIL INFO=$LC_INFO HUMAN-ACTS=$LC_HUMANS"
  lc_emit "SUMMARY" "$line"
  local f
  for f in "${LC_FAILS[@]}"; do lc_emit "SUMMARY" "  FAILED: $f"; done
  print -r -- "$line$( ((LC_FAIL)) && print ' RESULT=FAIL' || print ' RESULT=OK')" >> "$LC_RUN/summary.txt"
  for f in "${LC_HUMAN_LOG[@]}"; do print -r -- "  human: $f" >> "$LC_RUN/summary.txt"; done
  lc_emit "SUMMARY" "log: $LC_LOG"
  (( LC_FAIL )) && exit 1
  exit $rc
}

# Convenience for the "is this a stub in the selftest" question: none. Stages never ask.

# ---- sudo, cleanup, private scratch ----------------------------------------------------------

# The one admin-password act. sudo prompts on the terminal itself (so its prompt is
# visible), then every later lc_sudo uses the cached credential with -n.
lc_sudo_prime() {
  if (( LC_DRY )); then lc_dry "would ask a human (one act): type the admin password at the sudo prompt (sudo -v)"; (( LC_HUMANS++ )); LC_HUMAN_LOG+=("$LC_STAGE: admin password at the sudo prompt"); return 0; fi
  if sudo -n true 2>/dev/null; then lc_pass "sudo credential already cached"; return 0; fi
  (( LC_HUMANS++ )); LC_HUMAN_LOG+=("$LC_STAGE: admin password at the sudo prompt")
  lc_emit "HUMAN" ">>> ACTION REQUIRED (one act): type your admin password at the sudo prompt below"
  lc_emit "RUN " "sudo -v"
  sudo -v
  if sudo -n true 2>/dev/null; then lc_pass "sudo credential cached"; else lc_fail "sudo credential not cached; stage cannot continue"; exit 1; fi
  if (( LC_SLEEP_SCALE != 0 )); then
    ( while :; do sleep 45; sudo -n true 2>/dev/null || exit 0; done ) &
    LC_KEEPALIVE=$!
  fi
}

# A stage registers one function here; lc_finish runs it (restore the network, detach a DMG).
typeset -ga LC_CLEANUP_FNS
lc_on_exit() { LC_CLEANUP_FNS+=("$1"); }
lc_run_cleanups() {
  local fn
  [[ -n ${LC_KEEPALIVE:-} ]] && kill "$LC_KEEPALIVE" 2>/dev/null
  (( LC_DRY )) && return 0
  for fn in "${(@Oa)LC_CLEANUP_FNS}"; do "$fn"; done
}

# ---- DMG, package, installer, screenshots -------------------------------------------------------

# Like lc_run but the command keeps the terminal (a sudo or password prompt must be
# visible); its output is shown, appended to the log and left in LC_OUT.
lc_run_tty() {
  if (( LC_DRY )); then lc_emit "DRY " "would run: $*"; LC_OUT=''; LC_RC=0; return 0; fi
  lc_emit "RUN " "$*"
  local tmp
  tmp=$(mktemp "$LC_RUN/tty.XXXXXX")
  "$@" 2>&1 | tee "$tmp"
  LC_RC=${pipestatus[1]}
  LC_OUT=$(cat "$tmp")
  lc_log_only "  | ${LC_OUT:0:3000}"
  lc_log_only "  = exit $LC_RC"
  rm -f "$tmp"
  return 0
}

LC_MNT=''
LC_PKG=''
lc_detach_dmg() {
  [[ -n $LC_MNT ]] || return 0
  lc_run hdiutil detach "$LC_MNT"
  LC_MNT=''
}

# Mounts a DMG read-only at a directory this run owns and finds its single .pkg.
lc_attach_dmg() {   # dmg
  LC_MNT="$LC_RUN/mnt"
  (( LC_DRY )) && LC_MNT='<run-dir>/mnt'
  lc_live && { mkdir -p "$LC_MNT" || { lc_fail "cannot create $LC_MNT"; LC_MNT=''; return 1; }; }
  lc_run hdiutil attach -nobrowse -readonly -mountpoint "$LC_MNT" "$1"
  if lc_live; then
    expect_rc "DMG mounted" "$LC_RC" 0
    (( LC_RC == 0 )) || { LC_MNT=''; return 1; }
    lc_on_exit lc_detach_dmg
    local pkgs; pkgs=("$LC_MNT"/*.pkg(N))
    if (( ${#pkgs} == 1 )); then LC_PKG=$pkgs[1]; lc_pass "one package in the DMG: ${LC_PKG:t}"
    else lc_fail "expected exactly one .pkg in the DMG, found ${#pkgs}"; return 1; fi
  else
    LC_PKG='<mounted>/OFTC.pkg'
  fi
}

# The signature, Gatekeeper and notarization-ticket evidence for a package.
lc_verify_pkg() {   # pkg
  lc_run pkgutil --check-signature "$1"
  expect_contains "package signature chain" "$LC_OUT" "Developer ID Installer"
  expect_contains "package signature status" "$LC_OUT" "signed by a developer certificate issued by Apple"
  lc_run spctl --assess --type install -vv "$1"
  expect_contains "Gatekeeper accepts the package" "$LC_OUT" "accepted"
  expect_contains "package is notarized" "$LC_OUT" "Notarized Developer ID"
  lc_run stapler validate "$1"
  expect_contains "notarization ticket stapled" "$LC_OUT" "The validate action worked"
}

# Installs a package; the evidence is the installer's own exit status and output.
lc_install_pkg() {   # pkg
  lc_sudo installer -pkg "$1" -target /
}

LC_SHOTN=0
# Numbered screenshot of the main display into the run directory, for a reviewer to look at.
lc_shot() {   # name
  (( LC_SHOTN++ ))
  local f; f=$(printf '%s/shots/%02d-%s.png' "$LC_RUN" "$LC_SHOTN" "$1")
  if (( LC_DRY )); then lc_dry "would capture screenshot $f"; return 0; fi
  mkdir -p "$LC_RUN/shots"
  lc_run screencapture -x "$f"
  [[ -s $f ]] && lc_info "screenshot: $f" || lc_fail "screenshot $1 was not written (Screen Recording permission for the terminal?)"
}
