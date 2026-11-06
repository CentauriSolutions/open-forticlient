# Shared helpers for the livecheck stages. Source this from a stage script; never run it.
# See docs/livecheck.md. zsh, macOS only, nothing beyond what ships with macOS.
#
# Every external command is called by bare name (so the selftest's PATH shims stand in
# for the real tools) and every command that executes goes through lc_run, which prints
# it first. Nothing here reads, prints or logs a PSK or token.

setopt extendedglob
zmodload -F zsh/datetime b:strftime p:EPOCHSECONDS
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

# Terminal output is raw (the operator needs the ids); the log and summary are scrubbed:
# cheaply per line here, and by lc_scrub_files (profile ids, every IPv4 address) at the end.
lc_emit() {
  local tag=$1; shift
  print -r -- "$tag $*"
  [[ -n $LC_LOG ]] && print -r -- "$(strftime %T $EPOCHSECONDS) $(lc_scrub "$tag $*")" >> "$LC_LOG"
  return 0
}

# One sed pass over the run's log and summary: profile ids become <profile-N>, any IPv4
# address becomes <ip>, gateway= values are masked. Idempotent.
lc_scrub_files() {
  local id n=0 script='' f
  for id in ${=PROFILES} $FAIL_PROFILE; do
    (( n++ ))
    [[ $id == [a-z0-9-]## ]] && script+="s/[[:<:]]${id}[[:>:]]/<profile-$n>/g;"
  done
  script+='s/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/<ip>/g;s/gateway=[^ ]+/gateway=<gateway>/g'
  for f in "$LC_LOG" "$LC_RUN/summary.txt" "$LC_RUN/activate.out" "$LC_RUN/s5-resume.out"; do
    [[ -f $f ]] && sed -E -i '' "$script" "$f"
  done
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
  local quiet=0
  [[ ${1:-} == -q ]] && { quiet=1; shift; }   # -q: output is used but never logged
  if (( LC_DRY )); then lc_emit "DRY " "would run: $*"; LC_OUT=''; LC_RC=0; return 0; fi
  lc_emit "RUN " "$*"
  LC_OUT=$("$@" 2>&1)
  LC_RC=$?
  if (( quiet )); then
    lc_log_only "  (output not logged)"
  elif [[ -n $LC_OUT ]]; then
    local l
    while IFS= read -r l; do lc_log_only "  | $l"; done <<< "${LC_OUT:0:4000}"
  fi
  lc_log_only "  = exit $LC_RC"
  return 0
}

lc_log_only() {
  [[ -n $LC_LOG ]] && print -r -- "$(strftime %T $EPOCHSECONDS) $(lc_scrub "$*")" >> "$LC_LOG"
  return 0
}

# Like lc_run, but through sudo. Needs the credential cached by S0 (`sudo -v`), so it
# never prompts mid-stage: -n fails instead of waiting for a password nobody sees.
lc_sudo() { lc_run sudo -n "$@"; }
lc_sudoq() { lc_run -q sudo -n "$@"; }

lc_sleep() {
  # $1 seconds; scaled so the selftest does not wait; nothing waits in a dry run.
  (( LC_SLEEP_SCALE == 0 || LC_DRY )) && return 0
  sleep $(( $1 * LC_SLEEP_SCALE ))
}

# ---- assertions ---------------------------------------------------------------------

expect_eq() {   # desc actual expected
  if (( LC_DRY )); then lc_dry "would assert: $1 == '$3'"; return 0; fi
  if [[ $2 == "$3" ]]; then lc_pass "$1 (= $2)"; else lc_fail "$1: got '$2', expected '$3'"; fi
}

expect_contains() {   # desc haystack needle
  if (( LC_DRY )); then lc_dry "would assert: $1 contains '$3'"; return 0; fi
  if [[ $2 == *"$3"* ]]; then lc_pass "$1 (contains '$3')"; else lc_fail "$1: '$3' not found (${#2} bytes of output, not shown)"; fi
}

expect_not_contains() {
  if (( LC_DRY )); then lc_dry "would assert: $1 lacks '$3'"; return 0; fi
  if [[ $2 != *"$3"* ]]; then lc_pass "$1 (no '$3')"; else lc_fail "$1: unexpected '$3' found (output not shown)"; fi
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

# True when the last status read parsed. An older CLI has no `status --json`, so the
# state cannot be read at all: that is not the same as "no tunnel is connected".
lc_state_readable() { lc_refresh_status; [[ -n $LC_STATUS ]] && lc_json profiles <<< "$LC_STATUS" >/dev/null; }

# expect_pstate id value: asserts a profile state, or reports INFO when state is unreadable.
expect_pstate() {
  local id=$1 want=$2 desc=$3
  if lc_state_readable; then expect_eq "$desc" "$(lc_pfield "$id" state)" "$want"
  else lc_info "SKIP $desc: tunnel state cannot be read (this CLI has no working 'status --json')"; fi
}

# True when every configured profile has been set up: its state is not `setup` and, when the
# document reports a component, the component is ready. After a clean uninstall and reinstall
# the VPN configurations are gone ("OFTC configuration absent") until the app's setup repairs them.
lc_all_configured() {
  local id s c
  lc_state_readable || return 1
  c=$(lc_json component.state <<< "$LC_STATUS")
  [[ -z $c || $c == ready ]] || return 1
  for id in ${=PROFILES}; do
    s=$(lc_pfield "$id" state)
    [[ -n $s && $s != setup ]] || return 1
  done
  return 0
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
  local flags=(${LC_STAGE_FLAGS[@]:-}) opts=(${LC_STAGE_OPTS[@]:-})
  while (( $# )); do
    case $1 in
      --dry-run) LC_DRY=1 ;;
      --yes) LC_YES=1 ;;
      --config|--run-dir)
        (( $# >= 2 )) || { print -u2 "$1 needs a value"; exit 2; }
        if [[ $1 == --config ]]; then LIVECHECK_CONFIG=$2; else LIVECHECK_RUN_DIR=$2; fi; shift ;;
      -h|--help) lc_usage; exit 0 ;;
      *)
        if (( ${flags[(Ie)$1]} )); then LC_ARGS+=("$1")
        elif (( ${opts[(Ie)$1]} )); then
          (( $# >= 2 )) || { print -u2 "$1 needs a value"; exit 2; }
          LC_ARGS+=("$1" "$2"); shift
        else print -u2 "unknown argument '$1'"; lc_usage >&2; exit 2; fi ;;
    esac
    shift
  done
  [[ $(uname -s) == Darwin ]] || { print -u2 "livecheck is macOS only"; exit 2; }
  if (( LC_DRY )); then
    LC_RUN=${LIVECHECK_RUN_DIR:-}
  else
    LC_RUN=${LIVECHECK_RUN_DIR:-${TMPDIR:-/tmp}/oftc-livecheck/$(date +%Y%m%d-%H%M%S)}
    if [[ -d $LC_RUN ]]; then
      # An existing --run-dir is only reused if it is ours and already private.
      [[ -O $LC_RUN && ! -L $LC_RUN && $(stat -f %Lp "$LC_RUN") == 700 ]] || { print -u2 "$LC_RUN exists and is not a private (0700) directory of yours"; exit 2; }
    else
      (umask 077; mkdir -p "$LC_RUN") || { print -u2 "cannot create $LC_RUN"; exit 2; }
      chmod 700 "$LC_RUN"
    fi
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
    print -u2 "$LC_STAGE changes this Mac. Re-run with --yes, or --dry-run to see the plan."
    LC_ABORT_QUIET=1
    exit 3
  fi
}

lc_finish() {
  local rc=$?
  trap - EXIT
  (( ${LC_ABORT_QUIET:-0} )) && exit $rc
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
  lc_emit "SUMMARY" "log: $LC_LOG (private: profile ids and addresses are masked in it, but review before sharing)"
  lc_scrub_files
  (( ${LC_SUDO_PRIMED:-0} )) && sudo -k 2>/dev/null   # drop the credential only if this run asked for it
  (( LC_FAIL )) && exit 1
  exit $rc
}

# Convenience for the "is this a stub in the selftest" question: none. Stages never ask.

# ---- sudo, cleanup, private scratch ----------------------------------------------------------

# The one admin-password act. sudo prompts on the terminal itself (so its prompt is
# visible), then every later lc_sudo uses the cached credential with -n.
lc_sudo_prime() {
  if (( LC_DRY )); then lc_dry "would ask a human (one act): type the admin password at the sudo prompt (sudo -v)"; (( LC_HUMANS++ )); LC_HUMAN_LOG+=("$LC_STAGE: admin password at the sudo prompt"); return 0; fi
  if sudo -n true 2>/dev/null; then
    lc_pass "sudo credential already cached"
  else
    (( LC_HUMANS++ )); LC_HUMAN_LOG+=("$LC_STAGE: admin password at the sudo prompt")
    lc_emit "HUMAN" ">>> ACTION REQUIRED (one act): type your admin password at the sudo prompt below"
    lc_emit "RUN " "sudo -v"
    sudo -v
    LC_SUDO_PRIMED=1
    if sudo -n true 2>/dev/null; then lc_pass "sudo credential cached"; else lc_fail "sudo credential not cached; stage cannot continue"; exit 1; fi
  fi
  if (( LC_SLEEP_SCALE != 0 )); then
    # Refreshes the credential only while this script is alive: it ends when the parent is gone.
    local parent=$$
    ( while kill -0 "$parent" 2>/dev/null; do sleep 45; sudo -n true 2>/dev/null || exit 0; done ) &
    LC_KEEPALIVE=$!
  fi
}

# A stage registers one function here; lc_finish runs it (restore the network, detach a DMG).
typeset -ga LC_CLEANUP_FNS
lc_on_exit() { LC_CLEANUP_FNS+=("$1"); }
lc_run_cleanups() {
  local fn
  [[ -n ${LC_KEEPALIVE:-} ]] && kill "$LC_KEEPALIVE" 2>/dev/null
  [[ -n ${LC_ACT_PID:-} ]] && kill "$LC_ACT_PID" 2>/dev/null
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
  lc_log_only "  (output shown on the terminal, not logged)"
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
# ---- the product's system extension and Login Items records -----------------------------------
# Other products' extensions can be on the same Mac (a leftover test provider, say), so every
# extension check selects by the provider's bundle id, never by the word "oftc".
LC_PROVIDER_ID="$LC_BUNDLE_ID.provider"
lc_ext_lines() { systemextensionsctl list 2>/dev/null | grep -F "$LC_PROVIDER_ID (" || true; }
# Build of the bundled provider (it need not equal the host's); systemextensionsctl lists it as (ver/build).
lc_provider_build() { /usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP"/Contents/Library/SystemExtensions/*/Contents/Info.plist(N[1]) 2>/dev/null; }
lc_provider_active() {   # [build]: our provider, at this build if given, is 'activated enabled'
  local l; l=$(lc_ext_lines)
  [[ -n ${1:-} ]] && l=$(grep -F "/$1)" <<< "$l" || true)
  grep -q 'activated enabled' <<< "$l"
}
# From a `sfltool dumpbtm` dump on stdin: the file URLs of the entries that belong to this app.
# An entry starts at a "#N:" line; its identifier and URL lines may come in any order.
lc_btm_oftc_urls() {
  awk -v id="$LC_BUNDLE_ID" '
    /^ *#[0-9]+:/ { if (hit && url != "") print url; hit = 0; url = ""; next }
    index($0, id) { hit = 1 }
    /^ *URL:/ { u = $0; sub(/^ *URL: */, "", u); url = u }
    END { if (hit && url != "") print url }'
}
# Prints the paths those entries point at that no longer exist.
lc_btm_missing_paths() {
  local url p
  lc_btm_oftc_urls | while IFS= read -r url; do
    p=${url#file://}; p=${p//\%20/ }; p=${p%/}
    [[ -e $p ]] || print -r -- "$p"
  done
}

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

# True when the Mac has a default route (a network is up).
lc_has_network() { route -n get default >/dev/null 2>&1; }

# Seconds since the epoch; a seam so the selftest can jump the clock.
lc_now() { date +%s; }

# Waits for the Mac to really suspend, by watching for a jump in the wall clock between
# one-second ticks (`pmset sleepnow` returns before the machine sleeps, and the script
# is frozen while it does). Succeeds with the length of the jump in LC_SLEPT.
lc_detect_sleep() {   # max-ticks
  local prev now i
  prev=${LC_T0:-$(lc_now)}; LC_SLEPT=0
  for (( i = 0; i < $1; i++ )); do
    lc_sleep 1
    now=$(lc_now)
    if (( now - prev > 10 )); then LC_SLEPT=$(( now - prev )); return 0; fi
    prev=$now
  done
  return 1
}

# `OFTCAgent activate` waits for the user's approval with no timeout of its own, so it
# runs in the background; its output goes to a file in the run dir. Returns once the
# approval request appears (LC_APPROVAL=1) or the command finished (LC_APPROVAL=0).
lc_activate() {
  LC_APPROVAL=0; LC_ACT_PID=''
  if (( LC_DRY )); then lc_dry "would run in the background: $(lc_agent) activate, watching for the approval request"; return 0; fi
  local f="$LC_RUN/activate.out" i
  lc_emit "RUN " "$(lc_agent) activate (background; output kept in the run dir, not the log)"
  "$(lc_agent)" activate > "$f" 2>&1 &
  LC_ACT_PID=$!
  for (( i = 0; i < 120; i++ )); do
    grep -q 'approval required' "$f" 2>/dev/null && { LC_APPROVAL=1; return 0; }
    kill -0 "$LC_ACT_PID" 2>/dev/null || return 0
    lc_sleep 1
  done
  lc_fail "activate neither finished nor asked for approval within 120s"
}
lc_act_done() { ! kill -0 "$LC_ACT_PID" 2>/dev/null; }
# After the approval act: let activate finish (it exits 3 when a reboot is needed).
lc_activate_finish() {
  LC_ACT_RC=0
  [[ -n $LC_ACT_PID ]] || return 0
  if lc_poll 60 2 lc_act_done; then
    wait "$LC_ACT_PID"; LC_ACT_RC=$?
    lc_info "activate exited $LC_ACT_RC"
  else
    kill "$LC_ACT_PID" 2>/dev/null
    lc_fail "activate was still waiting 60s after the approval; stopped it"
  fi
}
