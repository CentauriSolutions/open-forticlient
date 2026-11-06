#!/bin/zsh
# Offline selftest for the livecheck harness: lib.sh helpers, snapshot/compare, and every
# stage (dry run, and canned good and bad worlds) against stub commands. Hermetic: a temp
# HOME, TMPDIR and PATH shim directory; nothing touches this Mac's tunnels, launchd, Keychain
# or network settings. macOS only (plutil, PlistBuddy). Run: zsh scripts/livecheck/selftest.sh
#
# This file is also the stub: the shim directory symlinks every faked command name to it, and
# when it is started under one of those names it answers from canned files (shim_main).
set -u

# ======================= shim mode: a fake command ========================================
shim_main() {
  local name=$SHIM_NAME S=$SHIM_STATE call="$SHIM_NAME $*" i=0 line rx outn rc hook n=0
  if [[ $name == date ]]; then   # passthrough, except `date +%s` jumps by the clock offset a hook sets
    local d; d=$(/bin/date "$@")
    if [[ "$*" == "+%s" ]]; then
      if [[ -f $S/clock_pending ]]; then mv "$S/clock_pending" "$S/clock_offset"   # the call that sees the suspend: this one is still before it
      elif [[ -f $S/clock_offset ]]; then d=$(( d + $(cat "$S/clock_offset") )); fi
    fi
    print -r -- "$d"; exit 0
  fi
  print -r -- "$call" >> "$S/calls.log"
  # sudo -v / sudo -n <cmd>: run the rest through PATH, so it hits the shim too.
  if [[ $name == sudo ]]; then
    while [[ ${1:-} == -n ]]; do shift; done
    [[ ${1:-} == -v || ${1:-} == -k ]] && exit 0
    exec "$@"
  fi
  if [[ $name == ps ]]; then ps_table "$@"; exit 0; fi
  while IFS=$'\037' read -r rx outn rc hook; do
    if [[ $call =~ $rx ]]; then
      n=$(( $(cat "$S/count.$i" 2>/dev/null || print 0) + 1 )); print -r -- $n > "$S/count.$i"
      local f="$S/out/$outn.$n"; [[ -f $f ]] || f="$S/out/$outn"
      [[ -n $outn && -f $f ]] && cat "$f"
      [[ -f "$f.rc" ]] && rc=$(cat "$f.rc")
      [[ -n $hook ]] && eval "$hook"
      exit ${rc:-0}
    fi
    (( i++ ))
  done < "$S/rules"
  exit 0
}

# Columns of the fake process table (S/procs: pid ppid pgid command).
ps_table() {
  local cols=${@[-1]}
  awk -v cols="$cols" 'BEGIN{n=split(cols,c,",")} {for(i=1;i<=n;i++){ v=""
      if(c[i]=="pid")v=$1; else if(c[i]=="ppid")v=$2; else if(c[i]=="pgid")v=$3; else if(c[i]=="etime")v="00:10";
      else if(c[i]=="command"){v=$4; for(j=5;j<=NF;j++)v=v" "$j}
      printf "%s%s", v, (i<n?" ":"\n")}}' "$SHIM_STATE/procs"
}

# World state, shared by the test driver and the shims (hooks call these).
BID=com.chris.openforticlient.oftc
# write_status id:state[:code[:detail]]...  -> status.json, scutil list
write_status() {
  local S=$SHIM_STATE spec id st code det json='' nc='' sep=''
  for spec in "$@"; do
    id=${spec%%:*}; rest=${spec#*:}; st=${rest%%:*}
    code=''; det=''
    if [[ $rest == *:*:* ]]; then c1=${rest#*:}; code=${c1%%:*}; det=${c1#*:}; fi
    err=null
    [[ -n $code ]] && err="{\"code\":\"$code\",\"detail\":\"$det\"}"
    json+="$sep{\"id\":\"$id\",\"state\":\"$st\",\"error\":$err}"; sep=,
    if [[ $st == connected ]]; then nc+="* (Connected)      X \"OFTC VPN ($id)\" [VPN:$BID]"$'\n'
    else nc+="* (Disconnected)   X \"OFTC VPN ($id)\" [VPN:$BID]"$'\n'; fi
  done
  print -r -- "{\"schema\":1,\"profiles\":[$json]}" > "$S/out/status.json"
  print -rn -- "$nc" > "$S/out/scutil"
}
# procs: supervisors for the listed ids plus the host service.
write_procs() {   # hostpid id...
  local S=$SHIM_STATE h=$1 id p=100; shift
  : > "$S/procs"
  for id in "$@"; do print "$p 1 $p /Applications/Open Forticlient.app/Contents/MacOS/OFTCAgent --profile $id supervise-profile" >> "$S/procs"; (( p++ )); done
  print "$h 1 $h /Applications/Open Forticlient.app/Contents/MacOS/OFTCAgent host serve" >> "$S/procs"
}
world_up()   { write_status p1:connected p2:connected; write_procs "${1:-200}" p1 p2; }
world_down() { write_status p1:disconnected p2:disconnected; write_procs "${1:-200}"; }
bump_rekeys() { local f="$SHIM_STATE/out/rekeys"; local n; n=$(grep -o '[0-9]*' "$f" | head -1); print "child_rekeys local=$(( n + 1 )) remote=0" > "$f"; }
set_version() {   # host build; the provider's build differs (host + 8), as in a real release
  local pb=$(( $1 + 8 )) xi="$FAKE_APP/Contents/Library/SystemExtensions/t.systemextension/Contents/Info.plist"
  plutil -replace CFBundleVersion -string "$1" "$FAKE_APP/Contents/Info.plist"
  mkdir -p "${xi:h}"; plutil -create xml1 "$xi"; plutil -insert CFBundleVersion -string "$pb" "$xi"
  print "*	*	$BID.provider (1.2.2/$pb)	OFTCTunnel	[activated enabled]" > "$SHIM_STATE/out/ext"
  print "*	*	$BID.provider (1.2.2/41)	OFTCTunnel	[terminated waiting to uninstall on reboot]" >> "$SHIM_STATE/out/ext"
}

# ---- rules ----------------------------------------------------------------------------------
rule() {   # regex outname rc [hook] : later rules win
  printf '%s\037%s\037%s\037%s\n' "$1" "$2" "$3" "${4:-}" | cat - "$SHIM_STATE/rules" > "$SHIM_STATE/rules.n"
  mv "$SHIM_STATE/rules.n" "$SHIM_STATE/rules"
}
put() { print -r -- "$2" > "$SHIM_STATE/out/$1"; }       # put name text
put_n() { print -r -- "$3" > "$SHIM_STATE/out/$1.$2"; }  # put_n name call# text
if [[ ${0:t} != selftest.sh ]]; then SHIM_NAME=${0:t}; shim_main "$@"; exit 0; fi

# ======================= driver ==============================================================
[[ $(uname -s) == Darwin ]] || { print "livecheck selftest needs macOS"; exit 2; }
HERE=${${(%):-%x}:A:h}
T=$(mktemp -d "${TMPDIR:-/tmp}/livecheck-selftest.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
export SHIM_STATE=$T/state HOME=$T/home TMPDIR=$T/tmp
setopt nonomatch
export FAKE_APP="$T/Applications/Open Forticlient.app"
export APP=$FAKE_APP
mkdir -p "$SHIM_STATE/out" "$HOME/Library/LaunchAgents" "$TMPDIR" "$T/shims"
for c in oftc OFTCAgent sudo launchctl systemextensionsctl scutil pmset networksetup hdiutil installer pkgutil spctl stapler codesign \
         ping nc netstat ps pgrep shutdown screencapture osascript route sfltool xcrun ifconfig date; do
  ln -s "$HERE/selftest.sh" "$T/shims/$c"
done
make_app() {   # the fake installed bundle; S5's uninstall hook deletes it
  rm -rf "$FAKE_APP"; mkdir -p "$FAKE_APP/Contents/MacOS" "$FAKE_APP/Contents/Helpers"
  ln -sf "$HERE/selftest.sh" "$FAKE_APP/Contents/MacOS/OFTCAgent"
  ln -sf "$HERE/selftest.sh" "$FAKE_APP/Contents/Helpers/oftc"
  ln -sf "$HERE/selftest.sh" "$T/shims/oftc"
  plutil -create xml1 "$FAKE_APP/Contents/Info.plist"
  plutil -insert CFBundleIdentifier -string $BID "$FAKE_APP/Contents/Info.plist"
  plutil -insert CFBundleShortVersionString -string 1.2.2 "$FAKE_APP/Contents/Info.plist"
  plutil -insert CFBundleVersion -string 41 "$FAKE_APP/Contents/Info.plist"
}
make_app
export PATH="$T/shims:/usr/bin:/bin:/usr/sbin:/sbin"
# Safety: every command that changes a system must resolve to its shim, or we stop.
for c in sudo launchctl installer pmset networksetup shutdown hdiutil systemextensionsctl; do
  [[ $(command -v $c) == "$T/shims/$c" ]] || { print "selftest: $c does not resolve to its shim; refusing to run"; exit 2; }
done
export LC_SLEEP_SCALE=0 OFTC_CLI="$T/shims/oftc" OLD_APP="$T/old/OFTC.app" INSTALL_LOG="$T/install.log"
export LIVECHECK_CONFIG="$T/livecheck.env"
cat > "$LIVECHECK_CONFIG" <<CFG
# test config: reserved names and addresses only
APP=$FAKE_APP
PROFILES=p1 p2
PING_TARGETS=p1=192.0.2.10 p2=198.51.100.20
TCP_TARGETS=p1=192.0.2.10:443
SOAK_MINUTES=1
SOAK_INTERVAL=30
NETWORK_SERVICE=Test Wi-Fi
DMG_PATH=$T/OFTC-test.dmg
EXPECT_VERSION=1.2.2
FAIL_PROFILE=p3
SLEEP_SECONDS=60
DISCONNECT_WAIT=30
BOGUS_KEY=ignored
CFG
touch "$T/OFTC-test.dmg"

reset_world() {
  [[ -n $T && $HOME == "$T/home" && $SHIM_STATE == "$T/state" ]] || { print "selftest: refusing to reset outside the temp dir"; exit 2; }
  rm -rf "$SHIM_STATE/out" "$SHIM_STATE"/count.* "$SHIM_STATE/calls.log" "$HOME/Library/Logs" "$HOME/Library/Application Support" "$T/old" "$T/mnt"
  mkdir -p "$SHIM_STATE/out" "$HOME/Library/Logs/OFTC" "$HOME/Library/Application Support/$BID/profiles/p1"
  : > "$SHIM_STATE/calls.log"; : > "$SHIM_STATE/rules"
  rm -f "$HOME/Library/LaunchAgents"/*.plist "$INSTALL_LOG" "$SHIM_STATE/clock_offset" "$SHIM_STATE/clock_pending"
  make_app
  set_version 41 >/dev/null; put ext "$(grep activated "$SHIM_STATE/out/ext" | head -1)"
  world_up 200
  put rekeys 'child_rekeys local=1 remote=0'
  put ping_ok '10 packets transmitted, 10 packets received, 0.0% packet loss'
  put ver 'oftc 1.2.2'
  put show 'OFTC profile p1 (P1): gateway=vpn.example.com saml-port=9443 transport=udp'
  put listp $'p1\tP1\tvpn.example.com\t9443\tudp'
  put psk 'OFTC PSK available'
  put login $'Menu launch at login: enabled\nVPN connect at login (p1): enabled'
  put netstat 'tcp4  0  0  10.0.0.2.50000  192.0.2.10.443  ESTABLISHED'
  rule '^pgrep -f ' '' 1
  rule '^pgrep -fl' pgrep 0
  rule '^launchctl (print|list|print-disabled)' launchctl 0
  rule '^launchctl kickstart' '' 0
  rule '^ping ' ping_ok 0
  rule '^netstat' netstat 0
  rule '^scutil --nc list' scutil 0
  rule '^systemextensionsctl list' ext 0
  rule '^(oftc|OFTCAgent) status --json' status.json 0
  rule '^oftc --version' ver 0
  rule '^oftc status$' '' 0
  rule '^oftc connect' '' 0 'world_up ${HOSTPID:-200}'
  rule '^oftc disconnect' '' 0 'world_down ${HOSTPID:-200}'
  rule '^OFTCAgent .*rekey-counts' rekeys 0
  rule '^OFTCAgent .*rekey-once' passed1 0 'bump_rekeys'
  rule '^OFTCAgent .*rekey-ike-once' passed2 0
  rule '^OFTCAgent .*show-profile' show 0
  rule '^OFTCAgent list-profiles' listp 0
  rule '^OFTCAgent .*has-psk' psk 0
  rule '^OFTCAgent login-settings' login 0
  rule '^OFTCAgent host register' reg 0
  rule '^OFTCAgent host restart' restarted 0
  rule '^OFTCAgent quit-menu' '' 0
  rule '^OFTCAgent activate' '' 0
  rule '^pmset sleepnow' '' 0 'print 75 > "$SHIM_STATE/clock_pending"'
  rule '^hdiutil attach' '' 0 'touch "${@[-2]}/OFTC-1.2.2.pkg"'
  rule '^hdiutil detach' '' 0
  rule '^pkgutil --check-signature' sig 0
  rule '^pkgutil --pkgs' pkgs 0
  rule '^pkgutil --pkg-info' pkginfo 0
  rule '^spctl --assess --type install' spctl_pkg 0
  rule '^spctl --assess --type execute' '' 0
  rule '^stapler validate' staple 0
  rule '^codesign' '' 0
  rule '^screencapture' '' 0 'print -r -- $RANDOM$RANDOM > "${@[-1]}"'
  rule '^osascript -e tell application' bounds 0
  put passed1 'CHILD_SA rekey probe passed'; put passed2 'IKE_SA rekey probe passed'
  put reg 'OFTC host registered'; put restarted 'OFTC host restarted'
  put sig $'Package "OFTC.pkg":\n   Status: signed by a developer certificate issued by Apple for distribution\n   1. Developer ID Installer: Example (ABCDE12345)'
  put spctl_pkg $'OFTC.pkg: accepted\nsource=Notarized Developer ID'
  put staple 'The validate action worked!'
  put pkgs 'com.chris.openforticlient.oftc.pkg'
  put pkginfo 'version: 1.2.2'
  put bounds '0, 0, 1728, 1117'
  put launchctl "100 0 $BID.host"
  put btm "identifier: $BID.host"
  rule '^sfltool dumpbtm' btm 0
  : > "$HOME/Library/Logs/OFTC/p1.log"; : > "$HOME/Library/Logs/OFTC/p2.log"
}

# ---- tiny assertion harness for the selftest itself ----------------------------------------------
PASSED=0; FAILED=0
ok()   { PASSED=$(( PASSED + 1 )); }
bad()  { FAILED=$(( FAILED + 1 )); print -r -- "SELFTEST FAIL: $*"; }
has()  { [[ $2 == *"$3"* ]] && ok || bad "$1: expected '$3' in: ${2: -700}"; }
lacks(){ [[ $2 != *"$3"* ]] && ok || bad "$1: unexpected '$3' in: ${2: -700}"; }
eq()   { [[ $2 == "$3" ]] && ok || bad "$1: got '$2' expected '$3'"; }
run() {   # stage args... ; sets OUT and RC
  local stage=$1; shift
  OUT=$(zsh "$HERE/$stage" "$@" 2>&1); RC=$?
}
no_calls() { [[ ! -s $SHIM_STATE/calls.log ]] && ok || bad "$1: commands ran: $(head -3 "$SHIM_STATE/calls.log")"; }

# Debug aid: zsh selftest.sh --run <stage.sh> [args]  runs one stage in the default good world.
if [[ ${1:-} == --run ]]; then shift; reset_world; [[ -n ${SELFTEST_SETUP:-} ]] && eval "$SELFTEST_SETUP"; run "$@"; print -r -- "$OUT"; print "rc=$RC"; [[ -n ${DEBUG_CALLS:-} ]] && { print -r -- "=== calls"; cat "$SHIM_STATE/calls.log"; print -r -- "=== rules"; head -5 "$SHIM_STATE/rules"; print -r -- "=== status"; cat "$SHIM_STATE/out/status.json"; }; exit 0; fi

# ======================= 1. lib.sh helpers ==========================================================
reset_world
cat > "$T/libtest.sh" <<'LT'
source "$1/lib.sh"
LC_RUN=$2; mkdir -p "$LC_RUN"; LC_LOG="$LC_RUN/lib.log"; LC_STAGE=T
case $3 in
  eq) expect_eq "a" x x; expect_eq "b" x y; expect_contains "c" hello ell; expect_contains "d" hello zz
      expect_not_contains "e" hello zz; expect_rc "f" 0 1; expect_num_ge "g" 5 3; expect_num_ge "h" abc 3 ;;
  wait) n=0; tick() { (( n++ )); (( n >= 3 )); }; wait_for "eventually" 30 5 tick; always_no() { false; }; wait_for "never" 10 5 always_no ;;
  human) yes_() { true; }; human "do X" "X done" 10 yes_; no_() { false; }; human "do Y" "Y done" 10 no_ ;;
  dry) LC_DRY=1; expect_eq "a" x y; wait_for "w" 10 5 false; human "do Z" "Z" 10 false ;;
  cfg) LIVECHECK_CONFIG=$4; lc_load_config; print "APP=$APP PROFILES=$PROFILES NS=$NETWORK_SERVICE SOAK=$SOAK_MINUTES"; lc_emit INFO "x gateway=vpn.example.com addr 192.0.2.10 y" ;;
esac
print "counts pass=$LC_PASS fail=$LC_FAIL humans=$LC_HUMANS"
LT
lib() { OUT=$(zsh "$T/libtest.sh" "$HERE" "$T/libruns" "$@" 2>&1); }
lib eq;   has "expect_eq pass" "$OUT" "PASS a (= x)"; has "expect_eq fail" "$OUT" "FAIL b: got 'x', expected 'y'"
has "expect_contains fail" "$OUT" "FAIL d:"; has "expect_rc fail" "$OUT" "FAIL f: exit 0, expected 1"
has "expect_num_ge non-number" "$OUT" "FAIL h:"; has "counts" "$OUT" "counts pass=4 fail=4"
lib wait; has "wait_for success" "$OUT" "PASS eventually"; has "wait_for timeout" "$OUT" "FAIL never: not observed within 10s"
lib human; has "human asks once, marked" "$OUT" "HUMAN >>> ACTION REQUIRED (one act): do X"; has "human observed" "$OUT" "PASS human act observed: X done"
has "human timeout" "$OUT" "FAIL human act not observed within 10s: Y done"; has "human counted" "$OUT" "humans=2"
lib dry; has "dry assert" "$OUT" "DRY  would assert"; has "dry human" "$OUT" "DRY  would ask a human"; has "dry counts" "$OUT" "pass=0 fail=0 humans=1"
lib cfg "$LIVECHECK_CONFIG"; has "config parsed, spaces kept" "$OUT" "NS=Test Wi-Fi"; has "config profiles" "$OUT" "PROFILES=p1 p2"
has "config unknown key ignored" "$OUT" "ignoring unknown key 'BOGUS_KEY'"; has "gateway scrubbed in the log" "$(cat "$T/libruns/lib.log")" "gateway=<gateway>"
has "configured address scrubbed in the log" "$(cat "$T/libruns/lib.log")" "addr <addr> y"; lacks "no raw address in log" "$(cat "$T/libruns/lib.log")" "192.0.2.10"
OUT=$(zsh -c "source '$HERE/s0-preflight.sh'" 2>&1); has "stage refuses to be sourced" "$OUT" "never sourced"

# ======================= 2. snapshot and compare ======================================================
reset_world
snap() { zsh "$HERE/snapshot.sh" "$1" 2>&1; }
snap before > "$T/a.snap"
has "snapshot shows the app" "$(cat "$T/a.snap")" "com.chris.openforticlient.oftc 1.2.2/41"
has "snapshot supervisors" "$(cat "$T/a.snap")" "supervisors (pid:pgid): 100:100 101:101"
has "snapshot profile by number only" "$(cat "$T/a.snap")" "profile#1 transport=udp psk=available connect-at-login=enabled"
lacks "snapshot has no names" "$(cat "$T/a.snap")" "vpn.example.com"; lacks "snapshot has no profile ids" "$(cat "$T/a.snap")" "P1"
world_down 201; set_version 42; put pkgs ''
snap after > "$T/b.snap"
CMP=$(zsh "$HERE/compare.sh" "$T/a.snap" "$T/b.snap")
has "compare: version" "$CMP" "VERSION"; has "compare: extension" "$CMP" "EXTENSION"; has "compare: process" "$CMP" "PROCESS"
has "compare: shows both sides" "$CMP" "< "; lacks "compare ignores the header timestamp" "$CMP" "== snapshot"
eq "compare of a file with itself is quiet" "$(zsh "$HERE/compare.sh" "$T/a.snap" "$T/a.snap" | grep -c '^[A-Z-]* [<>]')" 0

# ======================= 3. every stage in --dry-run: nothing runs ===================================
for st in s0-preflight s1-tunnels s2-disturb s3-host s4-installer s5-uninstall-reboot s6-failures s7-screenshots; do
  reset_world
  run $st.sh --dry-run
  eq "$st dry run exits 0" "$RC" 0; has "$st dry run prints a plan" "$OUT" "DRY"; no_calls "$st dry run"
  lacks "$st dry run asserts nothing" "$OUT" "PASS "; lacks "$st dry run fails nothing" "$OUT" "FAIL "
  [[ -z $(ls "$TMPDIR/oftc-livecheck" 2>/dev/null) ]] && ok || bad "$st dry run created a run directory"
done
reset_world; run s2-disturb.sh --dry-run; has "S2 dry run names the human acts" "$OUT" "would ask a human"
for st in s2-disturb s4-installer s5-uninstall-reboot; do
  reset_world; run $st.sh; eq "$st refuses without --yes" "$RC" 3; has "$st says why" "$OUT" "--yes"; no_calls "$st refusal"
done

# ======================= 4. stage logic against canned worlds ========================================
# S0
reset_world; world_down; run s0-preflight.sh
eq "S0 idle world" "$RC" 0; has "S0 asserts idle" "$OUT" "PASS OFTC VPNs connected (stage wants none) (= 0)"
has "S0 sudo cached" "$OUT" "PASS sudo credential"; has "S0 ping target set" "$OUT" "PASS ping target set for profile p2"
reset_world; run s0-preflight.sh
eq "S0 fails when a tunnel is up and the stage wants none" "$RC" 1; has "S0 says which check" "$OUT" "FAIL OFTC VPNs connected (stage wants none)"
run s0-preflight.sh --expect-connected; has "S0 --expect-connected passes" "$OUT" "PASS OFTC VPNs connected"
reset_world; put ext "$(printf '*\t*\t%s.provider (1.2.2/40)\tOFTCTunnel\t[terminated waiting to uninstall on reboot]' $BID)"; world_down; run s0-preflight.sh
has "S0 flags a stale extension" "$OUT" "FAIL no stale 'terminated waiting to uninstall' extension"

# S1
reset_world; run s1-tunnels.sh
eq "S1 good world" "$RC" 0; has "S1 connected" "$OUT" "PASS profile p1 state (= connected)"; has "S1 ping clean" "$OUT" "PASS ping through p2 at 0% loss"
has "S1 tcp" "$OUT" "PASS TCP connect through p1"; has "S1 child rekey" "$OUT" "PASS CHILD_SA rekey probe p1"; has "S1 ike rekey" "$OUT" "PASS IKE_SA rekey probe p2"
has "S1 counters" "$OUT" "PASS rekey counters increased for p1 (1 -> 2)"; has "S1 soak" "$OUT" "PASS soak: 2 probes"
has "S1 transport inferred, not claimed" "$OUT" "inferred"; has "S1 supervisors unchanged" "$OUT" "PASS supervisors unchanged across S1"
# transport inference: a long netstat with the 4443 socket late in it (an early ESTABLISHED line made grep -q quit while print was still writing; pipefail then lost the match)
reset_world; { print 'tcp4  0  0  10.0.0.2.50000  192.0.2.10.443  ESTABLISHED'; for i in {1..3000}; do print "tcp4  0  0  10.0.0.2.$((10000+i))  198.51.100.7.443  TIME_WAIT"; done; print 'tcp4  0  0  10.0.0.2.51000  203.0.113.5.4443  ESTABLISHED'; } > "$SHIM_STATE/out/netstat"; run s1-tunnels.sh
has "S1 finds an established 4443 socket in a long netstat" "$OUT" "a TCP connection to port 4443 is established"
# an older CLI cannot report state: say so, do not fail
reset_world; rule '^(oftc|OFTCAgent) status --json' '' 2; run s1-tunnels.sh
has "S1 old CLI: state skipped with a reason" "$OUT" "INFO SKIP profile p1 state: tunnel state cannot be read"; lacks "S1 old CLI: no state FAIL" "$OUT" "FAIL profile p1 state"
reset_world; put ping_ok '10 packets transmitted, 0 packets received, 100.0% packet loss'; run s1-tunnels.sh
eq "S1 fails on packet loss" "$RC" 1; has "S1 names the failed ping" "$OUT" "FAIL ping through p1 at 0% loss"
reset_world; rule '^OFTCAgent .*rekey-once' passed1 0 ''; run s1-tunnels.sh
has "S1 fails when counters do not move" "$OUT" "FAIL rekey counters did not increase for p1 (1 -> 1)"
reset_world; rule '^OFTCAgent .*rekey-ike-once' fail2 1; put fail2 'IKE_SA rekey probe failed (stage 5)'; run s1-tunnels.sh
has "S1 fails on a failed IKE rekey" "$OUT" "FAIL IKE_SA rekey probe p1"
reset_world; write_status p1:connected p2:reconnecting; run s1-tunnels.sh
has "S1 fails when a profile is not connected" "$OUT" "FAIL profile p2 state: got 'reconnecting'"
reset_world; rule '^OFTCAgent .*rekey-once' passed1 0 'bump_rekeys'; rule '^ping ' ping_ok 0 'true'
put_n ping_ok 40 '10 packets transmitted, 9 packets received, 10.0% packet loss'; : # (soak failure covered by the loss test above)

# S2 stop: good, then bad (a supervisor survives the stop)
reset_world; run s2-disturb.sh --yes --only stop --no-restore
eq "S2 stop good" "$RC" 0; has "S2 no reconnect" "$OUT" "PASS no reconnect during 30s"; has "S2 no supervisors" "$OUT" "PASS supervisor processes after the hold"
has "S2 no new attempt" "$OUT" "PASS no new connection attempt after the stop"
reset_world; rule '^oftc disconnect' '' 0 'write_status p1:disconnected p2:disconnected; write_procs 200 p1'; run s2-disturb.sh --yes --only stop --no-restore
eq "S2 stop bad: supervisor remains" "$RC" 1; has "S2 names the supervisor check" "$OUT" "FAIL supervisor processes after the hold"
reset_world; rule '^oftc disconnect' '' 0 'write_status p1:connected p2:disconnected'; run s2-disturb.sh --yes --only stop --no-restore
eq "S2 stop bad: tunnel stays up" "$RC" 1; has "S2 names the stop check" "$OUT" "FAIL every profile reports disconnected"
# S2 drop: the scripted drop takes the tunnel down, restore brings it back with the log lines
reset_world
rule '^networksetup -setnetworkserviceenabled .* off' '' 0 'write_status p1:disconnected p2:disconnected'
rule '^networksetup -setnetworkserviceenabled .* on' '' 0 'write_status p1:connected p2:connected; print "OFTC supervisor: VPN disconnected; fetching error\nOFTC supervisor: starting fresh SSO recovery\nOFTC supervisor: VPN connected" >> "$HOME/Library/Logs/OFTC/p1.log"'
run s2-disturb.sh --yes --only drop
eq "S2 drop good" "$RC" 0; has "S2 drop scripted" "$OUT" "RUN  sudo -n networksetup -setnetworkserviceenabled Test Wi-Fi off"
has "S2 drop sees the disconnect" "$OUT" "PASS supervisor log shows the disconnect"; has "S2 drop sees fresh sign-in" "$OUT" "PASS supervisor log shows fresh sign-in recovery"
has "S2 traffic after" "$OUT" "PASS after network drop: traffic through p1 at 0% loss"
reset_world
rule '^networksetup -setnetworkserviceenabled .* off' '' 0 'write_status p1:disconnected p2:disconnected'
rule '^networksetup -setnetworkserviceenabled .* on' '' 1 ''
run s2-disturb.sh --yes --only drop
eq "S2 drop: a failed network restore fails the stage" "$RC" 1; has "S2 prints the manual restore" "$OUT" "RESTORE MANUALLY: sudo networksetup -setnetworkserviceenabled \"Test Wi-Fi\" on"
reset_world
rule '^networksetup -setnetworkserviceenabled .* off' '' 1 ''
rule '^route' '' 0
run s2-disturb.sh --yes --only drop
has "S2 falls back to a human when scripting fails" "$OUT" "HUMAN >>> ACTION REQUIRED (one act): turn Wi-Fi off"
# S2 sleep
reset_world; run s2-disturb.sh --yes --only sleep
eq "S2 sleep good" "$RC" 0; has "S2 scheduled wake" "$OUT" "PASS scheduled wake"; has "S2 slept" "$OUT" "PASS Mac slept"; has "S2 sleepnow printed" "$OUT" "RUN  pmset sleepnow"
has "S2 wake traffic" "$OUT" "PASS after wake: traffic through p1 at 0% loss"
has "S2 sleep proven by a clock jump" "$OUT" "PASS Mac slept (clock jumped 75s"
reset_world; rule '^pmset sleepnow' '' 0 'print 20 > "$SHIM_STATE/clock_pending"'; run s2-disturb.sh --yes --only sleep
eq "S2 sleep bad: too short" "$RC" 1; has "S2 names the short sleep" "$OUT" "FAIL Mac slept only 20s"
reset_world; rule '^pmset sleepnow' '' 0 ''; run s2-disturb.sh --yes --only sleep
eq "S2 sleep bad: the Mac never slept" "$RC" 1; has "S2 names it" "$OUT" "FAIL no sleep detected"

# S3
reset_world; rule '^launchctl kickstart' '' 0 'write_procs 201 p1 p2'; run s3-host.sh
eq "S3 good" "$RC" 0; has "S3 one host" "$OUT" "PASS exactly one 'host serve' process"; has "S3 new pid" "$OUT" "PASS host service restarted under a new pid"
has "S3 supervisors same" "$OUT" "PASS supervisors (pid:pgid) unchanged"; has "S3 own groups" "$OUT" "PASS supervisor 100 leads its own process group"
has "S3 btm count" "$OUT" "PASS Login Items / BTM entries for the host label"; has "S3 register" "$OUT" "PASS host register (idempotent)"
reset_world; rule '^launchctl kickstart' '' 0 'write_procs 201 p1'; run s3-host.sh
eq "S3 bad: a supervisor died with the host" "$RC" 1; has "S3 names it" "$OUT" "FAIL supervisors (pid:pgid) unchanged"
reset_world; run s3-host.sh
eq "S3 bad: host pid never changes" "$RC" 1; has "S3 names the kickstart check" "$OUT" "FAIL host service restarted under a new pid"
reset_world; rule '^sfltool dumpbtm' '' 1; rule '^OFTCAgent host register' usage 2; put usage 'usage: OFTCAgent ...'; rule '^launchctl kickstart' '' 0 'write_procs 201 p1 p2'; run s3-host.sh
has "S3 tolerates a build without host register" "$OUT" "no 'host register' verb"; has "S3 says BTM is not observable without root" "$OUT" "BTM count not observable"

# S4: good upgrade, then bad variants
s4_world() {
  reset_world; : > "$INSTALL_LOG"
  put_n installer 1 'installer: Error - Disconnect every OFTC VPN from its controls or System Settings > VPN, then reopen this installer. Installer will ask to close the app. Your saved VPN settings will be kept.'; rule '^installer' installer 0 'true'
  : > "$INSTALL_LOG"
  put_n installer 2 $'installer: The install was successful.'
  rule '^installer' installer 0 'if [[ $(cat "$SHIM_STATE/count.0") == 1 ]]; then :; else set_version 42; write_procs 201 ; fi'
  print 1 > "$SHIM_STATE/out/installer.1.rc"
}
s4_world; run s4-installer.sh --yes
eq "S4 good upgrade" "$RC" 0; has "S4 signature" "$OUT" "PASS package signature chain"; has "S4 notarized" "$OUT" "PASS package is notarized"
has "S4 stapled" "$OUT" "PASS notarization ticket stapled"; has "S4 guard refused" "$OUT" "PASS installer exit status is nonzero (refused)"
has "S4 guard reason from installer output" "$OUT" "PASS installer refused with an OFTC message: Disconnect every OFTC VPN"; has "S4 install.log line is only INFO" "$OUT" "INFO no preinstall line in install.log"; has "S4 installed" "$OUT" "PASS installer says it succeeded"
has "S4 replaced" "$OUT" "PASS bundle replaced (build 41 -> 42)"; has "S4 no Frameworks" "$OUT" "PASS Frameworks directories in the bundle (= 0)"
has "S4 user data survived" "$OUT" "PASS profiles, PSK presence, auto-start, transport and pins"; has "S4 host kickstarted" "$OUT" "PASS postinstall kickstarted the host service"
has "S4 approval recorded" "$OUT" "approval requested: no"; lacks "S4 never exports or provisions a PSK" "$(cat "$SHIM_STATE/calls.log")" "export-profiles"
s4_world; put sig $'Package "OFTC.pkg":\n   Status: no signature'; run s4-installer.sh --yes
eq "S4 bad signature" "$RC" 1; has "S4 names it" "$OUT" "FAIL package signature chain"
lacks "S4 never calls installer after a bad signature" "$(cat "$SHIM_STATE/calls.log")" "installer -pkg"
s4_world; put_n installer 1 'installer: The install failed.'
run s4-installer.sh --yes; has "S4 bad: refusal without an OFTC message" "$OUT" "FAIL no OFTC refusal message in the installer output"
s4_world; print -r -- 'OFTC preinstall: An OFTC VPN is active.' > "$INSTALL_LOG"; run s4-installer.sh --yes
has "S4 install.log preinstall line is recorded as INFO when present" "$OUT" "INFO preinstall script also logged in install.log: An OFTC VPN is active"
s4_world; put_n installer 1 'installer: The install was successful.'; rm -f "$SHIM_STATE/out/installer.1.rc"
run s4-installer.sh --yes; has "S4 bad: installer ran with a tunnel up" "$OUT" "FAIL installer exit status is nonzero (refused)"
s4_world; rule '^(oftc|OFTCAgent) status --json' '' 2; run s4-installer.sh --yes
has "S4 old CLI: guard test skipped with a reason" "$OUT" "INFO SKIP guard test: tunnel state cannot be read"; lacks "S4 old CLI: not a FAIL" "$OUT" "FAIL guard test"
s4_world; put_n installer 2 'installer: The upgrade was successful.'; run s4-installer.sh --yes
has "S4 accepts 'The upgrade was successful'" "$OUT" "PASS installer says it succeeded"; has "S4 waits on the provider build, not the host's" "$OUT" "provider build 50"
s4_world; write_status p1:disconnected p2:disconnected; run s4-installer.sh --yes
has "S4 bad: guard needs a tunnel" "$OUT" "FAIL guard test needs a connected tunnel"
s4_world; rule '^pgrep -f ' '' 0; run s4-installer.sh --yes
has "S4 bad: host service trips the preinstall guard" "$OUT" "FAIL a process still matches the preinstall guard"
s4_world; rule '^OFTCAgent activate' act 0; put act 'macOS approval required for com.chris.openforticlient.oftc.provider'
rm -f "$SHIM_STATE/out/installer.1.rc"; put_n installer 1 'installer: The install was successful.'
rule '^installer' installer 0 'plutil -replace CFBundleVersion -string 42 "$FAKE_APP/Contents/Info.plist"; plutil -replace CFBundleVersion -string 50 "$FAKE_APP"/Contents/Library/SystemExtensions/t.systemextension/Contents/Info.plist; write_procs 201'
run s4-installer.sh --yes --skip-guard
has "S4 asks a human for approval when activate says so" "$OUT" "approval requested: yes"; has "S4 approval human act" "$OUT" "HUMAN >>> ACTION REQUIRED (one act): approve the OFTC Network Extension"

# S5 pre and post
reset_world; put ext ''; write_procs 200 p1 p2
rule '^oftc uninstall' '' 0 'write_status; : > "$SHIM_STATE/procs"; rm -rf "$FAKE_APP" "$OFTC_CLI"; put ext "*	*	$BID.provider (1.2.2/41)	OFTCTunnel	[terminated waiting to uninstall on reboot]"; put pkgs ""; put launchctl ""; put btm ""; rule "^launchctl (print|list|print-disabled)" "" 113 ""'
mkdir -p "$HOME/Library/Application Support/$BID/profiles/p1"
cp -R "$FAKE_APP" "$T/keep.app"
run s5-uninstall-reboot.sh --yes --no-reinstall --no-reboot
has "S5 uninstall ran" "$OUT" "RUN  $T/shims/oftc uninstall"; has "S5 app removed" "$OUT" "PASS app bundle removed"
has "S5 profiles retained" "$OUT" "PASS profile directories retained"; has "S5 launch agent gone" "$OUT" "PASS launch agent host is gone"
has "S5 deferred extension is info, not a pass" "$OUT" "expected until reboot"; has "S5 resume agent written" "$OUT" "PASS resume LaunchAgent written"
[[ -f "$HOME/Library/Application Support/oftc-livecheck/s5.marker" ]] && ok || bad "S5 marker not written"
plutil -lint "$HOME/Library/LaunchAgents/local.oftc-livecheck.s5-resume.plist" >/dev/null && ok || bad "S5 plist invalid"
has "S5 plist runs the post phase" "$(cat "$HOME/Library/LaunchAgents/local.oftc-livecheck.s5-resume.plist")" "<string>post</string>"
PRE_RUN=$(print -r -- "$OUT" | sed -n 's/^.*log: \(.*\)\/S5.log (private.*$/\1/p' | tail -1)
run s5-uninstall-reboot.sh --yes --no-reinstall --no-reboot
eq "S5 detects a half-run" "$RC" 1; has "S5 half-run message" "$OUT" "a previous S5 did not finish"
# post: stale entry still there -> FAIL, marker stays
write_procs 300; put ext "*	*	$BID.provider (1.2.2/41)	OFTCTunnel	[terminated waiting to uninstall on reboot]"
run s5-uninstall-reboot.sh --yes --no-reinstall --phase post --run-dir "$PRE_RUN"
eq "S5 post bad: stale extension survives reboot" "$RC" 1; has "S5 post names it" "$OUT" "FAIL extension list has no stale"
[[ -f "$HOME/Library/Application Support/oftc-livecheck/s5.marker" ]] && ok || bad "S5 marker must stay after a failed post"
[[ ! -e "$HOME/Library/LaunchAgents/local.oftc-livecheck.s5-resume.plist" ]] && ok || bad "S5 plist must be removed first"
# post good
write_procs 300; put ext ''
run s5-uninstall-reboot.sh --yes --no-reinstall --phase post --run-dir "$PRE_RUN"
eq "S5 post good" "$RC" 0; has "S5 post host" "$OUT" "PASS host service running after login"; has "S5 post extension cleared" "$OUT" "PASS no OFTC extension entries remain"
[[ ! -e "$HOME/Library/Application Support/oftc-livecheck/s5.marker" ]] && ok || bad "S5 marker must be removed after a good post"

reset_world; put sig $'Package "OFTC.pkg":\n   Status: no signature'; rule '^oftc uninstall' '' 0 ''
run s5-uninstall-reboot.sh --yes --no-reboot --dmg "$T/OFTC-test.dmg"
eq "S5 bad signature stops before uninstalling" "$RC" 1; has "S5 says nothing was uninstalled" "$OUT" "nothing was uninstalled"
lacks "S5 never uninstalls after a bad signature" "$(cat "$SHIM_STATE/calls.log")" "oftc uninstall"
lacks "S5 never installs after a bad signature" "$(cat "$SHIM_STATE/calls.log")" "installer -pkg"

# S6
reset_world; write_status p1:connected p2:connected p3:disconnected
rule '^oftc connect' '' 0 'write_status p1:connected p2:connected "p3:attention:network_blocked:The gateway did not answer over UDP or over TCP. This network may block UDP."'
rule '^oftc disconnect' '' 0 'write_status p1:connected p2:connected p3:disconnected'
run s6-failures.sh
eq "S6 good" "$RC" 0; has "S6 code" "$OUT" "PASS error.code (= network_blocked)"; has "S6 detail" "$OUT" "PASS error.detail (contains 'did not answer')"
has "S6 state" "$OUT" "PASS profile state (= attention)"; has "S6 human act is the SSO" "$OUT" "complete the browser sign-in for p3"
has "S6 cleared" "$OUT" "PASS error cleared and profile disconnected"
reset_world; write_status p1:connected p2:connected p3:disconnected
rule '^oftc connect' '' 0 'write_status p1:connected p2:connected "p3:attention:gateway_refused:The gateway refused to set up the tunnel."'
run s6-failures.sh; eq "S6 bad code" "$RC" 1; has "S6 names the code" "$OUT" "FAIL error.code: got 'gateway_refused', expected 'network_blocked'"
reset_world; write_status p1:connected p2:connected p3:disconnected
rule '^oftc connect' '' 0 'write_status p1:connected p2:connected "p3:attention:network_blocked:The gateway at 192.0.2.99 did not answer."'
run s6-failures.sh; has "S6 bad: address in the message" "$OUT" "FAIL error.detail contains an IPv4 address"
reset_world; write_status p1:connected p2:connected p3:disconnected; run s6-failures.sh
has "S6 times out with no error" "$OUT" "FAIL human act not observed within 420s"

# S7
reset_world; run s7-screenshots.sh
eq "S7 good" "$RC" 0; has "S7 human opens the popover" "$OUT" "click the OFTC icon in the menu bar"
has "S7 popover observed" "$OUT" "PASS human act observed: the screen region under the menu bar changes"
[[ $(ls "$TMPDIR"/oftc-livecheck/*/shots/*.png 2>/dev/null | wc -l | tr -d ' ') == 4 ]] && ok || bad "S7 expected 4 screenshots, got: $(ls "$TMPDIR"/oftc-livecheck/*/shots 2>/dev/null | tr '\n' ' ')"
has "S7 numbered names" "$(ls "$TMPDIR"/oftc-livecheck/*/shots | tr '\n' ' ')" "02-popover-connected.png"

# ======================= 4b. arguments, run dir, shareable logs ============================
reset_world; run s1-tunnels.sh --noreboot; eq "unknown argument is rejected" "$RC" 2; has "unknown argument named" "$OUT" "unknown argument '--noreboot'"; no_calls "unknown argument"
reset_world; mkdir -m 755 "$T/open-dir"; run s1-tunnels.sh --run-dir "$T/open-dir"; eq "non-private --run-dir is refused" "$RC" 2
eq "and is not chmod-ed" "$(stat -f %Lp "$T/open-dir")" 755
reset_world; run s1-tunnels.sh
RUNLOG=$(print -r -- "$OUT" | sed -n 's/^.*log: \(.*S1.log\) (private.*$/\1/p' | tail -1)
[[ -f $RUNLOG ]] && ok || bad "no S1 log path in: ${OUT: -300}"
eq "log has no raw profile id" "$(grep -cw 'p1\|p2' "$RUNLOG")" 0
eq "summary has no raw profile id" "$(grep -cw 'p1\|p2' "${RUNLOG:h}/summary.txt")" 0
eq "log has no IPv4 address" "$(grep -cE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$RUNLOG")" 0
has "log keeps a placeholder" "$(cat "$RUNLOG")" "<profile-1>"
lacks "quiet commands do not log their output" "$(cat "$RUNLOG")" "ESTABLISHED"
for f in "$HERE"/s[0-7]-*.sh; do
  grep -q "trap 'exit 130' INT TERM" "$f" && ok || bad "${f:t} has no INT/TERM trap"
done

# ======================= 5. repo hygiene ==============================================================
hits=$(grep -rnEi 'sfcompute|chris@|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$HERE"/*.sh | grep -vE '192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|\[0-9\]|0\.0\.0|1\.2\.2|10\.0\.0\.2' || true)
[[ -z $hits ]] && ok || bad "private-looking text in scripts: $hits"

print
print "livecheck selftest: $PASSED checks passed, $FAILED failed"
(( FAILED == 0 ))
