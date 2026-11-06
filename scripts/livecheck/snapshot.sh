#!/bin/zsh
# Read-only snapshot of OFTC state on this Mac, for diffing before and after an install,
# upgrade, uninstall or reboot. Prints no secrets, no profile names, no gateway names:
# profiles appear as numbers. Changes nothing. Usage: zsh snapshot.sh [label] > file
app=${APP:-/Applications/Open Forticlient.app}
bid=com.chris.openforticlient.oftc
uid=$(id -u)
agent="$app/Contents/MacOS/OFTCAgent"
cli=${OFTC_CLI:-/usr/local/bin/oftc}
[[ -x $cli ]] || cli="$app/Contents/Helpers/oftc"
print -- "== snapshot ${1:-unlabelled} $(date '+%F %T') macOS $(sw_vers -productVersion) $(uname -m)"
print -- "-- app bundle"
if [[ -d $app ]]; then
  for p in "$app/Contents/Info.plist" "$app"/Contents/Library/SystemExtensions/*/Contents/Info.plist(N); do
    print "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$p" 2>/dev/null) $(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$p" 2>/dev/null)/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$p" 2>/dev/null)"
  done
  print "Frameworks dirs: $(find "$app" -name Frameworks -maxdepth 6 2>/dev/null | wc -l | tr -d ' ')"
  print "LaunchAgents plists: $(ls "$app/Contents/Library/LaunchAgents" 2>/dev/null | tr '\n' ' ')"
  codesign --verify --deep --strict "$app" >/dev/null 2>&1 && print "codesign: ok" || print "codesign: FAILED"
  spctl --assess --type execute "$app" >/dev/null 2>&1 && print "gatekeeper: ok" || print "gatekeeper: REJECTED"
  print "cli: $([[ -x $cli ]] && "$cli" --version 2>&1 | head -1 || print absent)"
else
  print "app: not installed"
fi
print -- "-- installer receipts"
pkgutil --pkgs 2>/dev/null | grep -i openforticlient | while read -r r; do print "$r $(pkgutil --pkg-info "$r" 2>/dev/null | grep -E '^version' | tr '\n' ' ')"; done
print -- "-- system extensions (oftc)"
systemextensionsctl list 2>/dev/null | grep -i 'oftc' | sed -E 's/[[:space:]]+/ /g; s/[0-9A-F]{8}-[0-9A-F-]{27}/<uuid>/'
print "terminated-waiting entries: $(systemextensionsctl list 2>/dev/null | grep -i oftc | grep -ci 'terminated waiting')"
print "activated-enabled entries: $(systemextensionsctl list 2>/dev/null | grep -i oftc | grep -c 'activated enabled')"
print -- "-- launchd (labels containing oftc)"
launchctl list 2>/dev/null | grep -i oftc | awk '{print "pid="$1" status="$2" "$3}'
for l in agent host; do
  launchctl print "gui/$uid/$bid.$l" >/dev/null 2>&1 && print "gui domain has $bid.$l" || print "gui domain lacks $bid.$l"
done
print "launchctl disabled overrides: $(launchctl print-disabled "gui/$uid" 2>/dev/null | grep -ci oftc)"
print "user LaunchAgents plists: $(ls "$HOME/Library/LaunchAgents" 2>/dev/null | grep -i 'oftc\|openforticlient' | tr '\n' ' ')"
print -- "-- processes (pid ppid pgid)"
ps -axo pid,ppid,pgid,etime,command 2>/dev/null | grep -iE 'OFTCAgent|oftc\.provider|OFTCTunnel|Open Forticlient' | grep -v grep | sed -E 's#/Applications/Open Forticlient.app/Contents/##; s#--profile [a-z0-9-]+#--profile <id>#' | cut -c1-140
print "supervisors (pid:pgid): $(ps -axo pid,pgid,command 2>/dev/null | awk '/supervise-profile/ && !/awk/ {print $1":"$2}' | sort | tr '\n' ' ')"
print "host serve processes: $(ps -axo command 2>/dev/null | grep -c 'OFTCAgent host serve' | tr -d ' ')"
print -- "-- per-user data (names only, counts)"
sup="$HOME/Library/Application Support/$bid"
if [[ -d $sup ]]; then
  print "support dir entries: $(ls "$sup" | tr '\n' ' ')"
  print "profile dirs: $(ls "$sup/profiles" 2>/dev/null | wc -l | tr -d ' ')"
else
  print "support dir: absent"
fi
print "pins: $(ls "$HOME/.config/oftc/gateways" 2>/dev/null | wc -l | tr -d ' ')"
print "logs: $(ls "$HOME/Library/Logs/OFTC" 2>/dev/null | wc -l | tr -d ' ') files"
if [[ -x $agent ]]; then
  n=0
  "$agent" list-profiles 2>/dev/null | awk -F'\t' 'NF>=5 {print $1" "$5}' | while read -r pid transport; do
    (( n++ ))
    psk=$("$agent" --profile "$pid" has-psk 2>&1 | head -1 | sed 's/^OFTC PSK //')
    auto=$("$agent" login-settings 2>/dev/null | grep "(${pid}):" | sed -E 's/.*: //')
    print "profile#$n transport=$transport psk=$psk connect-at-login=${auto:-unknown}"
  done
fi
print -- "-- vpn entries (count only)"
scutil --nc list 2>/dev/null | grep -c "$bid" | sed 's/^/oftc entries: /'
print "oftc entries connected: $(scutil --nc list 2>/dev/null | grep "$bid" | grep -c '(Connected)')"
print -- "-- oftc status (states only)"
if [[ -x $cli ]]; then
  "$cli" status 2>&1 | grep -E 'status:|child_rekeys|Login agent|Menu launch|connect at login' | sed -E 's/^.* \(([a-z0-9-]+)\):/profile:/; s/\(.*\)//' | cut -c1-110
fi
print -- "-- interfaces"
print "utun count: $(ifconfig -l | tr ' ' '\n' | grep -c utun)"
print -- "== end"
