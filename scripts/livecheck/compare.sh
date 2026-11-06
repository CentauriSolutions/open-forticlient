#!/bin/zsh
# Usage: zsh compare.sh BEFORE.snap AFTER.snap
# Diffs two snapshot files and tags the lines that matter: version, receipt, extension,
# launchd, process and per-user-data changes. Exit 0 always; it reports, it does not judge.
(( $# == 2 )) || { print -u2 "usage: compare.sh BEFORE AFTER"; exit 2; }
[[ -r $1 && -r $2 ]] || { print -u2 "cannot read both files"; exit 2; }
changes=0
# Volatile fields that differ on every run are dropped before diffing.
norm() { grep -v '^== ' "$1" | sed -E 's/etime=[^ ]+//; s/^ *[0-9]+ +[0-9]+ +([0-9]+) +[0-9:.-]+ /<pid> <ppid> \1 <etime> /; s/pid=[0-9-]+/pid=N/'; }
diff <(norm "$1") <(norm "$2") | grep -E '^[<>]' | while IFS= read -r line; do
  side=${line[1]}; text=${line[3,-1]}
  case $text in
    *CFBundle*|*[0-9].[0-9]*/[0-9]*|cli:*|*com.chris.openforticlient*[0-9]/[0-9]*) tag=VERSION ;;
    pkg*|com.chris.openforticlient.*pkg*|*version:*) tag=RECEIPT ;;
    *terminated*|*activated*|*extension*|*oftc.provider*) tag=EXTENSION ;;
    *launchd*|*gui\ domain*|*LaunchAgents*|*disabled\ overrides*|pid=*) tag=LAUNCHD ;;
    *supervisors*|*host\ serve*|*OFTCAgent*|*OFTCTunnel*) tag=PROCESS ;;
    *profile*|*pins*|*support*|*logs:*|*psk=*|*oftc\ entries*) tag=USER-DATA ;;
    *codesign*|*gatekeeper*|*Frameworks*) tag=BUNDLE ;;
    *) tag=OTHER ;;
  esac
  print -r -- "$tag $side $text"
  (( changes++ ))
done
print -- "(changed lines shown above; '<' is before, '>' is after)"
