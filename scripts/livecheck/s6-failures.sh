#!/bin/zsh
# S6 readable failures: connect a profile that cannot reach its gateway over UDP or TCP and
# assert `oftc status --json` carries the expected profiles[].error code and message.
# Setup is the maintainer's (docs/livecheck.md): FAIL_PROFILE names a profile whose gateway
# answers its SAML port but drops UDP 500/4500 and TCP 4443.
set -u
setopt pipefail
source "${${(%):-%x}:A:h}/lib.sh"
LC_STAGE_SCRIPT=s6-failures.sh
lc_init S6 "$@" || exit $?
trap lc_finish EXIT; trap 'exit 130' INT TERM
cli=$(lc_cli)
[[ -n $FAIL_PROFILE ]] || { lc_fail "FAIL_PROFILE is not configured (see docs/livecheck.md)"; exit 1; }
has_error() { lc_refresh_status; [[ -n $(lc_pfield "$FAIL_PROFILE" error.code) ]]; }
no_error() { lc_refresh_status; [[ -z $(lc_pfield "$FAIL_PROFILE" error.code) ]]; }

lc_snapshot start
snap_start=$LC_SNAP
lc_step "precondition: $FAIL_PROFILE is not connected"
lc_live && { lc_is_connected "$FAIL_PROFILE" && { lc_fail "$FAIL_PROFILE is already connected"; exit 1; } || lc_pass "not connected"; }

lc_step "connect the failing profile"
lc_run -q "$cli" connect "$FAIL_PROFILE"
human "complete the browser sign-in for $FAIL_PROFILE (the connection fails after it, on purpose)" "profiles[].error is set for $FAIL_PROFILE" 420 has_error
if lc_live; then
  lc_refresh_status
  code=$(lc_pfield "$FAIL_PROFILE" error.code); detail=$(lc_pfield "$FAIL_PROFILE" error.detail)
  expect_eq "error.code" "$code" "$FAIL_EXPECT_CODE"
  expect_contains "error.detail" "$detail" "$FAIL_EXPECT_DETAIL"
  expect_eq "profile state" "$(lc_pfield "$FAIL_PROFILE" state)" attention
  lc_info "error.detail: $detail"
  # The reason must be readable by a person and carry nothing identifying.
  [[ $detail =~ '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' ]] && lc_fail "error.detail contains an IPv4 address" || lc_pass "error.detail has no address"
  expect_not_contains "status document" "$LC_STATUS" "psk"
else
  lc_dry "would assert error.code == $FAIL_EXPECT_CODE, error.detail contains '$FAIL_EXPECT_DETAIL', state attention, no address or secret in the document"
fi

lc_step "clean up: disconnect clears the error"
lc_run -q "$cli" disconnect "$FAIL_PROFILE"
wait_for "error cleared and profile disconnected" 60 3 no_error
lc_snapshot end
lc_snapdiff "$snap_start" "$LC_SNAP"
