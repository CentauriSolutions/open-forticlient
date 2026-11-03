#!/bin/zsh
# Sign an explicitly selected offline build. Never called by build.sh.
set -euo pipefail

root="${0:A:h}"
build="${OFTC_BUILD_DIR:-$root/build}"
if [[ "$build" != "$root/build" && ! "$build" =~ '^/private/tmp/oftc-build-[A-Za-z0-9-]+$' ]]; then
    print -u2 'OFTC_BUILD_DIR must be app/build or a /private/tmp/oftc-build-* path'
    exit 2
fi
app="$build/OFTC.app"
bundle_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist")
extension="$app/Contents/Library/SystemExtensions/${bundle_id}.provider.systemextension"
app_frameworks="$app/Contents/Frameworks"
provider_frameworks="$extension/Contents/Frameworks"
cli="$build/oftc"
[[ "$bundle_id" == "com.chris.openforticlient.oftc" ]] || {
    print -u2 'This release signs only the OFTC product bundle ID'; exit 2
}
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$extension/Contents/Info.plist") == "${bundle_id}.provider" ]] || {
    print -u2 'Provider bundle ID mismatch'; exit 2
}
for plist in "$app/Contents/Info.plist" "$extension/Contents/Info.plist"; do
    [[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$plist") =~ '^[0-9]+$' ]] || {
        print -u2 "Missing or non-numeric build number: $plist"; exit 2
    }
done
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist") == OFTCAgent \
   && $(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$extension/Contents/Info.plist") == OFTCTunnel \
   && -f "$app/Contents/Resources/OFTC.icns" && -f "$cli" ]] || {
    print -u2 'Release executable, icon, or CLI missing'; exit 2
}
: "${DEVELOPER_ID_IDENTITY:?Set DEVELOPER_ID_IDENTITY to the Developer ID Application identity}"
[[ "$DEVELOPER_ID_IDENTITY" =~ '^[A-Fa-f0-9]{40}$' ]] || {
    print -u2 'DEVELOPER_ID_IDENTITY must be the exact 40-character certificate SHA-1'; exit 2
}
: "${APP_PROFILE:?Set APP_PROFILE to the exact-ID host Developer ID provisioning profile}"
: "${EXTENSION_PROFILE:?Set EXTENSION_PROFILE to the exact-ID provider Developer ID provisioning profile}"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
openssl cms -verify -noverify -inform DER -in "$APP_PROFILE" -out "$tmpdir/app.plist" 2>/dev/null
openssl cms -verify -noverify -inform DER -in "$EXTENSION_PROFILE" -out "$tmpdir/extension.plist" 2>/dev/null
python3 - "$tmpdir/app.plist" "$bundle_id" "$tmpdir/extension.plist" "${bundle_id}.provider" "$tmpdir" "$DEVELOPER_ID_IDENTITY" <<'PY'
import datetime
import hashlib
import plistlib
import sys
from pathlib import Path

teams = []
for kind, path, bundle_id in (
    ('app', sys.argv[1], sys.argv[2]),
    ('extension', sys.argv[3], sys.argv[4]),
):
    with open(path, 'rb') as stream:
        profile = plistlib.load(stream)
    certificate_hashes = {
        hashlib.sha1(certificate).hexdigest().upper()
        for certificate in profile.get('DeveloperCertificates', [])
    }
    if sys.argv[6].upper() not in certificate_hashes:
        sys.exit(f'{kind} profile does not contain the selected signing certificate')
    teams_for_profile = profile.get('TeamIdentifier', [])
    claims = profile.get('Entitlements', {})
    if len(teams_for_profile) != 1:
        sys.exit(f'Invalid Developer ID team in {kind} profile')
    team = teams_for_profile[0]
    if claims.get('com.apple.application-identifier') != f'{team}.{bundle_id}':
        sys.exit(f'Profile does not authorize exact bundle ID: {bundle_id}')
    if 'packet-tunnel-provider-systemextension' not in claims.get(
        'com.apple.developer.networking.networkextension', []
    ):
        sys.exit(f'Profile lacks packet-tunnel entitlement: {bundle_id}')
    if not profile.get('ProvisionsAllDevices', False):
        sys.exit(f'Expected all-devices Developer ID profile: {bundle_id}')
    expiry = profile.get('ExpirationDate')
    if expiry is None or expiry <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
        sys.exit(f'Expired profile: {bundle_id}')
    if kind == 'app' and claims.get('com.apple.developer.system-extension.install') is not True:
        sys.exit('Host profile lacks system-extension.install')
    requested = {
        'com.apple.application-identifier': f'{team}.{bundle_id}',
        'com.apple.developer.team-identifier': team,
        'com.apple.developer.networking.networkextension': [
            'packet-tunnel-provider-systemextension'],
    }
    if kind == 'app':
        requested['com.apple.developer.system-extension.install'] = True
    with (Path(sys.argv[5]) / f'{kind}.entitlements').open('wb') as stream:
        plistlib.dump(requested, stream)
    teams.append(team)
if teams[0] != teams[1]:
    sys.exit('Host and provider profiles belong to different Developer teams')
print('Exact-ID Developer ID profiles authorize host and provider')
PY

cp "$APP_PROFILE" "$app/Contents/embedded.provisionprofile"
cp "$EXTENSION_PROFILE" "$extension/Contents/embedded.provisionprofile"
libraries=(
    "$app_frameworks/liboftc_host_bootstrap.dylib"
    "$provider_frameworks/liboftc_provider_ffi.dylib"
    "$provider_frameworks/liboftc_preflight.dylib"
)
for library in "${libraries[@]}"; do
    [[ -f "$library" ]] || { print -u2 "Missing nested library: $library"; exit 2; }
    codesign --force --sign "$DEVELOPER_ID_IDENTITY" --timestamp --options runtime "$library"
    codesign --verify --strict --verbose=2 "$library"
done
codesign --force --sign "$DEVELOPER_ID_IDENTITY" --timestamp --options runtime "$cli"
codesign --verify --strict --verbose=2 "$cli"
codesign --force --sign "$DEVELOPER_ID_IDENTITY" --timestamp --options runtime "$app/Contents/Helpers/oftc"
codesign --verify --strict --verbose=2 "$app/Contents/Helpers/oftc"
codesign --force --sign "$DEVELOPER_ID_IDENTITY" --timestamp --options runtime \
    --entitlements "$tmpdir/extension.entitlements" "$extension"
codesign --force --sign "$DEVELOPER_ID_IDENTITY" --timestamp --options runtime \
    --entitlements "$tmpdir/app.entitlements" "$app"
codesign --verify --strict --verbose=2 "$extension"
codesign --verify --deep --strict --verbose=2 "$app"
python3 - "$app" "$extension" "$cli" "$app/Contents/Helpers/oftc" "${libraries[@]}" <<'PY'
import subprocess
import sys

teams = set()
for path in sys.argv[1:]:
    detail = subprocess.run(
        ['codesign', '-dv', '--verbose=4', path],
        capture_output=True, text=True, check=True,
    ).stderr
    team = next((line.split('=', 1)[1] for line in detail.splitlines()
                 if line.startswith('TeamIdentifier=')), None)
    if not team or 'Authority=Developer ID Application:' not in detail or 'Timestamp=' not in detail:
        sys.exit(f'Missing Developer ID authority, team, or timestamp: {path}')
    teams.add(team)
if len(teams) != 1:
    sys.exit('Nested code has inconsistent Developer teams')
print(f'App, provider, CLI, and {len(sys.argv) - 5} dylibs share one Developer ID team and timestamps')
PY
print "Developer ID signed candidate: $app"
print 'This script did not notarize, install, activate, or start the candidate.'
