#!/bin/zsh
set -euo pipefail

root="${0:A:h}"
app="$root/build/IntegrationHost.app"
bundle_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist")
extension="$app/Contents/Library/SystemExtensions/${bundle_id}.provider.systemextension"
frameworks="$extension/Contents/Frameworks"
: "${DEVELOPER_ID_IDENTITY:?Set DEVELOPER_ID_IDENTITY to the Developer ID Application identity}"
: "${APP_PROFILE:?Set APP_PROFILE to the host Developer ID provisioning profile path}"
: "${EXTENSION_PROFILE:?Set EXTENSION_PROFILE to the provider Developer ID provisioning profile path}"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
# OpenSSL verifies the CMS signature while decoding. Do not print the profile:
# it contains account metadata and certificates unrelated to this test.
openssl cms -verify -noverify -inform DER -in "$APP_PROFILE" -out "$tmpdir/app.plist" 2>/dev/null
openssl cms -verify -noverify -inform DER -in "$EXTENSION_PROFILE" -out "$tmpdir/extension.plist" 2>/dev/null
python3 - "$tmpdir/app.plist" "$bundle_id" "$tmpdir/extension.plist" "${bundle_id}.provider" "$tmpdir" <<'PY'
import datetime
import plistlib
import sys
from pathlib import Path

teams = []
for kind, profile_path, bundle_id in (
    ('app', sys.argv[1], sys.argv[2]),
    ('extension', sys.argv[3], sys.argv[4]),
):
    with open(profile_path, 'rb') as stream:
        profile = plistlib.load(stream)
    team_ids = profile.get('TeamIdentifier', [])
    claims = profile.get('Entitlements', {})
    if len(team_ids) != 1 or claims.get('com.apple.application-identifier') != f'{team_ids[0]}.{bundle_id}':
        sys.exit(f'Profile does not authorize exact bundle ID: {bundle_id}')
    if 'packet-tunnel-provider-systemextension' not in claims.get('com.apple.developer.networking.networkextension', []):
        sys.exit(f'Profile lacks packet-tunnel-provider-systemextension: {bundle_id}')
    if not profile.get('ProvisionsAllDevices', False):
        sys.exit(f'Expected a Developer ID all-devices profile: {bundle_id}')
    expiry = profile.get('ExpirationDate')
    if expiry is None or expiry <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
        sys.exit(f'Expired profile: {bundle_id}')
    if kind == 'app' and claims.get('com.apple.developer.system-extension.install') is not True:
        sys.exit(f'Host profile lacks system-extension.install: {bundle_id}')
    teams.append(team_ids[0])
    requested = {
        'com.apple.application-identifier': f'{team_ids[0]}.{bundle_id}',
        'com.apple.developer.team-identifier': team_ids[0],
        'com.apple.developer.networking.networkextension': ['packet-tunnel-provider-systemextension'],
    }
    if kind == 'app':
        requested['com.apple.developer.system-extension.install'] = True
    with (Path(sys.argv[5]) / f'{kind}.entitlements').open('wb') as stream:
        plistlib.dump(requested, stream)
if teams[0] != teams[1]:
    sys.exit('Profiles belong to different Developer teams')
print('Exact-ID Developer ID profiles authorize host, provider, and packet tunnel')
PY

cp "$APP_PROFILE" "$app/Contents/embedded.provisionprofile"
cp "$EXTENSION_PROFILE" "$extension/Contents/embedded.provisionprofile"
for library in "$frameworks/libcrypto_swift.dylib" "$frameworks/liboftc_core.dylib"; do
    codesign --force --sign "$DEVELOPER_ID_IDENTITY" --timestamp --options runtime "$library"
    codesign --verify --strict --verbose=2 "$library"
done
codesign --force --sign "$DEVELOPER_ID_IDENTITY" --timestamp --options runtime \
    --entitlements "$tmpdir/extension.entitlements" "$extension"
codesign --force --sign "$DEVELOPER_ID_IDENTITY" --timestamp --options runtime \
    --entitlements "$tmpdir/app.entitlements" "$app"
codesign --verify --deep --strict --verbose=2 "$app"
python3 "$root/check_bundle.py" "$app" "$extension"
python3 - "$app" "$extension" "$frameworks/libcrypto_swift.dylib" "$frameworks/liboftc_core.dylib" <<'PY'
import subprocess
import sys
teams = set()
for path in sys.argv[1:]:
    detail = subprocess.run(['codesign', '-dv', '--verbose=4', path], capture_output=True, text=True, check=True).stderr
    team = next((line.split('=', 1)[1] for line in detail.splitlines() if line.startswith('TeamIdentifier=')), None)
    if not team or 'Authority=Developer ID Application:' not in detail or 'Timestamp=' not in detail:
        sys.exit(f'Missing Developer ID authority, team, or secure timestamp: {path}')
    teams.add(team)
if len(teams) != 1:
    sys.exit('Nested code has inconsistent Developer teams')
print('Host, provider, and both dylibs share one Developer ID team and secure timestamps')
PY
print "Developer ID signed integration bundle: $app"
