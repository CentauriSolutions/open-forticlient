#!/bin/zsh
set -euo pipefail

root="${0:A:h}"
app="$root/build/Gate0Host.app"
bundle_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist")
extension="$app/Contents/Library/SystemExtensions/${bundle_id}.provider.systemextension"
: "${DEVELOPER_ID_IDENTITY:?Set DEVELOPER_ID_IDENTITY to the Developer ID Application certificate name or SHA-1 hash}"
: "${APP_PROFILE:?Set APP_PROFILE to the host app Developer ID provisioning profile path}"
: "${EXTENSION_PROFILE:?Set EXTENSION_PROFILE to the system extension Developer ID provisioning profile path}"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
security cms -D -i "$APP_PROFILE" -o "$tmpdir/app.plist"
security cms -D -i "$EXTENSION_PROFILE" -o "$tmpdir/extension.plist"
python3 - "$tmpdir/app.plist" "$bundle_id" "$tmpdir/extension.plist" "${bundle_id}.provider" "$tmpdir" <<'PY'
import datetime
import plistlib
import sys
from pathlib import Path

team_ids = []
for kind, profile_path, bundle_id in [('app', sys.argv[1], sys.argv[2]), ('extension', sys.argv[3], sys.argv[4])]:
    with open(profile_path, 'rb') as stream:
        profile = plistlib.load(stream)
    teams = profile.get('TeamIdentifier', [])
    entitlements = profile.get('Entitlements', {})
    app_id = entitlements.get('com.apple.application-identifier')
    capability = entitlements.get('com.apple.developer.networking.networkextension', [])
    expiry = profile.get('ExpirationDate')
    if len(teams) != 1 or app_id != f'{teams[0]}.{bundle_id}':
        sys.exit(f'Profile does not authorize exact App ID: {bundle_id}')
    if 'packet-tunnel-provider-systemextension' not in capability:
        sys.exit(f'Profile lacks Developer ID packet tunnel entitlement: {bundle_id}')
    if not profile.get('ProvisionsAllDevices', False):
        sys.exit(f'Expected a Developer ID profile for all devices: {bundle_id}')
    if kind == 'app' and entitlements.get('com.apple.developer.system-extension.install') is not True:
        sys.exit(f'Host profile lacks system-extension.install: {bundle_id}')
    if expiry is None or expiry <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
        sys.exit(f'Profile expired: {bundle_id}')
    team_ids.append(teams[0])
    claims = {
        'com.apple.application-identifier': app_id,
        'com.apple.developer.team-identifier': teams[0],
        'com.apple.developer.networking.networkextension': ['packet-tunnel-provider-systemextension'],
    }
    if kind == 'app':
        claims['com.apple.developer.system-extension.install'] = True
    with (Path(sys.argv[5]) / f'{kind}.entitlements').open('wb') as stream:
        plistlib.dump(claims, stream)
if team_ids[0] != team_ids[1]:
    sys.exit('Host and extension profiles belong to different teams')
print(f'Profiles authorize both exact bundle IDs, packet tunnel, and host activation (team {team_ids[0]})')
PY

cp "$APP_PROFILE" "$app/Contents/embedded.provisionprofile"
cp "$EXTENSION_PROFILE" "$extension/Contents/embedded.provisionprofile"
codesign --force --sign "$DEVELOPER_ID_IDENTITY" --timestamp --options runtime \
    --entitlements "$tmpdir/extension.entitlements" "$extension"
codesign --force --sign "$DEVELOPER_ID_IDENTITY" --timestamp --options runtime \
    --entitlements "$tmpdir/app.entitlements" "$app"
codesign --verify --deep --strict --verbose=2 "$app"
signature_details=$(codesign -dv --verbose=4 "$app" 2>&1)
[[ "$signature_details" == *'Authority=Developer ID Application:'* ]] || {
    print -u2 'Signing identity did not produce a Developer ID Application signature'; exit 1;
}
print "Developer ID signed: $app"
