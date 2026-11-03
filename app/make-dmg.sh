#!/bin/zsh
# Wrap the notarized package in a signed, notarized disk image to hand to
# colleagues: the package, a Read me first, and optionally a .oftc file of
# default VPNs (OFTC_VPNS_FILE). Without that file the image is generic and
# safe to publish. Run after package.sh and notarize-package.sh.
set -euo pipefail

root="${0:A:h}"
build="${OFTC_BUILD_DIR:-$root/build}"
if [[ "$build" != "$root/build" && ! "$build" =~ '^/private/tmp/oftc-build-[A-Za-z0-9-]+$' ]]; then
    print -u2 'OFTC_BUILD_DIR must be app/build or a /private/tmp/oftc-build-* path'
    exit 2
fi
volume="Open Forticlient"
app="$build/OFTC.app"
version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist")
package="$build/OFTC-$version.pkg"
vpns="${OFTC_VPNS_FILE:-}"
suffix=""
[[ -n "$vpns" ]] && suffix="-with-vpns"
dmg="$build/Open-Forticlient-$version$suffix.dmg"
stage="$build/dmg-root$suffix"
writable="$build/dmg-writable$suffix.dmg"
mount="/Volumes/$volume"
: "${DEVELOPER_ID_IDENTITY:?Set DEVELOPER_ID_IDENTITY to the Developer ID Application identity}"
[[ "$DEVELOPER_ID_IDENTITY" =~ '^[A-Fa-f0-9]{40}$' ]] || {
    print -u2 'DEVELOPER_ID_IDENTITY must be the exact 40-character certificate SHA-1'; exit 2
}
notarize=1
if [[ "${OFTC_DMG_UNNOTARIZED_TEST:-}" == 1 ]]; then
    notarize=0
    print 'UNNOTARIZED TEST IMAGE: do not distribute it.'
else
    : "${NOTARY_PROFILE:?Set NOTARY_PROFILE to a notarytool keychain profile name}"
fi
[[ -f "$package" && ! -e "$stage" && ! -e "$dmg" && ! -e "$writable" && ! -e "$mount" ]] || {
    print -u2 'Need the notarized package, a fresh output path, and no mounted "Open Forticlient" volume'; exit 2
}
xcrun stapler validate "$package"
pkgutil --check-signature "$package" >/dev/null

step2='2. Add your VPN
   Click the OFTC icon in the menu bar, choose Settings > Add VPN, and enter
   your FortiGate gateway and SAML port. Your administrator may also give you
   a .oftc file: double-click it and OFTC offers to add its VPNs.'
if [[ -n "$vpns" ]]; then
    python3 - "$vpns" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert data.get("format") == "oftc-profiles" and data.get("version") == 1 and data.get("profiles"), "not an OFTC profile file"
PY
    step2='2. Add the VPNs
   Double-click "2 OFTC VPNs.oftc". OFTC lists the VPNs and asks before
   adding them. Install OFTC first, or the file will not open.'
fi

mkdir -p "$stage"
ditto "$package" "$stage/1 Install OFTC.pkg"
[[ -n "$vpns" ]] && { ditto "$vpns" "$stage/2 OFTC VPNs.oftc"; chmod 644 "$stage/2 OFTC VPNs.oftc"; }
python3 - "$root/package-resources/dmg-readme.txt" "$stage/Read me first.txt" "$step2" <<'PY'
import sys
text = open(sys.argv[1]).read().replace("@@STEP2@@", sys.argv[3])
open(sys.argv[2], "w").write(text)
PY
xcrun swiftc -O "$root/set-file-icon.swift" -o "$build/set-file-icon"
"$build/set-file-icon" "$root/assets/OFTCPackage.icns" "$stage/1 Install OFTC.pkg"
[[ -n "$vpns" ]] && "$build/set-file-icon" "$root/assets/OFTCDocument.icns" "$stage/2 OFTC VPNs.oftc"

hdiutil create -srcfolder "$stage" -volname "$volume" -fs HFS+ -format UDRW -size 64m -ov "$writable" >/dev/null
hdiutil attach "$writable" -noverify -noautoopen >/dev/null
trap 'hdiutil detach "$mount" -force >/dev/null 2>&1 || true' EXIT

# Window layout is cosmetic: try for a while, then carry on without it.
layout() {
    osascript <<OSA
tell application "Finder"
    tell disk "$volume"
        open
        delay 2
        tell container window
            set current view to icon view
            set toolbar visible to false
            set statusbar visible to false
            set bounds to {200, 120, 840, 440}
        end tell
        set options to the icon view options of container window
        set arrangement of options to not arranged
        set icon size of options to 112
        set text size of options to 12
        set position of item "1 Install OFTC.pkg" of container window to {130, 150}
        $( [[ -n "$vpns" ]] && print 'set position of item "2 OFTC VPNs.oftc" of container window to {320, 150}' )
        set position of item "Read me first.txt" of container window to {510, 150}
        update without registering applications
        delay 2
        close
    end tell
end tell
OSA
}
layout &
layout_pid=$!
for _ in {1..40}; do kill -0 $layout_pid 2>/dev/null || break; sleep 1; done
kill $layout_pid 2>/dev/null || print 'Finder layout applied.'
# After the Finder pass, which would otherwise disturb the volume's own icon.
cp "$root/assets/OFTC.icns" "$mount/.VolumeIcon.icns"
SetFile -a C "$mount"
sync
hdiutil detach "$mount" >/dev/null
trap - EXIT
hdiutil convert "$writable" -format UDZO -imagekey zlib-level=9 -o "$dmg" >/dev/null
rm -f "$writable"
codesign --force --sign "$DEVELOPER_ID_IDENTITY" --timestamp "$dmg"
codesign --verify --strict --verbose=2 "$dmg"
if (( notarize )); then
    xcrun notarytool submit "$dmg" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$dmg"
    xcrun stapler validate "$dmg"
    spctl --assess --type open --context context:primary-signature --verbose=2 "$dmg"
    print "Notarized and stapled image: $dmg"
else
    print "Signed (not notarized) test image: $dmg"
fi
