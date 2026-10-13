#!/usr/bin/env python3
"""Fail on wrong bundle layout, entitlements, or dynamic-library paths."""
import plistlib
import subprocess
import sys
from pathlib import Path

app, extension = map(Path, sys.argv[1:])
frameworks = extension / "Contents/Frameworks"
provider = extension / "Contents/MacOS/IntegrationProvider"
core = frameworks / "liboftc_core.dylib"
crypto = frameworks / "libcrypto_swift.dylib"


def output(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def entitlements(path: Path) -> dict:
    # Xcode 27's `--entitlements -` prints a human-readable dictionary. The
    # deprecated `:-` form still emits XML, so parse just the plist payload.
    result = output("codesign", "-d", "--entitlements", ":-", str(path))
    return plistlib.loads(result[result.index("<?xml"):].encode())


app_id = plistlib.loads((app / "Contents/Info.plist").read_bytes())["CFBundleIdentifier"]
extension_id = plistlib.loads((extension / "Contents/Info.plist").read_bytes())["CFBundleIdentifier"]
assert extension_id == f"{app_id}.provider"
assert extension.name == f"{extension_id}.systemextension"
for path in (app, extension):
    info = plistlib.loads((path / "Contents/Info.plist").read_bytes())
    assert (path / "Contents/MacOS" / info["CFBundleExecutable"]).is_file(), path
    claims = entitlements(path)
    assert claims["com.apple.developer.networking.networkextension"] == [
        "packet-tunnel-provider-systemextension"
    ], path
assert entitlements(app)["com.apple.developer.system-extension.install"] is True
assert "com.apple.developer.system-extension.install" not in entitlements(extension)
assert (app / "Contents/Library/SystemExtensions" / extension.name) == extension
provider_class = plistlib.loads((extension / "Contents/Info.plist").read_bytes())[
    "NetworkExtension"
]["NEProviderClasses"]["com.apple.networkextension.packet-tunnel"]
assert provider_class == "IntegrationProvider.PacketTunnelProvider"
assert output("file", str(provider)).find("arm64") >= 0
assert "@rpath/liboftc_core.dylib" in output("otool", "-L", str(provider))
assert "@rpath/libcrypto_swift.dylib" in output("otool", "-L", str(core))
assert "@executable_path/../Frameworks" in output("otool", "-l", str(provider))
assert "@loader_path" in output("otool", "-l", str(core))
assert output("otool", "-D", str(core)).strip().endswith("@rpath/liboftc_core.dylib")
assert output("otool", "-D", str(crypto)).strip().endswith("@rpath/libcrypto_swift.dylib")
print("PASS: bundle layout, entitlements, and dylib install/load paths")
