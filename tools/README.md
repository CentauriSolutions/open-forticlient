# Tools

Helpers used to reverse-engineer FortiClient and to exercise the SAML flow. All
are read-only / local; none store secrets.

## `annotate_macho.py`

Annotates an x86-64 `objdump` listing of a Swift/Obj-C Mach-O so you can read it:

- decodes `movabs` immediates as little-endian ASCII (Swift small-string literals),
- resolves RIP-relative `lea/mov` targets to C strings, CFStrings, and
  `__objc_selrefs`/`__objc_classrefs` names (follows chained-fixup pointers),
- labels `call` targets from the symbol table.

### Recipe

```bash
BIN="/Applications/FortiClient.app/Contents/Resources/runtime.helper/FortiClientAgent.app/Contents/Resources/FortiTray/FortiTray.app/Contents/MacOS/FortiTray"

# 1. thin out one arch (annotator expects a single-arch Mach-O)
lipo -thin x86_64 -output /tmp/fortitray_x86 "$BIN"

# 2. disassemble (Intel syntax, with the '## 0x… <symbol>' comments objdump adds)
xcrun objdump -d --no-show-raw-insn --x86-asm-syntax=intel /tmp/fortitray_x86 \
    > /tmp/fortitray_x86.asm

# 3. find a function's line range, then annotate it
grep -n '^[0-9a-f]* <_symbol_name>:' /tmp/fortitray_x86.asm
python3 annotate_macho.py /tmp/fortitray_x86 /tmp/fortitray_x86.asm <start> <end>
```

Tips used in this project:
- Dump name-map tables (notify/cfg/exchange/EAP codes) straight from the daemon's
  data segment instead of guessing — see the `_ikev2_*_map` arrays in `iked`.
- Fortinet notify types are stored as a little-endian 16-bit word at offset +2 of
  the notify payload, so e.g. `mov word ptr [rax+2], 0x50f0` is wire `0xF050`.

## `saml_catch.py`

A minimal loopback HTTP server that captures the gateway's post-SSO redirect
(`?tokenid=…&username=…`) — i.e. the data FortiTray feeds into IKE as the EAP
identity + OTP. Masks the token by default. See the file's docstring for the full
consent-gated, on-your-own-machine end-to-end probe recipe, and
`../docs/saml-ipsec-protocol.md` for what each step means.

```bash
python3 saml_catch.py --port 56299          # masked
python3 saml_catch.py --port 56299 --show-secrets   # raw token (only when you need it)
```

## Regenerating the raw analysis inputs

The large derived files (`*.asm`, `strings` dumps) are intentionally **not**
committed — they are tens of MB and trivially regenerated from the installed
binaries with the recipe above. The binaries analyzed:

- `…/FortiTray.app/Contents/MacOS/FortiTray` — VPN manager / SAML / sleep handling
- `/Library/Application Support/Fortinet/FortiClient/bin/iked` — IKEv2 + EAP daemon
- `/Library/Application Support/Fortinet/FortiClient/bin/fctctld` — daemon launcher
