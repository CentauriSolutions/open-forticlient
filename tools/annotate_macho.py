#!/usr/bin/env python3
"""Annotate an x86_64 objdump listing of a Swift Mach-O binary.

- movabs immediates are decoded as little-endian ASCII (Swift small strings)
- RIP-relative lea/mov targets are resolved to C strings (also trying the
  Swift large-string convention of storing address-0x20)
- call targets are resolved to symbols via `nm` (when present)

usage: annotate.py <macho_x86_64> <asm> <start_line> <end_line>
"""
import re
import struct
import subprocess
import sys

binpath, asmpath, start, end = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
data = open(binpath, "rb").read()

# --- parse segments/sections (64-bit Mach-O, thin) ---
magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, _ = struct.unpack_from("<IiiIIIII", data, 0)
assert magic == 0xFEEDFACF, "need a thin 64-bit Mach-O"
off = 32
sections = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = data[off + 8:off + 24].rstrip(b"\0").decode()
        nsects = struct.unpack_from("<I", data, off + 64)[0]
        soff = off + 72
        for _ in range(nsects):
            sectname = data[soff:soff + 16].rstrip(b"\0").decode()
            addr, size, foff = struct.unpack_from("<QQI", data, soff + 32)
            sections.append((segname, sectname, addr, size, foff))
            soff += 80
    off += cmdsize


def section_of(vaddr):
    for seg, sect, addr, size, foff in sections:
        if addr <= vaddr < addr + size:
            return sect, addr, foff
    return None, None, None


def read_ptr(vaddr):
    sect, addr, foff = section_of(vaddr)
    if sect is None or not foff:
        return None
    raw = struct.unpack_from("<Q", data, foff + (vaddr - addr))[0]
    # chained fixups (DYLD_CHAINED_PTR_64[_OFFSET]): low 36 bits = target
    tgt = raw & 0xFFFFFFFFF
    if tgt < 0x100000000:
        tgt += 0x100000000
    return tgt


def deref_name(vaddr):
    sect, _, _ = section_of(vaddr)
    if sect in ("__objc_selrefs", "__objc_classrefs", "__objc_superrefs"):
        p = read_ptr(vaddr)
        if p:
            s = read_cstr(p)
            if s:
                return f"{sect}->{s}"
            if p in syms:
                return f"{sect}->{syms[p]}"
    if sect == "__cfstring":
        p = read_ptr(vaddr + 16)
        if p:
            s = read_cstr(p)
            if s:
                return f"cfstr {s}"
    return None


def read_cstr(vaddr, maxlen=200):
    for seg, sect, addr, size, foff in sections:
        if addr <= vaddr < addr + size and foff:
            o = foff + (vaddr - addr)
            raw = data[o:o + maxlen]
            s = raw.split(b"\0", 1)[0]
            if len(s) >= 2 and all(32 <= c < 127 or c in (9, 10, 13) for c in s):
                return f"{sect}:\"{s.decode()[:120]}\""
            return None
    return None


syms = {}
try:
    out = subprocess.run(["nm", "-n", binpath], capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split(" ", 2)
        if len(parts) == 3:
            try:
                syms[int(parts[0], 16)] = parts[2]
            except ValueError:
                pass
except Exception:
    pass

imm_re = re.compile(r"movabs\s+\w+, 0x([0-9a-f]+)")
tgt_re = re.compile(r"# 0x([0-9a-f]+)")
call_re = re.compile(r"\bcall\s+0x([0-9a-f]+)")

with open(asmpath) as f:
    for i, line in enumerate(f, 1):
        if i < start:
            continue
        if i > end:
            break
        line = line.rstrip("\n")
        note = ""
        m = imm_re.search(line)
        if m:
            v = int(m.group(1), 16)
            b = v.to_bytes(8, "little")
            txt = "".join(chr(c) if 32 <= c < 127 else "." for c in b)
            note = f'  ;; imm "{txt}"'
        m = tgt_re.search(line)
        if m:
            t = int(m.group(1), 16)
            s = deref_name(t) or read_cstr(t) or read_cstr(t + 0x20)
            if s:
                note += f"  ;; {s}"
            elif t in syms:
                note += f"  ;; {syms[t]}"
        m = call_re.search(line)
        if m:
            t = int(m.group(1), 16)
            if t in syms:
                note += f"  ;; -> {syms[t][:110]}"
        print(f"{i}: {line}{note}")
