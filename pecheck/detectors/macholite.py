"""Minimal Mach-O triage (struct-only, mirrors elflite): arch/type line,
fat-header count, loaded dylibs (non-system paths), entitlements snippet,
code-signature presence (validity NOT verified), UPX marker."""
import struct

from ..model import Finding, CRITICAL

# file bytes -> (byte order, bits)
_THIN = {
    b"\xcf\xfa\xed\xfe": ("<", 64),   # MH_MAGIC_64 little-endian
    b"\xfe\xed\xfa\xcf": (">", 64),   # MH_MAGIC_64 big-endian
    b"\xce\xfa\xed\xfe": ("<", 32),   # MH_MAGIC little-endian
    b"\xfe\xed\xfa\xce": (">", 32),   # MH_MAGIC big-endian
}
_FAT = b"\xca\xfe\xba\xbe"            # fat headers are big-endian

_CPUTYPE = {7: "x86", 7 | 0x01000000: "x86_64", 12: "arm",
            12 | 0x01000000: "arm64", 18: "ppc", 0x0100000C: "arm64"}
_FILETYPE = {1: "object", 2: "executable", 3: "fvmlib", 4: "core", 5: "preload",
             6: "dylib", 7: "dylinker", 8: "bundle", 9: "dylib_stub", 10: "dSYM"}
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_CODE_SIGNATURE = 0x1D
_MAX_CMDS = 512  # ponytail: fuzzed headers - cap load-command walks


def _dylib_name(raw, off, end, fmt):
    """>> dylib path string for a load command at `off`, or None."""
    try:
        name_off = struct.unpack_from(fmt + "I", raw, off + 8)[0]
        p = off + name_off
        if not (off <= p < end):
            return None
        q = raw.find(b"\x00", p, min(end, p + 4096))
        return raw[p:q if q > 0 else end].decode("utf-8", "replace")
    except struct.error:
        return None


def _walk_cmds(raw, fmt, ncmds, off, out):
    """>> (dylib paths, codesig?) walking the load-command table (capped)."""
    end = min(len(raw), off + (1 << 20))
    dylibs, codesig = [], False
    p = off
    for _ in range(min(ncmds, _MAX_CMDS)):
        if p + 8 > end:
            break
        try:
            cmd, cmdsize = struct.unpack_from(fmt + "II", raw, p)
        except struct.error:
            out.append(Finding("STRUCT?", "truncated load command table"))
            break
        if cmdsize < 8 or p + cmdsize > end:
            break
        if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
            name = _dylib_name(raw, p, end, fmt)
            if name:
                dylibs.append(name)
        elif cmd == LC_CODE_SIGNATURE:
            codesig = True
        p += cmdsize
    return dylibs, codesig


def run(t):
    if not t.raw or t.kind != "MACHO":
        return []
    raw = t.raw
    out = []
    dylibs, codesig = [], False

    if raw[:4] == _FAT:
        try:
            n = struct.unpack_from(">I", raw, 4)[0]
        except struct.error:
            n = 0
        if 0 < n <= 64:
            out.append(Finding("NOTE", f"Mach-O fat binary: {n} architecture slice(s)"))
        else:
            out.append(Finding("STRUCT?", f"fat header claims {n} slices (implausible - forged?)"))
            return out  # header lies; slice walking would be garbage-in
    elif raw[:4] in _THIN:
        fmt, bits = _THIN[raw[:4]]
        hlen = 32 if bits == 64 else 28
        if len(raw) < hlen:
            return [Finding("STRUCT?", "Mach-O header truncated")]
        cputype, _cpusub, ftype, ncmds, _sz = struct.unpack_from(fmt + "iiIII", raw, 4)
        arch = _CPUTYPE.get(cputype, hex(cputype & 0xFFFFFF))
        out.append(Finding("NOTE", f"Mach-O {'64' if bits == 64 else '32'}-bit {arch} "
                                   f"{_FILETYPE.get(ftype, f'type {ftype}')}"))
        dylibs, codesig = _walk_cmds(raw, fmt, ncmds, hlen, out)
    else:
        return [Finding("STRUCT?", "Mach-O header unreadable")]

    bad = [d for d in dylibs
           if not d.startswith(("/usr/lib", "/System", "@rpath", "@executable_path", "@loader_path"))]
    if bad:
        out.append(Finding("MEM?", f"loads non-system dylib(s): {', '.join(bad[:5])}"))
    if codesig:
        out.append(Finding("PROV", "LC_CODE_SIGNATURE present (CMS blob - validity NOT verified)"))
    if b"UPX!" in raw[:262144]:
        out.append(Finding("PACKED?", "UPX-packed Mach-O (UPX! marker)", CRITICAL))
    if b"com.apple." in raw[:1 << 20]:
        out.append(Finding("PROV", "embedded entitlements/Info.plist keys (com.apple.*)"))
    return out
