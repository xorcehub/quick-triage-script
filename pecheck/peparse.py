"""Load a PE once; every detector shares the same Target."""
import hashlib
import os
import struct

import pefile

_ARCH = {0x8664: "x64", 0x14C: "x86", 0xAA64: "ARM64"}


def cert_table_range(raw, pe):
    """-> (start, end) file offsets of the certificate table, or None.
    Walks consecutive WIN_CERTIFICATE entries (dwLength, 8-byte aligned).
    SECURITY.VA should be a file offset but is unreliable in the wild
    (sometimes RVA-like); fall back to end-of-last-section, where the
    table lives by definition."""
    def walk(off):
        end, n = len(raw), 0
        while off + 8 <= end:
            dwl, rev = struct.unpack_from("<IH", raw, off)
            if dwl < 8 or off + dwl > end or rev not in (0x0100, 0x0200):
                break
            off += (dwl + 7) & ~7
            n += 1
        return off if n else None
    try:
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    except (IndexError, AttributeError):
        return None
    cands = []
    if d.VirtualAddress:
        cands.append(d.VirtualAddress)
    try:
        cands.append(max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections))
    except Exception:
        pass
    for c in cands:
        if c and 0 < c < len(raw):
            e = walk(c)
            if e and e > c:
                return (c, e)
    return None


# directories detectors actually read (EXPORT, IMPORT, RESOURCE, DEBUG, TLS,
# DELAY). Skipping the rest (BASERELOC, EXCEPTION, IAT, ...) makes load ~50x
# faster on large PEs. A detector needing another dir must add its index here.
_PARSE_DIRS = [0, 1, 2, 6, 9, 13]


def load(path):
    from .model import Target
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return Target(path=os.path.abspath(path), size=0, sha256="",
                      error=f"unreadable: {type(e).__name__}: {e}")
    h = hashlib.sha256(raw).hexdigest()
    t = Target(path=os.path.abspath(path), size=len(raw), sha256=h, raw=raw)
    try:
        t.pe = pefile.PE(data=raw, fast_load=True)
        t.pe.parse_data_directories(directories=_PARSE_DIRS)
    except Exception as e:
        t.error = f"{type(e).__name__}: {e}"
        return t
    t.arch = _ARCH.get(t.pe.FILE_HEADER.Machine, hex(t.pe.FILE_HEADER.Machine))
    return t


# non-PE files commonly used as droppers/launchers alongside the binaries
SIDE_EXTS = (".bat", ".cmd", ".lnk", ".scr", ".hta", ".ps1", ".vbs", ".js", ".url")


def collect(root_paths):
    """-> (targets, sibling map, side files). Walks dirs for .exe/.dll plus
    dropper-ish script/shortcut files; explicit args pass through as targets."""
    targets, side = [], []
    for t in root_paths:
        if os.path.isdir(t):
            for dirpath, _, files in os.walk(t):
                for fn in files:
                    low = fn.lower()
                    full = os.path.join(dirpath, fn)
                    if low.endswith((".exe", ".dll")):
                        targets.append(full)
                    elif low.endswith(SIDE_EXTS) or ":zone.identifier" in low:
                        side.append(full)
        else:
            targets.append(t)
    targets = sorted(set(os.path.abspath(p) for p in targets))
    sibs = {}
    for p in targets:
        sibs.setdefault(os.path.dirname(p), []).append(os.path.basename(p).lower())
    return targets, sibs, side
