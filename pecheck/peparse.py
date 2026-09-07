"""Load a file once; every detector shares the same Target.
Generic since v2: kind via identify.py, pefile only runs on PE-kind files.
sha256 is always streamed; `raw` is capped (huge game assets never fully
loaded - ponytail: raise RAW_CAP if dump-like inputs need full bytes)."""
import hashlib
import os
import struct

import pefile

from .identify import kind as _kind

RAW_CAP = 64 << 20  # 64MB analysis cap
_CHUNK = 1 << 20


def _read(path):
    """-> (raw<=RAW_CAP, sha256, size). Streams the hash, caps the buffer."""
    h = hashlib.sha256()
    size = 0
    parts = []
    with open(path, "rb") as f:
        while True:
            b = f.read(_CHUNK)
            if not b:
                break
            size += len(b)
            h.update(b)
            if len(parts) < RAW_CAP // _CHUNK:
                parts.append(b)
    return b"".join(parts), h.hexdigest(), size


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

_ARCH = {0x8664: "x64", 0x14C: "x86", 0xAA64: "ARM64"}


def load(path):
    """-> Target for any file. t.error only on OSError; PE-parse failure
    sets t.error too but scan.py maps that to REVIEW (MZ claims PE)."""
    from .model import Target
    ap = os.path.abspath(path)
    try:
        raw, sha, size = _read(ap)
    except OSError as e:
        return Target(path=ap, size=0, sha256="", kind="DATA",
                      error=f"unreadable: {type(e).__name__}: {e}")
    k = _kind(ap, raw[:4096])
    t = Target(path=ap, size=size, sha256=sha, raw=raw, kind=k)
    if k != "PE":
        return t
    try:
        t.pe = pefile.PE(data=raw, fast_load=True)
        t.pe.parse_data_directories(directories=_PARSE_DIRS)
        t.arch = _ARCH.get(t.pe.FILE_HEADER.Machine, hex(t.pe.FILE_HEADER.Machine))
    except Exception as e:
        t.error = f"{type(e).__name__}: {e}"
    return t


# context files listed (not scanned as targets): MOTW artifacts + scene markers
SIDE_EXTS = (".nfo", ".diz")


def collect(root_paths):
    """-> (targets, sibling map, side files). Every regular file is a target
    (zip members are handled by the archive detector, not walked here).
    side files: zone-identifier ADS artifacts + .nfo/.diz scene markers."""
    targets, side = [], []
    for t in root_paths:
        if os.path.isdir(t):
            for dirpath, _, files in os.walk(t):
                for fn in files:
                    if ":" in fn:      # NTFS ADS (zone.identifier) - never open
                        side.append(os.path.join(dirpath, fn))
                        continue
                    low = fn.lower()
                    full = os.path.join(dirpath, fn)
                    if low.endswith(SIDE_EXTS):
                        side.append(full)
                    targets.append(full)
        elif os.path.exists(t):
            targets.append(t)
    targets = sorted(set(os.path.abspath(p) for p in targets))
    sibs = {}
    for p in targets:
        sibs.setdefault(os.path.dirname(p), []).append(os.path.basename(p).lower())
    return targets, sibs, side
