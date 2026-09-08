"""Load a file once; every detector shares the same Target.
Generic since v2: kind via identify.py, pefile only runs on PE-kind files.
sha256 is always streamed; `raw` is capped (huge game assets never fully
loaded - ponytail: raise RAW_CAP if dump-like inputs need full bytes)."""
import hashlib
import os
import struct
import sys

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

_ZONE_KEYS = ("zoneid", "hosturl", "referrerurl", "downloadtime")


def parse_motw(data):
    """-> {zone, host, referrer, time} from Zone.Identifier ADS bytes, or None.
    Line-oriented [ZoneTransfer] INI; unknown keys ignored (browsers add more)."""
    out = {}
    for line in data.decode("utf-8", "replace").splitlines():
        k, sep, v = line.partition("=")
        if not sep:
            continue
        k = k.strip().lower()
        if k == "zoneid":
            out["zone"] = v.strip()
        elif k == "hosturl":
            out["host"] = v.strip()
        elif k == "referrerurl":
            out["referrer"] = v.strip()
        elif k == "downloadtime" and "time" not in out:
            out["time"] = v.strip()
    return out or None


def _probe_motw(path):
    """os.walk never lists NTFS ADS - probe the stream directly (no-op elsewhere)."""
    if os.name != "nt":
        return None
    try:
        with open(path + ":Zone.Identifier", "rb") as f:
            return parse_motw(f.read(4096))
    except OSError:
        return None


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
    k = _kind(ap, raw[:0x8808])
    t = Target(path=ap, size=size, sha256=sha, raw=raw, kind=k, truncated=size > len(raw))
    t.motw = _probe_motw(ap)
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
    side files: zone-identifier ADS artifacts + .nfo/.diz scene markers.
    Glob patterns (*, ?) are expanded here: cmd/PowerShell don't glob for
    native programs the way POSIX shells do."""
    import glob as _glob
    expanded = []
    for t in root_paths:
        if ("*" in t or "?" in t) and not os.path.exists(t):
            # ponytail: escape '[' so scene-release dirs like [GDZ] stay literal
            hits = sorted(_glob.glob(t.replace("[", "[[]"), recursive="**" in t))
            if not hits:
                print(f"warning: no files match: {t}", file=sys.stderr)
            expanded.extend(hits)
        else:
            expanded.append(t)
    targets, side = [], []
    for t in expanded:
        if os.path.isdir(t):
            for dirpath, _, files in os.walk(t):
                for fn in files:
                    if ":" in fn and os.name == "nt":  # NTFS ADS (zone.identifier)
                        side.append(os.path.join(dirpath, fn))
                        continue
                    low = fn.lower()
                    full = os.path.join(dirpath, fn)
                    if low.endswith(SIDE_EXTS):
                        side.append(full)
                        continue
                    targets.append(full)
        elif os.path.exists(t):
            targets.append(t)
        else:
            print(f"warning: not found: {t}", file=sys.stderr)
    targets = sorted(set(os.path.abspath(p) for p in targets))
    sibs = {}
    for p in targets:
        sibs.setdefault(os.path.dirname(p), []).append(os.path.basename(p).lower())
    return targets, sibs, side
