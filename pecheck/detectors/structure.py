"""Structure anomalies: overlay, entry point, section sizing,
packer/packager magic, embedded PEs."""
import math

from ..model import Finding

PACKER_SECTIONS = {"upx0", "upx1", "upx2", "upx!", "mpress1", "mpress2",
                   ".aspack", ".adata", ".themida", ".vmp0", ".vmp1", ".enigma1", "pebundle"}
# magic -> label (checked at overlay start and inside RCDATA-style resources)
MAGICS = (
    (b"MEI\x0c\x0b\x0a\x0b\x0e", "PyInstaller archive"),
    (b"\x7fELF", "embedded ELF"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"PK\x03\x04", "zip archive"),
    (b"Rar!", "rar archive"),
    (b"Nullsoft", "NSIS installer data"),
    (b"zlb\x1a", "Inno Setup data"),
    (b"IPC!", "InstallCreator"),
)
GO_BUILDINF = b" Go buildinf:"  # appears as "\xff Go buildinf:" or similar in Go PE data


def shannon(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _overlay_region(pe, raw):
    """-> (start, end) byte range of overlay (after sections, minus cert blob)."""
    ends = [s.PointerToRawData + s.SizeOfRawData for s in pe.sections if s.PointerToRawData]
    if not ends:
        return None
    start = max(ends)
    end = len(raw)
    try:
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # SECURITY: VA is a file offset
        if sec.VirtualAddress and sec.VirtualAddress > start:
            cert_end = sec.VirtualAddress + sec.Size
            if cert_end <= end:
                # overlay = gap before cert + anything after cert
                pre = (start, sec.VirtualAddress)
                post = (cert_end, end) if cert_end < end else None
                return pre, post
    except Exception:
        pass
    return (start, end)


def _sniff(blob):
    hits = [label for magic, label in MAGICS if blob[:16].startswith(magic)]
    if blob[:2] == b"MZ":
        hits.append("embedded PE")
    if GO_BUILDINF in blob[:4096]:
        hits.append("Go buildinfo")
    return hits


def run(t):
    if t.error or t.pe is None:
        return []
    pe = t.pe
    out = []

    # packer section names
    for s in pe.sections:
        nm = s.Name.rstrip(b"\x00").decode(errors="replace").lower()
        if nm in PACKER_SECTIONS:
            out.append(Finding("PACKED?", f"packer section name '{nm}'", "CRITICAL"))

    # overlay
    reg = _overlay_region(pe, t.raw)
    regions = reg if reg and isinstance(reg[0], tuple) else (reg,) if reg else ()
    total = sum(e - s for s, e in regions)
    if total > 4096:
        blob = b"".join(t.raw[s:e][:65536] for s, e in regions)
        e = round(shannon(blob), 2)
        hits = _sniff(t.raw[regions[0][0]:regions[0][0] + 64])
        detail = f"overlay {total:,}B entropy={e}"
        if hits:
            detail += f" starts with: {', '.join(hits)}"
            out.append(Finding("PACKED?", detail, "CRITICAL"))
        elif total > 0.25 * max(1, len(t.raw)):
            out.append(Finding("MEM?", detail + " (>25% of file - inspect)"))
        else:
            out.append(Finding("STRUCT", detail))

    # embedded PE / packager magic inside resources
    res = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if res is not None:
        try:
            tree = getattr(res, "entries", res)
            for rt in tree:
                for e in rt.directory.entries:
                    for l in e.directory.entries:
                        try:
                            blob = pe.get_data(l.data.struct.OffsetToData, min(l.data.struct.Size, 64))
                        except Exception:
                            continue
                        hits = _sniff(blob)
                        if hits:
                            out.append(Finding("PACKED?", f"resource type {getattr(rt, 'id', '?')} contains {', '.join(hits)}"))
        except Exception:
            pass

    # entry-point placement
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if ep:
        secs = [s for s in pe.sections]
        for i, s in enumerate(secs):
            if s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                exec_ = bool(s.Characteristics & 0x20000000)
                nm = s.Name.rstrip(b"\x00").decode(errors="replace")
                if not exec_:
                    out.append(Finding("EVADE?", f"entry point in non-executable section {nm}"))
                elif i == len(secs) - 1 and len(secs) > 2:
                    out.append(Finding("PACKED?", f"entry point in LAST section {nm} (packer/unpacker pattern)"))
                break

    # VirtualSize >> RawSize on an executable section: in-memory staging area
    for s in pe.sections:
        vs, rs = s.Misc_VirtualSize, s.SizeOfRawData
        if vs > 0x10000 and rs * 4 < vs and (s.Characteristics & 0x20000000):
            nm = s.Name.rstrip(b"\x00").decode(errors="replace")
            out.append(Finding("MEM?", f"section {nm}: VirtualSize {vs:,} >> RawSize {rs:,} (unpack/staging area)"))

    # EXE with exports (rare; dual-mode/installer/proxy)
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    if not is_dll and pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress:
        out.append(Finding("STRUCT", "executable exports functions (dual-mode/installer or export proxy)"))
    return out
