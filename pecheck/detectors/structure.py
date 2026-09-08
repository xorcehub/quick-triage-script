"""Structure anomalies: overlay, entry point, section sizing,
packer/packager magic, embedded PEs."""
from ..model import Finding
from ..peparse import dd
from .sections import shannon

PACKER_SECTIONS = {"upx0", "upx1", "upx2", "upx!", "mpress1", "mpress2",
                   ".aspack", ".adata", ".themida", ".vmp0", ".vmp1", ".enigma1", "pebundle"}
# magic -> label; sniffed within the first 2KB of overlay/resource blobs
# (installers often prefix archive data with SFX config scripts)
MAGICS = (
    (b"MEI\x0c\x0b\x0a\x0b\x0e", "PyInstaller archive"),
    (b"\x7fELF", "embedded ELF"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b";@Install@", "7-Zip SFX config (installer)"),
    (b"!@Install@", "7-Zip SFX config (installer)"),
    (b"PK\x03\x04", "zip archive"),
    (b"Rar!", "rar archive"),
    (b"NullsoftInst", "NSIS installer"),
    (b"zlb\x1a", "Inno Setup data"),
)
GO_BUILDINF = b" Go buildinf:"  # appears as "\xff Go buildinf:" or similar in Go PE data


def _sniff(blob):
    """-> labels for magics found in the first 2KB."""
    head = blob[:2048]
    hits = [label for magic, label in MAGICS if magic in head]
    if head[:2] == b"MZ":
        hits.append("embedded PE")
    if GO_BUILDINF in head:
        hits.append("Go buildinfo")
    return hits


def _overlay_regions(pe, raw):
    """-> list of (start, end) byte ranges forming the overlay
    (after sections, minus the full certificate chain)."""
    ends = [s.PointerToRawData + s.SizeOfRawData for s in pe.sections if s.PointerToRawData]
    if not ends:
        return []
    start, end = max(ends), len(raw)
    if start >= end:
        return []
    try:
        rng = cert_table_range(raw, pe)
        if rng and rng[0] >= start and rng[1] <= end:
            # overlay = gap before cert + anything after the full cert chain
            return [(s, e) for s, e in ((start, rng[0]), (rng[1], end)) if e > s]
    except Exception:
        pass
    return [(start, end)]


def _nm(s):
    return s.Name.rstrip(b"\x00").decode(errors="replace")


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
    regions = _overlay_regions(pe, t.raw)
    total = sum(e - s for s, e in regions)
    if total > 4096:
        blob = b"".join(t.raw[s:e][:65536] for s, e in regions)
        e = round(shannon(blob), 2)
        hits = _sniff(t.raw[regions[0][0]:regions[0][0] + 2048])
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
                            blob = pe.get_data(l.data.struct.OffsetToData, min(l.data.struct.Size, 2048))
                        except Exception:
                            continue
                        hits = _sniff(blob)
                        if hits:
                            out.append(Finding("PACKED?", f"resource type {getattr(rt, 'id', '?')} contains {', '.join(hits)}"))
        except Exception:
            pass

    # overlapping raw ranges: parser-confusion / SFX-packing class
    mapped = sorted((s for s in pe.sections if s.PointerToRawData and s.SizeOfRawData),
                    key=lambda s: s.PointerToRawData)
    for a, b in zip(mapped, mapped[1:]):
        if b.PointerToRawData < a.PointerToRawData + a.SizeOfRawData:
            out.append(Finding("EVADE?", f"sections overlap raw ranges: "
                                         f"{_nm(a)} and {_nm(b)} cover the same file bytes"))
            break

    # header CheckSum wrong - only meaningful on signed binaries (unsigned
    # installers ship zero/stale checksums routinely; the cert gate kills the FP)
    try:
        dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        hdr_sum = pe.OPTIONAL_HEADER.CheckSum
        if hdr_sum and len(dirs) > 4 and dirs[4].VirtualAddress:
            calc = pe.generate_checksum()
            if calc and calc != hdr_sum:
                out.append(Finding("STRUCT?", f"header CheckSum {hdr_sum:#x} != computed "
                                              f"{calc:#x} on a signed image (edited after signing?)"))
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
    exp = dd(pe, 0)
    if not is_dll and exp and exp.VirtualAddress:
        out.append(Finding("STRUCT", "executable exports functions (dual-mode/installer or export proxy)"))
    return out
