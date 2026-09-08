"""Provenance: who built this, under what name.
PDB paths, VS_VERSION_INFO consistency, RT_MANIFEST elevation."""
import os

from ..model import Finding, CRITICAL
from ..peparse import dd

_DEBUG_CODEVIEW = 2  # IMAGE_DEBUG_TYPE_CODEVIEW


def _pdb_path(pe):
    for de in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        try:
            if de.struct.Type != _DEBUG_CODEVIEW:
                continue
            blob = pe.get_data(de.struct.AddressOfRawData, de.struct.SizeOfData)
            if blob[:4] == b"RSDS":
                return blob[24:].split(b"\x00", 1)[0].decode(errors="replace")
        except Exception:
            continue
    return None


def _version_strings(pe):
    """-> dict of StringFileInfo entries (CompanyName, ProductName, ...)."""
    out = {}
    try:
        for group in getattr(pe, "FileInfo", []):
            for fi in group:
                if getattr(fi, "Key", b"") in (b"StringFileInfo", "StringFileInfo"):
                    for st in fi.StringTable:
                        for k, v in st.entries.items():
                            kk = k.decode(errors="replace") if isinstance(k, bytes) else k
                            vv = v.decode(errors="replace") if isinstance(v, bytes) else v
                            out[kk] = vv
    except Exception:
        pass
    return out


def _rich(raw, tds):
    """-> (linker_product, linker_build, n_entries, checksum) or None.
    Rich header lives in the DOS stub: XORED compid pairs ending at the plain
    'Rich' marker + XOR key; DanS signature anchors the start (16-aligned).
    checksum (plain dword right before 'Rich') is conventionally TimeDateStamp."""
    import struct
    end = raw.find(b"Rich", 0, 0x2000)
    if end < 4 or end + 8 > len(raw) or (end & 3):
        return None
    key = struct.unpack_from("<I", raw, end + 4)[0]
    start = None
    for off in range(end - 4, max(end - 0x800, -1), -4):
        if struct.unpack_from("<I", raw, off)[0] ^ key == 0x536E6144:  # "DanS"
            start = off
            break
    if start is None or start & 0xF:  # DanS sits 16-aligned by spec
        return None
    compids = []
    for off in range(start + 8, end - 4, 8):
        c = struct.unpack_from("<I", raw, off)[0] ^ key
        if c:
            compids.append(c)
    if not compids:
        return None
    first = compids[0]
    return (first >> 16, first & 0xFFFF, len(compids),
            struct.unpack_from("<I", raw, end - 4)[0])


def _manifest_blob(pe):
    """-> bytes of the first RT_MANIFEST (type 24) resource, or None."""
    res = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if res is None:
        return None
    tree = getattr(res, "entries", res)
    try:
        for t in tree:
            if getattr(t, "id", None) != 24:
                continue
            for e in t.directory.entries:
                for l in e.directory.entries:
                    return pe.get_data(l.data.struct.OffsetToData, l.data.struct.Size)
    except Exception:
        pass
    return None


def run(t):
    if t.error or t.pe is None:
        return []
    pe = t.pe
    out = []

    pdb = _pdb_path(pe)
    if pdb:
        out.append(Finding("PROV", f"pdb: {pdb}"))

    vi = _version_strings(pe)
    base = os.path.basename(t.path).lower()
    orig = (vi.get("OriginalFilename") or vi.get("InternalName") or "").lower()
    company = vi.get("CompanyName", "")
    if vi:
        out.append(Finding("PROV", f"version-info: {company or '?'} / {vi.get('ProductName', '?')}"))
        if orig and orig != base:
            out.append(Finding("PROV?", f"OriginalFilename '{orig}' != actual filename '{base}' (renamed/tampered?)"))
        if not company:
            out.append(Finding("PROV?", "version info present but CompanyName missing"))
    elif not getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None):
        out.append(Finding("PROV?", "no version-info resource (uncommon for shipped software)"))

    # kernel drivers: unsigned/broken signature is categorically worse than usermode.
    # sig tuple gates (catalog signing returns Valid); cert-table is only the
    # weak-mode fallback so legit signed drivers don't FP off-Windows.
    if t.ext == ".sys":
        sec = dd(pe, 4)
        cert = sec.VirtualAddress if sec else 0
        if t.sig and t.sig[0] == "Valid":
            pass
        elif t.sig:  # NotSigned / HashMismatch / trust-engine error
            out.append(Finding("PROV!", f"kernel driver signature problem: {t.sig[0]} - "
                                         "drivers run in ring 0", CRITICAL))
        elif cert:
            out.append(Finding("PROV?", "kernel driver; cert table present but validity NOT "
                                        "verified (weak mode) - verify before loading"))
        else:
            out.append(Finding("PROV!", "unsigned kernel driver - drivers run in ring 0", CRITICAL))

    # Rich header: compiler fingerprint + forgery cross-checks
    com = dd(pe, 14)  # COM descriptor (dotnet assemblies may legitimately lack Rich)
    rich = _rich(t.raw, pe.FILE_HEADER.TimeDateStamp)
    if rich:
        prod, build, n, chk = rich
        out.append(Finding("PROV", f"Rich header: linker build {build}, {n} compid entr"
                                   f"{'y' if n == 1 else 'ies'}"))
        if "microsoft" in company.lower() and prod != 1:
            # product 1 is the MSVC linker; anything else contradicts the vendor string
            out.append(Finding("PROV?", f"CompanyName says Microsoft but Rich linker product "
                                        f"is {prod} (MinGW/other toolchain claiming vendor identity?)"))
        if chk and chk != pe.FILE_HEADER.TimeDateStamp:
            out.append(Finding("PROV?", f"Rich checksum ({chk:#x}) != TimeDateStamp "
                                        f"({pe.FILE_HEADER.TimeDateStamp:#x}) - stub edited/repacked"))
    elif not (com and com.Size):
        out.append(Finding("PROV?", "no Rich header (stripped or non-MSVC toolchain - "
                                    "Go/Rust/deliberate removal are legit)"))

    man = _manifest_blob(pe)
    if man:
        low = man.lower()
        if b"requireadministrator" in low:
            out.append(Finding("PROV?", "manifest requests requireAdministrator (check signature above)"))
        if b'uiaccess="true"' in low or b"uiaccess='true'" in low:
            out.append(Finding("PROV?", "manifest uiAccess=true (UIAccess auto-elevate)"))
    return out
