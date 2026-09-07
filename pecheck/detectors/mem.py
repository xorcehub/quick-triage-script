"""Memory-only-staging surface audit: TLS callbacks, PEB walks/scrubs,
import call-site coverage, encrypted-blob attribution."""
import struct

from ..model import Finding

MEM_APIS = ("VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
            "WriteProcessMemory", "CreateRemoteThread", "SetThreadContext", "QueueUserAPC",
            "SetWindowsHookExA", "SetWindowsHookExW", "AddVectoredExceptionHandler",
            "RtlAddFunctionTable", "NtMapViewOfSection")
# direct TEB/PEB access = candidate for manual module/API resolution
PEB_PATS = (
    ("gs:[0x30] TEB read (x64)", bytes.fromhex("65488b042530000000"), "teb"),
    ("gs:[0x60] PEB read (x64)", bytes.fromhex("65488b042560000000"), "peb"),
    ("fs:[0x30] TEB read (x86)", bytes.fromhex("648b042530000000"), "teb"),
)
# anti-anti-debug scrubs: PEB->BeingDebugged = 0 / NtGlobalFlag heap flags masked off
SCRUB_PATS = (
    ("write PEB->BeingDebugged=0", bytes.fromhex("c6400200")),
    ("mask PEB->NtGlobalFlag (heap debug flags)", bytes.fromhex("80a0bc0000008f")),
)
ROR13 = bytes.fromhex("c1c80d")
ROR14 = bytes.fromhex("c1c80e")


def _iat_call_sites(pe, mach):
    """count ff15/ff25 references to each IAT slot; -> {import name: site count}
    x64: rip-relative; x86: absolute imm32. Includes delay imports."""
    img = pe.OPTIONAL_HEADER.ImageBase
    slots = {}
    for e in list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])) + \
             list(getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", [])):
        for i in e.imports:
            if i.name:
                slots[i.address - img] = i.name.decode(errors="replace")
    counts = {}
    x64 = (mach == 0x8664)
    for s in pe.sections:
        if not (s.Characteristics & 0x20000000):
            continue
        d = s.get_data()
        if not d:
            continue
        base = s.VirtualAddress
        for code in (b"\xff\x15", b"\xff\x25"):
            i = 0
            while True:
                i = d.find(code, i)
                if i < 0 or i + 6 > len(d):
                    break
                if x64:
                    tgt = base + i + 6 + struct.unpack_from("<i", d, i + 2)[0]
                else:
                    tgt = struct.unpack_from("<I", d, i + 2)[0] - img
                nm = slots.get(tgt)
                if nm:
                    counts[nm] = counts.get(nm, 0) + 1
                i += 2
    return counts


def _rsrc_icon_coverage(pe):
    """bytes of .rsrc explainable as PNG (clean IEND, zero trailer) or BMP DIB icons;
    None if no resource tree."""
    res = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if res is None:
        return None
    tree = getattr(res, "entries", res)
    covered = 0
    try:
        for t in tree:
            for e in t.directory.entries:
                for l in e.directory.entries:
                    de = l.data.struct
                    try:
                        blob = pe.get_data(de.OffsetToData, de.Size)
                    except Exception:
                        continue
                    if blob[:4] == b"\x89PNG":
                        iend = blob.find(b"IEND")
                        if iend != -1 and not any(blob[iend + 8:]):
                            covered += de.Size
                    elif blob[:4] == b"(\x00\x00\x00":
                        covered += de.Size
    except Exception:
        pass
    return covered


def run(t):
    if t.error or t.pe is None:
        return []
    pe = t.pe
    mach = pe.FILE_HEADER.Machine
    flags = []
    imported = set()
    for e in list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])) + \
             list(getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", [])):
        for i in e.imports:
            if i.name:
                imported.add(i.name.decode(errors="replace"))
    # 1) call-site coverage for memory-staging APIs (imported but never ff15/ff25-called = indirect)
    counts = _iat_call_sites(pe, mach)
    for api in MEM_APIS:
        if api not in imported:
            continue
        if counts.get(api):
            flags.append(Finding("MEM", f"{api}: {counts[api]} direct call-site(s)"))
        else:
            flags.append(Finding("MEM?", f"{api}: imported but 0 direct call-sites (indirect only / unused)"))
    # 2) PEB/TEB access, anti-debug scrubs, ROR-hash density
    for s in pe.sections:
        if not (s.Characteristics & 0x20000000):
            continue
        d = s.get_data()
        if not d:
            continue
        nm = s.Name.rstrip(b"\x00").decode(errors="replace")
        for label, pat, kind in PEB_PATS:
            i = d.find(pat)
            if i < 0:
                continue
            near = d[max(0, i - 64):i + 96]
            scrubs = [lbl for lbl, sp in SCRUB_PATS if sp in near]
            if kind == "peb":
                flags.append(Finding("MEM?", f"direct PEB access ({label}) in {nm} - manual module walk?"))
            if scrubs:
                flags.append(Finding("EVADE", f"{nm}: {' + '.join(scrubs)} near TEB/PEB access (anti-anti-debug scrub)"))
        n = d.count(ROR13) + d.count(ROR14)
        if n >= 32:
            clusters = 0
            for w in range(0, len(d) - 512, 512):
                if d[w:w + 512].count(ROR13) + d[w:w + 512].count(ROR14) >= 4:
                    clusters += 1
            flags.append(Finding("MEM?", f"{nm}: {n} ROR-13/14 rotates ({clusters} dense windows) - API-hash loops or crypto code"))
    # 3) TLS callbacks
    try:
        if pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress:
            st = pe.DIRECTORY_ENTRY_TLS.struct
            arr = st.AddressOfCallBacks
            img = pe.OPTIONAL_HEADER.ImageBase
            n, addrs = 0, []
            if arr:
                off = pe.get_offset_from_rva(arr - img)
                fmt, ent = ("<Q", 8) if mach == 0x8664 else ("<I", 4)
                while n < 33:
                    v = struct.unpack_from(fmt, pe.__data__, off + n * ent)[0]
                    if v == 0:
                        break
                    addrs.append(v)
                    n += 1
            if n == 0:
                flags.append(Finding("MEM", "TLS directory present, 0 callbacks (CRT boilerplate)"))
            elif n > 32:
                flags.append(Finding("MEM?", "TLS callback array >32 entries - inspect manually"))
            else:
                flags.append(Finding("MEM?", f"{n} TLS callback(s): " + " ".join(hex(a) for a in addrs)))
    except Exception:
        pass
    # 4) high-entropy non-code sections: attribute .rsrc to icons, flag the rest
    for s in pe.sections:
        nm = s.Name.rstrip(b"\x00").decode(errors="replace")
        if s.Misc_VirtualSize < 1024 or s.get_entropy() <= 7.3:
            continue
        e = round(s.get_entropy(), 2)
        if nm == ".rsrc":
            covered = _rsrc_icon_coverage(pe)
            if covered is not None:
                unexpl = s.Misc_VirtualSize - covered
                if unexpl > 0.25 * s.Misc_VirtualSize:
                    flags.append(Finding("MEM?", f".rsrc entropy {e}: icons explain only {covered}/{s.Misc_VirtualSize}B ({100*unexpl/s.Misc_VirtualSize:.0f}% unattributed - likely compressed resources, verify)"))
                else:
                    flags.append(Finding("MEM-OK", f".rsrc entropy {e} attributed to icons/resources ({covered}/{s.Misc_VirtualSize}B)"))
        elif not (s.Characteristics & 0x20000000):
            flags.append(Finding("MEM?", f"high-entropy data section {nm} ({e}) - verify contents"))
    return flags
