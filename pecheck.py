#!/usr/bin/env python3
"""pecheck2.py - static PE triage: suspicious imports, signatures, packing heuristics,
plus memory-only-staging surface audit (TLS callbacks, PEB walks/scrubs, W+X,
import call-site coverage, encrypted-blob attribution).  Original: pecheck.py.
Usage: python3 pecheck2.py <dir|file> ...
"""
import sys, os, math, hashlib, struct
import pefile

FUNC_FLAGS = [
    ("URLDownloadToFile", "NET-DL", "direct file download"),
    ("URLDownloadToCacheFile", "NET-DL", "download to cache"),
    ("InternetOpenUrl", "NET-DL", "direct URL fetch"),
    ("HttpSendRequest", "NET", "HTTP request"),
    ("InternetConnect", "NET", "open remote connection"),
    ("WinHttpConnect", "NET", "WinHTTP connect"),
    ("WinHttpSendRequest", "NET", "WinHTTP request"),
    ("connect", "NET", "socket connect"),
    ("WSAStartup", "NET", "socket init"),
    ("WSASocket", "NET", "socket create"),
    ("CreateProcess", "EXEC", "spawn process"),
    ("WinExec", "EXEC", "spawn process (legacy)"),
    ("ShellExecute", "EXEC", "shell execute (URLs/procs)"),
    ("CreateRemoteThread", "INJECT", "inject into other process"),
    ("WriteProcessMemory", "INJECT", "write to other process memory"),
    ("NtUnmapViewOfSection", "INJECT", "process hollowing primitive"),
    ("ZwUnmapViewOfSection", "INJECT", "process hollowing primitive"),
    ("SetThreadContext", "INJECT", "hijack thread context"),
    ("VirtualAllocEx", "INJECT", "alloc in remote process"),
    ("SetWindowsHookEx", "INJECT", "global hook / keylogger primitive"),
    ("GetAsyncKeyState", "KEYLOG?", "keystroke polling"),
    ("RegSetValue", "PERSIST", "registry value write (Run keys etc.)"),
    ("RegCreateKey", "PERSIST", "registry key create"),
    ("CryptEncrypt", "CRYPTO", "file encryption capability"),
    ("VirtualProtect", "EVADE?", "self-modifying code / unpacking"),
    ("IsDebuggerPresent", "EVADE", "anti-debug"),
    ("CheckRemoteDebuggerPresent", "EVADE", "anti-debug"),
]
NET_DLLS = {"wininet.dll", "winhttp.dll", "ws2_32.dll", "wsock32.dll", "urlmon.dll"}

# ---- memory-only-staging audit constants (second-pass addendum, 2026-09-07) ----
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

def mem_tricks(pe, mach):
    """memory-only staging surface audit; -> list of (cat, desc)."""
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
            flags.append(("MEM", f"{api}: {counts[api]} direct call-site(s)"))
        else:
            flags.append(("MEM?", f"{api}: imported but 0 direct call-sites (indirect only / unused)"))
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
                flags.append(("MEM?", f"direct PEB access ({label}) in {nm} - manual module walk?"))
            if scrubs:
                flags.append(("EVADE", f"{nm}: {' + '.join(scrubs)} near TEB/PEB access (anti-anti-debug scrub)"))
        n = d.count(ROR13) + d.count(ROR14)
        if n >= 32:
            clusters = 0
            for w in range(0, len(d) - 512, 512):
                if d[w:w + 512].count(ROR13) + d[w:w + 512].count(ROR14) >= 4:
                    clusters += 1
            flags.append(("MEM?", f"{nm}: {n} ROR-13/14 rotates ({clusters} dense windows) - API-hash loops or crypto code"))
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
                flags.append(("MEM", "TLS directory present, 0 callbacks (CRT boilerplate)"))
            elif n > 32:
                flags.append(("MEM?", "TLS callback array >32 entries - inspect manually"))
            else:
                flags.append(("MEM?", f"{n} TLS callback(s): " + " ".join(hex(a) for a in addrs)))
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
                    flags.append(("MEM?", f".rsrc entropy {e}: icons explain only {covered}/{s.Misc_VirtualSize}B ({100*unexpl/s.Misc_VirtualSize:.0f}% unattributed - likely compressed resources, verify)"))
                else:
                    flags.append(("MEM-OK", f".rsrc entropy {e} attributed to icons/resources ({covered}/{s.Misc_VirtualSize}B)"))
        elif not (s.Characteristics & 0x20000000):
            flags.append(("MEM?", f"high-entropy data section {nm} ({e}) - verify contents"))
    return flags

# ---- Authenticode via WinVerifyTrust (pure ctypes, no subprocess) ----
# ABI layouts transcribed from the Windows SDK 10.0.26100 headers
# (wintrust.h, mscat.h, SoftPub.h, wincrypt.h, winerror.h). Digest + chain
# are validated by the Windows trust engine (same as Explorer/PowerShell);
# revocation is NOT checked (offline-safe, no CRL/AIA fetches).
def sigs_via_wintrust(paths):
    """-> {normcase abspath: (status, signer)} or None if unavailable.
    Covers embedded signatures and OS catalog-signed files."""
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes
    try:
        wt = ctypes.WinDLL("wintrust")
        crypt32 = ctypes.WinDLL("crypt32")
        kernel32 = ctypes.WinDLL("kernel32")
    except OSError:
        return None

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]
    GV2 = GUID(0x00aac56b, 0xcd44, 0x11d0, (ctypes.c_ubyte*8)(0x8c,0xc2,0x00,0xc0,0x4f,0xc2,0x95,0xee))
    DAV = GUID(0xf750e6c3, 0x38ee, 0x11d1, (ctypes.c_ubyte*8)(0x85,0xe5,0x00,0xc0,0x4f,0xc2,0x95,0xee))

    class WFI(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]
    class CATINFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", ctypes.c_wchar * 260)]
    class WCI(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD),
                    ("pcwszCatalogFilePath", wintypes.LPCWSTR), ("pcwszMemberTag", wintypes.LPCWSTR),
                    ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE),
                    ("pbCalculatedFileHash", ctypes.c_void_p), ("cbCalculatedFileHash", wintypes.DWORD),
                    ("pcCatalogContext", ctypes.c_void_p), ("hCatAdmin", wintypes.HANDLE)]
    class WTD(ctypes.Structure):
        class _U(ctypes.Union):
            _fields_ = [("pFile", ctypes.POINTER(WFI)), ("pCatalog", ctypes.POINTER(WCI))]
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("pPolicyCallbackData", ctypes.c_void_p), ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", wintypes.DWORD), ("fdwRevocationChecks", wintypes.DWORD),
                    ("dwUnionChoice", wintypes.DWORD), ("u", _U),
                    ("dwStateAction", wintypes.DWORD), ("hWVTStateData", wintypes.HANDLE),
                    ("pwszURLReference", wintypes.LPWSTR), ("dwProvFlags", wintypes.DWORD),
                    ("dwUIContext", wintypes.DWORD)]
    class PROV_CERT(ctypes.Structure):  # leading fields only; pCert at offset 8
        _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", ctypes.c_void_p)]

    wt.WinVerifyTrust.restype = ctypes.c_long
    wt.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(WTD)]
    wt.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
    wt.WTHelperProvDataFromStateData.argtypes = [wintypes.HANDLE]
    wt.WTHelperGetProvSignerFromChain.restype = ctypes.c_void_p
    wt.WTHelperGetProvSignerFromChain.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    wt.WTHelperGetProvCertFromChain.restype = ctypes.c_void_p
    wt.WTHelperGetProvCertFromChain.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL
    wt.CryptCATAdminCalcHashFromFileHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminAcquireContext.restype = wintypes.BOOL
    wt.CryptCATAdminAcquireContext.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
    wt.CryptCATAdminEnumCatalogFromHash.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    wt.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
    wt.CryptCATCatalogInfoFromContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL
    wt.CryptCATAdminReleaseCatalogContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminReleaseContext.restype = wintypes.BOOL
    wt.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    if hasattr(wt, "CryptCATAdminAcquireContext2"):  # Win8+
        wt.CryptCATAdminAcquireContext2.restype = wintypes.BOOL
        wt.CryptCATAdminAcquireContext2.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD]
        wt.CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL
        wt.CryptCATAdminCalcHashFromFileHandle2.argtypes = [ctypes.c_void_p, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD]
    crypt32.CertGetNameStringW.restype = wintypes.DWORD
    crypt32.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                           ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    NOSIG, HR = 0x800B0100, {0x80096010: "HashMismatch", 0x800B0101: "Expired",
                              0x800B0109: "UntrustedRoot", 0x800B010A: "Chaining", 0x800B010C: "Revoked"}

    def signer(h_state):
        if not h_state:
            return "-"
        try:
            prov = wt.WTHelperProvDataFromStateData(h_state)
            sgnr = wt.WTHelperGetProvSignerFromChain(prov, 0, False, 0)
            cert = ctypes.cast(wt.WTHelperGetProvCertFromChain(sgnr, 0), ctypes.POINTER(PROV_CERT)).contents
            fl = wintypes.DWORD(0x02000000)  # CERT_NAME_STR_REVERSE_FLAG: CN first
            n = crypt32.CertGetNameStringW(cert.pCert, 2, 0, ctypes.byref(fl), None, 0)
            buf = ctypes.create_unicode_buffer(n)
            crypt32.CertGetNameStringW(cert.pCert, 2, 0, ctypes.byref(fl), buf, n)
            return buf.value or "-"
        except Exception:
            return "-"

    def embedded(path):
        fi = WFI(ctypes.sizeof(WFI), path, None, None)
        wd = WTD(ctypes.sizeof(WTD), None, None, 2, 0, 1)  # UI_NONE, REVOKE_NONE, CHOICE_FILE
        wd.u.pFile = ctypes.pointer(fi)
        wd.dwStateAction = 1
        hr = wt.WinVerifyTrust(None, ctypes.byref(GV2), ctypes.byref(wd))
        who = signer(wd.hWVTStateData) if hr == 0 else "-"
        wd.dwStateAction = 2
        wt.WinVerifyTrust(None, ctypes.byref(GV2), ctypes.byref(wd))
        return hr, who

    def catalog(path, alg):
        """-> (hr, signer) if a catalog containing this hash exists, else None"""
        h = kernel32.CreateFileW(path, 0x80000000, 1, None, 3, 0, None)
        if not h or h == ctypes.c_size_t(-1).value:
            return None
        try:
            ctx = ctypes.c_void_p()
            if alg and hasattr(wt, "CryptCATAdminAcquireContext2"):
                if not wt.CryptCATAdminAcquireContext2(ctypes.byref(ctx), ctypes.byref(DAV), alg, None, 0):
                    return None
                calc = lambda buf, pcb: wt.CryptCATAdminCalcHashFromFileHandle2(ctx, h, ctypes.byref(pcb), buf, 0)
            else:
                if not wt.CryptCATAdminAcquireContext(ctypes.byref(ctx), ctypes.byref(DAV), 0):
                    return None
                calc = lambda buf, pcb: wt.CryptCATAdminCalcHashFromFileHandle(h, ctypes.byref(pcb), buf, 0)
            pcb = wintypes.DWORD(0)
            if not calc(None, pcb):
                return None
            buf = ctypes.create_string_buffer(pcb.value)
            if not calc(buf, pcb):
                return None
            cat = wt.CryptCATAdminEnumCatalogFromHash(ctx, buf, pcb.value, 0, None)
            if not cat:
                return None
            try:
                ci = CATINFO(ctypes.sizeof(CATINFO))
                if not wt.CryptCATCatalogInfoFromContext(cat, ctypes.byref(ci), 0):
                    return None
                gc = WCI(ctypes.sizeof(WCI), 0, ci.wszCatalogFile,
                         buf.raw[:pcb.value].hex().upper(), path, h, None, 0, None, ctx)
                wd = WTD(ctypes.sizeof(WTD), None, None, 2, 0, 2)  # CHOICE_CATALOG
                wd.u.pCatalog = ctypes.pointer(gc)
                wd.dwStateAction = 1
                hr = wt.WinVerifyTrust(None, ctypes.byref(DAV), ctypes.byref(wd))
                who = signer(wd.hWVTStateData) if hr == 0 else "-"
                wd.dwStateAction = 2
                wt.WinVerifyTrust(None, ctypes.byref(DAV), ctypes.byref(wd))
                return hr, who
            finally:
                wt.CryptCATAdminReleaseCatalogContext(ctx, cat, 0)
        finally:
            wt.CryptCATAdminReleaseContext(ctx, 0)
            kernel32.CloseHandle(h)

    def one(path):
        hr, who = embedded(path)
        hru = hr & 0xFFFFFFFF
        if hr == 0:
            return "Valid", who
        if hru != NOSIG:
            return HR.get(hru, f"error 0x{hru:08X}"), who
        for alg in ("SHA256", None):  # modern catalogs first, SHA-1 fallback
            r = catalog(path, alg)
            if r is None:
                continue
            hr2, who2 = r
            if hr2 == 0:
                return "Valid", who2
            if (hr2 & 0xFFFFFFFF) != NOSIG:
                return HR.get(hr2 & 0xFFFFFFFF, f"error 0x{hr2 & 0xFFFFFFFF:08X}"), who2
        return "NotSigned", "-"

    res = {}
    for p in paths:
        try:
            res[os.path.normcase(os.path.abspath(p))] = one(p)
        except Exception:
            pass
    return res

def shannon(data):
    if not data: return 0.0
    counts = [0]*256
    for b in data: counts[b] += 1
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in counts if c)

def check(path):
    r = {"path": path, "size": os.path.getsize(path), "flags": [], "signed": False,
         "sections": [], "error": None, "sha256": None, "arch": None}
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    r["sha256"] = h.hexdigest()
    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception as e:
        r["error"] = f"{type(e).__name__}: {e}"
        return r
    mach = pe.FILE_HEADER.Machine
    r["arch"] = {0x8664: "x64", 0x14c: "x86", 0xaa64: "ARM64"}.get(mach, hex(mach))
    try:
        secdir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        r["signed"] = secdir.VirtualAddress != 0
    except Exception:
        pass
    entries = list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])) + \
              list(getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []))
    for entry in entries:
        dll = entry.dll.decode(errors="replace").lower()
        if dll in NET_DLLS:
            r["flags"].append(("NET-DLL", f"links {dll}"))
        for imp in entry.imports:
            name = (imp.name or b"").decode(errors="replace")
            if not name: continue
            for pat, cat, note in FUNC_FLAGS:
                if pat.lower() in name.lower():
                    r["flags"].append((cat, f"{dll}!{name}  ({note})"))
                    break
    total_imports = sum(len(entry.imports) for entry in entries)
    is_dotnet = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size > 0  # COM descriptor
    if is_dotnet:
        r["flags"].append(("NOTE", ".NET assembly - import table is not authoritative, scan with a .NET tool"))
    elif 0 < total_imports <= 4:
        r["flags"].append(("EVADE?", f"only {total_imports} imports - dynamic resolution (LoadLibrary/GetProcAddress)?"))
    if not is_dotnet and mach in (0x8664, 0x14c):
        try:
            r["flags"].extend(mem_tricks(pe, mach))
        except Exception as e:
            r["flags"].append(("NOTE", f"mem-trick audit failed: {type(e).__name__}: {e}"))
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        data = s.get_data()[:1 << 20]
        e = shannon(data) if data else 0.0
        kb = round(s.SizeOfRawData/1024, 1)
        r["sections"].append((name, round(e, 2), kb))
        exec_ = bool(s.Characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
        if exec_ and (s.Characteristics & 0x80000000):  # IMAGE_SCN_MEM_WRITE
            r["flags"].append(("EVADE?", f"section {name} is writable+executable"))
        if exec_ and e > 7.5 and kb > 10:
            r["flags"].append(("PACKED?", f"executable section {name} entropy {round(e, 2)} (packed/shellcode?)"))
    return r

def main():
    targets = []
    for t in sys.argv[1:]:
        if os.path.isdir(t):
            for root, _, files in os.walk(t):
                for fn in files:
                    if fn.lower().endswith((".exe", ".dll")):
                        targets.append(os.path.join(root, fn))
        else:
            targets.append(t)
    strong = sigs_via_wintrust([os.path.abspath(p) for p in targets])
    SEV = {"INJECT": "CRITICAL", "NET-DL": "CRITICAL", "PACKED?": "CRITICAL", "NET-DLL": "note", "NOTE": "note",
           "NET": "note", "KEYLOG?": "note", "EVADE?": "note",
           "EVADE": "note", "EXEC": "note", "PERSIST": "note", "CRYPTO": "note",
           "MEM": "note", "MEM?": "note", "MEM-OK": "note"}
    results = []
    for p in sorted(targets):
        r = check(p)
        sig = strong.get(os.path.normcase(os.path.abspath(p))) if strong else None
        r["sig"] = sig
        # severity roll-up per file; strong path = Windows-validated signature,
        # weak path = cert-table presence only (validity NOT verified)
        crit = [f for c, f in r["flags"] if SEV.get(c) == "CRITICAL"]
        if sig:
            r["verdict"] = "REVIEW" if (crit or sig[0] == "HashMismatch") \
                else ("ok" if sig[0] == "Valid" else "unsigned/unknown")
        else:
            r["verdict"] = "REVIEW" if crit \
                else ("ok" if (not r["error"] and r["signed"]) else "unsigned/unknown")
        r["crit"] = crit
        results.append(r)
        print(f"\n=== {p}")
        if r["error"]:
            print(f"  ERROR: {r['error']}"); continue
        print(f"  arch={r['arch']}  size={r['size']:,}  sha256={r['sha256'][:16]}...")
        if sig:
            print(f"  signature: {sig[0]}" + (f" ({sig[1]})" if sig[1] not in ("-", "") else ""))
        else:
            print(f"  signature: {'cert-table present' if r['signed'] else 'unsigned'} (weak mode: validity NOT verified)")
        for name, e, kb in r["sections"]:
            marker = "  <-- HIGH (>7.5)" if e > 7.5 and kb > 10 else ""
            print(f"    section {name:12} entropy={e:5.2f} rawKB={kb}{marker}")
        if r["flags"]:
            for cat, desc in dict.fromkeys(r["flags"]):
                print(f"  [{cat}] {desc}")
        else:
            print("  no suspicious imports")

    # ---- summary ----
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    review = [r for r in results if r["verdict"] == "REVIEW"]
    signed_ok = [r for r in results if r["verdict"] == "ok"]
    unknown = [r for r in results if r["verdict"] == "unsigned/unknown"]

    if review:
        print("\n  !! REVIEW REQUIRED:")
        for r in review:
            print(f"  !! {r['path']}")
            for f in r["crit"]:
                print(f"     [CRITICAL] {f}")
            if r.get("sig") and r["sig"][0] == "HashMismatch":
                print("     [CRITICAL] signature hash mismatch - file modified after signing")
        print("\n  -> Upload these files (or their SHA256) to virustotal.com before running anything.")

    if signed_ok:
        lbl = "validly signed" if strong else "with cert table (validity NOT verified)"
        print(f"\n  OK  {len(signed_ok)} {lbl}, no critical imports:")
        for r in signed_ok:
            who = r["sig"][1][:60] if r.get("sig") else "cert-table present"
            print(f"     {os.path.basename(r['path']):45} {who}")

    if unknown:
        print("\n  i  Unsigned / signature not verified (not necessarily bad, just unproven):")
        for r in unknown:
            print(f"     {os.path.basename(r['path']):45} sha256={r['sha256'][:16]}...")
        print("  i  Verify these on VirusTotal before running, if unsure.")

    print("\n  VERDICT: " + (
        f"REVIEW REQUIRED - {len(review)} file(s) flagged (see above)" if review
        else f"no critical findings: {len(signed_ok)} signed, {len(unknown)} unsigned/unknown"))

if __name__ == "__main__":
    main()
