"""Authenticode via WinVerifyTrust (pure ctypes, no subprocess)."""
import os


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
