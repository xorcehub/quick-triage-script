"""Import-table triage: suspicious APIs, network DLLs, import-count anomalies."""
from ..model import Finding, CRITICAL, NOTE

# exact-name flags: substring match would FP on names like LsaConnectUntrusted
FUNC_FLAGS_EXACT = {
    "connect": ("NET", "socket connect"),
    "WSAConnect": ("NET", "socket connect"),
    "WSAConnectByName": ("NET", "socket connect by name"),
}
FUNC_FLAGS_SUBSTR = [
    ("URLDownloadToFile", "NET-DL", "direct file download", CRITICAL),
    ("URLDownloadToCacheFile", "NET-DL", "download to cache", CRITICAL),
    ("InternetOpenUrl", "NET-DL", "direct URL fetch", CRITICAL),
    ("HttpSendRequest", "NET", "HTTP request", NOTE),
    ("InternetConnect", "NET", "open remote connection", NOTE),
    ("WinHttpConnect", "NET", "WinHTTP connect", NOTE),
    ("WinHttpSendRequest", "NET", "WinHTTP request", NOTE),
    ("WSAStartup", "NET", "socket init", NOTE),
    ("WSASocket", "NET", "socket create", NOTE),
    ("CreateProcess", "EXEC", "spawn process", NOTE),
    ("WinExec", "EXEC", "spawn process (legacy)", NOTE),
    ("ShellExecute", "EXEC", "shell execute (URLs/procs)", NOTE),
    ("CreateRemoteThread", "INJECT", "inject into other process", CRITICAL),
    ("WriteProcessMemory", "INJECT", "write to other process memory", CRITICAL),
    ("NtUnmapViewOfSection", "INJECT", "process hollowing primitive", CRITICAL),
    ("ZwUnmapViewOfSection", "INJECT", "process hollowing primitive", CRITICAL),
    ("SetThreadContext", "INJECT", "hijack thread context", CRITICAL),
    ("VirtualAllocEx", "INJECT", "alloc in remote process", CRITICAL),
    ("SetWindowsHookEx", "INJECT", "global hook / keylogger primitive", CRITICAL),
    ("GetAsyncKeyState", "KEYLOG?", "keystroke polling", NOTE),
    ("RegSetValue", "PERSIST", "registry value write (Run keys etc.)", NOTE),
    ("RegCreateKey", "PERSIST", "registry key create", NOTE),
    ("CryptEncrypt", "CRYPTO", "file encryption capability", NOTE),
    ("VirtualProtect", "EVADE?", "self-modifying code / unpacking", NOTE),
    ("IsDebuggerPresent", "EVADE", "anti-debug", NOTE),
    ("CheckRemoteDebuggerPresent", "EVADE", "anti-debug", NOTE),
]
NET_DLLS = {"wininet.dll", "winhttp.dll", "ws2_32.dll", "wsock32.dll", "urlmon.dll"}


def run(t):
    out = []
    if t.error or t.pe is None:
        return out
    pe = t.pe
    entries = list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])) + \
              list(getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []))
    for entry in entries:
        dll = entry.dll.decode(errors="replace").lower()
        if dll in NET_DLLS:
            out.append(Finding("NET-DLL", f"links {dll}"))
        for imp in entry.imports:
            name = (imp.name or b"").decode(errors="replace")
            if not name:
                continue
            if name in FUNC_FLAGS_EXACT:
                cat, note = FUNC_FLAGS_EXACT[name]
                out.append(Finding(cat, f"{dll}!{name}  ({note})"))
                continue
            low = name.lower()
            for pat, cat, note, sev in FUNC_FLAGS_SUBSTR:
                if pat.lower() in low:
                    out.append(Finding(cat, f"{dll}!{name}  ({note})", sev))
                    break
    total_imports = sum(len(e.imports) for e in entries)
    is_dotnet = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size > 0  # COM descriptor
    if is_dotnet:
        out.append(Finding("NOTE", ".NET assembly - import table is not authoritative"))
    elif total_imports == 0:
        out.append(Finding("EVADE?", "0 imports on native PE - shellcode/loader or hand-built IAT",
                           CRITICAL))
    elif total_imports <= 4:
        out.append(Finding("EVADE?", f"only {total_imports} imports - dynamic resolution (LoadLibrary/GetProcAddress)?"))
    return out
