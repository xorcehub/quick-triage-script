"""Managed (.NET) triage: COR20 -> BSJB metadata root -> #Strings/#US heaps.
Stream-level only (no metadata-table walk); keyword scoring + reuse of the
strings-detector regexes for user-string literals."""
import re
import struct

from ..model import Finding, NOTE
from ..peparse import dd
from .strings import URL_RE, IP_RE, CMDLINE_RE

COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x08

# token -> (category, note); shown when found in #Strings (type/method names)
DOTNET_TOKENS = [
    ("DownloadString", "NET-DL", "WebClient DownloadString"),
    ("DownloadFile", "NET-DL", "WebClient DownloadFile"),
    ("DownloadData", "NET-DL", "WebClient DownloadData"),
    ("OpenRead", "NET-DL", "WebClient OpenRead"),
    ("Invoke-WebRequest", "NET-DL", "powershell web request"),
    ("Process", "EXEC", "System.Diagnostics.Process"),
    ("CreateRemoteThread", "INJECT", "CreateRemoteThread via P/Invoke"),
    ("WriteProcessMemory", "INJECT", "WriteProcessMemory via P/Invoke"),
    ("VirtualAllocEx", "INJECT", "VirtualAllocEx via P/Invoke"),
    ("SetWindowsHookEx", "INJECT", "SetWindowsHookEx via P/Invoke"),
    ("GetAsyncKeyState", "KEYLOG?", "keystroke polling"),
    ("RegistryKey", "PERSIST", "registry access"),
    ("FromBase64String", "EVADE?", "base64 decode"),
    ("Assembly", "EVADE?", "reflection/assembly load"),
    ("DllImportAttribute", "NOTE", "P/Invoke present"),
]
OBFUSCATORS = ("ConfuserEx", "Confuser.Runtime", "SmartAssembly", "Eazfuscator",
               "dotNet protector", "BabelObfuscator", "Agile.NET")
US_EXTRA = re.compile(rb"(?:powershell|cmd\.exe|schtasks|bitsadmin|certutil|mshta)", re.I)


def _streams(pe):
    """-> (cor20_flags, {name: (offset, size)}) or None."""
    d = dd(pe, 14)
    if not d or not d.Size or not d.VirtualAddress:
        return None
    raw = pe.__data__
    try:
        off = pe.get_offset_from_rva(d.VirtualAddress)
        cb, _maj, _mino, md_rva, _md_size = struct.unpack_from("<IHHII", raw, off)
        flags = struct.unpack_from("<I", raw, off + 16)[0]
        md = pe.get_offset_from_rva(md_rva)
        if raw[md:md + 4] != b"BSJB":
            return None
        ver_len = struct.unpack_from("<I", raw, md + 12)[0]
        p = md + 16 + ver_len
        _sf, n = struct.unpack_from("<HH", raw, p)
        p += 4
        streams = {}
        for _ in range(n):
            so, ss = struct.unpack_from("<II", raw, p)
            p += 8
            start = p
            while p < len(raw) and raw[p]:
                p += 1
            name = raw[start:p].decode(errors="replace")
            p += 1
            p = (p + 3) & ~3
            streams[name] = (md + so, ss)
        return flags, streams
    except Exception:
        return None


def run(t):
    if t.error or t.pe is None:
        return []
    got = _streams(t.pe)
    if got is None:
        return []
    flags, streams = got
    out = [Finding("NOTE", ".NET assembly (managed) - import table not authoritative; heaps scanned")]
    if not (flags & COMIMAGE_FLAGS_STRONGNAMESIGNED):
        out.append(Finding("PROV?", ".NET: no strong-name signature"))

    raw = t.pe.__data__
    s_heap = u_heap = b""
    if "#Strings" in streams:
        o, s = streams["#Strings"]
        s_heap = raw[o:o + s]
    if "#US" in streams:
        o, s = streams["#US"]
        u_heap = raw[o:o + s]

    hits = []
    for tok, cat, note in DOTNET_TOKENS:
        if tok.encode() in s_heap:
            hits.append((cat, f"{tok} ({note})"))
    if hits:
        strong = any(c in ("NET-DL", "INJECT") for c, _ in hits)
        sev = "CRITICAL" if strong else NOTE
        joined = "; ".join(f"{tok}" for _, tok in hits[:8])
        out.append(Finding("NET-DOTNET" if strong else "DOTNET", f".NET tokens: {joined}", sev))
        if strong and b"DllImportAttribute" in s_heap:
            out.append(Finding("DOTNET", "P/Invoke (DllImport) combined with net/inject tokens"))

    for obf in OBFUSCATORS:
        if obf.encode() in s_heap:
            out.append(Finding("EVADE?", f".NET obfuscator marker: {obf}"))
            break

    # user strings: URLs, IPs, script-host command lines
    for rx, cat, lbl in ((URL_RE, "NET-DL", "url"), (IP_RE, "STR", "ip literal")):
        found = {m.group().decode("latin-1", "replace") for m in rx.finditer(u_heap)}
        found |= {m.group().decode("latin-1", "replace")
                  for m in rx.finditer(u_heap.decode("utf-16le", errors="ignore").encode("latin-1", "ignore"))}
        if found:
            sev = "CRITICAL" if cat == "NET-DL" else NOTE
            out.append(Finding(cat, f".NET user-string {lbl}: {', '.join(sorted(found)[:5])}", sev))
    cm = CMDLINE_RE.search(u_heap.decode("utf-16le", errors="ignore").encode("latin-1", "ignore"))
    if cm:
        out.append(Finding("EXEC?", f".NET user-string command line: {cm.group().decode('latin-1','replace')[:100]}"))
    elif US_EXTRA.search(u_heap):
        out.append(Finding("EXEC?", ".NET user-strings reference script hosts (powershell/cmd/schtasks...)"))
    return out
