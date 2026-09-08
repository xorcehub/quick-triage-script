"""Script + shortcut triage: obfuscation, download/decode-execute pairs,
dropper patterns. Markers matched against a normalized view (lowercase,
whitespace/backtick/caret/quote/plus-stripped) to defeat case/space
obfuscation plus backtick (PowerShell), caret (cmd.exe) and quote-concat
("ie"+"x") splitting. Long base64/hex/decimal
runs are decoded and the payload token-scanned (what does it actually do?). LNK gets
a header check plus command-marker scan over the raw bytes (ANSI + UTF-16)."""
import base64
import codecs
import html
import re
import struct
import zlib

from ..model import Finding, CRITICAL
from .strings import URL_RE

PY_DL = (b"urllib.request", b"urlopen", b"requests.get", b"requests.post",
         b"socket.socket", b"http.client")
PY_EX = (b"exec(", b"eval(", b"compile(", b"__import__", b"os.popen")
PY_DEC = (b"base64.b64decode", b"b64decode", b"codecs.decode", b"unhexlify",
          b"zlib.decompress", b"marshal.loads", b"pickle.loads")
SH_DL = (b"curl", b"wget", b"fetch")
_PIPE_SHELL = (b"|sh", b"|bash", b"|sudosh", b"|sudobash", b"|python", b"|perl")
_NC_E = re.compile(rb"(?i)(?:^|[\s;&|])(?:nc|ncat)(?:\.exe)?[^\r\n]{0,40}-e[\s/]")  # nc -e /bin/sh

_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
_NORM_WS = re.compile(b"[\\s`^\"'+]+")  # ws + PS backtick + cmd caret, plus quote/plus
# stripped so concat obfuscation ("ie"+"x") re-joins for marker matching


def _xview(raw):
    """html-entity-decoded view: &#112;owershell and &#x70;owershell spell powershell."""
    try:
        return html.unescape(raw.decode("utf-8", "replace")).encode("latin-1", "replace")
    except Exception:
        return b""


def _strip_comments(raw):
    """Drop full-line comments (PS #, VBS ', JS/PHP //, bat ::/REM) and block
    comments (<##>, /**/): markers inside comments are documentation, not
    behavior - stripping them kills the comment-FP class. Inline # stays."""
    raw = re.sub(rb"<#.*?#>", b"", raw, flags=re.S)
    raw = re.sub(rb"/\*.*?\*/", b"", raw, flags=re.S)
    out = []
    for ln in raw.splitlines():
        ls = ln.lstrip()
        if ls.startswith((b"#", b"'", b"//", b"::")) or ls.lower().startswith((b"rem ", b"rem	")):
            continue
        out.append(ln)
    return b"\n".join(out)


def _norm(raw):
    n = _NORM_WS.sub(b"", raw).lower()
    if b"\x00" in raw[:512]:  # utf-16le saves: decode so markers still match
        try:
            u16 = raw.decode("utf-16le", errors="ignore").encode("latin-1", "ignore")
            n += _NORM_WS.sub(b"", u16).lower()
        except Exception:
            pass
    return n


_VENDOR_URL_OK = (b"chocolatey.org", b"powershellgallery.com", b"aka.ms", b"microsoft.com")


def _vendor_only(raw):
    """True when every http(s) url in the text is a known software-vendor host
    (choco/winget/psgallery installers legitimately do iex+downloadstring)."""
    urls = URL_RE.findall(raw)
    return bool(urls) and all(any(v in u.lower() for v in _VENDOR_URL_OK) for u in urls)


def _hits(norm, pats):
    return [p.decode() for p in pats if p in norm]


PS_DL = (b"downloadstring", b"downloadfile", b"downloaddata", b"invoke-webrequest",
         b"invoke-restmethod", b"net.webclient", b"httpwebrequest", b"webclient",
         b"start-bitstransfer")
PS_EX = (b"invoke-expression", b"iex", b"start-process", b"&(")
PS_DEC = (b"frombase64string", b"-encodedcommand", b"-enc", b"gzipstream", b"deflatestream")
PS_STAGE = (b"set-content", b"out-file", b"add-content", b"writeallbytes", b"writealltext")
_A1 = b"amsi" + b"init" + b"failed"
_A2 = b"amsi" + b"utils"
PS_TAMPER = (_A1, _A2, b"set-mppreference", b"add-mppreference",
             b"-disablerealtimemonitoring", b"virtualprotect", b"getprocaddress")

BAT_BAD = ((b"powershell", b"-enc", b"-ec", b"-encodedcommand", b"-w1", b"-whidden",
            b"-windowstylehidden", b"-nop", b"-noprofile"),
           (b"certutil", b"-urlcache", b"-decode", b"-verifyctl"),
           (b"bitsadmin", b"/transfer", b"/create", b"/addfile"),
           (b"mshta", b"vbscript:", b"http"),
           (b"regsvr32", b"/i:"),
           (b"rundll32", b"javascript:"),
           (b"regadd", b"currentversion\\run"),
           (b"curl", b"http"), (b"wget", b"http"))
PS_INLINE = (b"powershell", b"iex", b"invoke-expression", b"downloadstring", b"downloadfile",
             b"net.webclient", b"frombase64string")  # one-liner body from bat (-c/-command)
VBS_NET = (b"msxml2.xmlhttp", b"winhttp.winhttprequest", b"msxml2.serverxmlhttp", b"adodb.stream")
VBS_EX = (b"savetofile", b".run(", b"shellexecute", b"wscript.shell", b"createobject(")
LNK_BAD = (b"powershell", b"cmd.exe", b"-enc", b"-ec", b"-encodedcommand", b"whidden",
           b"windowstyle", b"certutil", b"mshta", b"wscript", b"rundll32")

# html smuggling: inline decode + programmatic download/drop
HTML_DECODE = (b"atob(", b"fromcharcode(", b"unescape(")
HTML_DROP = (b"newblob(", b"blob([", b"msaveoropenblob", b".click()", b"createobjecturl")

_PEEK_TOKENS = (b"powershell", b"cmd.exe", b"http://", b"https://", b"invoke-expression",
                b"frombase64string", b"certutil", b"/dev/tcp")
_B64_RUN = re.compile(rb"[A-Za-z0-9+/]{120,}={0,2}")
_HEX_RUN = re.compile(rb"(?:[0-9a-fA-F]{2}){80,}")   # >=80 encoded bytes
_DEC_ARR = re.compile(rb"\d{1,3}(?:,\s*\d{1,3}){24,}")  # PS [char[]](104,116,...) style
_B64_FRAG = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")       # pieces of a split payload


def _inflate(dec):
    """base64 payloads are often gzip/deflate-compressed on top: try both, else raw.
    Capped at 1MB: token scan only needs the head; blocks decompression bombs."""
    for wbits in (47, -15):  # 47 = auto gzip/zlib, -15 = raw deflate
        try:
            return zlib.decompressobj(wbits).decompress(dec, 1 << 20)
        except Exception:
            continue
    return dec


def _decoded_runs(raw):
    """Every encoded payload we can carve: top b64 / hex / decimal-array runs."""
    for m in list(_B64_RUN.finditer(raw))[:3]:
        blob = m.group()
        try:
            yield "base64", base64.b64decode(blob + b"=" * (-len(blob) % 4))
        except Exception:
            pass
    for m in list(_HEX_RUN.finditer(raw))[:3]:
        try:
            yield "hex", bytes.fromhex(m.group().decode("ascii"))
        except Exception:
            pass
    for m in list(_DEC_ARR.finditer(raw))[:3]:
        try:
            yield "decimal", bytes(int(x) for x in m.group().split(b","))
        except Exception:
            pass
    joined = b"".join(_B64_FRAG.findall(raw))  # chunk-split payload: reassemble, try once
    if len(joined) >= 160:
        try:
            yield "base64-joined", base64.b64decode(joined + b"=" * (-len(joined) % 4))
        except Exception:
            pass


def _unfold(dec):
    """Nested encoding: peel inner b64/hex layers (up to 3) off the payload."""
    for _ in range(3):
        m, h = _B64_RUN.search(dec), _HEX_RUN.search(dec)
        m = m if m and (not h or m.start() <= h.start()) else h
        if m is None:
            break
        blob = m.group()
        try:
            inner = (base64.b64decode(blob + b"=" * (-len(blob) % 4)) if m.re is _B64_RUN
                     else bytes.fromhex(blob.decode("ascii")))
        except Exception:
            break
        if len(inner) < 8 or inner == dec:
            break
        dec = _inflate(inner)
    return dec


def _xor_sweep(head):
    """First single-byte-XOR view that shows >=2 marker tokens, else empty.
    Classic strings-with-xor: stops at the first revealing key, no report
    on lone short-token luck (random data occasionally shows one)."""
    toks = [p for p in _PEEK_TOKENS if len(p) >= 6]  # skip 4-5 char luck magnets
    for k in range(1, 256):
        v = head.translate(bytes(i ^ k for i in range(256)))
        hits = [p.decode() for p in toks if p in v]
        if len(hits) >= 2:
            return v
    return b""


def _scan_payload(label, dec, seen, out):
    """Unfold+inflate, token-scan (ascii + utf-16 + rot13 views), emit finding."""
    dec = _unfold(_inflate(dec))
    head = dec[:8192]
    if head in seen:
        return
    seen.add(head)
    view = (head.decode("utf-16-le", "ignore").encode("latin-1", "ignore") + head)
    try:  # rot13-wrapped payloads are common free obfuscation
        view += codecs.encode(head.decode("latin-1", "ignore"), "rot13").encode("latin-1", "ignore")
    except Exception:
        pass
    view += _xor_sweep(head)
    hits = [p.decode() for p in _PEEK_TOKENS if p in view]
    if dec[:2] == b"MZ":
        hits.insert(0, "MZ executable")
    if hits:
        hot = any(h in hits for h in ("MZ executable", "powershell", "cmd.exe", "/dev/tcp"))
        out.append(Finding("OBF!" if hot else "OBF?",
                           f"decoded {label} payload ({len(dec):,}B) contains: "
                           + ", ".join(hits[:4]), CRITICAL if hot else "note"))


def _peek(raw):
    """Decode encoded runs, token-scan each payload (what does it actually do?)."""
    out, seen = [], set()
    for label, dec in _decoded_runs(raw):
        _scan_payload(label, dec, seen, out)
    return out


def _sibling_refs(t, raw):
    """Script names an executable that actually sits next to it: staging link."""
    if not t.siblings:
        return []
    base = t.basename.lower()
    hits = set()
    for m in _SIB_REF.finditer(raw[:65536]):
        n = m.group().decode("latin-1", "replace").strip().lower()
        if n != base and n in t.siblings:
            hits.add(n)
    if hits:
        return [Finding("SCRIPT?", "references sibling file(s) present here: "
                        + ", ".join(sorted(hits)[:4]))]
    return []


def _persist(norm):
    """Persistence markers valid for any script kind."""
    out = []
    if b"schtasks" in norm and b"/create" in norm:
        out.append(Finding("PERSIST?", "scheduled-task creation (schtasks /create)"))
    if b"__eventfilter" in norm and b"commandlineeventconsumer" in norm:
        out.append(Finding("PERSIST!", "WMI event-subscription persistence (EventFilter + Consumer)", CRITICAL))
    if b"imagefileexecutionoptions" in norm and b"debugger" in norm:
        out.append(Finding("PERSIST!", "IFEO debugger hijack", CRITICAL))
    if b"currentversion\\runonce" in norm:
        out.append(Finding("PERSIST!", "RunOnce persistence key", CRITICAL))
    return out


def _html(t, raw, norm):
    if any(p in norm for p in HTML_DECODE) and any(p in norm for p in HTML_DROP):
        return [Finding("SCRIPT!", "HTML smuggling pattern: inline base64 decode + blob/auto-download", CRITICAL)]
    return []


def _ps1(t, raw, norm):
    out = []
    dl, ex, dec = _hits(norm, PS_DL), _hits(norm, PS_EX), _hits(norm, PS_DEC)
    if dl and ex and not _vendor_only(raw):
        out.append(Finding("SCRIPT!", "powershell download+execute: " + ", ".join(dl[:3]) + " + " + ex[0], CRITICAL))
    elif dec and ex:
        out.append(Finding("SCRIPT!", "powershell decode+execute: " + dec[0] + " + " + ex[0], CRITICAL))
    elif dl and _hits(norm, PS_STAGE):
        out.append(Finding("SCRIPT?", "downloader + file write: staged dropper (" + dl[0] + ")"))
    elif dl:
        out.append(Finding("NET-DL", "powershell downloader tokens: " + ", ".join(dl[:3])))
    tamp = _hits(norm, PS_TAMPER)
    if tamp:
        out.append(Finding("EVADE!", "AMSI/AV tamper tokens: " + ", ".join(tamp[:3]), CRITICAL))
    if b"sockets.tcpclient" in norm and b"getstream" in norm:
        out.append(Finding("SCRIPT!", "powershell TcpClient+GetStream: reverse-shell pattern", CRITICAL))
    return out


def _bat(t, raw, norm):
    if _vendor_only(raw):  # vendor installers legitimately carry ps flags + iex
        return []
    out = []
    for group in BAT_BAD:
        h = _hits(norm, group)
        if len(h) >= 2:
            out.append(Finding("SCRIPT!", "batch dropper combo: " + " + ".join(h[:3]), CRITICAL))
    if len(_hits(norm, PS_INLINE)) >= 2:
        out.append(Finding("SCRIPT!", "batch powershell one-liner: "
                           + " + ".join(_hits(norm, PS_INLINE)[:3]), CRITICAL))
    return out


def _vbsjs(t, raw, norm):
    out = []
    net, ex = _hits(norm, VBS_NET), _hits(norm, VBS_EX)
    if net and any(e in ex for e in ("savetofile", ".run(", "shellexecute")):
        out.append(Finding("SCRIPT!", "dropper trio: " + net[0] + " + " + ex[0], CRITICAL))
    elif net and b"createtextfile(" in norm:
        out.append(Finding("SCRIPT?", "net fetch + CreateTextFile: staged write (" + net[0] + ")"))
    elif any(e in ex for e in ("wscript.shell", "createobject(")):
        out.append(Finding("SCRIPT?", "wscript/shell object creation"))
    if raw[:4] == b"#@~^":
        out.append(Finding("OBF!", "encoded script (VBE/JSE #@~^ header) - needs decoder, near-zero legit use", CRITICAL))
    n_chr = norm.count(b"chr(")
    if n_chr > 20 and b"execute" in norm:
        out.append(Finding("OBF", "chr()-obfuscation density %d + execute" % n_chr))
    n_fcc = norm.count(b"fromcharcode(")
    if n_fcc > 20 and b"eval(" in norm:
        out.append(Finding("OBF", f"fromCharCode density {n_fcc} + eval"))
    if b"unescape(" in norm and b"eval(" in norm:
        out.append(Finding("OBF?", "unescape + eval (encoded-string execution)"))
    if b"child_process" in norm:
        out.append(Finding("SCRIPT?", "node child_process usage"))
    return out


def _hta(t, raw, norm):
    out = [Finding("NOTE", "HTA application (runs with script engine privileges)")]
    out += _vbsjs(t, raw, norm)
    return out


_REG_HIJACKS = (  # (label, tokens that must all be present in norm)
    ("Winlogon Shell hijack", (b"currentversion\\winlogon", b"shell=")),
    ("Winlogon UserInit hijack", (b"currentversion\\winlogon", b"userinit=")),
    ("AppInit_DLLs hijack", (b"appinit_dlls=",)),
    ("service ImagePath hijack", (b"currentcontrolset\\services", b"imagepath=")),
    ("Active Setup StubPath", (b"stubpath=",)),
)


def _reg(t, raw, norm):
    out = []
    if b"[hkey_current_user\\software\\microsoft\\windows\\currentversion\\run" in norm \
            or b"[hkey_local_machine\\software\\microsoft\\windows\\currentversion\\run" in norm:
        out.append(Finding("PERSIST!", ".reg file writes Run key", CRITICAL))
    for label, marks in _REG_HIJACKS:
        if all(m in norm for m in marks):
            out.append(Finding("PERSIST!", ".reg writes " + label, CRITICAL))
    return out


def _url(t, raw, norm):
    m = re.search(rb"url=file:([^\r\n]+)", norm)
    if m:
        return [Finding("SCRIPT!", ".url shortcut targets local file: "
                       + m.group(1)[:60].decode(errors="replace"), CRITICAL)]
    if b"\\\\" in norm:  # icon/target on remote share: NTLM hash leaks on open
        return [Finding("NET?", ".url references UNC path (credential-leak lure)")]
    return []


_SIB_REF = re.compile(rb"(?i)[a-z0-9_][a-z0-9_.-]{0,59}\.(?:exe|dll|scr|msi|bat|cmd|ps1|vbs|js|jse|hta|jar|lnk|py)\b")

_ENV_SUB = re.compile(rb"(?i)[%!][a-z0-9_]{2,}:~[-0-9]")  # %windir:~-4% substring syntax


def _lnk_struct(raw):
    """-> (args, icon, machine_id) where parsed, else None. Field walk per
    MS-SHLLINK; tolerated failure = fall back to the raw blob scan."""
    try:
        if len(raw) < 76 or raw[:4] != b"\x4c\x00\x00\x00":
            return None
        flags = struct.unpack_from("<I", raw, 20)[0]
        uni = bool(flags & 0x80)
        off = 76
        if flags & 0x1:  # HasLinkTargetIDList
            off += 2 + struct.unpack_from("<H", raw, off)[0]
        if flags & 0x2:  # HasLinkInfo
            off += struct.unpack_from("<I", raw, off)[0]

        def rds(o):
            n = struct.unpack_from("<H", raw, o)[0]
            w = 2 if uni else 1
            txt = raw[o + 2:o + 2 + n * w]
            return txt.decode("utf-16-le" if uni else "latin-1", "replace"), o + 2 + n * w

        fields = {}
        for bit, name in ((0x4, "name"), (0x8, "rel"), (0x10, "dir"),
                          (0x20, "args"), (0x40, "icon")):
            if flags & bit:
                fields[name], off = rds(off)
        mid = b""
        sig = raw.find(b"\x03\x00\x00\xa0")  # TrackerDataBlock (build machine)
        if sig >= 0:
            mid = raw[sig + 8:sig + 24].split(b"\x00")[0]
            if not all(32 <= c < 127 for c in mid):
                mid = b""
        return fields.get("args", ""), fields.get("icon", ""), mid.decode("ascii", "replace")
    except Exception:
        return None


def _lnk(t, raw):
    out = []
    if len(raw) < 24:
        return [Finding("STRUCT?", "truncated LNK")]
    if raw[4:20] != _LNK_CLSID:
        out.append(Finding("STRUCT?", "LNK header CLSID mismatch (forged/custom shortcut)"))
    blob = raw + raw.decode("utf-16le", errors="ignore").encode("latin-1", "ignore")
    norm = _norm(blob)
    h = _hits(norm, LNK_BAD)
    if h:
        bad = any(x in h for x in ("-enc", "-encodedcommand", "whidden", "windowstyle", "mshta", "certutil"))
        m = re.search(rb"(powershell|cmd\.exe|wscript|rundll32|mshta)[^\x00]{0,80}", norm)
        detail = m.group()[:90].decode(errors="replace") if m else ", ".join(h[:3])
        out.append(Finding("SCRIPT!" if bad else "SCRIPT?",
                           "LNK arguments reference: " + detail, CRITICAL if bad else "note"))
    if b"\\\\" in norm:  # icon/target on remote share: NTLM hash leaks on open
        out.append(Finding("NET?", "LNK references UNC path (credential-leak lure)"))
    if _ENV_SUB.search(blob):
        out.append(Finding("OBF!", "env-var substring syntax in args (%var:~-N% name splicing)", CRITICAL))
    st = _lnk_struct(raw)
    if st and st[2]:
        out.append(Finding("PROV", "LNK built on machine: " + st[2]))
    return out


def _py(t, raw, norm):
    out = []
    dl = _hits(norm, PY_DL)
    ex = _hits(norm, PY_EX)
    dec = _hits(norm, PY_DEC)
    if dl and ex:
        out.append(Finding("SCRIPT!", "python download+execute: " + ", ".join(dl[:3])
                           + " + " + ex[0], CRITICAL))
    elif dec and ex:
        out.append(Finding("SCRIPT!", "python decode+execute: " + dec[0] + " + " + ex[0], CRITICAL))
    elif dl and b"subprocess" in norm:
        out.append(Finding("NET-DL", "python downloader tokens + subprocess: " + ", ".join(dl[:3])))
    if b"os.system" in norm and b"chmod" in norm:
        out.append(Finding("SCRIPT?", "os.system + chmod (staged execution)"))
    if b"socket" in norm and b"dup2" in norm:
        out.append(Finding("SCRIPT!", "socket + dup2: python reverse-shell pattern", CRITICAL))
    if b"pty.spawn" in norm and b"socket" in norm:
        out.append(Finding("SCRIPT!", "pty.spawn over socket (interactive reverse shell)", CRITICAL))
    return out


def _sh(t, raw, norm):
    out = []
    dl = _hits(norm, SH_DL)
    if dl and any(p in norm for p in _PIPE_SHELL):
        out.append(Finding("SCRIPT!", "curl/wget piped straight into shell", CRITICAL))
    if b"/dev/tcp/" in norm:
        out.append(Finding("SCRIPT!", "bash /dev/tcp/ reverse shell", CRITICAL))
    if _NC_E.search(raw) or (b"socat" in norm and b"exec:" in norm):
        out.append(Finding("SCRIPT!", "netcat/socat -e reverse shell", CRITICAL))
    if b"chmodx" in norm and (b"~/." in norm or b"/tmp/." in norm):  # '+' stripped in norm
        out.append(Finding("SCRIPT?", "chmod +x onto hidden-dir path"))
    elif dl and b"chmodx" in norm:
        out.append(Finding("SCRIPT?", "downloader + chmod: staged binary (" + dl[0] + ")"))
    if b"$(curl" in norm or b"$(wget" in norm:
        out.append(Finding("SCRIPT!", "curl/wget command-substitution executed inline", CRITICAL))
    if b"base64-d" in norm and any(p in norm for p in _PIPE_SHELL):
        out.append(Finding("SCRIPT!", "base64-decoded payload piped into shell", CRITICAL))
    if b"ld.so.preload" in norm:
        out.append(Finding("SCRIPT!", "touches /etc/ld.so.preload (rootkit persistence)", CRITICAL))
    elif b"authorized_keys" in norm:
        out.append(Finding("PERSIST?", "writes authorized_keys (ssh persistence)"))
    return out


def _wsf(t, raw, norm):
    out = [Finding("NOTE", "WSF/SCT scriptlet container (WSH host, regsvr32 abuse vector)")]
    return out + _vbsjs(t, raw, norm)


def _php(t, raw, norm):
    inp = _hits(norm, (b"$_post", b"$_request", b"$_get", b"$_cookie"))
    exe = _hits(norm, (b"eval(", b"assert(", b"system(", b"shell_exec", b"passthru(",
                       b"popen(", b"base64_decode", b"file_put_contents"))
    if inp and exe:
        return [Finding("SCRIPT!", "webshell: " + inp[0] + " input into " + exe[0], CRITICAL)]
    return []


def _scf(t, raw, norm):
    if b"iconfile=\\\\" in norm:
        return [Finding("NET?", "SCF IconFile on UNC share (credential-leak lure)")]
    return []


def _setms(t, raw, norm):
    h = _hits(norm, LNK_BAD)
    if h:
        bad = any(x in h for x in ("-enc", "-encodedcommand", "whidden", "windowstyle", "mshta", "certutil"))
        return [Finding("SCRIPT!" if bad else "SCRIPT?",
                        "settingcontent-ms command tokens: " + ", ".join(h[:3]),
                        CRITICAL if bad else "note")]
    return []


def _libms(t, raw, norm):
    if b"\\\\" in norm:
        return [Finding("NET?", "library-ms references UNC path (credential-leak lure)")]
    return []


_H = {".ps1": _ps1, ".psm1": _ps1, ".bat": _bat, ".cmd": _bat, ".vbs": _vbsjs,
      ".py": _py, ".pyw": _py, ".sh": _sh,
      ".vbe": _vbsjs, ".js": _vbsjs, ".jse": _vbsjs, ".hta": _hta, ".reg": _reg,
      ".url": _url, ".wsf": _wsf, ".sct": _wsf,
      ".php": _php, ".scf": _scf, ".settingcontent-ms": _setms, ".library-ms": _libms}


def run(t):
    if not t.raw:
        return []
    if t.kind == "LNK":
        return _lnk(t, t.raw) + _peek(t.raw)
    if t.ext in (".html", ".htm", ".mht", ".xhtml"):  # kind TEXT: html smuggling is script territory
        return _html(t, t.raw, _norm(t.raw))
    if t.kind == "TEXT":  # renamed scripts: extension lies, content doesn't
        head = t.raw[:256]
        if head[:2] == b"#!":  # shebang -> route by interpreter (default sh)
            h = _py if b"python" in head.splitlines()[0] else _sh
            n = _norm(_strip_comments(t.raw))
            return h(t, t.raw, n) + _persist(n)
        if b"<?php" in head:
            return _php(t, t.raw, _norm(_strip_comments(t.raw)))
        return []
    if t.kind == "COMPILED":
        return [Finding("NOTE", "compiled script bytecode (.pyc/.class): source not "
                                "scannable as text - see strings below, treat as opaque")]
    if t.kind != "SCRIPT":
        return []
    norm = _norm(_strip_comments(t.raw))
    if t.ext in (".wsf", ".sct", ".settingcontent-ms", ".library-ms"):  # XML carriers
        norm += _norm(_xview(t.raw))
    h = _H.get(t.ext)
    out = h(t, t.raw, norm) if h else []
    return out + _persist(norm) + _peek(t.raw) + _sibling_refs(t, t.raw)
