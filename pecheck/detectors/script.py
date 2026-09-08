"""Script + shortcut triage: obfuscation, download/decode-execute pairs,
dropper patterns. Markers matched against a normalized view (lowercase,
whitespace/backtick/caret/quote/plus-stripped) to defeat case/space
obfuscation plus backtick (PowerShell), caret (cmd.exe) and quote-concat
("ie"+"x") splitting. Long base64 runs are
decoded and the payload token-scanned (what does it actually do?). LNK gets
a header check plus command-marker scan over the raw bytes (ANSI + UTF-16)."""
import base64
import re
import zlib

from ..model import Finding, CRITICAL

PY_DL = (b"urllib.request", b"urlopen", b"requests.get", b"requests.post",
         b"socket.socket", b"http.client")
PY_EX = (b"exec(", b"eval(", b"compile(", b"__import__", b"os.popen")
PY_DEC = (b"base64.b64decode", b"b64decode", b"codecs.decode", b"unhexlify",
          b"zlib.decompress", b"marshal.loads", b"pickle.loads")
SH_DL = (b"curl", b"wget", b"fetch")

_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
_NORM_WS = re.compile(b"[\\s`^\"'+]+")  # ws + PS backtick + cmd caret, plus quote/plus
# stripped so concat obfuscation ("ie"+"x") re-joins for marker matching


def _norm(raw):
    n = _NORM_WS.sub(b"", raw).lower()
    if b"\x00" in raw[:512]:  # utf-16le saves: decode so markers still match
        try:
            u16 = raw.decode("utf-16le", errors="ignore").encode("latin-1", "ignore")
            n += _NORM_WS.sub(b"", u16).lower()
        except Exception:
            pass
    return n


def _hits(norm, pats):
    return [p.decode() for p in pats if p in norm]


PS_DL = (b"downloadstring", b"downloadfile", b"downloaddata", b"invoke-webrequest",
         b"invoke-restmethod", b"net.webclient", b"httpwebrequest", b"webclient",
         b"start-bitstransfer")
PS_EX = (b"invoke-expression", b"iex", b"start-process", b"&(")
PS_DEC = (b"frombase64string", b"-encodedcommand", b"-enc", b"gzipstream", b"deflatestream")
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
           (b"curl", b"http"), (b"wget", b"http"),
           # PS one-liner body invoked from bat (-c/-command): powershell + exec/dl token
           (b"powershell", b"iex", b"invoke-expression", b"downloadstring", b"downloadfile",
            b"net.webclient", b"frombase64string"))
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


def _inflate(dec):
    """base64 payloads are often gzip/deflate-compressed on top: try both, else raw."""
    for wbits in (47, -15):  # 47 = auto gzip/zlib, -15 = raw deflate
        try:
            return zlib.decompress(dec, wbits)
        except Exception:
            continue
    return dec


def _b64peek(raw):
    """Decode long base64 runs, token-scan the payload (ascii + utf-16 views)."""
    out = []
    for m in list(_B64_RUN.finditer(raw))[:3]:
        blob = m.group()
        try:
            dec = _inflate(base64.b64decode(blob + b"=" * (-len(blob) % 4)))
        except Exception:
            continue
        view = (dec[:8192].decode("utf-16-le", "ignore").encode("latin-1", "ignore")
                + dec[:8192])  # ascii + utf-16 stored payload both visible to byte tokens
        hits = [p.decode() for p in _PEEK_TOKENS if p in view]
        if dec[:2] == b"MZ":
            hits.insert(0, "MZ executable")
        if hits:
            hot = any(h in hits for h in ("MZ executable", "powershell", "cmd.exe", "/dev/tcp"))
            out.append(Finding("OBF!" if hot else "OBF?",
                               f"decoded base64 payload ({len(dec):,}B) contains: "
                               + ", ".join(hits[:4]), CRITICAL if hot else "note"))
    return out


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
    if dl and ex:
        out.append(Finding("SCRIPT!", "powershell download+execute: " + ", ".join(dl[:3]) + " + " + ex[0], CRITICAL))
    elif dec and ex:
        out.append(Finding("SCRIPT!", "powershell decode+execute: " + dec[0] + " + " + ex[0], CRITICAL))
    elif dl:
        out.append(Finding("NET-DL", "powershell downloader tokens: " + ", ".join(dl[:3])))
    tamp = _hits(norm, PS_TAMPER)
    if tamp:
        out.append(Finding("EVADE!", "AMSI/AV tamper tokens: " + ", ".join(tamp[:3]), CRITICAL))
    return out


def _bat(t, raw, norm):
    out = []
    for group in BAT_BAD:
        h = _hits(norm, group)
        if len(h) >= 2:
            out.append(Finding("SCRIPT!", "batch dropper combo: " + " + ".join(h[:3]), CRITICAL))
    return out


def _vbsjs(t, raw, norm):
    out = []
    net, ex = _hits(norm, VBS_NET), _hits(norm, VBS_EX)
    if net and any(e in ex for e in ("savetofile", ".run(", "shellexecute")):
        out.append(Finding("SCRIPT!", "dropper trio: " + net[0] + " + " + ex[0], CRITICAL))
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


def _reg(t, raw, norm):
    if b"[hkey_current_user\\software\\microsoft\\windows\\currentversion\\run" in norm \
            or b"[hkey_local_machine\\software\\microsoft\\windows\\currentversion\\run" in norm:
        return [Finding("PERSIST!", ".reg file writes Run key", CRITICAL)]
    return []


def _url(t, raw, norm):
    m = re.search(rb"url=file:([^\r\n]+)", norm)
    if m:
        return [Finding("SCRIPT!", ".url shortcut targets local file: "
                       + m.group(1)[:60].decode(errors="replace"), CRITICAL)]
    return []


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
    if dl and (b"|sh" in norm or b"|bash" in norm):
        out.append(Finding("SCRIPT!", "curl/wget piped straight into shell", CRITICAL))
    if b"/dev/tcp/" in norm:
        out.append(Finding("SCRIPT!", "bash /dev/tcp/ reverse shell", CRITICAL))
    if b"chmod+x" in norm and (b"~/." in norm or b"/tmp/." in norm):
        out.append(Finding("SCRIPT?", "chmod +x onto hidden-dir path"))
    if b"$(curl" in norm or b"$(wget" in norm:
        out.append(Finding("SCRIPT!", "curl/wget command-substitution executed inline", CRITICAL))
    if b"base64-d" in norm and (b"|sh" in norm or b"|bash" in norm):
        out.append(Finding("SCRIPT!", "base64-decoded payload piped into shell", CRITICAL))
    if b"ld.so.preload" in norm:
        out.append(Finding("SCRIPT!", "touches /etc/ld.so.preload (rootkit persistence)", CRITICAL))
    elif b"authorized_keys" in norm:
        out.append(Finding("PERSIST?", "writes authorized_keys (ssh persistence)"))
    return out


def _wsf(t, raw, norm):
    out = [Finding("NOTE", "WSF/SCT scriptlet container (WSH host, regsvr32 abuse vector)")]
    return out + _vbsjs(t, raw, norm)


_H = {".ps1": _ps1, ".psm1": _ps1, ".bat": _bat, ".cmd": _bat, ".vbs": _vbsjs,
      ".py": _py, ".pyw": _py, ".sh": _sh,
      ".vbe": _vbsjs, ".js": _vbsjs, ".jse": _vbsjs, ".hta": _hta, ".reg": _reg,
      ".url": _url, ".wsf": _wsf, ".sct": _wsf}


def run(t):
    if not t.raw:
        return []
    if t.kind == "LNK":
        return _lnk(t, t.raw) + _b64peek(t.raw)
    if t.ext in (".html", ".htm"):  # kind TEXT: html smuggling is script territory
        return _html(t, t.raw, _norm(t.raw))
    if t.kind != "SCRIPT":
        return []
    norm = _norm(t.raw)
    h = _H.get(t.ext)
    out = h(t, t.raw, norm) if h else []
    return out + _persist(norm) + _b64peek(t.raw)
