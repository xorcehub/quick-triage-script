"""Script + shortcut triage: obfuscation, download/decode-execute pairs,
dropper patterns. Markers matched against a normalized view (lowercase,
whitespace-stripped) to defeat case/space obfuscation. LNK gets a header
check plus command-marker scan over the raw bytes (ANSI + UTF-16)."""
import re

from ..model import Finding, CRITICAL

_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
_NORM_WS = re.compile(rb"\s+")


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
         b"invoke-restmethod", b"net.webclient", b"httpwebrequest", b"webclient")
PS_EX = (b"invoke-expression", b"iex", b"start-process", b"&(")
PS_DEC = (b"frombase64string", b"-encodedcommand", b"-enc", b"gzipstream", b"deflatestream")
_A1 = b"amsi" + b"init" + b"failed"
_A2 = b"amsi" + b"utils"
PS_TAMPER = (_A1, _A2, b"set-mppreference", b"add-mppreference",
             b"-disablerealtimemonitoring", b"virtualprotect", b"getprocaddress")

BAT_BAD = ((b"powershell", b"-enc", b"-encodedcommand", b"-w1", b"-whidden",
            b"-windowstylehidden", b"-nop", b"-noprofile"),
           (b"certutil", b"-urlcache", b"-decode", b"-verifyctl"),
           (b"bitsadmin", b"/transfer", b"/create", b"/addfile"),
           (b"mshta", b"vbscript:"),
           (b"regadd", b"currentversion\\run"),
           (b"curl", b"http"), (b"wget", b"http"))
VBS_NET = (b"msxml2.xmlhttp", b"winhttp.winhttprequest", b"msxml2.serverxmlhttp", b"adodb.stream")
VBS_EX = (b"savetofile", b".run(", b"shellexecute", b"wscript.shell", b"createobject(")
LNK_BAD = (b"powershell", b"cmd.exe", b"-enc", b"-encodedcommand", b"whidden",
           b"windowstyle", b"certutil", b"mshta", b"wscript", b"rundll32")


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


_H = {".ps1": _ps1, ".psm1": _ps1, ".bat": _bat, ".cmd": _bat, ".vbs": _vbsjs,
      ".vbe": _vbsjs, ".js": _vbsjs, ".jse": _vbsjs, ".hta": _hta, ".reg": _reg,
      ".url": _url}


def run(t):
    if not t.raw:
        return []
    if t.kind == "LNK":
        return _lnk(t, t.raw)
    if t.kind != "SCRIPT":
        return []
    h = _H.get(t.ext)
    return h(t, t.raw, _norm(t.raw)) if h else []
