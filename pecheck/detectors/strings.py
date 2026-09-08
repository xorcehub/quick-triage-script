"""Strings/IOC sweep: one ASCII+UTF-16 extraction pass, then per-family regexes
over the (small) string corpus instead of the raw file - ~10x faster on large
PEs with identical hit sets (all families only match runs >= 6 printable chars).
Mutexes/pipe names are displayed, not scored. No base64-blob scoring (FP machine)."""
import re

from ..model import Finding, CRITICAL, NOTE
from ..peparse import cert_table_range

MIN_LEN = 6
MAX_ASCII = 200000   # cap extracted ascii strings (corpus stays a few MB)
MAX_UTF16 = 20000

URL_RE = re.compile(rb"(?:https?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&()*+,;=%]{4,}", re.I)
IP_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RUNKEY_RE = re.compile(rb"[Ss]oftware\\[Mm]icrosoft\\[Ww]indows\\[Cc]urrent[Vv]ersion\\[Rr]un\w*")
MUTEX_RE = re.compile(rb"(?:[Gg]lobal|[Ll]ocal)\\[A-Za-z0-9_.\-{}]{4,}|\\\\\.\\pipe\\[A-Za-z0-9_]{4,}")
WEBHOOK_RE = re.compile(
    rb"(?:https?://(?:[a-z0-9-]+\.)*discord(?:app)?\.com/api/webhooks/[A-Za-z0-9%/_-]+"
    rb"|https?://api\.telegram\.org/bot[A-Za-z0-9:_-]+"
    rb"|https?://hooks\.slack\.com/services/[A-Za-z0-9/_-]+)", re.I)
STEALER_RE = re.compile(
    rb"(?:AppData\\Roaming\\(?:discord|telegram)"
    rb"|AppData\\Local\\(?:Google\\Chrome|Microsoft\\Edge|BraveSoftware|Opera)"
    rb"|Login Data|Local State|wallet\.dat|[Cc]oinbase|[Mm]etamask|[Ee]xodus"
    rb"|[Ee]lectrum|[Kk]eystore)")
ANTIANALYSIS_RE = re.compile(
    rb"\b(?:vmware|vbox|virtualbox|sandboxie|qemu|x64dbg|ollydbg|wireshark|procmon"
    rb"|process monitor|autoruns|pestudio|die_detector)\b", re.I)
CMDLINE_RE = re.compile(
    rb"(?:powershell(?:\.exe)?\s+-(?:enc|e|nop|w|c|hidden)|cmd\.exe\s+/c\s+|"
    rb"schtasks\s+/create|reg\s+add\s+.*CurrentVersion\\Run|rundll32(?:\.exe)?\s+\S+,\S+|"
    rb"mshta\s+|certutil\s+-urlcache|bitsadmin\s+/transfer|curl\s+-o\s+\S+\s+https?://)", re.I)

BENIGN_DOMAINS = (b"microsoft.com", b"windows.com", b"msdn.com", b"w3.org", b"xmlsoap.org",
                  b"openxmlformats.org", b"openssl.org", b"python.org", b"intel.com",
                  b"nvidia.com", b"apple.com", b"adobe.com", b"mozilla.org", b"ietf.org",
                  b"purl.org", b"sourceforge.net", b"digicert.com", b"symantec.com")
_URLDOM_RE = re.compile(rb"(?:https?|ftp)://([^/:?#]+)", re.I)


def extract_corpus(raw, pe):
    """-> bytes corpus of printable strings; masks the cert blob (its URLs/OIDs are noise)."""
    data = raw[:64 << 20]  # ponytail: 64MB cap, raise if dump-like inputs appear
    try:
        rng = cert_table_range(data, pe)
        if rng:
            s, e = rng
            data = data[:s] + b"\x00" * (e - s) + data[e:]
    except Exception:
        pass
    asc = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
    u16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LEN)
    parts = [m.group() for m in asc.finditer(data)][:MAX_ASCII]
    parts += [m.group() for m in u16.finditer(data)][:MAX_UTF16]
    return b"\n".join(parts)


def _benign(u):
    m = _URLDOM_RE.match(u.encode("latin-1", "ignore"))
    dom = m.group(1).lower() if m else b""
    return any(dom == d or dom.endswith(b"." + d) for d in BENIGN_DOMAINS)


def run(t):
    """Generic: any kind with bytes (cert masking is a no-op without a PE)."""
    if not t.raw:
        return []
    out = []
    corpus = extract_corpus(t.raw, t.pe)

    urls = {u.decode("latin-1", "replace") for u in URL_RE.findall(corpus)}
    if urls:
        sus = {u for u in urls if not _benign(u)}
        if sus:
            show = sorted(sus)[:5]
            out.append(Finding("STR", "urls: " + ", ".join(show) + (f" (+{len(sus)-5} more)" if len(sus) > 5 else "")))
        else:
            out.append(Finding("STR", f"{len(urls)} url(s), all known-vendor (cert/doc links)"))
    # exfil-capable webhooks: rare-but-review-worthy in binaries, plausible in scripts;
    # NUL-stripped corpus catches UTF-16LE-stored configs (common in real samples)
    corpus_nc = corpus.replace(b"\x00", b"")
    hooks = sorted({h.decode("latin-1", "replace") for h in
                    WEBHOOK_RE.findall(corpus) + WEBHOOK_RE.findall(corpus_nc)})
    if hooks:
        crit = t.kind in ("PE", "ELF", "MACHO") and not (t.sig and t.sig[0] == "Valid")
        out.append(Finding("STR!" if crit else "STR?",
                           "exfil webhook (discord/telegram/slack): "
                           + ", ".join(h[:80] for h in hooks[:2])
                           + (f" (+{len(hooks) - 2} more)" if len(hooks) > 2 else ""),
                           CRITICAL if crit else NOTE))
    ips = {i.decode() for i in IP_RE.findall(corpus)}
    ips = {i for i in ips if not i.startswith(("0.", "255.", "127.")) and not i.endswith((".0", ".255"))}
    # ASN.1 OIDs (2.5.4.3 etc) masquerade as IPs; real public IPs rarely have all-small octets
    ips = {i for i in ips if max(int(o) for o in i.split(".")) > 64}
    if ips:
        out.append(Finding("STR", "ip literals: " + ", ".join(sorted(ips)[:8])))
    for m in sorted(set(RUNKEY_RE.findall(corpus)))[:3]:
        out.append(Finding("PERSIST", f"registry Run-key string: {m.decode(errors='replace')}"))
    for m in sorted(set(MUTEX_RE.findall(corpus)))[:5]:
        out.append(Finding("STR", f"mutex/pipe-style name: {m.decode(errors='replace')}"))
    for m in sorted(set(STEALER_RE.findall(corpus)))[:3]:
        out.append(Finding("STR?", f"stealer-target string present: {m.decode(errors='replace')}"))
    aa = sorted({m.decode("latin-1", "replace").lower() for m in ANTIANALYSIS_RE.findall(corpus)})
    if aa:
        out.append(Finding("EVADE", "anti-analysis strings: " + ", ".join(aa[:6])))
    if t.kind != "SCRIPT":  # script.py owns command-line triage for scripts
        for m in sorted(set(CMDLINE_RE.findall(corpus)))[:3]:
            out.append(Finding("EXEC?", f"suspicious command line: {m.decode(errors='replace')[:100]}"))
    return out
