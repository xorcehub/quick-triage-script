"""Strings/IOC sweep: language-agnostic ASCII+UTF-16 extraction with keyword scoring.
Mutexes are displayed, not scored (family-specific). No base64-blob scoring (FP machine)."""
import re

from ..model import Finding

MIN_LEN = 6
MAX_STRINGS = 20000  # cap work on huge sections
BENIGN_DOMAINS = (b"microsoft.com", b"windows.com", b"msdn.com", b"w3.org", b"xmlsoap.org",
                  b"openxmlformats.org", b"openssl.org", b"python.org", b"intel.com",
                  b"nvidia.com", b"apple.com", b"adobe.com", b"mozilla.org", b"ietf.org")
_URLDOM_RE = re.compile(rb"(?:https?|ftp)://([^/:?#]+)", re.I)

URL_RE = re.compile(rb"(?:https?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&()*+,;=%]{4,}", re.I)
IP_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RUNKEY_RE = re.compile(rb"(?:Software\\(?:Microsoft\\Windows\\)?CurrentVersion\\Run\w*)", re.I)
MUTEX_RE = re.compile(rb"(?:Global|Local)\\[A-Za-z0-9_.\-{}]{4,}")
# stealer target paths / product strings (display-level signal)
STEALER_RE = re.compile(
    rb"(AppData\\Roaming\\(discord|telegram)|"
    rb"AppData\\Local\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware|Opera)|"
    rb"Login Data|Local State|wallet\.dat|coinbase|metamask|exodus|electrum|keystore)", re.I)
ANTIANALYSIS_RE = re.compile(
    rb"\b(vmware|vbox|virtualbox|sandboxie|qemu|x64dbg|ollydbg|wireshark|procmon|"
    rb"process monitor|autoruns|pestudio|die_detector)\b", re.I)
CMDLINE_RE = re.compile(
    rb"(?:powershell(\.exe)?\s+-(?:enc|e|nop|w|c|hidden)|cmd\.exe\s+/c\s+|"
    rb"schtasks\s+/create|reg\s+add\s+.*CurrentVersion\\Run|rundll32(?:\.exe)?\s+\S+,\S+|"
    rb"mshta\s+|certutil\s+-urlcache|bitsadmin\s+/transfer|curl\s+-o\s+\S+\s+https?://)", re.I)


def extract(raw, min_len=MIN_LEN):
    """-> (ascii_strings, utf16_strings), capped."""
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    asc = [m.group() for m in ascii_re.finditer(raw, MAX_STRINGS * 40)]
    u16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    uni = [m.group().decode("utf-16le", errors="replace") for m in u16.finditer(raw, MAX_STRINGS * 40)]
    return asc[:MAX_STRINGS], uni[:MAX_STRINGS]


def run(t):
    if t.error or t.pe is None or not t.raw:
        return []
    out = []
    raw = t.raw[:64 << 20]  # ponytail: 64MB cap, full parse if ever needed
    # mask the embedded certificate blob: its URLs/OIDs are pure noise
    try:
        sec = t.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if sec.VirtualAddress and sec.VirtualAddress < len(raw):
            end = min(sec.VirtualAddress + sec.Size, len(raw))
            raw = raw[:sec.VirtualAddress] + b"\x00" * (end - sec.VirtualAddress) + raw[end:]
    except Exception:
        pass
    asc, uni = extract(raw)
    joined_u = "\n".join(uni)

    def u_hits(rx):
        return set(m.group() for m in rx.finditer(joined_u.encode("utf-16le" if False else "latin-1", "ignore")))

    urls = {u.decode("latin-1", "replace") for u in URL_RE.findall(raw)}
    urls |= {u.decode("latin-1", "replace") for u in URL_RE.findall(joined_u.encode("latin-1", "ignore"))}
    ips = {i.decode() for i in IP_RE.findall(raw)} | {i.decode() for i in IP_RE.findall(joined_u.encode("latin-1", "ignore"))}
    ips = {i for i in ips if not i.startswith(("0.", "255.", "127.")) and not i.endswith((".0", ".255"))}
    # ASN.1 OIDs (2.5.4.3 etc) masquerade as IPs; real public IPs rarely have all-small octets
    ips = {i for i in ips if max(int(o) for o in i.split(".")) > 64}

    if urls:
        def benign(u):
            m = _URLDOM_RE.match(u.encode("latin-1", "ignore"))
            dom = m.group(1).lower() if m else b""
            return dom == b"schemas.microsoft.com" or any(dom == d or dom.endswith(b"." + d) for d in BENIGN_DOMAINS)
        sus = {u for u in urls if not benign(u)}
        if sus:
            show = sorted(sus)[:5]
            out.append(Finding("STR", "urls: " + ", ".join(show) + (f" (+{len(sus)-5} more)" if len(sus) > 5 else "")))
        else:
            out.append(Finding("STR", f"{len(urls)} url(s), all known-vendor (cert/doc links)"))
    if ips:
        out.append(Finding("STR", "ip literals: " + ", ".join(sorted(ips)[:8])))
    for m in sorted(set(RUNKEY_RE.findall(raw)))[:3]:
        out.append(Finding("PERSIST", f"registry Run-key string: {m.decode(errors='replace')}"))
    for m in sorted(set(MUTEX_RE.findall(raw)))[:5]:
        out.append(Finding("STR", f"mutex-style name: {m.decode(errors='replace')}"))
    if STEALER_RE.search(raw) or STEALER_RE.search(joined_u.encode("latin-1", "ignore")):
        m = STEALER_RE.search(raw) or STEALER_RE.search(joined_u.encode("latin-1", "ignore"))
        out.append(Finding("STR?", f"stealer-target string present: {m.group().decode(errors='replace')}"))
    aa = sorted({m.group().decode("latin-1", "replace").lower() for m in ANTIANALYSIS_RE.finditer(raw)} |
                {m.group().decode("latin-1", "replace").lower() for m in ANTIANALYSIS_RE.finditer(joined_u.encode("latin-1", "ignore"))})
    if aa:
        out.append(Finding("EVADE", "anti-analysis strings: " + ", ".join(aa[:6])))
    cm = CMDLINE_RE.search(raw) or CMDLINE_RE.search(joined_u.encode("latin-1", "ignore"))
    if cm:
        out.append(Finding("EXEC?", f"suspicious command line: {cm.group().decode(errors='replace')[:100]}"))
    return out
