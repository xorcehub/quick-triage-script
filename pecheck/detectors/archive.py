"""Container triage. zip members via stdlib zipfile: names/flags only +
512-byte head sniff of exe/script members (never full inflate). 7z/rar/xz/
gzip/bzip2: magic + note (no stdlib member parser - report, don't guess)."""
import io
import re
import zipfile

from ..model import Finding, CRITICAL

_MEMBER_HEAD_EXTS = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".hta",
                     ".vbs", ".js", ".lnk", ".jse", ".vbe", ".jar")
_TRAVERSAL = re.compile(r"(^/|\.\./|^[a-zA-Z]:)")


def _zip(t):
    out = []
    try:
        # disk file: EOCD lives at the end, beyond the 64MB raw cap on big archives
        zf = zipfile.ZipFile(t.path)
        infos = zf.infolist()
    except Exception:
        try:  # fall back to the raw prefix (mem/incomplete copies)
            zf = zipfile.ZipFile(io.BytesIO(t.raw))
            infos = zf.infolist()
        except Exception as e:
            return [Finding("STRUCT?", f"zip unreadable: {type(e).__name__}")]
    exes, scripts, nested, encrypted, bombs, seen_kinds = [], [], [], [], [], []
    for info in infos:
        name = info.filename.replace("\\", "/")
        low = name.lower()
        if _TRAVERSAL.search(name):
            out.append(Finding("ARCH!", f"traversal member name: {name[:80]}", CRITICAL))
        if (info.external_attr >> 16) & 0xF000 == 0xA000:
            out.append(Finding("ARCH?", f"symlink member: {name[:60]}"))
        if info.flag_bits & 0x1:
            encrypted.append(name)
        if info.compress_size and info.file_size / info.compress_size > 100:
            bombs.append(name)
        if low.endswith((".exe", ".dll", ".scr", ".jar")):
            exes.append(name)
        elif low.endswith(_MEMBER_HEAD_EXTS):
            scripts.append(name)
        elif low.endswith((".zip", ".7z", ".rar", ".gz")):
            nested.append(name)
        # head-sniff every member (capped): catches hidden binaries behind any ext
        if len(infos) <= 128:
            try:
                with zf.open(info) as f:  # lazy: reads only the needed chunk
                    head = f.read(512)
            except Exception:
                head = b""
            if head[:2] == b"MZ":       # MZ head: PE or DOS image either way
                seen_kinds.append((name, "PE"))
            elif head[:4] == b"\x7fELF":
                seen_kinds.append((name, "ELF"))
            elif head[:4] == b"#@~^":
                seen_kinds.append((name, "encoded script"))
        elif low.endswith((".zip", ".7z", ".rar", ".gz")):
            nested.append(name)
    if any(i.filename == "[Content_Types].xml" for i in infos):
        out += _ooxml(zf, infos)  # members triaged, oleObject MZ heads already caught above
    if exes:
        out.append(Finding("NOTE", f"zip contains {len(exes)} exe/dll member(s): "
                                  f"{', '.join(exes[:5])}{'...' if len(exes) > 5 else ''}"))
    if scripts:
        out.append(Finding("ARCH?", f"zip contains script member(s): {', '.join(scripts[:5])}"))
    _ok_exec_exts = ("exe", "dll", "scr", "jar", "ocx", "cpl", "sys")
    for name, kind in seen_kinds:
        ext = name.rsplit(".", 1)[-1].lower()
        if kind == "PE" and ext not in _ok_exec_exts:
            out.append(Finding("ARCH!", f"member '{name[:60]}' is a PE hidden behind .{ext}", CRITICAL))
        elif kind == "encoded script":
            out.append(Finding("ARCH!", f"member '{name[:60]}' is an encoded script", CRITICAL))
        elif ext not in _ok_exec_exts:
            out.append(Finding("NOTE", f"member '{name[:60]}' head-sniff: {kind}"))
    if nested:
        out.append(Finding("NOTE", f"nested archive member(s): {', '.join(nested[:3])}"))
    if encrypted:
        out.append(Finding("ARCH?", f"{len(encrypted)} password-protected member(s)"))
    if bombs:
        out.append(Finding("ARCH?", f"high compression ratio member(s) (bomb?): {', '.join(bombs[:3])}"))
    return out


_OTHER = {"SEVENZ": "7z", "RAR": "rar", "GZIP": "gzip", "XZ": "xz", "BZIP2": "bzip2",
          "CAB": "cab", "RPM": "rpm", "AR": "ar", "SQUASHFS": "squashfs",
          "TAR": "tar", "ISO": "iso"}


def _member_head(zf, name, n=2048):
    """-> first n bytes of a member, or b'' (never raises)."""
    try:
        with zf.open(name) as f:
            return f.read(n)
    except Exception:
        return b""


def _ooxml(zf, infos):
    """OOXML (docx/xlsx/...) maldoc markers - head-sniff only, no full inflate."""
    out = []
    names = [i.filename.replace("\\", "/") for i in infos]
    has_vba = any(n.lower().endswith("vbaproject.bin") for n in names)
    if has_vba:
        out.append(Finding("DOC?", "VBA project in OOXML container (macro-enabled document)"))
    settings = _member_head(zf, "word/settings.xml", 4096)
    update_fields = b"w:updateFields" in settings and b'"false"' not in settings.split(b"w:updateFields")[0][-16:]
    if has_vba and update_fields:
        out.append(Finding("DOC!", "VBA project + w:updateFields (forces macro re-run on open)",
                           CRITICAL))
    elif update_fields:
        out.append(Finding("DOC?", "w:updateFields set (field/macro update on open)"))
    # external relationships: file:// targets and package-level http targets are
    # object/template launches; plain hyperlink rels are stock in every real docx
    for n in names:
        low = n.lower()
        if not (low.endswith(".rels") and ("/_rels/" in low or low.startswith("_rels/"))):
            continue
        d = _member_head(zf, n, 4096)
        if b'TargetMode="External"' not in d:
            continue
        if b'Target="file:' in d:
            out.append(Finding("DOC!", f"external file:// relationship target in {n[-40:]}",
                               CRITICAL))
        elif b'Target="http' in d and (n == "_rels/.rels" or b"attachedTemplate" in d):
            out.append(Finding("DOC!", f"external http relationship in {n[-40:]} "
                                       "(package/template-level launch)", CRITICAL))
    doc = _member_head(zf, "word/document.xml", 16384)
    if b"DDEAUTO" in doc or (b"DDE" in doc and b"instrText" in doc):
        out.append(Finding("DOC!", "DDE/DDEAUTO field in word/document.xml (code execution via field)",
                           CRITICAL))
    return out


def run(t):
    if not t.raw:
        return []
    if t.kind == "ZIP":
        return _zip(t)
    label = _OTHER.get(t.kind)
    if label:
        return [Finding("NOTE", f"{label} container - members not listed (no stdlib parser); "
                               "extract then re-scan for member triage")]
    return []
