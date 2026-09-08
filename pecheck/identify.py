"""File-kind identification by magic bytes + extension. One function: kind().
Zero-offset magic wins; PDF/RTF may carry a small prefix (checked in first 1KB).
Everything unrecognized falls to DATA (unknown binary) or SCRIPT/TEXT via ext.
Kinds: PE, DOS, ELF, MACHO, ZIP, SEVENZ, RAR, GZIP, XZ, BZIP2, OLE, RTF, PDF,
LNK, SCRIPT, TEXT, MEDIA, DATA, EMPTY, CAB, RPM, AR, SQUASHFS, TAR, ISO.
peparse passes a >=0x8808 head so the ISO PVD at 0x8001 is reachable."""
import os
import struct

# magic at offset 0 -> kind. Longest match first where prefixes overlap.
MAGICS = (
    (b"MZ", "PE"),                       # confirmed PE below, else DOS
    (b"\x7fELF", "ELF"),
    (b"\xcf\xfa\xed\xfe", "MACHO"),
    (b"\xfe\xed\xfa\xcf", "MACHO"),     # 64-bit big-endian
    (b"\xca\xfe\xba\xbe", "MACHO"),
    (b"\xfe\xed\xfa\xce", "MACHO"),
    (b"\xce\xfa\xed\xfe", "MACHO"),
    (b"PK\x03\x04", "ZIP"),
    (b"PK\x05\x06", "ZIP"),              # empty zip (EOCD only)
    (b"PK\x07\x08", "ZIP"),              # spanned
    (b"7z\xbc\xaf\x27\x1c", "SEVENZ"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"\x1f\x8b", "GZIP"),
    (b"\xfd7zXZ\x00", "XZ"),
    (b"BZh", "BZIP2"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE"),
    (b"%PDF-", "PDF"),
    (b"{\\rtf", "RTF"),
    (b"\x4c\x00\x00\x00", "LNK"),        # L + zero HeaderSize
    (b" #@~^", "SCRIPT"),                # encoded VBE/JSE (often BOM-prefixed)
    (b"#@~^", "SCRIPT"),
    (b"\x89PNG", "MEDIA"),
    (b"\xff\xd8\xff", "MEDIA"),
    (b"GIF8", "MEDIA"),
    (b"BM", "MEDIA"),
    (b"DDS ", "MEDIA"),
    (b"OggS", "MEDIA"),
    (b"RIFF", "MEDIA"),
    (b"ID3", "MEDIA"),
    (b"\xff\xfb", "MEDIA"),
    (b"\xff\xf3", "MEDIA"),
    (b"\x1aE\xdf\xa3", "MEDIA"),
    (b"MSCF", "CAB"),                    # MS cabinet (MSU packages, cracked-game installers)
    (b"\xed\xab\xee\xdb", "RPM"),
    (b"!<arch>\n", "AR"),               # .deb / .pkg ar archives
    (b"hsqs", "SQUASHFS"),
)

# fixed-offset magics (checked separately: offset != 0)
_FIXED = ((257, b"ustar", "TAR"),        # ustar magic inside the tar header block
          (0x8001, b"CD001", "ISO"))     # ISO9660 primary volume descriptor

# magic that may sit anywhere in the first 1KB (formats allowing a prefix)
_PREFIX_OK = (b"%PDF-", b"{\\rtf")

SCRIPT_EXTS = (".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
               ".hta", ".reg", ".sh", ".py", ".url")
TEXT_EXTS = (".txt", ".nfo", ".diz", ".ini", ".cfg", ".json", ".xml", ".html",
             ".htm", ".csv", ".log", ".md")


def kind(path, head=None):
    """-> kind string. head: first bytes of the file if already read."""
    if head is None:
        try:
            with open(path, "rb") as f:
                head = f.read(0x8808)  # >= ISO PVD offset; text/prefix checks cap themselves
        except OSError:
            return "DATA"
    if not head:
        return "EMPTY"
    for magic, k in MAGICS:
        if head.startswith(magic):
            if k == "PE" and not _has_pe_sig(path, head):
                return "DOS"
            return k
    for off, magic, k in _FIXED:
        if head[off:off + len(magic)] == magic:
            return k
    for magic in _PREFIX_OK:  # junk-prefixed PDF/RTF: magic within first 1KB
        i = head.find(magic, 1, 1024)
        if i > 0:
            return "PDF" if magic == b"%PDF-" else "RTF"
    ext = os.path.splitext(path)[1].lower()
    if ext in SCRIPT_EXTS:
        return "SCRIPT"
    if _looks_text(head):
        return "TEXT" if ext not in (".exe", ".dll", ".scr") else "DATA"
    return "DATA"


def _has_pe_sig(path, head):
    """True if the MZ file has a PE\\0\\0 signature at e_lfanew."""
    if len(head) < 0x40:
        return False
    try:
        off = struct.unpack_from("<I", head, 0x3C)[0]
    except struct.error:
        return False
    if not (0 < off < 0x1000):
        return False
    if off + 4 <= len(head):
        return head[off:off + 4] == b"PE\x00\x00"
    # signature beyond the head we have: read it from disk
    try:
        with open(path, "rb") as f:
            f.seek(off)
            return f.read(4) == b"PE\x00\x00"
    except OSError:
        return False


def _looks_text(head):
    """>=90% printable/whitespace (or UTF-16LE: printable + NUL padding) -> text."""
    if not head:
        return False
    n = min(len(head), 4096)
    printable = sum(1 for b in head[:n] if 0x20 <= b < 0x7f or b in (9, 10, 13))
    ratio = printable / n
    if ratio >= 0.9:
        return True
    # utf-16le: half the bytes are NUL, the rest printable ascii
    nulls = sum(1 for b in head[:n] if b == 0)
    return ratio >= 0.35 and (printable + nulls) / n >= 0.9
