"""Raw-bytes heuristics for ANY file kind: embedded executables (validated),
embedded container magics in text-ish files, base64/hex mammoths, unexplained
high entropy, compressed-stream probing, stealer-family escalation."""
import bz2
import lzma
import re
import struct
import zlib

from ..model import Finding, CRITICAL
from .sections import shannon

# kinds where embedded-binary hits are structural (members/segments), not findings
_SKIP = {"ZIP", "SEVENZ", "RAR", "GZIP", "XZ", "BZIP2", "MACHO", "EMPTY", "MEDIA",
         "CAB", "RPM", "AR", "SQUASHFS", "TAR", "ISO"}  # members are structural, not findings
_TEXTISH = {"SCRIPT", "TEXT", "LNK", "PDF", "OLE", "RTF"}
B64_RE = re.compile(rb"[A-Za-z0-9+/]{4096,}")
HEX_RE = re.compile(rb"[0-9a-fA-F]{8192,}")
STEALER_FAMS = (rb"AppData\\Roaming\\discord", rb"AppData\\Roaming\\telegram",
                rb"Login Data", rb"Local State", rb"wallet\.dat", rb"[Mm]etamask",
                rb"[Ee]xodus", rb"[Ee]lectrum", rb"[Kk]eystore", rb"BraveSoftware")


def _valid_pe_at(raw, off):
    """>> True if offset points at a plausible PE: MZ, sane e_lfanew, PE\\0\\0."""
    if off + 0x40 > len(raw):
        return False
    try:
        lfa = struct.unpack_from("<I", raw, off + 0x3C)[0]
    except struct.error:
        return False
    if not (0 < lfa < 0x1000) or off + lfa + 4 > len(raw):
        return False
    return raw[off + lfa:off + lfa + 4] == b"PE\x00\x00"


def _valid_elf_at(raw, off):
    if off + 6 > len(raw):
        return False
    return raw[off + 4] in (1, 2) and raw[off + 5] in (1, 2)  # class, data


def _scan_execs(t):
    """-> (pe offsets, elf offsets) of validated embedded binaries (self at 0 excluded)."""
    raw = t.raw
    pes, elfs = [], []
    i = 0
    while True:
        i = raw.find(b"MZ", i)
        if i < 0:
            break
        if _valid_pe_at(raw, i) and not (i == 0 and t.kind == "PE"):
            pes.append(i)
        i += 2
    i = 0
    while True:
        i = raw.find(b"\x7fELF", i)
        if i < 0:
            break
        if _valid_elf_at(raw, i) and not (i == 0 and t.kind == "ELF"):
            elfs.append(i)
        i += 4
    return pes, elfs


_STREAM_CAP = 64 << 20     # ponytail: scan window; raise for dump-like inputs
_FEED = 256 << 10          # bytes fed per decompression attempt
_MIN_OUT = 512             # smaller successful inflates are noise, not signal
_MAX_TRIES = 512           # decompression attempts per codec (FP-offset budget)


def _try_stream(codec, blob):
    """-> (produced, output head) on successful decompression, else None.
    Validation IS the decompression - magic bytes only nominate candidates."""
    try:
        if codec == "zlib/gzip":
            out = zlib.decompressobj(wbits=47).decompress(blob)  # auto zlib|gzip
        elif codec == "xz":
            out = lzma.LZMADecompressor(format=lzma.FORMAT_AUTO).decompress(blob)
        else:
            out = bz2.BZ2Decompressor().decompress(blob)
    except Exception:
        return None
    if len(out) < _MIN_OUT:
        return None
    return out


def _candidates(raw, codec):
    """-> offsets of plausible stream starts (magic only nominates; decompression gates)."""
    out, i, tries = [], 0, 0
    if codec == "zlib/gzip":
        while len(out) < _MAX_TRIES:
            g = raw.find(b"\x1f\x8b\x08", i)
            z = raw.find(b"\x78", i)
            if g == -1 and z == -1:
                break
            if z == -1 or (g != -1 and g < z):
                out.append(g)
                i = g + 3
            elif z + 1 < len(raw) and ((raw[z] << 8) | raw[z + 1]) % 31 == 0:
                out.append(z)  # CMF/FLG checksum-valid zlib header
                i = z + 2
            else:
                i = z + 1
    elif codec == "xz":
        while len(out) < _MAX_TRIES:
            i = raw.find(b"\xfd7zXZ\x00", i)
            if i < 0:
                break
            out.append(i)
            i += 6
    else:
        while len(out) < _MAX_TRIES:
            i = raw.find(b"BZh", i)
            if i < 0 or i + 3 >= len(raw):
                break
            if 0x31 <= raw[i + 3] <= 0x39:
                out.append(i)
            i += 3
    return out


def _prober(t):
    """DATA/TEXTISH kinds: find really-decompresses streams, sniff the output."""
    raw = t.raw[:_STREAM_CAP]
    if len(raw) < 2048:
        return []
    out, hits = [], 0
    for codec in ("zlib/gzip", "xz", "bzip2"):
        for off in _candidates(raw, codec):
            got = _try_stream(codec, raw[off:off + _FEED])
            if got is None:
                continue
            hits += 1
            what = None
            if got[:2] == b"MZ" and _valid_pe_at(got, 0):
                what = "a PE executable"
            elif got[:4] == b"\x7fELF" and _valid_elf_at(got, 0):
                what = "an ELF executable"
            elif got[:2] == b"#!":
                what = "a script (#!)"
            detail = f"{codec} stream at offset {off:#x}: {len(raw[off:off + _FEED]):,}B fed -> {len(got):,}B"
            if what:
                out.append(Finding("EMBED", f"decompressed payload contains {what} "
                                            f"({detail})", CRITICAL))
            else:
                out.append(Finding("OBF", f"decompressible {detail} "
                                          "(embedded compressed blob?)"))
            if hits >= 3:
                return out  # one confirmation is signal, five is noise
    return out


def run(t):
    if not t.raw or t.kind in _SKIP:
        return []
    out = []
    if t.kind == "DOS":
        out.append(Finding("STRUCT", "DOS/legacy MZ image (not PE) - triaged as raw bytes"))

    pes, elfs = _scan_execs(t)
    if pes or elfs:
        parts = []
        if pes:
            parts.append(f"PE at offset(s) {', '.join(hex(p) for p in pes[:4])}"
                         + (f" +{len(pes)-4} more" if len(pes) > 4 else ""))
        if elfs:
            parts.append(f"ELF at offset(s) {', '.join(hex(p) for p in elfs[:4])}")
        sev = CRITICAL if t.kind in _TEXTISH or t.kind in ("ELF", "DOS") else "note"
        out.append(Finding("EMBED", "embedded executable: " + "; ".join(parts)
                           + ("" if sev == CRITICAL else " (structural for this kind?)"), sev))

    n_fams = sum(1 for fam in STEALER_FAMS if re.search(fam, t.raw))
    if n_fams >= 3:
        out.append(Finding("STR!", f"{n_fams} distinct stealer-target families in one file "
                                    "(browser paths + wallets)", CRITICAL))

    if t.kind in _TEXTISH:
        if b"PK\x03\x04" in t.raw and b"PK\x05\x06" in t.raw[-70000:]:
            out.append(Finding("EMBED", "embedded zip archive in text-ish file (appended payload?)", CRITICAL))
        for magic, label in ((b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar")):
            if magic in t.raw[:65536]:
                out.append(Finding("EMBED", f"embedded {label} archive in text-ish file"))

        b64 = B64_RE.search(t.raw)
        hexm = HEX_RE.search(t.raw)
        if b64 or hexm:
            which = f"base64 ({len(b64.group()):,}B)" if b64 else f"hex ({len(hexm.group()):,}B)"
            # note for TEXT and .js bundles (long data-URIs are stock); critical otherwise
            sev = "note" if t.kind == "TEXT" or t.ext == ".js" else CRITICAL
            out.append(Finding("OBF", f"{which} mammoth run - encoded payload?", sev))

    # compressed-stream prober: "fake text/image with appended payload" pattern
    if t.kind == "DATA" or t.kind in _TEXTISH:
        out += _prober(t)

    # windowed entropy on unknown binaries (containers/execs legitimately compress)
    if t.kind == "DATA" and len(t.raw) > 32768:
        W, STEP = 65536, 16384
        windows = list(range(0, len(t.raw) - W + 1, STEP))
        hi = sum(1 for o in windows if shannon(t.raw[o:o + W]) > 7.2)
        if windows and hi / len(windows) > 0.6:
            out.append(Finding("MEM?", f"{100*hi//len(windows)}% of {len(t.raw):,}B at entropy>7.2 "
                                      "(encrypted/compressed blob without container magic)"))
    return out
