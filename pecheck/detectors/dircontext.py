"""Directory-level context: future-dated headers and loaders referencing
sibling PEs. Cross-file signals (twins, duplicates) live in scan.py which
sees all targets."""
import os
import time

from ..model import Finding


def run(t):
    if t.error or t.pe is None:
        return []
    pe = t.pe
    out = []

    # future-dated TimeDateStamp (repacked/forged headers; old stamps are never flagged)
    tds = pe.FILE_HEADER.TimeDateStamp
    if tds and tds > time.time() + 86400:
        out.append(Finding("EVADE?", f"TimeDateStamp in the future "
                                     f"({time.strftime('%Y-%m-%d', time.gmtime(tds))}) - forged/obfuscated header"))

    # small-ish EXE that names a sibling EXE (full name or distinctive stem)
    if not (pe.FILE_HEADER.Characteristics & 0x2000):  # not a DLL
        for sib in t.siblings:
            if sib == os.path.basename(t.path).lower() or not sib.endswith(".exe"):
                continue
            stem = sib[:-4]
            if len(stem) < 6:
                continue  # short stems FP
            if sib.encode() in t.raw[:1 << 20] or stem.encode() in t.raw[:1 << 20] \
                    or sib.encode("utf-16le") in t.raw[:1 << 20]:
                out.append(Finding("LOADER?", f"references sibling PE '{sib}' (launcher/proxy/loader?)"))
                break
    return out
