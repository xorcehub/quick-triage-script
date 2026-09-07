"""Section-level heuristics: entropy, W+X, packed exec sections."""
import math

from ..model import Finding, CRITICAL


def shannon(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


ENTROPY_CAP = 4 << 20  # sample cap: packed-vs-normal detection needs no more


def entropy_of(t, s):
    """Cached per-section entropy (sampled to ENTROPY_CAP bytes)."""
    key = id(s)
    cache = t.__dict__.setdefault("_entropy", {})
    if key not in cache:
        cache[key] = round(shannon(s.get_data()[:ENTROPY_CAP]), 4)
    return cache[key]


def section_table(t):
    """-> [(name, entropy, kb)] for the report."""
    rows = []
    if t.error or t.pe is None:
        return rows
    for s in t.pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        rows.append((name, round(entropy_of(t, s), 2), round(s.SizeOfRawData / 1024, 1)))
    return rows


def run(t):
    out = []
    if t.error or t.pe is None:
        return out
    for s in t.pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        e = entropy_of(t, s)
        kb = round(s.SizeOfRawData / 1024, 1)
        exec_ = bool(s.Characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
        if exec_ and (s.Characteristics & 0x80000000):  # IMAGE_SCN_MEM_WRITE
            out.append(Finding("EVADE?", f"section {name} is writable+executable"))
        if exec_ and e > 7.5 and kb > 10:
            out.append(Finding("PACKED?", f"executable section {name} entropy {round(e, 2)} (packed/shellcode?)", CRITICAL))
    return out
