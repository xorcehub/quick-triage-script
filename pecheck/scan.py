"""Pipeline: load -> detectors -> signature -> verdict. Cross-file signals
(duplicates, near-identical twins) run after the per-file pass."""
import os

from . import peparse
from .model import FileReport, Finding, ScanResult, CRITICAL
from .detectors import ALL
from .wintrust import sigs_via_wintrust, weak_cert_info


def _scan_target(t, siblings, sig):
    r = FileReport(path=t.path, size=t.size, sha256=t.sha256, arch=t.arch, error=t.error)
    if t.error:
        r.verdict = "error"
        return r
    t.siblings = list(siblings)
    pe = t.pe
    try:
        r.signed = bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress)  # SECURITY dir
    except (IndexError, AttributeError):
        r.signed = False  # truncated NumberOfRvaAndSizes
    for det in ALL:
        try:
            r.findings.extend(det.run(t))
        except Exception as e:
            r.findings.append(Finding("NOTE", f"{det.__name__} detector failed: {type(e).__name__}: {e}"))
    from .detectors.sections import section_table
    r.sections = section_table(t)

    crit = [f for f in r.findings if f.severity == CRITICAL]
    if sig:
        r.sig = tuple(sig)
        if crit or sig[0] == "HashMismatch":
            r.verdict = "REVIEW"
        else:
            r.verdict = "ok" if sig[0] == "Valid" else "unsigned/unknown"
    else:
        r.verdict = "REVIEW" if crit else ("ok" if r.signed else "unsigned/unknown")
        if r.signed:  # best-effort cert info when the trust engine is unavailable
            info = weak_cert_info(pe)
            if info:
                r.weak_cert = info
                if info[2]:  # expired
                    r.findings.append(Finding("PROV?", f"embedded certificate expired {info[1]}"))
    return r


def scan_file(path, sig=None):
    """Scan one file. sig: (status, signer) tuple from wintrust, or None."""
    t = peparse.load(path)
    return _scan_target(t, (), sig)


def scan_targets(paths, use_sigs=True):
    """-> ScanResult over all targets (dirs are walked). Deduplicates identical
    files, flags near-identical twins (same size + TimeDateStamp, different bytes)."""
    targets, sibs, side = peparse.collect(paths)
    sigs = sigs_via_wintrust(targets) if use_sigs else None
    reports, seen, meta = [], {}, {}
    for i, p in enumerate(targets):
        t = peparse.load(p)
        if t.sha256 and t.sha256 in seen:
            first = seen[t.sha256]
            rep = FileReport(path=t.path, size=t.size, sha256=t.sha256, arch=t.arch,
                             verdict=first.verdict, duplicate_of=first.path)
            rep.findings.append(Finding("NOTE", f"byte-identical to {os.path.basename(first.path)}"))
            reports.append(rep)
            continue
        rep = _scan_target(t, sibs.get(os.path.dirname(p), []),
                           sigs.get(os.path.normcase(p)) if sigs else None)
        seen[t.sha256] = rep
        meta[t.path] = (t.size, t.pe.FILE_HEADER.TimeDateStamp if t.pe else 0, t.sha256)
        reports.append(rep)
    # near-identical twins: same size + same compile timestamp, different content
    from collections import defaultdict
    groups = defaultdict(list)
    for p, (size, tds, sha) in meta.items():
        if size and tds:
            groups[(size, tds)].append((p, sha))
    for (size, tds), members in groups.items():
        if len(members) > 1 and len({m[1] for m in members}) > 1:
            for p, _ in members:
                other = next(n for n, _ in members if n != p)
                rep = next(r for r in reports if r.path == p)
                rep.findings.append(Finding(
                    "PROV?", f"near-duplicate of {os.path.basename(other)}: same size+TimeDateStamp, "
                             f"different bytes (patched/tampered twin?)"))
    return ScanResult(reports=reports, side_files=side)
