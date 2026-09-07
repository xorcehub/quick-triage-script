"""Pipeline: load -> detectors -> signature -> verdict."""
import os

from . import peparse
from .model import FileReport, Finding, CRITICAL
from .detectors import ALL
from .wintrust import sigs_via_wintrust


def scan_file(path, siblings=(), sigs=None):
    """-> FileReport. sigs: precomputed {path: (status, signer)} or None (skips/weak)."""
    t = peparse.load(path)
    t.siblings = list(siblings)
    r = FileReport(path=t.path, size=t.size, sha256=t.sha256, arch=t.arch, error=t.error)
    if t.error:
        r.verdict = "unsigned/unknown"
        return r
    pe = t.pe
    r.signed = bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress)  # SECURITY dir
    for det in ALL:
        try:
            r.findings.extend(det.run(t))
        except Exception as e:
            r.findings.append(Finding("NOTE", f"{det.__name__} detector failed: {type(e).__name__}: {e}"))
    from .detectors.sections import section_table
    r.sections = section_table(t)
    # signature verdict
    sig = sigs.get(os.path.normcase(r.path)) if sigs else None
    r.sig = sig
    crit = [f for f in r.findings if f.severity == CRITICAL]
    if sig:
        if crit or sig[0] == "HashMismatch":
            r.verdict = "REVIEW"
        else:
            r.verdict = "ok" if sig[0] == "Valid" else "unsigned/unknown"
    else:
        r.verdict = "REVIEW" if crit else ("ok" if r.signed else "unsigned/unknown")
    return r


def scan_targets(paths, sigs=None, use_sigs=True):
    """-> (targets, sibmap, reports). Signature check batched over all targets."""
    targets, sibs = peparse.collect(paths)
    if use_sigs and sigs is None:
        sigs = sigs_via_wintrust(targets)
    reports = [scan_file(p, siblings=sibs.get(os.path.dirname(p), []), sigs=sigs or {})
               for p in targets]
    return targets, sibs, reports
