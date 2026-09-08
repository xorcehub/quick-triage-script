"""Pipeline: load -> detectors -> signature -> verdict -> rollup.
ALL detectors are PE-only (self-gated); GENERIC detectors run on every file
kind. Cross-file signals (duplicates, near-identical twins) run after the
per-file pass. Verdict logic lives in verdict.py."""
import os
from collections import defaultdict

from . import peparse
from .model import FileReport, Finding, ScanResult, CRITICAL
from .detectors import ALL, GENERIC
from .verdict import verdict as _verdict, downgrade as _downgrade, rollup as _rollup


def _scan_target(t, siblings, sig):
    r = FileReport(path=t.path, size=t.size, sha256=t.sha256, kind=t.kind,
                   arch=t.arch, error=t.error, motw=t.motw)
    if t.error and t.kind != "PE":
        r.verdict = "error"       # unreadable (OSError) - PE-parse errors fall through
        return r
    t.siblings = list(siblings)
    t.sig = sig
    pe = t.pe
    if t.error:  # pefile failed on an MZ file: forged/truncated - flag it
        sev = "note" if t.truncated else CRITICAL  # big-file cap, not malice
        r.findings.append(Finding("EVADE?", f"PE parse error on MZ image"
                                   + (" (analysis capped at 64MB)" if t.truncated else "")
                                   + f": {t.error}", sev))
    if pe is not None:
        try:
            r.signed = bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress)  # SECURITY dir
        except (IndexError, AttributeError):
            r.signed = False  # truncated NumberOfRvaAndSizes
        try:
            r.imphash = pe.get_imphash() or ""
        except Exception:
            r.imphash = ""

    for det in ALL + GENERIC:
        try:
            r.findings.extend(det.run(t))
        except Exception as e:
            r.findings.append(Finding("NOTE", f"{det.__name__} detector failed: {type(e).__name__}: {e}"))

    r.findings = _downgrade(r.findings)
    r.verdict = _verdict(t, r.findings, sig=sig, signed=r.signed)

    if pe is not None:
        from .detectors.sections import section_table
        r.sections = section_table(t)
        if not sig and r.signed:  # best-effort cert info when trust engine unavailable
            from .wintrust import weak_cert_info
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
    """-> ScanResult over all targets (dirs are walked; every file is scanned).
    Deduplicates identical files, flags near-identical twins (same size +
    TimeDateStamp, different bytes - PE only)."""
    targets, sibs, side = peparse.collect(paths)
    sigs = None
    if use_sigs:
        from .wintrust import sigs_via_wintrust
        sig_paths = [p for p in targets if p.lower().endswith(
            (".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl", ".mui"))]
        sigs = sigs_via_wintrust(sig_paths) if sig_paths else None
    reports, seen, meta = [], {}, {}
    for i, p in enumerate(targets):
        t = peparse.load(p)
        if t.sha256 and t.sha256 in seen:
            first = seen[t.sha256]
            rep = FileReport(path=t.path, size=t.size, sha256=t.sha256, kind=t.kind, arch=t.arch,
                             verdict=first.verdict, duplicate_of=first.path)
            rep.findings.append(Finding("NOTE", f"byte-identical to {os.path.basename(first.path)}"))
            reports.append(rep)
            continue
        rep = _scan_target(t, sibs.get(os.path.dirname(p), []),
                           sigs.get(os.path.normcase(p)) if sigs else None)
        seen[t.sha256] = rep
        if t.pe is not None:
            meta[t.path] = (t.size, t.pe.FILE_HEADER.TimeDateStamp, t.sha256)
        reports.append(rep)
    # near-identical twins: same size + same compile timestamp, different content
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
    return ScanResult(reports=reports, side_files=side, folders=_rollup(reports, side))
