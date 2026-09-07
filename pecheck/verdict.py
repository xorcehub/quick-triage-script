"""Verdict computation, decoupled from signature checking.
REVIEW | note | ok | unsigned/unknown | error. Folder rollup lives here too."""
from collections import Counter

from .model import FileReport, FolderRollup, CRITICAL

_ORDER = ("REVIEW", "error", "unsigned/unknown", "note", "ok")


def verdict(t, findings, sig=None, signed=False, weak_cert=None):
    """>> verdict string for one target.
    sig: (status, signer) from wintrust or None. signed: cert-table present."""
    crit = [f for f in findings if f.severity == CRITICAL]
    if t.kind == "PE" and t.error:
        # MZ file claiming PE that pefile cannot parse: forged/truncated
        return "REVIEW"
    if t.kind != "PE":
        return "REVIEW" if crit else ("note" if findings else "ok")
    if sig:
        if crit or sig[0] == "HashMismatch":
            return "REVIEW"
        return "ok" if sig[0] == "Valid" else "unsigned/unknown"
    if crit:
        return "REVIEW"
    return "ok" if signed else "unsigned/unknown"


def downgrade(findings):
    """Apply context downgrades: steam-emu CONTEXT downgrades SIDELOAD? crits."""
    has_emu = any(f.category == "CONTEXT" and "verdict downgraded" in f.detail for f in findings)
    if not has_emu:
        return findings
    out = []
    for f in findings:
        if f.category == "SIDELOAD?" and f.severity == CRITICAL:
            f = type(f)(f.category, f.detail + " [downgraded: steam-emu context]", "note")
        out.append(f)
    return out


def rollup(reports, side_files=()):
    """>> [FolderRollup] for every directory directly containing scanned files."""
    groups = {}
    for r in reports:
        if r.duplicate_of:  # don't count byte-identical copies twice
            continue
        import os.path
        groups.setdefault(os.path.dirname(r.path) or ".", []).append(r)
    out = []
    for path in sorted(groups):
        rs = groups[path]
        counts = Counter(r.verdict for r in rs)
        cats = Counter(f.category for r in rs for f in r.findings)
        top = sorted(cats.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
        out.append(FolderRollup(
            path=path, total=len(rs), review=counts["REVIEW"], note=counts["note"],
            ok=counts["ok"], unknown=counts["unsigned/unknown"], error=counts["error"],
            top_categories=top))
    return out
