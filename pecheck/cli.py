"""CLI: human + JSON output, exit codes (0 clean, 1 review, 2 error)."""
import argparse
import json
import os
import sys

from . import __version__
from .scan import scan_targets
from .model import CRITICAL

# REVIEW first, then errors, then unknown, then notes, then ok
_ORDER = {"REVIEW": 0, "error": 1, "unsigned/unknown": 2, "note": 3, "ok": 4}


def _vt(sha256):
    return f"https://www.virustotal.com/gui/file/{sha256}"


def print_report(r):
    print(f"\n=== {r.path}")
    if r.verdict == "error":
        print(f"  ERROR: {r.error}")
        return
    if r.duplicate_of:
        print(f"  byte-identical to {r.duplicate_of} (deduplicated)")
        return
    print(f"  kind={r.kind}  arch={r.arch or '-'}  size={r.size:,}  sha256={r.sha256[:16]}..."
          + (f"  imphash={r.imphash}" if r.imphash else ""))
    if r.motw:
        bits = [f"zone={r.motw.get('zone', '?')}"]
        if r.motw.get("host"):
            bits.append(f"from={r.motw['host'][:80]}")
        print("  motw: " + "  ".join(bits))
    if r.kind == "PE" or r.signed or r.sig:
        if r.sig:
            s, who = r.sig
            print(f"  signature: {s}" + (f" ({who})" if who not in ("-", "") else ""))
        elif r.weak_cert:
            orgs, notafter, _ = r.weak_cert
            extra = (f"; signer strings ~ {orgs}" if orgs else "") + \
                    (f"; notAfter {notafter}" if notafter else "")
            print(f"  signature: cert-table present (weak mode, validity NOT verified{extra})")
        else:
            print(f"  signature: {'cert-table present' if r.signed else 'unsigned'} (weak mode: validity NOT verified)")
    for name, e, kb in r.sections:
        marker = "  <-- HIGH (>7.5)" if e > 7.5 and kb > 10 else ""
        print(f"    section {name:12} entropy={e:5.2f} rawKB={kb}{marker}")
    if r.findings:
        seen = set()
        for f in sorted(r.findings, key=lambda f: (f.severity != CRITICAL, f.category, f.detail)):
            key = (f.category, f.detail)
            if key in seen:
                continue
            seen.add(key)
            print(f"  [{f.category}] {f.detail}")
    elif r.kind == "PE":
        print("  no suspicious imports")


def print_summary(result):
    reports = result.reports
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    review = [r for r in reports if r.verdict == "REVIEW"]
    errors = [r for r in reports if r.verdict == "error"]
    notes = [r for r in reports if r.verdict == "note"]
    signed_ok = [r for r in reports if r.verdict == "ok" and r.kind == "PE"]
    clean = [r for r in reports if r.verdict == "ok" and r.kind != "PE"]
    unknown = [r for r in reports if r.verdict == "unsigned/unknown"]

    if review:
        print("\n  !! REVIEW REQUIRED:")
        for r in review:
            print(f"  !! {r.path}")
            for f in r.findings:
                if f.severity == CRITICAL:
                    print(f"     [CRITICAL] {f.detail}")
            print(f"     vt: {_vt(r.sha256)}")
        print("\n  -> Check the VT links above before running anything.")

    if errors:
        print("\n  x  Unreadable / unparseable:")
        for r in errors:
            print(f"     {os.path.basename(r.path):45} {r.error}")

    if result.folders:
        print("\n  Folder rollup:")
        for f in result.folders:
            bits = [f"{f.total} file(s)"]
            if f.review:
                bits.append(f"{f.review} REVIEW")
            if f.error:
                bits.append(f"{f.error} error")
            if f.unknown:
                bits.append(f"{f.unknown} unsigned/unknown")
            if f.note:
                bits.append(f"{f.note} note")
            if f.ok:
                bits.append(f"{f.ok} ok")
            line = f"     {f.path}: {', '.join(bits)}"
            if f.top_categories:
                line += "  top: " + ", ".join(f"{c}x{n}" for c, n in f.top_categories)
            print(line)

    if signed_ok:
        print(f"\n  OK  {len(signed_ok)} signed PE(s), no critical imports:")
        for r in signed_ok:
            who = r.sig[1][:60] if r.sig else "cert-table present"
            print(f"     {os.path.basename(r.path):45} {who}")

    if clean:
        print(f"\n  OK  {len(clean)} non-PE file(s) clean ({len(notes)} with notes total)")

    if unknown:
        print("\n  i  Unsigned / signature not verified (not necessarily bad, just unproven):")
        for r in unknown:
            print(f"     {os.path.basename(r.path):45} vt: {_vt(r.sha256)}")

    downloads = [r for r in reports if r.motw and (r.motw.get("host") or r.motw.get("referrer"))]
    if downloads:
        print(f"\n  i  Download provenance (MOTW), {len(downloads)} file(s):")
        for r in downloads[:10]:
            src = r.motw.get("host") or r.motw.get("referrer") or "?"
            print(f"     {os.path.basename(r.path):40} {src[:70]}")
        if len(downloads) > 10:
            print(f"     ... +{len(downloads) - 10} more")

    if result.side_files:
        print("\n  i  Context files present (scene markers / MOTW artifacts):")
        for p in result.side_files[:10]:
            print(f"     {p}")
        if len(result.side_files) > 10:
            print(f"     ... +{len(result.side_files) - 10} more")

    print("\n  VERDICT: " + (
        f"REVIEW REQUIRED - {len(review)} file(s) flagged (see above)" if review
        else f"no critical findings: {len(signed_ok)} signed, {len(unknown)} unsigned/unknown, "
             f"{len(clean)} clean non-PE, {len(notes)} notes"))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pecheck", description="static triage for any binary: PE, ELF, scripts, archives, docs")
    ap.add_argument("targets", nargs="+", help="file or directory")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--no-sigs", action="store_true", help="skip WinVerifyTrust signature check")
    ap.add_argument("--quiet", action="store_true", help="summary only (suppresses per-file blocks and progress)")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass

    result = scan_targets(args.targets, use_sigs=not args.no_sigs)
    # human output reads best REVIEW-first; JSON keeps scan order
    ordered = sorted(result.reports, key=lambda r: (_ORDER.get(r.verdict, 9), r.path))
    n = len(result.reports)
    if args.json:
        payload = {
            "schema": "pecheck-report/1",
            "pecheck": __version__,
            "files": [r.to_dict() for r in result.reports],
            "folders": [f.__dict__ for f in result.folders],
            "side_files": result.side_files,
        }
        print(json.dumps(payload, indent=1))
    elif not args.quiet:
        for i, r in enumerate(ordered, 1):
            print(f"[{i}/{n}] {os.path.basename(r.path)}", file=sys.stderr)
            print_report(r)

    if not args.json:
        print_summary(result)

    has_error = any(r.verdict == "error" for r in result.reports) or n == 0
    has_review = any(r.verdict == "REVIEW" for r in result.reports)
    return 2 if has_error or n == 0 else (1 if has_review else 0)


if __name__ == "__main__":
    sys.exit(main())
