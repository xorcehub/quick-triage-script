"""CLI: human + JSON output."""
import argparse
import json
import os
import sys

from .scan import scan_targets


def print_report(r):
    print(f"\n=== {r.path}")
    if r.error:
        print(f"  ERROR: {r.error}")
        return
    print(f"  arch={r.arch}  size={r.size:,}  sha256={r.sha256[:16]}...")
    if r.sig:
        s, who = r.sig
        print(f"  signature: {s}" + (f" ({who})" if who not in ("-", "") else ""))
    else:
        print(f"  signature: {'cert-table present' if r.signed else 'unsigned'} (weak mode: validity NOT verified)")
    for name, e, kb in r.sections:
        marker = "  <-- HIGH (>7.5)" if e > 7.5 and kb > 10 else ""
        print(f"    section {name:12} entropy={e:5.2f} rawKB={kb}{marker}")
    if r.findings:
        seen = set()
        for f in r.findings:
            key = (f.category, f.detail)
            if key in seen:
                continue
            seen.add(key)
            print(f"  [{f.category}] {f.detail}")
    else:
        print("  no suspicious imports")


def print_summary(reports, strong):
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    review = [r for r in reports if r.verdict == "REVIEW"]
    signed_ok = [r for r in reports if r.verdict == "ok"]
    unknown = [r for r in reports if r.verdict == "unsigned/unknown"]

    if review:
        print("\n  !! REVIEW REQUIRED:")
        for r in review:
            print(f"  !! {r.path}")
            for c in r.crit:
                print(f"     [CRITICAL] {c}")
        print("\n  -> Upload these files (or their SHA256) to virustotal.com before running anything.")

    if signed_ok:
        lbl = "validly signed" if strong else "with cert table (validity NOT verified)"
        print(f"\n  OK  {len(signed_ok)} {lbl}, no critical imports:")
        for r in signed_ok:
            who = r.sig[1][:60] if r.sig else "cert-table present"
            print(f"     {os.path.basename(r.path):45} {who}")

    if unknown:
        print("\n  i  Unsigned / signature not verified (not necessarily bad, just unproven):")
        for r in unknown:
            print(f"     {os.path.basename(r.path):45} sha256={r.sha256[:16]}...")
        print("  i  Verify these on VirusTotal before running, if unsure.")

    print("\n  VERDICT: " + (
        f"REVIEW REQUIRED - {len(review)} file(s) flagged (see above)" if review
        else f"no critical findings: {len(signed_ok)} signed, {len(unknown)} unsigned/unknown"))


def main(argv=None):
    ap = argparse.ArgumentParser(description="static PE triage")
    ap.add_argument("targets", nargs="+", help="file or directory")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--no-sigs", action="store_true", help="skip WinVerifyTrust signature check")
    args = ap.parse_args(argv)

    _, _, reports = scan_targets(args.targets, use_sigs=not args.no_sigs)
    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=1))
        return 0
    for r in reports:
        print_report(r)
    strong = any(r.sig for r in reports)
    print_summary(reports, strong)
    return 0


if __name__ == "__main__":
    sys.exit(main())
