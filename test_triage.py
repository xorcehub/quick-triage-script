#!/usr/bin/env python3
"""Self-check for the pecheck package.

Usage:
    python3 test_triage.py [sample_dir]

The sample dir (arg or $PECHECK_SAMPLES) is any directory of PEs to
triage - nothing about it is hardcoded. Without one, corpus assertions
are skipped and only the CLI/JSON contract is checked.
"""
import contextlib
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pecheck import scan_targets   # noqa: E402


def _samples():
    return sys.argv[1] if len(sys.argv) > 1 else os.environ.get("PECHECK_SAMPLES", "")


def check_samples(samples):
    assert os.path.isdir(samples), f"sample dir missing: {samples}"
    result = scan_targets([samples], use_sigs=False)
    reps = result.reports
    assert len(reps) >= 5, f"expected >=5 reports, got {len(reps)}"
    assert all(r.verdict != "error" for r in reps), "unexpected parse errors"
    review = {r.basename for r in reps if r.verdict == "REVIEW"}
    # signal-driven assertions (no hardcoded sample names)
    hijack = [r for r in reps if any("SetThreadContext" in f.detail for f in r.findings)]
    assert hijack and all(r.verdict == "REVIEW" for r in hijack), "thread-hijack import not escalated"
    twins = [r for r in reps if any("near-duplicate" in f.detail for f in r.findings)]
    assert twins, "twin detection found nothing"
    sideload = [r for r in reps if any("sideload" in f.detail for f in r.findings)]
    assert sideload and all(r.verdict == "REVIEW" for r in sideload), "sideload name missed"
    future = [r for r in reps if any("TimeDateStamp in the future" in f.detail for f in r.findings)]
    assert future, "future-timestamp check found nothing"
    print(f"samples: {len(reps)} files, {len(review)} REVIEW, hijack+twins+sideload+ts OK")


def check_cli(samples):
    from pecheck.cli import main
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main([samples, "--json", "--no-sigs"])
    payload = json.loads(out.getvalue())
    assert payload["schema"] == "pecheck-report/1"
    assert payload["pecheck"] and payload["files"]
    f0 = payload["files"][0]
    for k in ("path", "size", "sha256", "verdict", "findings", "sections"):
        assert k in f0, f"json missing {k}"
    assert all("severity" in f for r in payload["files"] for f in r["findings"])
    assert code in (0, 1, 2)
    print(f"cli/json: schema stable, exit={code}")


if __name__ == "__main__":
    samples = _samples()
    if samples and os.path.isdir(samples):
        check_samples(samples)
        check_cli(samples)
    else:
        print("no sample dir given (arg or $PECHECK_SAMPLES): corpus assertions skipped")
    print("ALL OK")
