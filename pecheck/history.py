"""Local scan history: sha256 -> {first_seen, last_seen, last_verdict, last_paths}.
JSON sidecar in the state dir (env override PECHECK_HISTORY). Never fails a
scan for bookkeeping: corrupt/missing file starts fresh, save errors are
swallowed. Turns 'unsigned unknown' into 'first seen today, never clean' and
remembers previously-flagged hashes on re-scans."""
import json
import os
import time

from .model import Finding


def default_path():
    return os.environ.get("PECHECK_HISTORY") or os.path.join(
        os.path.expanduser("~"), ".config", "pecheck", "history.json")


def load(path=None):
    try:
        with open(path or default_path()) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def record(reports, path=None):
    """Annotate reports in place (first-seen-today, previously-flagged) and
    -> updated cache dict (caller saves)."""
    cache = load(path)
    today = time.strftime("%Y-%m-%d")
    for r in reports:
        if not r.sha256 or r.duplicate_of or r.verdict == "error":
            continue
        e = cache.get(r.sha256)
        if e is None:
            cache[r.sha256] = {"first_seen": today, "last_seen": today,
                               "last_verdict": r.verdict, "last_paths": [r.basename]}
            continue
        if e.get("last_verdict") == "REVIEW" and r.verdict != "REVIEW":
            r.findings.append(Finding("PROV?", f"previously flagged REVIEW on "
                                               f"{e.get('last_seen', '?')} (same sha256)"))
        if e.get("first_seen") == today and r.verdict == "unsigned/unknown":
            r.findings.append(Finding("PROV?", "first seen today - no history of this hash "
                                               "ever being clean"))
        e["last_seen"] = today
        e["last_verdict"] = r.verdict
        paths = e.get("last_paths", [])
        if r.basename not in paths:
            paths = (paths + [r.basename])[-4:]
        e["last_paths"] = paths
    return cache


def save(cache, path=None):
    p = path or default_path()
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cache, f)
        os.replace(tmp, p)
    except OSError:
        pass
