"""Load a PE once; every detector shares the same Target."""
import hashlib
import os

import pefile

_ARCH = {0x8664: "x64", 0x14C: "x86", 0xAA64: "ARM64"}


def load(path) -> "Target":  # noqa: F821 (model.Target)
    from .model import Target
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return Target(path=os.path.abspath(path), size=0, sha256="",
                      error=f"unreadable: {type(e).__name__}: {e}")
    h = hashlib.sha256(raw).hexdigest()
    t = Target(path=os.path.abspath(path), size=len(raw), sha256=h, raw=raw)
    try:
        t.pe = pefile.PE(data=raw, fast_load=False)
    except Exception as e:
        t.error = f"{type(e).__name__}: {e}"
        return t
    t.arch = _ARCH.get(t.pe.FILE_HEADER.Machine, hex(t.pe.FILE_HEADER.Machine))
    return t


def collect(root_paths):
    """Expand dirs/files into a target list (.exe/.dll walk) + fill sibling names."""
    targets = []
    for t in root_paths:
        if os.path.isdir(t):
            for dirpath, _, files in os.walk(t):
                for fn in files:
                    if fn.lower().endswith((".exe", ".dll")):
                        targets.append(os.path.join(dirpath, fn))
        else:
            targets.append(t)
    targets = sorted(set(os.path.abspath(p) for p in targets))
    sibs = {}
    for p in targets:
        sibs.setdefault(os.path.dirname(p), []).append(os.path.basename(p).lower())
    return targets, sibs
