"""--unpack: recursive extraction into temp dirs, then re-scan children.
stdlib zipfile covers the common ZIP case with zero dependencies; 7z (any
variant on PATH) handles 7z/rar/cab/iso/ar/tar/gzip/xz/bzip2/rpm/squashfs and
installer EXEs (NSIS/Inno/SFX). Caps are enforced BEFORE extraction; extracted
paths are verified to stay inside our temp root (zip-slip belt & braces)."""
import os
import shutil
import subprocess
import tempfile
import zipfile

CAP_BYTES = 1 << 30    # ponytail: raise for game-ISO workflows
CAP_ENTRIES = 20000
TIMEOUT = 120

EXTRACTABLE = {"ZIP", "SEVENZ", "RAR", "CAB", "ISO", "AR", "GZIP", "XZ", "BZIP2",
               "TAR", "SQUASHFS", "RPM"}


def sevenz_bin():
    for b in ("7z", "7za", "7zr"):
        w = shutil.which(b)
        if w:
            return w
    return None


def _verify_inside(root):
    """Zip-slip guard: delete anything that resolves outside the temp root."""
    rootr = os.path.realpath(root)
    for dirpath, _, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            try:
                if os.path.commonpath([rootr, os.path.realpath(p)]) != rootr:
                    os.remove(p)
            except OSError:
                pass


def _caps_zip(zf):
    infos = zf.infolist()
    return len(infos), sum(i.file_size for i in infos)


def _list_7z(bin_, path):
    """-> (entries, total_size) from `7z l -slt -ba`, or None if not extractable."""
    try:
        r = subprocess.run([bin_, "l", "-slt", "-ba", "--", path],
                           capture_output=True, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    n = total = 0
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("Size = "):
            v = line[7:].strip()
            if v.isdigit():
                total += int(v)
                n += 1
    if n == 0:  # -slt blocks always carry a Size line; nothing listed = fail
        return None
    return n, total


def _extract_zip(path, dest):
    with zipfile.ZipFile(path) as zf:
        n, total = _caps_zip(zf)
        if n > CAP_ENTRIES or total > CAP_BYTES:
            return False
        for info in zf.infolist():
            zf.extract(info, dest)  # zipfile sanitizes names; realpath check below
    return True


def _extract_7z(path, dest):
    bin_ = sevenz_bin()
    if not bin_:
        return False
    got = _list_7z(bin_, path)
    if got is None:
        return False
    n, total = got
    if n > CAP_ENTRIES or total > CAP_BYTES:
        return False
    try:
        r = subprocess.run([bin_, "x", "-y", "-o" + dest, "--", path],
                           capture_output=True, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def extract(path, kind):
    """-> extracted temp dir, or None (unsupported / caps / extractor absent /
    not actually a container). Caller owns cleanup (shutil.rmtree)."""
    if kind not in EXTRACTABLE and kind != "PE":  # PE: let 7z try installers/SFX
        return None
    dest = tempfile.mkdtemp(prefix="pecheck_unpack_")
    try:
        ok = _extract_zip(path, dest) if kind == "ZIP" else _extract_7z(path, dest)
        if not ok:
            shutil.rmtree(dest, ignore_errors=True)
            return None
        _verify_inside(dest)
        with os.scandir(dest) as it:  # empty extraction = nothing to re-scan
            if not any(it):
                shutil.rmtree(dest, ignore_errors=True)
                return None
        return dest
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        return None


def find_targets(root):
    """-> ([paths], sibling map) under an extracted tree (same shape as collect)."""
    targets = []
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if ":" in fn and os.name == "nt":
                continue
            targets.append(os.path.join(dirpath, fn))
    sibs = {}
    for p in targets:
        sibs.setdefault(os.path.dirname(p), []).append(os.path.basename(p).lower())
    return targets, sibs
