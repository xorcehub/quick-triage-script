"""Sideload-prone DLL names shipped next to an EXE + export-proxy pattern
(mostly-forwarded exports + a few own exports = classic sideload shell)."""
import os

from ..model import Finding, CRITICAL

SIDLOAD_NAMES = {
    "version.dll", "winmm.dll", "dxgi.dll", "d3d9.dll", "d3d11.dll", "d3d12.dll",
    "dinput8.dll", "xinput1_3.dll", "xinput1_4.dll", "dbghelp.dll", "dbgcore.dll",
    "cryptbase.dll", "profapi.dll", "responderhelper.dll", "wlidprov.dll",
}


def _forward_stats(pe):
    """-> (total, forwarded, {target dll}, own_exports) from the export table."""
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp is None:
        return 0, 0, set(), 0
    total = forwarded = 0
    targets = set()
    own = 0
    for s in exp.symbols:
        if s.forwarder is not None:
            forwarded += 1
            try:
                targets.add(s.forwarder.decode(errors="replace").split(".", 1)[0].lower())
            except Exception:
                pass
        else:
            own += 1
        total += 1
    return total, forwarded, targets, own


def run(t):
    if t.error or t.pe is None:
        return []
    out = []
    base = os.path.basename(t.path).lower()
    is_dll = bool(t.pe.FILE_HEADER.Characteristics & 0x2000)

    if is_dll and base in SIDLOAD_NAMES:
        has_exe = any(s.endswith(".exe") for s in t.siblings)
        if has_exe:
            out.append(Finding("SIDELOAD?", f"'{base}' shipped in app dir - classic sideload name "
                                            "(should load from System32; verify signer)", CRITICAL))
    total, forwarded, targets, own = _forward_stats(t.pe)
    if total >= 6 and forwarded >= 0.6 * total and own >= 1:
        out.append(Finding("SIDELOAD?", f"export proxy: {forwarded}/{total} exports forwarded to "
                                        f"{', '.join(sorted(targets))} + {own} own export(s) - sideload shell?",
                           CRITICAL))
    return out
