"""Game-folder context: scene/piracy markers, steam emulators, redist names,
double-extension and bidi spoofs, executable-behind-decoy-extension disguises.
Context beats filename heuristics, valid signature
beats context (wintrust path, N/A off-Windows). Emits notes + one targeted
downgrade signal (steam-emu) consumed by scan.py."""
import os
import re

from ..model import Finding, CRITICAL

SCENE = ("codex", "skidrow", "plaza", "hoodlum", "empress",
         "tenoke", "fitgirl", "dodi", "online-fix",
         "keygen", "nocd", "crack", "cracked")
_SCENE_RX = re.compile(r"\b(?:" + "|".join(re.escape(s) for s in SCENE) + r")\b")
REDIST = ("vcredist", "vc_redist", "directx", "dxsetup", "dotnet", "oalinst",
          "ueprereqsetup", "_commonredist")
EMU_MARKS = (b"goldberg", b"creamapi", b"smartsteamemu", b"spacewar")
MOD_MARKS = (b"reshade", b"specialk", b"enbseries", b"ultimate asi loader")
STEAM_API = ("steam_api.dll", "steam_api64.dll")
SPOOF_FINAL = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".jar", ".lnk", ".hta",
               ".vbs", ".js", ".com", ".pif", ".msc")
SPOOF_DECOY = (".pdf", ".doc", ".docx", ".txt", ".jpg", ".png", ".gif", ".xlsx",
               ".pptx", ".mp3", ".mp4", ".avi", ".zip")
_TRAIL = re.compile("|".join(re.escape(e) + r"$" for e in SPOOF_DECOY))
# kind -> label when executable content sits behind a decoy extension (icon spoof)
EXEC_KINDS = {"PE": "PE executable", "ELF": "ELF executable", "MACHO": "Mach-O executable"}
# bidi overrides + isolates: 'love\u202egnp.jpg' renders as 'lovejpg.png' - real ext hidden
_BIDI = ("\u202e", "\u202d", "\u2066", "\u2067", "\u2068", "\u2069")


def _plausible_dos(raw):
    """MZ without PE sig: require a sane e_lfanew so two random bytes can't trip us."""
    return len(raw) >= 0x40 and 0 < int.from_bytes(raw[0x3c:0x40], "little") < 0x1000


def run(t):
    if not t.raw and t.kind == "EMPTY":
        return []
    out = []
    parts = [p.lower() for p in t.path.replace("\\", "/").split("/")]
    base = os.path.basename(t.path).lower()

    # double-extension spoof: real extension hides behind a document/media tail
    stem, ext = os.path.splitext(base)
    if ext in SPOOF_FINAL and _TRAIL.search(stem):
        out.append(Finding("EVADE!", f"double extension '{base}': poses as "
                                     f"{stem[stem.rfind('.'):]} file but is {ext}", CRITICAL))

    # executable content hiding behind a document/media extension (icon spoof)
    if ext in SPOOF_DECOY:
        label = EXEC_KINDS.get(t.kind) or (
            "DOS MZ executable" if t.kind == "DOS" and _plausible_dos(t.raw) else None)
        if label:
            out.append(Finding("EVADE!", f"content mismatch: {label} disguised as {ext} file",
                               CRITICAL))

    # bidi override chars: displayed filename lies about the real extension
    if any(c in t.basename for c in _BIDI):
        shown = t.basename
        for c in _BIDI:
            shown = shown.replace(c, "\\u%04x" % ord(c))
        out.append(Finding("EVADE!", f"bidi override char in filename '{shown}': "
                                     "displayed name lies about the real extension", CRITICAL))

    m = _SCENE_RX.search("/".join(parts[:-1]))
    if m:
        out.append(Finding("CONTEXT", f"scene/crack marker in path: {m.group()} "
                                      "- pirated-release context, raise suspicion of bundled malware"))

    if any(r in base for r in REDIST):
        out.append(Finding("CONTEXT", f"'{base}' looks like a known redistributable "
                                      "(verify signature before trusting)"))

    # context downgrade signals (steam emu / graphics mods ship unsigned proxy DLLs)
    sibset = set(t.siblings)
    if base.startswith("steam_api") and base.endswith(".dll"):
        emu_ctx = any(s in sibset for s in ("steam_appid.txt", "steam_settings")) \
            or any(os.path.splitext(s)[1] == ".cfg" and s.startswith("steam_") for s in sibset) \
            or any(m in t.raw for m in EMU_MARKS)
        if emu_ctx:
            out.append(Finding("CONTEXT", "steam emulator pattern (goldberg/creamapi-style "
                                          "steam_api replacement) - proxy-DLL verdict downgraded"))
    if base in ("dxgi.dll", "d3d9.dll", "d3d11.dll", "d3d12.dll", "dinput8.dll",
                "winmm.dll", "version.dll"):
        mod_ctx = any(m in t.raw for m in MOD_MARKS) \
            or any(s in sibset for s in ("reshade.ini", "enblocal.ini")) \
            or any(s.endswith(".fx") for s in sibset)
        if mod_ctx:
            out.append(Finding("CONTEXT", "graphics/input mod proxy (ReShade/SpecialK/ENB-style) "
                                          "- proxy-DLL verdict downgraded"))
    return out
