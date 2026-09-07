"""Game-folder context: scene/piracy markers, steam emulators, redist names,
double-extension spoofs. Context beats filename heuristics, valid signature
beats context (wintrust path, N/A off-Windows). Emits notes + one targeted
downgrade signal (steam-emu) consumed by scan.py."""
import os
import re

from ..model import Finding, CRITICAL

SCENE = ("codex", "skidrow", "cpy", "plaza", "hoodlum", "rune", "empress",
         "tenoke", "fitgirl", "dodi", "rg mechanics", "online-fix", "3dm",
         "keygen", "nocd", "crack", "cracked")
REDIST = ("vcredist", "vc_redist", "directx", "dxsetup", "dotnet", "oalinst",
          "ueprereqsetup", "_commonredist")
EMU_MARKS = (b"goldberg", b"creamapi", b"smartsteamemu", b"spacewar")
STEAM_API = ("steam_api.dll", "steam_api64.dll")
SPOOF_FINAL = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".jar", ".lnk", ".hta",
               ".vbs", ".js", ".com", ".pif", ".msc")
SPOOF_DECOY = (".pdf", ".doc", ".docx", ".txt", ".jpg", ".png", ".gif", ".xlsx",
               ".pptx", ".mp3", ".mp4", ".avi", ".zip")
_TRAIL = re.compile("|".join(re.escape(e) + r"$" for e in SPOOF_DECOY))


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

    scene = [m for m in SCENE if any(m in p for p in parts[:-1])]
    if scene or any(m == parts[-1].rsplit(".", 1)[0] for m in ("keygen", "crack", "nocd")):
        out.append(Finding("CONTEXT", f"scene/crack marker in path: {scene[0] if scene else base} "
                                      "- pirated-release context, raise suspicion of bundled malware"))

    if any(r in base for r in REDIST):
        out.append(Finding("CONTEXT", f"'{base}' looks like a known redistributable "
                                      "(verify signature before trusting)"))

    # steam emulator downgrade signal
    if base in STEAM_API:
        sibset = set(t.siblings)
        emu_ctx = any(s in sibset for s in ("steam_appid.txt", "steam_settings")) \
            or any(os.path.splitext(s)[1] == ".cfg" and s.startswith("steam_") for s in sibset) \
            or any(m in t.raw for m in EMU_MARKS)
        if emu_ctx:
            out.append(Finding("CONTEXT", "steam emulator pattern (goldberg/creamapi-style "
                                          "steam_api replacement) - downgrade sideload verdict"))
    return out
