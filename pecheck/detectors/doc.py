"""Document triage: PDF / OLE (doc/xls/msi) / RTF abuse markers - regex only.
PDF/RTF may carry junk prefixes (identify allows 1KB), so scan the whole
head region rather than offset 0."""
from ..model import Finding, CRITICAL

_HEAD = 1 << 20

PDF_JS = (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch",
          b"/EmbeddedFile", b"/RichMedia", b"/URI")
OLE_MACROS = (b"AutoOpen", b"Auto_Open", b"AutoExec", b"Workbook_Open", b"Document_Open")
OLE_VERBS = (b"CreateObject", b"URLDownloadToFile", b"powershell", b"Shell ",
             b"WScript.Shell", b"certutil")
RTF_OBJ = (b"\\objdata", b"\\objautlink", b"\\objupdate", b"{\\object")
RTF_DDE = (b"\\fldinst", b"DDEAUTO")


def _pdf(t, raw):
    head = raw[:_HEAD]
    hits = [m.decode() for m in PDF_JS if m in head]
    out = []
    if not hits:
        return out  # clean PDF - silence (a note on every legit PDF is noise)
    js = "/JavaScript" in hits or "/JS" in hits
    launch = "/Launch" in hits
    if launch and js:
        out.append(Finding("DOC!", "PDF /Launch + /JavaScript (classic exploit-doc combo)", CRITICAL))
    for h in hits:
        cat = "DOC?" if h in ("/OpenAction", "/AA", "/Launch", "/RichMedia") else "NOTE"
        out.append(Finding(cat, f"PDF marker {h}"))
    return out


def _ole(t, raw):
    head = raw[:_HEAD]
    out = []
    macros = [m.decode() for m in OLE_MACROS if m in head]
    verbs = [v.decode() for v in OLE_VERBS if v in head]
    if macros and verbs:
        out.append(Finding("DOC!", f"OLE auto-macro ({', '.join(macros[:2])}) + dropper verb "
                                   f"({verbs[0]})", CRITICAL))
    elif macros:
        out.append(Finding("DOC?", f"OLE auto-macro name(s): {', '.join(macros[:3])}"))
    elif b"VBA" in head or b"ThisDocument" in head:
        out.append(Finding("NOTE", "OLE container with VBA project strings"))
    return out


def _rtf(t, raw):
    head = raw[:_HEAD]
    out = []
    objdata = b"\\objdata" in head
    autlink = b"\\objautlink" in head or b"\\objupdate" in head
    if objdata and (autlink or b"{\\object" in head):
        out.append(Finding("DOC!", "RTF embedded auto-linked object (\\objdata + object) - near-zero legit use", CRITICAL))
    elif objdata:
        out.append(Finding("DOC?", "RTF \\objdata blob"))
    if b"DDEAUTO" in head and b"\\fldinst" in head:
        out.append(Finding("DOC!", "RTF DDEAUTO field (code execution via field)", CRITICAL))
    return out


def run(t):
    if not t.raw:
        return []
    if t.kind == "PDF":
        return _pdf(t, t.raw)
    if t.kind == "OLE":
        return _ole(t, t.raw)
    if t.kind == "RTF":
        return _rtf(t, t.raw)
    return []
