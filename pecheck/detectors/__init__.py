"""Detector registry. Each module exposes run(target) -> list[Finding].
ALL: PE-only detectors (self-gate on t.pe). GENERIC: run on every file kind.
A detector gets the already-loaded Target; it never re-reads the file."""
from . import imports, mem, sections, provenance, structure, dotnet, sideload, dircontext
from . import strings, raw, script, doc, archive, elflite, context

# PE-only: unchanged v1 registry minus strings (moved to GENERIC, runs on all)
ALL = [imports, sections, mem, provenance, structure, dotnet, sideload, dircontext]
GENERIC = [strings, raw, script, doc, archive, elflite, context]
