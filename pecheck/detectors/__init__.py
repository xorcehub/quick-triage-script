"""Detector registry. Each module exposes run(target) -> list[Finding].
A detector gets the already-parsed Target; it never re-reads the file."""
from . import imports, mem, sections, provenance, structure, strings, dotnet, sideload

ALL = [imports, sections, mem, provenance, structure, strings, dotnet, sideload]
