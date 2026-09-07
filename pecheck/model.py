"""Data model shared by all detectors."""
from dataclasses import dataclass, field, asdict

CRITICAL = "CRITICAL"
NOTE = "note"


@dataclass
class Finding:
    category: str          # e.g. INJECT, PACKED?, MEM?, PROV, STR, SIDELoad...
    detail: str
    severity: str = NOTE   # CRITICAL | note


@dataclass
class Target:
    """One parsed PE file plus context shared by all detectors."""
    path: str
    size: int
    sha256: str
    pe: object = None      # pefile.PE (None on parse error)
    raw: bytes = b""
    arch: str = None       # x64 | x86 | ARM64 | hex
    error: str = None      # pefile parse failure text
    siblings: list = field(default_factory=list)  # lowercase basenames of other PEs in same dir

    @property
    def basename(self) -> str:
        import os
        return os.path.basename(self.path)


@dataclass
class FileReport:
    path: str
    size: int
    sha256: str
    arch: str = None
    error: str = None
    signed: bool = False            # cert table present (weak presence check)
    sig: tuple = None               # wintrust result: (status, signer) or None
    sections: list = field(default_factory=list)   # (name, entropy, kb)
    findings: list = field(default_factory=list)   # [Finding]
    verdict: str = None             # REVIEW | ok | unsigned/unknown
    engine: str = None              # reserved: per-file provenance note

    @property
    def crit(self):
        return [f.detail for f in self.findings if f.severity == CRITICAL]

    def to_dict(self):
        d = asdict(self)
        d["crit"] = self.crit
        return d
