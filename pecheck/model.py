"""Data model shared by all detectors."""
import os
from dataclasses import dataclass, field, asdict
from typing import Literal

CRITICAL = "CRITICAL"
NOTE = "note"
Severity = Literal["CRITICAL", "note"]


@dataclass
class Finding:
    category: str          # e.g. INJECT, PACKED?, MEM?, PROV, STR, IOC, SCRIPT
    detail: str
    severity: Severity = NOTE


@dataclass
class Target:
    """One loaded file plus context shared by all detectors (any kind)."""
    path: str
    size: int
    sha256: str
    kind: str = "DATA"     # identify.py kind: PE|ELF|ZIP|SCRIPT|PDF|...
    raw: bytes = b""       # first RAW_CAP bytes
    truncated: bool = False  # size > RAW_CAP: analysis saw only the head
    pe: object = None      # pefile.PE when kind==PE (None on parse error)
    arch: str = None       # x64 | x86 | ARM64 | hex
    error: str = None      # OSError text; PE-parse failure text (kind stays PE)
    sig: tuple = None       # wintrust result (status, signer); set before detectors run
    motw: dict = None       # parsed Zone.Identifier ADS (MOTW) - zone/host/referrer/time
    siblings: list = field(default_factory=list)  # lowercase basenames of other files in same dir

    @property
    def basename(self) -> str:
        return os.path.basename(self.path)

    @property
    def ext(self) -> str:
        return os.path.splitext(self.path)[1].lower()


@dataclass
class FileReport:
    path: str
    size: int
    sha256: str
    kind: str = "DATA"
    arch: str = None
    error: str = None
    signed: bool = False            # cert table present (weak presence check)
    sig: tuple = None               # wintrust result: (status, signer) or None
    sections: list = field(default_factory=list)   # (name, entropy, kb)
    findings: list = field(default_factory=list)   # [Finding]
    verdict: str = None             # REVIEW | note | ok | unsigned/unknown | error
    imphash: str = None             # pefile import hash (PE only, "" on failure)
    motw: dict = None               # parsed Zone.Identifier ADS (any kind)
    parent: str = None              # archive this file was extracted from (--unpack)
    weak_cert: tuple = None         # (signer strings, notAfter str) when sig check unavailable
    duplicate_of: str = None        # path of the byte-identical file we deduped against

    @property
    def basename(self) -> str:
        return os.path.basename(self.path)

    @property
    def crit(self):
        return [f.detail for f in self.findings if f.severity == CRITICAL]

    def to_dict(self):
        d = asdict(self)
        d["findings"] = [{"severity": f.severity, "category": f.category, "detail": f.detail}
                         for f in sorted(self.findings, key=lambda f: (f.severity != CRITICAL,))]
        if self.sig is not None:
            d["sig"] = {"status": self.sig[0], "signer": self.sig[1]}
        return d


@dataclass
class FolderRollup:
    """Verdict aggregate for one directory that directly contains files."""
    path: str
    total: int
    review: int
    note: int
    ok: int
    unknown: int
    error: int
    top_categories: list = field(default_factory=list)  # [(category, count)]


@dataclass
class ScanResult:
    reports: list
    side_files: list = field(default_factory=list)
    folders: list = field(default_factory=list)          # [FolderRollup]

    def __iter__(self):
        return iter(self.reports)

    def __len__(self):
        return len(self.reports)

    def __getitem__(self, i):
        return self.reports[i]
