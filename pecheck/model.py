"""Data model shared by all detectors."""
import os
from dataclasses import dataclass, field, asdict
from typing import Literal

CRITICAL = "CRITICAL"
NOTE = "note"
Severity = Literal["CRITICAL", "note"]


@dataclass
class Finding:
    category: str          # e.g. INJECT, PACKED?, MEM?, PROV, STR, IOC
    detail: str
    severity: Severity = NOTE


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
    verdict: str = None             # REVIEW | ok | unsigned/unknown | error
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
        d.pop("crit", None)
        d["findings"] = [{"severity": f.severity, "category": f.category, "detail": f.detail}
                         for f in sorted(self.findings, key=lambda f: (f.severity != CRITICAL,))]
        if self.sig is not None:
            d["sig"] = {"status": self.sig[0], "signer": self.sig[1]}
        return d


@dataclass
class ScanResult:
    reports: list
    side_files: list = field(default_factory=list)

    def __iter__(self):
        return iter(self.reports)

    def __len__(self):
        return len(self.reports)

    def __getitem__(self, i):
        return self.reports[i]
