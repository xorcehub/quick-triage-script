"""pecheck - static PE triage: imports, signatures, packing and staging heuristics."""
from .model import Finding, Target, FileReport, CRITICAL, NOTE
from .scan import scan_file, scan_targets

__all__ = ["Finding", "Target", "FileReport", "CRITICAL", "NOTE", "scan_file", "scan_targets"]
