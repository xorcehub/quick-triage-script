import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pecheck.model import Finding, FileReport, Target, CRITICAL  # noqa: E402
from pecheck.verdict import verdict, downgrade, rollup  # noqa: E402


def tgt(kind="DATA", err=None):
    return Target(path="/x", size=1, sha256="h", kind=kind, error=err)


class TestVerdict(unittest.TestCase):
    def test_nonpe_critical_review(self):
        self.assertEqual(verdict(tgt(), [Finding("X", "d", CRITICAL)]), "REVIEW")

    def test_nonpe_notes_only_note(self):
        self.assertEqual(verdict(tgt(), [Finding("X", "d")]), "note")

    def test_nonpe_clean_ok(self):
        self.assertEqual(verdict(tgt(), []), "ok")

    def test_pe_parse_error_review(self):
        self.assertEqual(verdict(tgt("PE", err="PEFormatError: x"), []), "REVIEW")

    def test_pe_valid_sig_no_crit_ok(self):
        self.assertEqual(verdict(tgt("PE"), [], sig=("Valid", "Corp")), "ok")

    def test_pe_hashmismatch_review(self):
        self.assertEqual(verdict(tgt("PE"), [], sig=("HashMismatch", "-")), "REVIEW")

    def test_pe_crit_beats_valid_sig(self):
        self.assertEqual(verdict(tgt("PE"), [Finding("X", "d", CRITICAL)], sig=("Valid", "C")), "REVIEW")

    def test_pe_unsigned_unknown(self):
        self.assertEqual(verdict(tgt("PE"), []), "unsigned/unknown")

    def test_pe_signed_weak_ok(self):
        self.assertEqual(verdict(tgt("PE"), [], signed=True), "ok")


class TestDowngrade(unittest.TestCase):
    def test_steam_emu_downgrades_sideload(self):
        fs = [Finding("SIDELOAD?", "classic sideload name", CRITICAL),
              Finding("CONTEXT", "steam emulator pattern - downgrade sideload verdict")]
        out = downgrade(fs)
        sl = next(f for f in out if f.category == "SIDELOAD?")
        self.assertEqual(sl.severity, "note")
        self.assertIn("downgraded", sl.detail)

    def test_no_context_no_downgrade(self):
        fs = [Finding("SIDELOAD?", "classic sideload name", CRITICAL)]
        self.assertEqual(downgrade(fs), fs)


class TestRollup(unittest.TestCase):
    def _rep(self, path, verdict, cats=()):
        return FileReport(path=path, size=1, sha256=path, verdict=verdict,
                          findings=[Finding(c, "d") for c in cats])

    def test_counts_and_categories(self):
        rs = [self._rep("/a/x.exe", "REVIEW", ("INJECT", "INJECT")),
              self._rep("/a/y.txt", "ok"),
              self._rep("/a/z.ps1", "note", ("STR",)),
              self._rep("/b/w.dll", "unsigned/unknown")]
        folders = rollup(rs)
        self.assertEqual(len(folders), 2)
        a = next(f for f in folders if f.path == "/a")
        self.assertEqual((a.total, a.review, a.ok, a.note, a.unknown), (3, 1, 1, 1, 0))
        self.assertEqual(a.top_categories[0], ("INJECT", 2))

    def test_duplicates_not_counted(self):
        rs = [self._rep("/a/x.exe", "REVIEW", ("INJECT",)),
              FileReport(path="/a/copy.exe", size=1, sha256="s", verdict="REVIEW",
                         duplicate_of="/a/x.exe")]
        folders = rollup(rs)
        self.assertEqual(folders[0].total, 1)


if __name__ == "__main__":
    unittest.main()
