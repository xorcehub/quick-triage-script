import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.base import CorpusTest  # noqa: E402


class TestZip(CorpusTest):
    def cats(self, name):
        return [(f.category, f.detail) for f in self.report(name).findings]

    def test_traversal_member_critical(self):
        crit = [d for c, d in self.cats("evil.zip") if c == "ARCH!"]
        self.assertTrue(any("traversal" in d for d in crit))
        self.assertEqual(self.report("evil.zip").verdict, "REVIEW")

    def test_hidden_pe_member_critical(self):
        crit = [d for c, d in self.cats("evil.zip") if c == "ARCH!"]
        self.assertTrue(any("hidden" in d and "PE" in d for d in crit))

    def test_exe_member_listed(self):
        notes = [d for c, d in self.cats("mod.zip") if c == "NOTE"]
        self.assertTrue(any("mod.dll" in d for d in notes))

    def test_nested_archive_note(self):
        notes = [d for c, d in self.cats("mod.zip") if c == "NOTE"]
        self.assertTrue(any("nested" in d for d in notes))

    def test_benign_zip_not_review(self):
        self.assertNotEqual(self.report("mod.zip").verdict, "REVIEW")

    def test_other_containers_get_note(self):
        import gzip as gz
        with gz.open(self.path("g.gz"), "wb") as f:
            f.write(b"data")
        r = self.report("g.gz")
        self.assertTrue(any("not listed" in f.detail for f in r.findings))


if __name__ == "__main__":
    unittest.main()
