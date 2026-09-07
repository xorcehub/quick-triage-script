import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.base import CorpusTest  # noqa: E402


class TestDocs(CorpusTest):
    def crit(self, name):
        r = self.report(name)
        return [f.detail for f in r.findings if f.severity == "CRITICAL"], r.verdict

    def test_pdf_openaction_js_review(self):
        crit, v = self.crit("exploit.pdf")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("auto-run" in d for d in crit))

    def test_clean_pdf_ok(self):
        r = self.report("clean.pdf")
        self.assertNotIn(r.verdict, ("REVIEW",))

    def test_rtf_objdata_autlink_review(self):
        crit, v = self.crit("evil.rtf")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("objdata" in d for d in crit))

    def test_rtf_ddeauto_review(self):
        crit, v = self.crit("dde.rtf")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("DDEAUTO" in d for d in crit))

    def test_ole_macro_plus_verb_review(self):
        crit, v = self.crit("macro.doc")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("auto-macro" in d for d in crit))

    def test_ole_boring_note_only(self):
        r = self.report("boring.doc")
        self.assertNotEqual(r.verdict, "REVIEW")
        self.assertTrue(any("VBA" in f.detail for f in r.findings))


if __name__ == "__main__":
    unittest.main()
