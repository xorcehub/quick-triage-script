import contextlib
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.base import CorpusTest  # noqa: E402
from pecheck.cli import main  # noqa: E402
from pecheck.scan import scan_targets  # noqa: E402


class TestCliJson(CorpusTest):
    def _run(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main([self.dir, "--json", "--no-sigs", *args])
        return json.loads(out.getvalue()), code

    def test_json_contract(self):
        payload, code = self._run()
        self.assertEqual(payload["schema"], "pecheck-report/1")
        for key in ("path", "size", "sha256", "verdict", "findings", "sections", "kind"):
            self.assertIn(key, payload["files"][0], key)
        self.assertIn("folders", payload)
        self.assertIn("side_files", payload)
        self.assertTrue(all("severity" in f for r in payload["files"] for f in r["findings"]))
        self.assertEqual(code, 1)  # corpus contains REVIEW files

    def test_exit_1_on_review(self):
        _, code = self._run()
        self.assertEqual(code, 1)

    def test_exit_0_on_clean_dir(self):
        import shutil
        clean = os.path.join(self.dir, "cleandir")
        os.makedirs(clean, exist_ok=True)
        open(os.path.join(clean, "a.txt"), "w").write("hello")
        open(os.path.join(clean, "b.png"), "wb").write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8)
        _, code = self._run()
        self.assertIn(code, (0, 1))  # whole corpus includes REVIEW; clean-only below
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code2 = main([clean, "--json", "--no-sigs"])
        self.assertEqual(code2, 0)

    def test_human_summary_mentions_rollup_and_review(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            main([self.dir, "--no-sigs", "--quiet"])
        text = out.getvalue()
        self.assertIn("Folder rollup", text)
        self.assertIn("REVIEW REQUIRED", text)
        self.assertIn("dropper.ps1", text)

    def test_folders_rollup_counts(self):
        res = scan_targets([self.dir], use_sigs=False)
        by = {f.path: f for f in res.folders}
        root = by.get(self.dir)
        self.assertIsNotNone(root, by.keys())
        self.assertGreater(root.review, 0)


if __name__ == "__main__":
    unittest.main()
