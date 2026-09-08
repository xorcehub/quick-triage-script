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

    def test_glob_expansion_and_missing_warn(self):
        clean = os.path.join(self.dir, "cleandir")
        os.makedirs(clean, exist_ok=True)
        open(os.path.join(clean, "a.txt"), "w").write("hello")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main([os.path.join(clean, "*.txt"), "--json", "--no-sigs"])
        payload = json.loads(out.getvalue())
        self.assertEqual(len(payload["files"]), 1)
        self.assertEqual(code, 0)
        nested = os.path.join(clean, "sub")
        os.makedirs(nested, exist_ok=True)
        open(os.path.join(nested, "c.txt"), "w").write("hi")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main([os.path.join(clean, "**", "*.txt"), "--json", "--no-sigs"])
        self.assertEqual(len(json.loads(out.getvalue())["files"]), 2)  # a.txt + sub/c.txt
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = main([os.path.join(clean, "*.nomatch"), "--no-sigs", "--quiet"])
        self.assertIn("warning: no files match", err.getvalue())
        self.assertEqual(code, 2)

    def test_ext_flag_filters_and_reports_skipped(self):
        clean = os.path.join(self.dir, "extdir")
        os.makedirs(clean, exist_ok=True)
        open(os.path.join(clean, "a.txt"), "w").write("hello")
        open(os.path.join(clean, "b.png"), "wb").write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8)
        open(os.path.join(clean, "c.exe"), "wb").write(b"MZ" + b"\x00" * 62)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main([clean, "--json", "--no-sigs", "--ext", "EXE, .txt"])
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["skipped"], 1)          # b.png
        self.assertEqual({os.path.basename(f["path"]) for f in payload["files"]},
                         {"a.txt", "c.exe"})
        self.assertEqual(code, 0)  # stub MZ lands ok - the filter is what we test
        # library level
        res = scan_targets([clean], use_sigs=False, exts=(".exe",))
        self.assertEqual(res.skipped, 2)
        self.assertEqual(len(res.reports), 1)

    def test_norm_exts(self):
        from pecheck.cli import _norm_exts
        self.assertEqual(_norm_exts("exe, .DLL"), (".dll", ".exe"))
        self.assertEqual(_norm_exts(""), ())

    def test_wizard_parsing(self):
        import builtins
        from pecheck.cli import _ask_filter
        real_input = builtins.input
        try:
            builtins.input = lambda *a: ""                      # Enter = everything
            self.assertEqual(_ask_filter(), (None, None))
            builtins.input = lambda *a: "2,4"                   # combined groups
            exts, names = _ask_filter()
            self.assertEqual(names, "executables+documents")
            self.assertIn(".exe", exts) and self.assertIn(".pdf", exts)
            answers = iter(["6", "exe, py"])                   # menu pick, then custom list
            builtins.input = lambda *a: next(answers)
            exts2, names2 = _ask_filter()
            self.assertEqual((exts2, names2), ((".exe", ".py"), "custom"))
        finally:
            builtins.input = real_input

    def test_wizard_custom_shows_folder_inventory(self):
        import builtins
        from pecheck.cli import _ask_filter, _ext_inventory
        clean = os.path.join(self.dir, "invdir")
        os.makedirs(clean, exist_ok=True)
        for fn in ("a.txt", "b.txt", "c.exe"):
            open(os.path.join(clean, fn), "w").write("x")
        inv = _ext_inventory([clean])
        self.assertEqual(dict(inv), {".txt": 2, ".exe": 1})
        answers = iter(["6", "txt"])
        real_input = builtins.input
        out = io.StringIO()
        try:
            builtins.input = lambda *a: next(answers)
            import contextlib as _cl
            with _cl.redirect_stdout(out):
                exts, names = _ask_filter(inv)
        finally:
            builtins.input = real_input
        self.assertIn(".txt x2", out.getvalue())
        self.assertIn(".exe x1", out.getvalue())
        self.assertEqual((exts, names), ((".txt",), "custom"))
        finally:
            builtins.input = real_input

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
