"""Plan 2.4: local reputation cache / scan history."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.gen import craft_pe  # noqa: E402
from pecheck import history  # noqa: E402
from pecheck.scan import scan_targets  # noqa: E402


class TestHistory(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="pecheck_h_")
        self.cache = os.path.join(self.d, "history.json")
        self._old = os.environ.pop("PECHECK_HISTORY", None)
        os.environ["PECHECK_HISTORY"] = self.cache
        self.addCleanup(os.environ.pop, "PECHECK_HISTORY")
        if self._old is not None:
            self.addCleanup(os.environ.__setitem__, "PECHECK_HISTORY", self._old)

    def _scan(self):
        return scan_targets([self._dir()], use_sigs=False)

    def _dir(self):
        d = os.path.join(self.d, "files")
        os.makedirs(d, exist_ok=True)
        craft_pe(os.path.join(d, "unsigned.exe"), imports=("CreateFileA",))  # not flagged -> unsigned/unknown
        return d

    def test_two_runs_first_seen_note(self):
        r1 = self._scan()
        self.assertFalse([f for r in r1.reports for f in r.findings if "first seen today" in f.detail])
        r2 = self._scan()
        notes = [f for r in r2.reports for f in r.findings if "first seen today" in f.detail]
        self.assertEqual(len(notes), 1)  # unsigned/unknown PE re-seen same day
        self.assertTrue(os.path.exists(self.cache))
        data = json.load(open(self.cache))
        self.assertEqual(len(data), 1)
        e = next(iter(data.values()))
        self.assertIn("first_seen", e)

    def test_previously_flagged_remembered(self):
        # seed the cache with a REVIEW verdict for this sha
        r1 = self._scan()
        sha = r1.reports[0].sha256
        json.dump({sha: {"first_seen": "2020-01-01", "last_seen": "2020-01-01",
                         "last_verdict": "REVIEW", "last_paths": ["x.exe"]}},
                  open(self.cache, "w"))
        r2 = self._scan()
        prev = [f for r in r2.reports for f in r.findings if "previously flagged" in f.detail]
        self.assertEqual(len(prev), 1)

    def test_corrupt_cache_never_breaks_scan(self):
        open(self.cache, "w").write("{not json at all")
        r = self._scan()
        self.assertTrue(r.reports)
        data = json.load(open(self.cache))  # rewritten fresh
        self.assertIsInstance(data, dict)

    def test_no_history_flag(self):
        self._scan()
        os.remove(self.cache)
        scan_targets([self._dir()], use_sigs=False, use_history=False)
        self.assertFalse(os.path.exists(self.cache))

    def test_cli_flag(self):
        import contextlib
        import io
        from pecheck.cli import main
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main([self._dir(), "--json", "--no-sigs", "--no-history"])
        self.assertTrue(json.loads(out.getvalue())["files"])


if __name__ == "__main__":
    unittest.main()
