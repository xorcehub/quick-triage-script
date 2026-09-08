"""Plan 2.1: --unpack recursive extraction (self-contained zip fixtures; the
7z path degrades to a hint when 7z is absent - the sandbox has none)."""
import io
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pecheck import unpack  # noqa: E402
from pecheck.scan import scan_targets  # noqa: E402

README = b"plain readme, nothing hidden\n" * 10


def nested_zip(inner_members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in inner_members:
            z.writestr(name, data)
    return buf.getvalue()


class TestUnpack(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="pecheck_up_")

    def _outer(self):
        inner = nested_zip([("payload.exe", b"MZ" + b"\x90" * 200),
                            ("readme.txt", README)])
        p = os.path.join(self.d, "installer.zip")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("inner.zip", inner)
            z.writestr("readme.txt", README)
        return p

    def test_unpack_zip_children_with_parent(self):
        res = scan_targets([self._outer()], use_sigs=False, unpack=True)
        kids = [r for r in res.reports if r.parent]
        self.assertEqual(len(kids), 2)  # inner.zip + readme.txt
        self.assertTrue(all("installer.zip" in r.parent for r in kids))
        self.assertTrue(all(any("extracted from installer.zip" in f.detail for f in r.findings)
                            for r in kids))

    def test_depth_cap_default_one(self):
        res = scan_targets([self._outer()], use_sigs=False, unpack=True, max_depth=1)
        # inner.zip is extracted (level 1) but its members are not (would need level 2)
        self.assertFalse([r for r in res.reports if r.parent and "inner.zip" in r.parent])

    def test_depth_two_recurses(self):
        res = scan_targets([self._outer()], use_sigs=False, unpack=True, max_depth=2)
        grandkids = [r for r in res.reports if r.parent and "inner.zip" in r.parent]
        self.assertEqual(len(grandkids), 2)

    def test_no_unpack_unchanged(self):
        res = scan_targets([self._outer()], use_sigs=False)
        self.assertFalse([r for r in res.reports if r.parent])

    def test_traversal_member_stays_inside(self):
        p = os.path.join(self.d, "evil.zip")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("../escape.txt", b"nope")
            z.writestr("ok.txt", b"fine")
        res = scan_targets([p], use_sigs=False, unpack=True)
        self.assertFalse(os.path.exists(os.path.join(self.d, "escape.txt")))
        kids = [r for r in res.reports if r.parent]
        self.assertTrue(any(r.basename == "ok.txt" for r in kids))

    def test_caps_block_extraction(self):
        p = self._outer()
        old = unpack.CAP_ENTRIES
        unpack.CAP_ENTRIES = 1  # force cap violation
        try:
            res = scan_targets([p], use_sigs=False, unpack=True)
        finally:
            unpack.CAP_ENTRIES = old
        self.assertFalse([r for r in res.reports if r.parent])

    def test_sevenz_absent_degrades(self):
        self.assertIsNone(unpack.extract(os.path.join(self.d, "nope.7z"), "SEVENZ"))

    def test_json_parent_field(self):
        import json
        from pecheck.cli import main
        import contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main([self._outer(), "--json", "--no-sigs", "--unpack"])
        files = json.loads(out.getvalue())["files"]
        self.assertTrue(any(f.get("parent") for f in files))
        self.assertIn(code, (0, 1, 2))


if __name__ == "__main__":
    unittest.main()
