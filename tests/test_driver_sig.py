"""Plan 1.2 (driver/exec wintrust coverage + unsigned-driver escalation)
and 1.3 (imphash in report)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.gen import craft_pe  # noqa: E402
from pecheck.scan import scan_file  # noqa: E402


class TestDriverEscalation(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="pecheck_drv_")

    def _sys(self, name="evil.sys", **kw):
        return craft_pe(os.path.join(self.d, name), imports=("ZwMapViewOfSection",), **kw)

    def test_unsigned_sys_critical(self):
        r = scan_file(self._sys())
        crit = [f for f in r.findings if f.severity == "CRITICAL"]
        self.assertTrue(any("unsigned kernel driver" in f.detail for f in crit))
        self.assertEqual(r.verdict, "REVIEW")

    def test_cert_table_sys_note_not_crit(self):
        """sig unavailable (non-Windows) but cert table present: weak-mode note."""
        r = scan_file(self._sys(cert_dir=True))
        crit = [f for f in r.findings if f.severity == "CRITICAL"
                and "kernel driver" in f.detail]
        notes = [f for f in r.findings if "validity NOT verified" in f.detail]
        self.assertFalse(crit)
        self.assertTrue(any("kernel driver" in f.detail for f in notes))

    def test_signed_sys_silent(self):
        """Valid sig tuple -> no driver finding at all."""
        from pecheck.scan import _scan_target
        from pecheck import peparse
        p = self._sys(name="good.sys")
        t = peparse.load(p)
        r = _scan_target(t, (), ("Valid", "Microsoft Windows"))
        self.assertFalse([f for f in r.findings if "kernel driver" in f.detail])

    def test_hashmismatch_sys_critical(self):
        from pecheck.scan import _scan_target
        from pecheck import peparse
        t = peparse.load(self._sys())
        r = _scan_target(t, (), ("HashMismatch", "-"))
        crit = [f for f in r.findings if f.severity == "CRITICAL"]
        self.assertTrue(any("ring 0" in f.detail for f in crit))

    def test_unsigned_exe_no_driver_finding(self):
        p = craft_pe(os.path.join(self.d, "plain.exe"))
        r = scan_file(p)
        self.assertFalse([f for f in r.findings if "kernel driver" in f.detail])


class TestImphash(unittest.TestCase):
    def test_imphash_present_and_stable(self):
        d = tempfile.mkdtemp(prefix="pecheck_ih_")
        a = craft_pe(os.path.join(d, "a.exe"))
        b = craft_pe(os.path.join(d, "b_copy.exe"), tds=0x77777777)
        ra, rb = scan_file(a), scan_file(b)
        self.assertTrue(ra.imphash)
        self.assertEqual(ra.imphash, rb.imphash)  # same imports -> same imphash

    def test_imphash_json(self):
        import json
        import io
        import contextlib
        from pecheck.cli import main
        d = tempfile.mkdtemp(prefix="pecheck_ihj_")
        p = craft_pe(os.path.join(d, "x.exe"))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main([p, "--json", "--no-sigs"])
        f0 = json.loads(out.getvalue())["files"][0]
        self.assertIn("imphash", f0)


if __name__ == "__main__":
    unittest.main()
