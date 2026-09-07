import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests import gen  # noqa: E402
from pecheck.scan import scan_file  # noqa: E402

_ = unittest.skipUnless(gen.GCC, "gcc not available")


class TestElfSamples(unittest.TestCase):
    """Malware-like C binaries compiled on the fly, then scanned."""

    @classmethod
    def setUpClass(cls):
        if not gen.GCC:
            raise unittest.SkipTest("gcc not available")
        cls.dir = os.path.dirname(os.path.abspath(__file__)) + "/../_elfsamples"
        cls.dir = os.path.abspath(cls.dir)
        os.makedirs(cls.dir, exist_ok=True)

    def sample(self, name):
        p = os.path.join(self.dir, name)
        if not os.path.exists(p):
            r = gen.gcc_sample(self.dir, name)
            if r is None:
                raise unittest.SkipTest(f"compile failed: {name}")
        return scan_file(p)

    @_
    def test_stealer_escalates(self):
        r = self.sample("stealer.elf")
        crit = [f for f in r.findings if f.severity == "CRITICAL"]
        self.assertTrue(any("stealer" in f.detail for f in crit), [f.detail for f in r.findings])
        self.assertEqual(r.verdict, "REVIEW")

    @_
    def test_dropper_embedded_elf_critical(self):
        r = self.sample("dropper.elf")
        crit = [f for f in r.findings if f.severity == "CRITICAL"]
        self.assertTrue(any("embedded executable" in f.detail for f in crit))
        self.assertEqual(r.verdict, "REVIEW")

    @_
    def test_upx_marker_critical(self):
        r = self.sample("packed.elf")
        crit = [f for f in r.findings if f.severity == "CRITICAL"]
        self.assertTrue(any("UPX" in f.detail for f in crit))
        self.assertEqual(r.verdict, "REVIEW")

    @_
    def test_revshell_flagged(self):
        r = self.sample("revshell.elf")
        self.assertEqual(r.verdict, "note")
        self.assertTrue(any(f.category in ("STR", "MEM?") for f in r.findings),
                        [f.detail for f in r.findings])

    @_
    def test_elflite_reports_arch(self):
        r = self.sample("stealer.elf")
        self.assertTrue(any(f.category == "NOTE" and "ELF" in f.detail and "x86-64" in f.detail
                            for f in r.findings))

    @_
    def test_entropy_sample_scans_clean(self):
        r = self.sample("entropy.elf")   # smoke: big random blob must not crash scan
        self.assertIn(r.verdict, ("ok", "note"))


if __name__ == "__main__":
    unittest.main()
