import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests import gen  # noqa: E402
from pecheck.scan import scan_file  # noqa: E402


class TestElfSamples(unittest.TestCase):
    """Synthetic malware-like ELFs (gen.elf_sample, no compiler) then scanned."""

    @classmethod
    def setUpClass(cls):
        import tempfile
        cls.dir = tempfile.mkdtemp(prefix="pecheck_elf_")

    def sample(self, name):
        p = os.path.join(self.dir, name)
        if not os.path.exists(p):
            gen.elf_sample(self.dir, name)
        return scan_file(p)

    def test_stealer_escalates(self):
        r = self.sample("stealer.elf")
        crit = [f for f in r.findings if f.severity == "CRITICAL"]
        self.assertTrue(any("stealer" in f.detail for f in crit), [f.detail for f in r.findings])
        self.assertEqual(r.verdict, "REVIEW")

    def test_dropper_embedded_elf_critical(self):
        r = self.sample("dropper.elf")
        crit = [f for f in r.findings if f.severity == "CRITICAL"]
        self.assertTrue(any("embedded executable" in f.detail for f in crit))
        self.assertEqual(r.verdict, "REVIEW")

    def test_upx_marker_critical(self):
        r = self.sample("packed.elf")
        crit = [f for f in r.findings if f.severity == "CRITICAL"]
        self.assertTrue(any("UPX" in f.detail for f in crit))
        self.assertEqual(r.verdict, "REVIEW")

    def test_upx_section_name_critical(self):
        # names only, no UPX! bytes: pins the shstrtab -> section-name operand
        r = self.sample("packed_secname.elf")
        crit = [f for f in r.findings if f.severity == "CRITICAL"]
        self.assertTrue(any("UPX" in f.detail for f in crit), [f.detail for f in r.findings])
        self.assertEqual(r.verdict, "REVIEW")

    def test_revshell_flagged(self):
        r = self.sample("revshell.elf")
        self.assertEqual(r.verdict, "note")
        self.assertTrue(any(f.category in ("STR", "MEM?") for f in r.findings),
                        [f.detail for f in r.findings])
        self.assertTrue(any("dynamic" in f.detail for f in r.findings),   # interpreter string
                        [f.detail for f in r.findings])

    def test_elflite_reports_arch(self):
        r = self.sample("stealer.elf")
        self.assertTrue(any(f.category == "NOTE" and "ELF" in f.detail and "x86-64" in f.detail
                            for f in r.findings))

    def test_entropy_sample_scans_clean(self):
        r = self.sample("entropy.elf")   # smoke: big random blob must not crash scan
        self.assertIn(r.verdict, ("ok", "note"))


if __name__ == "__main__":
    unittest.main()
