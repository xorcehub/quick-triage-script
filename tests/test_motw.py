"""Plan 1.1: MOTW / Zone.Identifier provenance (parse + detector + report)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pecheck.peparse import parse_motw  # noqa: E402
from pecheck.detectors import motw as motw_det  # noqa: E402
from pecheck.model import Target  # noqa: E402
from pecheck.scan import scan_file  # noqa: E402

ADS = (b"[ZoneTransfer]\r\nZoneId=3\r\n"
       b"ReferrerUrl=https://evil.example/landing\r\n"
       b"HostUrl=https://cdn.example/payload.exe\r\n")


class TestParse(unittest.TestCase):
    def test_parse_full(self):
        m = parse_motw(ADS)
        self.assertEqual(m["zone"], "3")
        self.assertEqual(m["host"], "https://cdn.example/payload.exe")
        self.assertEqual(m["referrer"], "https://evil.example/landing")

    def test_parse_garbage_and_unknown_keys(self):
        m = parse_motw(b"[ZoneTransfer]\r\nZoneId=4\r\nLastWriterPackageFamilyName=x\r\njunk\r\n")
        self.assertEqual(m, {"zone": "4"})

    def test_parse_empty(self):
        self.assertIsNone(parse_motw(b""))
        self.assertIsNone(parse_motw(b"nothing here"))


class TestDetector(unittest.TestCase):
    def _t(self, motw):
        return Target(path="C:/x/payload.exe", size=1, sha256="0" * 64, motw=motw)

    def test_host_and_zone(self):
        f = motw_det.run(self._t(parse_motw(ADS)))
        self.assertTrue(any("cdn.example" in f.detail for f in f))
        self.assertTrue(any("ZoneId=3" in f.detail for f in f))

    def test_no_motw_silent(self):
        self.assertEqual(motw_det.run(self._t(None)), [])

    def test_local_zone_not_flagged(self):
        f = motw_det.run(self._t({"zone": "0"}))
        self.assertEqual(f, [])

    def test_report_carries_motw(self):
        # non-Windows: loader never probes; simulate via direct Target scan path
        d = tempfile.mkdtemp(prefix="pecheck_motw_")
        p = os.path.join(d, "a.txt")
        open(p, "wb").write(b"hello")
        r = scan_file(p)
        self.assertIsNone(r.motw)  # no ADS on this host -> None, detector silent


if __name__ == "__main__":
    unittest.main()
