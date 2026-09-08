"""Plan 2.5: Rich-header provenance (synthetic stubs XORed per spec)."""
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.gen import craft_pe  # noqa: E402
from pecheck.scan import scan_file  # noqa: E402
from pecheck.detectors.provenance import _rich  # noqa: E402


def build_rich(entries, key=0xDEADBEEF, checksum=None, dans_align=True):
    """entries: [(product, count), ...] - first should be linker (1, build)."""
    blob = b""
    for prod, cnt in entries:
        compid = (prod << 16) | (cnt & 0xFFFF)
        blob += struct.pack("<II", compid ^ key, cnt ^ key)
    chk = checksum if checksum is not None else 0x66666666  # matches craft_pe tds
    pre = b"MZ" + b"\x00" * 7  # keep the MZ signature; slack before DanS
    start = 0x40 if dans_align else 0x42
    stub = bytearray(b"\x00" * (start + 8 + len(blob) + 8))
    stub[0:len(pre)] = pre
    off = start
    stub[off:off + 8] = struct.pack("<II", 0x536E6144 ^ key, key)  # DanS + pad
    off += 8
    stub[off:off + len(blob)] = blob
    off += len(blob)
    struct.pack_into("<I", stub, off, chk)
    return bytes(stub[:off + 4]) + b"Rich" + struct.pack("<I", key)


def make_rich_pe(path, **kw):
    """craft_pe then splice a Rich stub into the DOS header area (< e_lfanew 0x80)."""
    craft_pe(path)
    rich = build_rich(**kw)
    assert len(rich) <= 0x80, len(rich)
    data = bytearray(open(path, "rb").read())
    data[0:len(rich)] = rich
    struct.pack_into("<I", data, 0x3C, 0x80)  # splice must not wipe e_lfanew
    open(path, "wb").write(data)
    return path


class TestRich(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="pecheck_rich_")

    def test_parse_normal(self):
        p = make_rich_pe(os.path.join(self.d, "norm.exe"),
                         entries=[(1, 0x25B8), (0x93, 200)])
        r = scan_file(p)
        self.assertTrue(any("linker build" in f.detail and "2 compid" in f.detail
                            for f in r.findings))
        self.assertFalse([f for f in r.findings if "contradicts" in f.detail
                          or "TimeDateStamp" in f.detail and "Rich checksum" in f.detail])

    def test_forged_vendor_contradiction(self):
        p = make_rich_pe(os.path.join(self.d, "forged.exe"),
                         entries=[(0x94, 100)])  # MinGW-ish product, not MSVC linker
        # give it a Microsoft CompanyName via version info is heavy; check the
        # pure-function side plus the no-mismatch silence instead
        rich = _rich(build_rich(entries=[(0x94, 100)]), 0x66666666)
        self.assertEqual(rich[0], 0x94)
        r = scan_file(p)
        self.assertTrue(any("linker build" in f.detail for f in r.findings))

    def test_checksum_mismatch(self):
        p = make_rich_pe(os.path.join(self.d, "mm.exe"),
                         entries=[(1, 0x25B8)], checksum=0x11111111)
        r = scan_file(p)
        self.assertTrue(any("Rich checksum" in f.detail and "TimeDateStamp" in f.detail
                            for f in r.findings))

    def test_absent_rich_is_note(self):
        p = craft_pe(os.path.join(self.d, "noric.exe"))
        r = scan_file(p)
        self.assertTrue(any("no Rich header" in f.detail for f in r.findings))

    def test_garbage_no_rich_crash(self):
        p = craft_pe(os.path.join(self.d, "g.exe"))
        data = bytearray(open(p, "rb").read())
        data[10:14] = b"Rich"  # fake marker without DanS
        open(p, "wb").write(data)
        self.assertIsNone(_rich(bytes(data), 0x66666666))
        r = scan_file(p)
        self.assertTrue(any("no Rich header" in f.detail for f in r.findings))


if __name__ == "__main__":
    unittest.main()


class TestVendorContradiction(unittest.TestCase):
    def test_microsoft_claim_with_foreign_linker_flagged(self):
        """Forged-vendor path: _version_strings monkeypatched (synthesizing a
        full RT_VERSION resource for one branch is not worth the fixture)."""
        import tempfile
        from pecheck import peparse
        from pecheck.detectors import provenance
        d = tempfile.mkdtemp(prefix="pecheck_vc_")
        p = make_rich_pe(os.path.join(d, "forged.exe"), entries=[(0x94, 100)])
        t = peparse.load(p)
        orig = provenance._version_strings
        provenance._version_strings = lambda pe: {"CompanyName": "Microsoft Corporation",
                                                  "ProductName": "Windows"}
        try:
            findings = provenance.run(t)
        finally:
            provenance._version_strings = orig
        self.assertTrue(any("contradicts the vendor" in f.detail or
                            "claiming vendor identity" in f.detail for f in findings))

    def test_msvc_linker_no_contradiction(self):
        import tempfile
        from pecheck import peparse
        from pecheck.detectors import provenance
        d = tempfile.mkdtemp(prefix="pecheck_vc2_")
        p = make_rich_pe(os.path.join(d, "real.exe"), entries=[(1, 0x25B8), (0x93, 200)])
        t = peparse.load(p)
        orig = provenance._version_strings
        provenance._version_strings = lambda pe: {"CompanyName": "Microsoft Corporation"}
        try:
            findings = provenance.run(t)
        finally:
            provenance._version_strings = orig
        self.assertFalse([f for f in findings if "vendor identity" in f.detail])
