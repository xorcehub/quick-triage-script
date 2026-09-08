"""Plan 2.6: overlapping sections, checksum-on-signed, non-standard W+X name."""
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.gen import craft_pe  # noqa: E402
from pecheck import peparse  # noqa: E402
from pecheck.scan import scan_file  # noqa: E402


def overlapping_pe(path):
    """craft_pe, then add a second section overlapping the first's raw range."""
    craft_pe(path)
    data = bytearray(open(path, "rb").read())
    # original section header sits right after the optional header; append another
    sh_off = 0x80 + 4 + 20 + 0xF0
    old = data[sh_off:sh_off + 40]
    name, vs, rva, rs, rp = b".sec2", 0x200, 0x2000, 0x600, 0x400  # rp+rs overlaps [0x400..0xA00) vs [0x400..0xA00)
    new = struct.pack("<8sIIIIIIHHI", name, vs, rva, rs, rp, 0, 0, 0, 0, 0x60000020)
    data[sh_off + 40:sh_off + 40] = new
    # bump NumberOfSections
    n, = struct.unpack_from("<H", data, 0x80 + 6)
    struct.pack_into("<H", data, 0x80 + 6, n + 1)
    open(path, "wb").write(data)
    return path


class TestOverlaps(unittest.TestCase):
    def test_overlap_flagged(self):
        d = tempfile.mkdtemp(prefix="pecheck_ov_")
        r = scan_file(overlapping_pe(os.path.join(d, "ov.exe")))
        self.assertTrue(any("overlap raw ranges" in f.detail for f in r.findings))

    def test_normal_no_overlap_finding(self):
        d = tempfile.mkdtemp(prefix="pecheck_ov2_")
        r = scan_file(craft_pe(os.path.join(d, "ok.exe")))
        self.assertFalse([f for f in r.findings if "overlap" in f.detail])


class TestChecksum(unittest.TestCase):
    def test_mismatch_on_cert_pe_noted(self):
        d = tempfile.mkdtemp(prefix="pecheck_cs_")
        p = craft_pe(os.path.join(d, "signed.exe"), cert_dir=True)
        data = bytearray(open(p, "rb").read())
        # set a wrong header checksum (nonzero, not the computed value)
        is64 = True
        struct.pack_into("<I", data, 0x80 + 4 + 20 + 64, 0xDEADBEEF)
        open(p, "wb").write(data)
        r = scan_file(p)
        self.assertTrue(any("CheckSum" in f.detail and "!=" in f.detail for f in r.findings))

    def test_unsigned_no_checksum_finding(self):
        d = tempfile.mkdtemp(prefix="pecheck_cs2_")
        p = craft_pe(os.path.join(d, "unsigned.exe"))
        data = bytearray(open(p, "rb").read())
        struct.pack_into("<I", data, 0x80 + 4 + 20 + 64, 0xDEADBEEF)
        open(p, "wb").write(data)
        r = scan_file(p)
        self.assertFalse([f for f in r.findings if "CheckSum" in f.detail])


SH_OFF = 0x80 + 4 + 20 + 0xF0  # section headers: after sig + file + optional hdr


def wx_pe(path, section):
    """craft_pe with the section flipped to writable+executable."""
    craft_pe(path, section=section)
    data = bytearray(open(path, "rb").read())
    struct.pack_into("<I", data, SH_OFF + 36, 0xE0000060)  # CODE|EXEC|READ|WRITE
    open(path, "wb").write(data)
    return path


class TestWXName(unittest.TestCase):
    def test_nonstandard_wx_name(self):
        d = tempfile.mkdtemp(prefix="pecheck_wx_")
        r = scan_file(wx_pe(os.path.join(d, "wx.exe"), b".thunk"))
        self.assertTrue(any("writable+executable" in f.detail and "non-standard" in f.detail
                            for f in r.findings))

    def test_standard_wx_name_plain(self):
        d = tempfile.mkdtemp(prefix="pecheck_wx2_")
        r = scan_file(wx_pe(os.path.join(d, "wx.exe"), b".text"))
        hits = [f for f in r.findings if "writable+executable" in f.detail]
        self.assertTrue(hits)
        self.assertFalse(any("non-standard" in f.detail for f in hits))


if __name__ == "__main__":
    unittest.main()
