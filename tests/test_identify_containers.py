import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pecheck.identify import kind  # noqa: E402
from tests.base import CorpusTest  # noqa: E402


class TestNewContainerMagics(CorpusTest):
    def _write(self, name, data):
        p = self.path(name)
        open(p, "wb").write(data)
        return p

    def test_cab(self):
        p = self._write("pkg.cab", b"MSCF" + b"\x00" * 32)
        self.assertEqual(kind(p), "CAB")

    def test_rpm(self):
        p = self._write("pkg.rpm", b"\xed\xab\xee\xdb" + b"\x03\x00" + b"\x00" * 32)
        self.assertEqual(kind(p), "RPM")

    def test_ar_deb(self):
        p = self._write("pkg.deb", b"!<arch>\n" + b"debian-binary   4\n")
        self.assertEqual(kind(p), "AR")

    def test_squashfs(self):
        p = self._write("img.squashfs", b"hsqs" + b"\x00" * 32)
        self.assertEqual(kind(p), "SQUASHFS")

    def test_tar_ustar_at_257(self):
        blk = bytearray(b"\x00" * 512)
        blk[257:262] = b"ustar"
        blk[0:8] = b"file.txt"  # name field, makes it look like a real header
        p = self._write("arc.tar", bytes(blk) + b"\x00" * 1024)
        self.assertEqual(kind(p), "TAR")

    def test_iso_pvd_at_0x8001(self):
        img = bytearray(b"\x00" * (0x8001 + 5))
        img[0x8000] = 1  # volume descriptor type
        img[0x8001:0x8006] = b"CD001"
        p = self._write("disc.iso", bytes(img))
        self.assertEqual(kind(p), "ISO")

    def test_short_file_not_iso(self):
        # files shorter than the PVD offset must not slice-match
        p = self._write("tiny.bin", b"\x00" * 100)
        self.assertEqual(kind(p), "DATA")

    def test_container_note_via_scan(self):
        from pecheck.scan import scan_file
        p = self._write("note.cab", b"MSCF" + b"\x00" * 64)
        r = scan_file(p)
        self.assertEqual(r.kind, "CAB")
        self.assertTrue(any("cab" in f.detail and "re-scan" in f.detail for f in r.findings))
        # raw detector must NOT scream "embedded executable" at container members
        self.assertFalse([f for f in r.findings if f.category == "EMBED"])


if __name__ == "__main__":
    unittest.main()
