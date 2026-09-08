"""Plan 2.2: Mach-O lite detector - synthetic thin/fat/garbage fixtures."""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pecheck.detectors import macholite  # noqa: E402
from pecheck.model import Target, CRITICAL  # noqa: E402

LC_LOAD_DYLIB = 0xC
LC_CODE_SIGNATURE = 0x1D


def thin_macho(dylibs=(), codesig=False, cputype=0x01000007):
    """Minimal 64-bit LE Mach-O: 32-byte header + load commands."""
    cmds = b""
    for d in dylibs:
        name = d.encode() + b"\x00"
        # dylib struct at cmd+8: lc_str name offset 24 (8 hdr + 4 fields), ts, ver, compat
        body = struct.pack("<IIII", 24, 0, 0, 0) + name
        pad = (-len(body)) % 8
        cmds += struct.pack("<II", LC_LOAD_DYLIB, 8 + len(body) + pad) + body + b"\x00" * pad
    if codesig:
        cmds += struct.pack("<II", LC_CODE_SIGNATURE, 16) + b"\x00" * 8
    ncmds = len(dylibs) + bool(codesig)
    hdr = struct.pack("<iiIIIII", cputype, 0, 2, ncmds, len(cmds), 0, 0)
    return b"\xcf\xfa\xed\xfe" + hdr + cmds + b"\x00" * 64


def fat_macho(n=2):
    return b"\xca\xfe\xba\xbe" + struct.pack(">I", n) + b"\x00" * (20 * n)


def target(data):
    return Target(path="dropper", size=len(data), sha256="0" * 64, kind="MACHO", raw=data)


class TestMachOLite(unittest.TestCase):
    def test_thin_header_line(self):
        f = macholite.run(target(thin_macho()))
        self.assertTrue(any("Mach-O 64-bit x86_64 executable" in x.detail for x in f))

    def test_dylib_paths_flagged(self):
        f = macholite.run(target(thin_macho(dylibs=("/usr/lib/libSystem.dylib",
                                                    "/Users/x/libinject.dylib"))))
        hit = [x for x in f if "non-system dylib" in x.detail]
        self.assertEqual(len(hit), 1)
        self.assertIn("libinject", hit[0].detail)

    def test_system_dylibs_not_flagged(self):
        f = macholite.run(target(thin_macho(dylibs=("/usr/lib/libSystem.dylib",))))
        self.assertFalse([x for x in f if "non-system dylib" in x.detail])

    def test_codesig_note(self):
        f = macholite.run(target(thin_macho(codesig=True)))
        self.assertTrue(any("LC_CODE_SIGNATURE" in x.detail and "NOT verified" in x.detail
                            for x in f))

    def test_fat_count(self):
        f = macholite.run(target(fat_macho(3)))
        self.assertTrue(any("3 architecture slice" in x.detail for x in f))

    def test_upx_critical(self):
        f = macholite.run(target(thin_macho()[:64] + b"UPX!" + b"\x00" * 64))
        self.assertTrue(any(x.severity == CRITICAL and "UPX" in x.detail for x in f))

    def test_garbage_no_crash(self):
        f = macholite.run(target(b"\xcf\xfa\xed\xfe" + os.urandom(16)))
        self.assertTrue(any("truncated" in x.detail for x in f))

    def test_fat_implausible_count(self):
        f = macholite.run(target(b"\xca\xfe\xba\xbe" + struct.pack(">I", 99999)))
        self.assertTrue(any("implausible" in x.detail for x in f))

    def test_fat_still_checks_markers(self):
        data = fat_macho(2) + b"UPX!" + b"\x00" * 32
        f = macholite.run(target(data))
        self.assertTrue(any(x.severity == CRITICAL and "UPX" in x.detail for x in f))


if __name__ == "__main__":
    unittest.main()
