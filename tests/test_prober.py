"""Plan 1.6: compressed-stream prober (fixtures built in-test with stdlib)."""
import bz2
import io
import lzma
import os
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pecheck.detectors import raw  # noqa: E402
from pecheck.model import Target, CRITICAL  # noqa: E402
from pecheck.scan import scan_file  # noqa: E402

# valid embedded-PE fixture: e_lfanew=0x80 set at 0x3C, sig at 0x80
# MZ | e_lfanew(0x80) at 0x3C | PE\0\0 at 0x80 - satisfies raw._valid_pe_at
MZ = (b"MZ" + b"\x00" * 0x3a + b"\x80\x00\x00\x00" + b"\x00" * 0x40
      + b"PE\x00\x00" + b"A" * 4096)


def target(kind, data, path="f.bin"):
    return Target(path=path, size=len(data), sha256="0" * 64, kind=kind, raw=data)


class TestProber(unittest.TestCase):
    def test_gzip_mz_appended_to_text_critical(self):
        payload = zlib.compress(MZ, 9)[2:-4]  # strip to raw deflate? no - keep gzip
        buf = io.BytesIO()
        with __import__("gzip").open(buf, "wb", compresslevel=9) as f:
            f.write(MZ)
        data = b"plain readme text " * 200 + buf.getvalue()
        f = raw.run(target("TEXT", data, "readme.txt"))
        crit = [x for x in f if x.severity == CRITICAL and "decompressed" in x.detail]
        self.assertTrue(crit)
        self.assertIn("PE executable", crit[0].detail)

    def test_zlib_stream_in_data(self):
        data = b"\x00" * 64 + zlib.compress(b"#!/bin/sh\n" + b"curl x | sh\n" * 400, 9) \
            + b"trailing filler " * 300
        f = raw.run(target("DATA", data))
        crit = [x for x in f if x.severity == CRITICAL and "decompressed" in x.detail]
        self.assertTrue(any("script" in x.detail for x in crit))

    def test_xz_stream_note(self):
        data = b"JUNKJUNK" * 300 + lzma.compress(b"document content " * 512)
        f = raw.run(target("DATA", data))
        self.assertTrue(any("xz" in x.detail and "decompressible" in x.detail for x in f))

    def test_bzip2_stream(self):
        data = b"xx" * 1024 + bz2.compress(b"B" * 10000, 9)
        f = raw.run(target("DATA", data))
        self.assertTrue(any("bzip2" in x.detail for x in f))

    def test_high_entropy_random_gains_nothing(self):
        rnd = os.urandom(256 * 1024)
        f = [x for x in raw.run(target("DATA", rnd)) if "decompress" in x.detail]
        self.assertEqual(f, [])  # entropy window may speak; prober must not

    def test_scan_file_integration(self):
        d = tempfile.mkdtemp(prefix="pecheck_pr_")
        p = os.path.join(d, "readme.txt")
        buf = io.BytesIO()
        with __import__("gzip").open(buf, "wb") as f:
            f.write(MZ)
        open(p, "wb").write(b"hello " * 400 + buf.getvalue())
        r = scan_file(p)
        self.assertEqual(r.verdict, "REVIEW")
        self.assertTrue(any("decompressed payload" in x.detail for x in r.findings))


if __name__ == "__main__":
    unittest.main()
