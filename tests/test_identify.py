import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pecheck.identify import kind  # noqa: E402
from tests.base import CorpusTest  # noqa: E402


class TestCorpusKinds(CorpusTest):
    def test_kinds(self):
        expect = {
            "dropper.ps1": "SCRIPT", "decoder.ps1": "SCRIPT", "tamper.ps1": "SCRIPT",
            "benign.ps1": "SCRIPT", "dl.bat": "SCRIPT", "benign.bat": "SCRIPT",
            "dropper.vbs": "SCRIPT", "enc.vbe": "SCRIPT", "run.reg": "SCRIPT",
            "evil.url": "SCRIPT", "good.url": "SCRIPT",
            "readme.lnk": "LNK", "game.lnk": "LNK",
            "exploit.pdf": "PDF", "clean.pdf": "PDF",
            "evil.rtf": "RTF", "dde.rtf": "RTF",
            "macro.doc": "OLE", "boring.doc": "OLE",
            "mod.zip": "ZIP", "evil.zip": "ZIP",
            "asset.dat": "DATA", "encoded.txt": "TEXT", "nosig.bin": "DATA",
            "Invoice.pdf.exe": "PE",
            "CoolGame-CODEX/game.exe": "PE", "CoolGame-CODEX/steam_api64.dll": "PE",
        }
        for name, k in expect.items():
            self.assertEqual(kind(self.path(name)), k, name)

    def test_gzip_7z_rar_magic(self):
        import gzip as gz
        with gz.open(self.path("t.gz"), "wb") as f:
            f.write(b"data")
        self.assertEqual(kind(self.path("t.gz")), "GZIP")
        open(self.path("t.7z"), "wb").write(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 8)
        self.assertEqual(kind(self.path("t.7z")), "SEVENZ")
        open(self.path("t.rar"), "wb").write(b"Rar!\x1a\x07\x00" + b"\x00" * 8)
        self.assertEqual(kind(self.path("t.rar")), "RAR")

    def test_empty_and_missing(self):
        open(self.path("empty.bin"), "wb").close()
        self.assertEqual(kind(self.path("empty.bin")), "EMPTY")
        self.assertEqual(kind(self.path("nope.bin")), "DATA")

    def test_mz_without_pe_sig_is_dos(self):
        open(self.path("dos.exe"), "wb").write(b"MZ" + b"\x00" * 100)
        self.assertEqual(kind(self.path("dos.exe")), "DOS")

    def test_utf16_detects_text(self):
        open(self.path("u16.txt"), "wb").write("hello unicode\n".encode("utf-16le") * 10)
        self.assertEqual(kind(self.path("u16.txt")), "TEXT")


if __name__ == "__main__":
    unittest.main()
