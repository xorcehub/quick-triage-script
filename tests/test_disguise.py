"""Quick-win triage: extension/content mismatch disguise, bidi (RTLO)
filename spoof, exfil webhook URLs."""
import os
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.gen import craft_pe  # noqa: E402
from pecheck.scan import scan_file  # noqa: E402


class TestDisguise(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="pecheck_disguise_")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _scan(self, name, data=None, builder=None, sig=None):
        p = os.path.join(self.dir, name)
        if builder:
            builder(p)
        else:
            with open(p, "wb") as f:
                f.write(data)
        return scan_file(p, sig=sig)

    def crit(self, r):
        return [f.detail for f in r.findings if f.severity == "CRITICAL"]

    # -- 1: executable content behind a decoy extension --------------------

    def test_pe_disguised_as_jpeg_review(self):
        r = self._scan("vacation.jpg", builder=lambda p: craft_pe(p, imports=("CreateFileA",)))
        self.assertTrue(any("content mismatch" in d for d in self.crit(r)))
        self.assertEqual(r.verdict, "REVIEW")

    def test_uppercase_decoy_ext_flagged(self):
        r = self._scan("vacation.JPG", builder=lambda p: craft_pe(p, imports=("CreateFileA",)))
        self.assertTrue(any("content mismatch" in d for d in self.crit(r)))

    def test_elf_disguised_as_pdf_review(self):
        r = self._scan("invoice.pdf", b"\x7fELF" + b"\x00" * 0x40 + b"meh")  # ELF-kind bytes
        self.assertTrue(any("ELF executable" in d and "content mismatch" in d for d in self.crit(r)))
        self.assertEqual(r.verdict, "REVIEW")

    def test_real_dos_disguise_flagged(self):
        raw = bytearray(b"MZ" + b"\x00" * 0x3E + b"\x00" * 64)  # sane e_lfanew, no PE sig
        struct.pack_into("<I", raw, 0x3C, 0x40)
        r = self._scan("photo.jpg", bytes(raw))
        self.assertTrue(any("DOS MZ executable" in d for d in self.crit(r)))

    def test_random_mz_bytes_not_flagged(self):
        r = self._scan("photo.jpg", b"MZ" + b"\xff" * 62)  # DOS kind, insane e_lfanew
        self.assertFalse(any("content mismatch" in f.detail for f in r.findings))

    def test_real_image_not_flagged(self):
        r = self._scan("photo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
        self.assertFalse(any("content mismatch" in f.detail for f in r.findings))
        self.assertEqual(r.verdict, "ok")

    def test_pe_with_exec_ext_not_flagged(self):
        r = self._scan("tool.exe", builder=lambda p: craft_pe(p, imports=("CreateFileA",)))
        self.assertFalse(any("content mismatch" in f.detail for f in r.findings))

    def _scan_name(self, name, data=None):
        """_scan, but falls back to an in-memory Target when the AV refuses to
        read the file: Defender persistently blocks reads of some bidi-named
        files (EINVAL), and the findings under test here are filename-derived,
        not content-derived. Skips only peparse I/O (covered everywhere else)."""
        p = os.path.join(self.dir, name)
        with open(p, "wb") as f:
            f.write(data)
        r = scan_file(p)
        if r.verdict != "error":
            return r
        from pecheck.model import Target
        from pecheck.scan import _scan_target
        t = Target(path=p, size=len(data), sha256="0" * 64,
                   raw=data, kind="DATA")
        return _scan_target(t, [], None)

    # -- 2: bidi (RTLO) filename spoof --------------------------------------

    def test_rtlo_filename_review(self):
        r = self._scan_name("Q3\u202egnp.scr", b"payload bytes\r\n")
        self.assertTrue(any("bidi override" in d and "u202e" in d for d in self.crit(r)))
        self.assertEqual(r.verdict, "REVIEW")

    def test_lro_variant_flagged(self):
        r = self._scan_name("a\u202db.exe", b"hello\r\n")
        self.assertTrue(any("bidi override" in d and "u202d" in d for d in self.crit(r)))
        self.assertEqual(r.verdict, "REVIEW")

    def test_isolate_variant_flagged(self):
        r = self._scan_name("a\u2066gpj.exe", b"hello\r\n")
        self.assertTrue(any("bidi override" in d and "u2066" in d for d in self.crit(r)))

    def test_clean_name_not_flagged(self):
        r = self._scan("plain.txt", b"hello\r\n")
        self.assertFalse(any("bidi" in f.detail for f in r.findings))

    # -- 3: exfil webhook URLs ----------------------------------------------

    _HOOK = b"https://discord.com/api/webhooks/1234567890/AbCdEf-token-x9\r\n"

    def test_webhook_in_binary_critical(self):
        p = os.path.join(self.dir, "game.exe")
        craft_pe(p, imports=("CreateFileA",))
        with open(p, "ab") as f:
            f.write(self._HOOK)
        r = scan_file(p)
        hits = [f for f in r.findings if f.detail.startswith("exfil webhook")]
        self.assertTrue(hits and hits[0].severity == "CRITICAL")
        self.assertIn("discord.com", hits[0].detail)
        self.assertEqual(r.verdict, "REVIEW")

    def test_webhook_valid_signature_downgraded(self):
        p = os.path.join(self.dir, "signed.exe")
        craft_pe(p, imports=("CreateFileA",))
        with open(p, "ab") as f:
            f.write(self._HOOK)
        r = scan_file(p, sig=("Valid", "Discord Inc."))
        hits = [f for f in r.findings if f.detail.startswith("exfil webhook")]
        self.assertTrue(hits and hits[0].severity == "note")
        self.assertEqual(r.verdict, "ok")

    def test_webhook_in_script_note(self):
        r = self._scan("notify.ps1", b"$r = Invoke-WebRequest -Uri '" + self._HOOK.strip() + b"'\r\n")
        hits = [f for f in r.findings if f.detail.startswith("exfil webhook")]
        self.assertTrue(hits and hits[0].severity == "note")
        self.assertNotEqual(r.verdict, "REVIEW")

    def test_utf16_webhook_caught(self):
        r = self._scan("notes.txt", self._HOOK.decode().encode("utf-16-le"))
        hits = [f for f in r.findings if f.detail.startswith("exfil webhook")]
        self.assertTrue(hits)

    def test_telegram_and_slack_hook_patterns(self):
        corpus = (b"https://api.telegram.org/bot110201543:AAHdqTcvCH1vGWJxfSeofSAsKkPAL\r\n"
                  b"https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXX\r\n")
        r = self._scan("hooks.txt", corpus)
        d = " ".join(f.detail for f in r.findings if f.detail.startswith("exfil webhook"))
        self.assertIn("api.telegram.org", d)
        self.assertIn("hooks.slack.com", d)

    def test_plain_urls_not_webhook(self):
        r = self._scan("site.ps1", b"Invoke-WebRequest https://store.steampowered.com/x\r\n")
        self.assertFalse(any("webhook" in f.detail for f in r.findings))


if __name__ == "__main__":
    unittest.main()
