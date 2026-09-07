import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.base import CorpusTest  # noqa: E402


class TestScripts(CorpusTest):
    def crit(self, name):
        r = self.report(name)
        return [f.detail for f in r.findings if f.severity == "CRITICAL"], r.verdict

    def test_ps1_download_execute_review(self):
        crit, v = self.crit("dropper.ps1")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("download+execute" in d for d in crit))

    def test_ps1_decode_execute_review(self):
        crit, v = self.crit("decoder.ps1")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("decode+execute" in d for d in crit))

    def test_ps1_amsi_tamper_review(self):
        crit, v = self.crit("tamper.ps1")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("tamper" in d.lower() for d in crit))

    def test_benign_ps1_ok(self):
        r = self.report("benign.ps1")
        self.assertEqual(r.verdict, "ok")

    def test_bat_certutil_combo_review(self):
        crit, v = self.crit("dl.bat")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("batch dropper combo" in d for d in crit))

    def test_benign_bat_ok(self):
        self.assertEqual(self.report("benign.bat").verdict, "ok")

    def test_vbs_dropper_trio_review(self):
        crit, v = self.crit("dropper.vbs")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("dropper trio" in d for d in crit))

    def test_vbe_encoded_review(self):
        crit, v = self.crit("enc.vbe")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("encoded script" in d for d in crit))

    def test_reg_runkey_review(self):
        crit, v = self.crit("run.reg")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("Run key" in d for d in crit))

    def test_url_local_target_review(self):
        crit, v = self.crit("evil.url")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("local file" in d for d in crit))

    def test_good_url_not_review(self):
        r = self.report("good.url")
        self.assertNotEqual(r.verdict, "REVIEW")

    def test_lnk_powershell_args_review(self):
        crit, v = self.crit("readme.lnk")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("LNK arguments" in d for d in crit))

    def test_lnk_game_target_ok(self):
        r = self.report("game.lnk")
        self.assertNotEqual(r.verdict, "REVIEW")


if __name__ == "__main__":
    unittest.main()
