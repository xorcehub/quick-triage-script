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

    # ---- v1.2: obfuscation-resistance, smuggling, peek, persistence, lolbas

    def test_backtick_obfuscation_review(self):
        crit, v = self.crit("backtick.ps1")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("download+execute" in d for d in crit))

    def test_ec_short_flag_and_b64_payload(self):
        crit, v = self.crit("enc2.bat")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("batch dropper combo" in d for d in crit))
        self.assertTrue(any("decoded base64 payload" in d for d in crit))

    def test_b64peek_details_payload(self):
        r = self.report("peek.ps1")
        crit = [f.detail for f in r.findings if f.severity == "CRITICAL"]
        self.assertTrue(any("decoded base64 payload" in d and "powershell" in d for d in crit))

    def test_schtasks_persist(self):
        r = self.report("task.bat")
        self.assertTrue(any(f.category.startswith("PERSIST") and "schtasks" in f.detail
                            for f in r.findings))

    def test_wsf_wsh_shell(self):
        r = self.report("wsh.wsf")
        self.assertEqual(r.kind, "SCRIPT")
        self.assertTrue(any("WSH" in f.detail or "shell" in f.detail.lower()
                            for f in r.findings))

    def test_html_smuggling_review(self):
        crit, v = self.crit("smuggle.html")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("smuggling" in d for d in crit))

    def test_mht_smuggling_review(self):
        crit, v = self.crit("smuggle.mht")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("smuggling" in d for d in crit))

    def test_xhtml_smuggling_review(self):
        crit, v = self.crit("smuggle.xhtml")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("smuggling" in d for d in crit))

    def test_renamed_shell_script_review(self):
        crit, v = self.crit("renamed.sh.txt")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("piped straight into shell" in d for d in crit))

    def test_renamed_python_script_review(self):
        crit, v = self.crit("renamed.py.txt")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("download" in d.lower() for d in crit))

    def test_renamed_php_review(self):
        crit, v = self.crit("renamed.php.txt")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("webshell" in d for d in crit))

    def test_php_webshell_review(self):
        crit, v = self.crit("shell.php")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("webshell" in d for d in crit))

    def test_scf_unc_leak(self):
        r = self.report("leak.scf")
        self.assertEqual(r.kind, "SCRIPT")
        self.assertTrue(any("UNC" in f.detail for f in r.findings))

    def test_settingcontent_ms_args_review(self):
        crit, v = self.crit("evil.settingcontent-ms")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("settingcontent-ms" in d for d in crit))

    def test_library_ms_unc(self):
        r = self.report("lure.library-ms")
        self.assertEqual(r.kind, "SCRIPT")
        self.assertTrue(any("UNC" in f.detail for f in r.findings))

    def test_sh_command_substitution_review(self):
        crit, v = self.crit("pipe.sh")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("command-substitution" in d for d in crit))

    def test_py_reverse_shell_review(self):
        crit, v = self.crit("rev.py")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("reverse-shell" in d for d in crit))

    def test_bat_ps_one_liner_review(self):
        crit, v = self.crit("oneliner.bat")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("batch dropper combo" in d for d in crit))

    def test_concat_split_exec_review(self):
        crit, v = self.crit("concat.ps1")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("download+execute" in d for d in crit))

    def test_reg_winlogon_hijack_review(self):
        crit, v = self.crit("winlogon.reg")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("Winlogon" in d for d in crit))

    def test_reg_service_imagepath_review(self):
        crit, v = self.crit("svc.reg")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("ImagePath" in d for d in crit))

    def test_ps_tcpclient_revshell_review(self):
        crit, v = self.crit("tcpclient.ps1")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("reverse-shell" in d for d in crit))

    def test_sh_nc_e_revshell_review(self):
        crit, v = self.crit("ncshell.sh")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("netcat" in d for d in crit))

    def test_sh_sudo_pipe_review(self):
        crit, v = self.crit("sudopipe.sh")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("piped straight into shell" in d for d in crit))

    def test_gzipped_b64_payload_review(self):
        crit, v = self.crit("gzpeek.ps1")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("decoded base64 payload" in d for d in crit))

    # ---- false-positive side: benign look-alikes stay clean

    def test_benign_html_atob_ok(self):
        r = self.report("chart.html")
        self.assertEqual(r.verdict, "ok")

    def test_benign_py_socket_server_ok(self):
        self.assertEqual(self.report("serve.py").verdict, "ok")

    def test_benign_sh_curl_to_file_not_critical(self):
        r = self.report("dl.sh")
        self.assertNotEqual(r.verdict, "REVIEW")
        self.assertFalse(any("command-substitution" in f.detail for f in r.findings))

    def test_good_url_not_review(self):
        r = self.report("good.url")
        self.assertNotEqual(r.verdict, "REVIEW")

    def test_url_unc_icon_leak_note(self):
        r = self.report("uncicon.url")
        self.assertEqual(r.verdict, "note")   # lure-worthy but not REVIEW
        self.assertTrue(any("UNC" in f.detail for f in r.findings))

    def test_lnk_unc_leak_note(self):
        # game.lnk targets a local exe - no UNC - stays clean
        r = self.report("game.lnk")
        self.assertFalse(any("UNC" in f.detail for f in r.findings))

    def test_lnk_powershell_args_review(self):
        crit, v = self.crit("readme.lnk")
        self.assertEqual(v, "REVIEW")
        self.assertTrue(any("LNK arguments" in d for d in crit))

    def test_lnk_game_target_ok(self):
        r = self.report("game.lnk")
        self.assertNotEqual(r.verdict, "REVIEW")


if __name__ == "__main__":
    unittest.main()
