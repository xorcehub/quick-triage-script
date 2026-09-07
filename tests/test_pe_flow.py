import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.base import CorpusTest  # noqa: E402
from tests.gen import craft_pe, craft_forged_pe  # noqa: E402
from pecheck.scan import scan_targets, scan_file  # noqa: E402


class TestCraftedPE(CorpusTest):
    def test_inject_import_review(self):
        p = craft_pe(self.path("hijack.exe"), imports=("SetThreadContext",))
        r = scan_file(p)
        crit = [f for f in r.findings if f.severity == "CRITICAL"]
        self.assertTrue(any("SetThreadContext" in f.detail for f in crit))
        self.assertEqual(r.verdict, "REVIEW")

    def test_zero_imports_review(self):
        r = self.report("Invoice.pdf.exe")
        crit = [f for f in r.findings if f.severity == "CRITICAL"]
        self.assertTrue(any("0 imports" in f.detail for f in crit))

    def test_double_extension_review(self):
        r = self.report("Invoice.pdf.exe")
        crit = [f for f in r.findings if f.severity == "CRITICAL"]
        self.assertTrue(any("double extension" in f.detail for f in crit))

    def test_forged_pe_is_review_not_error(self):
        p = craft_forged_pe(self.path("forged.exe"))
        r = scan_file(p)
        self.assertEqual(r.kind, "PE")
        self.assertEqual(r.verdict, "REVIEW")
        self.assertTrue(any("PE parse error" in f.detail for f in r.findings))

    def test_twins_detected(self):
        a = craft_pe(self.path("twin_a.dll"), imports=("CreateFileA",), dll_chars=0x2102)
        b = craft_pe(self.path("twin_b.dll"), imports=("CreateFileW",), dll_chars=0x2102)
        res = scan_targets([a, b], use_sigs=False)
        twins = [r for r in res.reports if any("near-duplicate" in f.detail for f in r.findings)]
        self.assertEqual(len(twins), 2)

    def test_dedup_identical(self):
        a = craft_pe(self.path("dup1.exe"), imports=("CreateFileA",))
        shutil.copy(a, self.path("dup2.exe"))
        res = scan_targets([self.path("dup1.exe"), self.path("dup2.exe")], use_sigs=False)
        dups = [r for r in res.reports if r.duplicate_of]
        self.assertEqual(len(dups), 1)

    def test_sideload_name_critical(self):
        gd = os.path.join(self.dir, "sideloadtest")
        os.makedirs(gd, exist_ok=True)
        craft_pe(os.path.join(gd, "app.exe"), imports=("CreateFileA",))
        craft_pe(os.path.join(gd, "version.dll"), imports=("CreateFileA",), dll_chars=0x2102)
        res = scan_targets([gd], use_sigs=False)
        vrep = next(r for r in res.reports if r.basename == "version.dll")
        self.assertEqual(vrep.verdict, "REVIEW")
        self.assertTrue(any("sideload" in f.detail.lower() for f in vrep.findings))

    def test_steam_emu_context_noted(self):
        # context needs siblings -> folder scan, not single-file
        res = scan_targets([self.path("CoolGame-CODEX")], use_sigs=False)
        r = next(r for r in res.reports if r.basename == "steam_api64.dll")
        self.assertTrue(any(f.category == "CONTEXT" and "steam emulator" in f.detail
                            for f in r.findings))

    def test_scene_marker_noted(self):
        r = self.report("CoolGame-CODEX/game.exe")
        self.assertTrue(any(f.category == "CONTEXT" and "scene" in f.detail
                            for f in r.findings))


if __name__ == "__main__":
    unittest.main()
