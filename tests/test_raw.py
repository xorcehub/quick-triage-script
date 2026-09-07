import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.base import CorpusTest  # noqa: E402
from pecheck.model import Target  # noqa: E402
from pecheck.detectors.raw import run  # noqa: E402


def raw_findings(name_or_bytes, path="/tmp/raw_t.bin", kind=None):
    from pecheck.identify import kind as ikind
    if isinstance(name_or_bytes, bytes):
        with open(path, "wb") as f:
            f.write(name_or_bytes)
    else:
        path = name_or_bytes
    with open(path, "rb") as f:
        data = f.read()
    t = Target(path=path, size=len(data), sha256="x",
               kind=kind or ikind(path, data[:4096]), raw=data)
    return run(t)


class TestRawEmbedded(CorpusTest):
    def test_embedded_pe_in_data_is_flagged(self):
        fs = raw_findings(self.path("asset.dat"))
        cats = [f.category for f in fs]
        self.assertIn("EMBED", cats)

    def test_embedded_pe_in_script_is_critical(self):
        pe = open(self.path("CoolGame-CODEX/game.exe"), "rb").read()
        fs = raw_findings(b"# comment\n" + pe, path="/tmp/raw_ps1.ps1")
        crit = [f for f in fs if f.severity == "CRITICAL"]
        self.assertTrue(any("embedded executable" in f.detail for f in crit))

    def test_coincidental_mz_not_flagged(self):
        # random MZ bytes without a PE sig at e_lfanew must not count
        fs = raw_findings(os.urandom(4096) + b"MZ" + os.urandom(4096))
        self.assertFalse(any("embedded executable" in f.detail for f in fs))

    def test_base64_mammoth(self):
        fs = raw_findings(self.path("encoded.txt"))
        self.assertTrue(any(f.category == "OBF" for f in fs))

    def test_entropy_blob_note(self):
        fs = raw_findings(self.path("nosig.bin"))
        self.assertTrue(any("entropy" in f.detail for f in fs))

    def test_dos_note(self):
        fs = raw_findings(b"MZ" + b"\x00" * 100, path="/tmp/raw_dos.bin")
        self.assertTrue(any("DOS/legacy" in f.detail for f in fs))

    def test_zip_container_skipped(self):
        fs = raw_findings(self.path("mod.zip"))
        self.assertEqual(fs, [])

    def test_stealer_escalation(self):
        fs = raw_findings(b"AppData\\Local\\Google\\Chrome\\User Data\\Login Data\x00"
                          b"wallet.dat\x00metamask\x00keystore", path="/tmp/raw_st.bin")
        crit = [f for f in fs if f.severity == "CRITICAL"]
        self.assertTrue(any("stealer" in f.detail for f in crit))


if __name__ == "__main__":
    unittest.main()
