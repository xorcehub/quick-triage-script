"""Plan 1.4: OOXML maldoc markers inside the zip detector (in-memory docx fixtures)."""
import io
import os
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pecheck.model import Target  # noqa: E402
from pecheck.detectors import archive  # noqa: E402


def docx(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        for name, data in members:
            z.writestr(name, data)
    return Target(path="mal.docx", size=buf.tell(), sha256="0" * 64, kind="ZIP", raw=buf.getvalue())


def findings(t):
    return archive.run(t)


class TestOOXML(unittest.TestCase):
    def test_macro_updatefields_combo_critical(self):
        t = docx([("word/vbaProject.bin", b"\xd0\xcf\x11\xe0 garbage"),
                  ("word/settings.xml", "<w:settings><w:updateFields w:val=\"true\"/></w:settings>")])
        f = findings(t)
        crit = [x for x in f if x.severity == "CRITICAL"]
        self.assertTrue(any("updateFields" in x.detail for x in crit))

    def test_vba_only_is_note(self):
        t = docx([("word/vbaProject.bin", b"\xd0\xcf\x11\xe0 garbage"),
                  ("word/settings.xml", "<w:settings/>")])
        f = findings(t)
        self.assertTrue(any("VBA project" in x.detail and x.severity != "CRITICAL" for x in f))
        self.assertFalse([x for x in f if "updateFields" in x.detail])

    def test_plain_docx_stays_clean(self):
        t = docx([("word/document.xml", "<w:document><w:body><w:p>hi</w:p></w:body></w:document>"),
                  ("word/settings.xml", "<w:settings/>")])
        f = findings(t)
        self.assertFalse([x for x in f if x.category.startswith("DOC")])

    def test_dde_field_critical(self):
        t = docx([("word/document.xml",
                   "<w:p><w:fldChar/><w:instrText> DDEAUTO cmd /c calc </w:instrText></w:p>")])
        crit = [x for x in findings(t) if x.severity == "CRITICAL"]
        self.assertTrue(any("DDE" in x.detail for x in crit))

    def test_external_file_rel_critical(self):
        t = docx([("_rels/.rels", '<Relationship Target="file://c:/x/evil.bin" '
                                  'TargetMode="External" Type="t"/>')])
        crit = [x for x in findings(t) if x.severity == "CRITICAL"]
        self.assertTrue(any("file://" in x.detail for x in crit))

    def test_plain_hyperlink_rel_not_critical(self):
        t = docx([("word/_rels/document.xml.rels",
                   '<Relationship Target="https://example.com/page" '
                   'TargetMode="External" Type=".../hyperlink"/>')])
        f = findings(t)
        self.assertFalse([x for x in f if x.severity == "CRITICAL" and "relationship" in x.detail])

    def test_embedded_pe_bin_critical(self):
        # MZ hidden behind .bin member: existing head-sniff path must catch it
        mz = b"MZ" + b"\x00" * 0x3e + b"\x80\x00\x00\x00" + b"PE\x00\x00" + b"\x00" * 64
        t = docx([("word/embeddings/oleObject1.bin", mz)])
        crit = [x for x in findings(t) if x.severity == "CRITICAL"]
        self.assertTrue(any("hidden" in x.detail for x in crit))


if __name__ == "__main__":
    unittest.main()
