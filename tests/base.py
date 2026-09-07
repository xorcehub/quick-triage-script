"""Shared fixture: one mixed download-folder corpus per test class."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.gen import build_folder  # noqa: E402


class CorpusTest(unittest.TestCase):
    """Builds gen.build_folder corpus into a class tmpdir; helper get(name)."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="pecheck_test_")
        build_folder(cls.dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    @classmethod
    def path(cls, name):
        return os.path.join(cls.dir, name)

    @classmethod
    def report(cls, name):
        from pecheck.scan import scan_file
        return scan_file(cls.path(name))
