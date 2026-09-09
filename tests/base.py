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
        from pecheck.scan import _scan_target  # fixture: per-file scan + sibling context
        from pecheck import peparse
        t = peparse.load(cls.path(name))
        sibs = [f.lower() for f in os.listdir(cls.dir)
                if os.path.isfile(os.path.join(cls.dir, f))]
        return _scan_target(t, sibs, None)
