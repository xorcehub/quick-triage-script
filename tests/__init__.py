"""Test package: keep scan-history bookkeeping out of the real HOME dir."""
import os
import tempfile

os.environ.setdefault("PECHECK_HISTORY",
                      os.path.join(tempfile.mkdtemp(prefix="pecheck_test_hist_"), "history.json"))
