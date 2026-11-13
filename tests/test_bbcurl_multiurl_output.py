"""Regression: bbcurl must refuse N URLs with a single plain -o.

curl writes only the FIRST body to that file and sends URLs 2..n to stdout; a body with
no trailing newline then swallows the next -w prefix, so statuses are attributed to the
WRONG URL. That produced a bogus 401 inside a 15-URL batch on 2026-11-05 and the batch had
to be re-fired one arm at a time. The refusal is cheaper than a wrong number in a write-up.
"""
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BBCURL = REPO / "scripts" / "bbcurl"
PROJ = REPO / "Targets" / "standoff365" / "wildberries"


def run(args):
    return subprocess.run([sys.executable, str(BBCURL), *args], capture_output=True,
                          text=True, cwd=str(PROJ),
                          env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home()),
                               "CBH_PROJECT": "standoff365/wildberries"})


@unittest.skipUnless(BBCURL.exists() and PROJ.exists(), "bbcurl or engagement missing")
class MultiUrlSingleOutput(unittest.TestCase):
    URLS = ["https://www.wildberries.ru/robots.txt", "https://seller.wildberries.ru/robots.txt"]

    def test_refused(self):
        r = run(["--bb-dry-run", "-s", "-o", "/tmp/zzqx-test.txt", *self.URLS])
        self.assertIn("refusing", r.stderr)
        self.assertNotIn("would run:", r.stdout)

    def test_multi_url_without_output_is_allowed(self):
        r = run(["--bb-dry-run", "-s", "-D", "-", *self.URLS])
        self.assertIn("would run:", r.stdout)

    def test_single_url_with_output_is_allowed(self):
        r = run(["--bb-dry-run", "-s", "-o", "/tmp/zzqx-test.txt", self.URLS[0]])
        self.assertIn("would run:", r.stdout)

    def test_single_dump_header_file_refused(self):
        # Same bug class, different flag: curl pools the header dumps for URLs 2..n into
        # one file instead of rotating it, so a per-URL header reading taken that way is
        # void. One lane discarded a whole b2b-gateway pass over this on 2026-11-05.
        r = run(["--bb-dry-run", "-s", "-D", "/tmp/zzqx-hdr.txt", *self.URLS])
        self.assertIn("refusing", r.stderr)
        self.assertNotIn("would run:", r.stdout)

    def test_dump_header_to_stream_is_allowed(self):
        r = run(["--bb-dry-run", "-s", "-D", "-", *self.URLS])
        self.assertIn("would run:", r.stdout)

    def test_output_template_is_allowed(self):
        r = run(["--bb-dry-run", "-s", "-o", "out-#1.txt", *self.URLS])
        self.assertIn("would run:", r.stdout)


if __name__ == "__main__":
    unittest.main()
