"""`cbh diff` must not crash when every stored body is identical.

The one-distinct-body branch was gated on `requests >= 3`, so **two** requests returning the
same body fell through to `hashes[-2]` and died with `IndexError: list index out of range`
(`cbh/cli.py`). That is the worst possible place for a crash: it happened while checking whether
an endpoint reflected a swapped `Host` header, where "the answer never moved" **was** the result
being looked for. A tool whose job is to say "nothing reacted" must be able to say it.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


class CbhDiffSingleBodyTests(unittest.TestCase):
    def _run(self, n_requests: int):
        """Seed a memory dir with n identical-body audit rows, then run `cbh diff`."""
        tmp = Path(tempfile.mkdtemp())
        eng = "konsol"
        (tmp / "responses" / eng).mkdir(parents=True)
        body = "HTTP/1.1 200 OK\n\nsame body every time\n"
        import hashlib
        h = hashlib.sha256(body.encode()).hexdigest()
        (tmp / "responses" / eng / f"{h}.txt").write_text(body)
        with (tmp / "audit.jsonl").open("w") as fh:
            for i in range(n_requests):
                fh.write(json.dumps({
                    "source": "bbcurl", "engagement": eng, "http_code": 200,
                    "url_effective": "https://example.test/sso/request",
                    "body_sha256": h, "body_bytes": len(body), "body_stored": True,
                    "timestamp": f"2026-10-18T0{i}:00:00+00:00",
                }) + "\n")
        env = dict(os.environ, CBH_MEMORY_DIR=str(tmp))
        return subprocess.run(
            [sys.executable, "-m", "cbh.cli", "diff", "sso/request", "--engagement", eng],
            capture_output=True, text=True, env=env, cwd=str(REPO), timeout=120)

    def test_two_identical_bodies_does_not_crash(self):
        p = self._run(2)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("IndexError", p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.assertIn("ONE distinct body", p.stdout)

    def test_one_body_does_not_crash(self):
        p = self._run(1)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("Traceback", p.stderr)

    def test_three_identical_bodies_still_gives_the_rotate_signal(self):
        p = self._run(3)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("not reacting to input", p.stdout)
        self.assertIn("rotate signal", p.stdout)


if __name__ == "__main__":
    unittest.main()
