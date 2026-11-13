"""`CBH_PROJECT` must name an engagement regardless of where the shell stands.

`find_project_dir()` walked up from the cwd looking for `<parent>/Targets/<name>`, so a
worker running from a scratchpad directory outside the workspace tree resolved to `None`.
`bbcurl` then refused every request — correctly, and with exit 3 — but the refusal text
went only to stderr. A sweep wrapper that discarded both stderr and the exit code read
that as a clean run and emitted a 142-row table of 404s having fired nothing at all
(konsol, 2026-10-18).

That is this workspace's recurring failure shape, and the third instance in one session:
a path that resolves to nothing, exits clean, and reports success. The brakes were never
the problem — the silence was. `CBH_PROJECT` now resolves against `targets_root()` first,
and the refusal names which of the two causes actually applied.
"""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "engine"))

import pacing  # noqa: E402
from paths import targets_root  # noqa: E402


def _an_engagement() -> str | None:
    """Any real engagement name, nested or flat, or None if the tree has none."""
    root = targets_root()
    for depth in ("*", "*/*"):
        for p in sorted(root.glob(f"{depth}/profile.json")):
            return p.parent.relative_to(root).as_posix()
    return None


class CbhProjectCwdIndependenceTests(unittest.TestCase):
    def setUp(self):
        self.name = _an_engagement()
        if not self.name:
            self.skipTest("no engagement with a profile.json in this tree")
        self._saved = os.environ.get("CBH_PROJECT")
        os.environ["CBH_PROJECT"] = self.name

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("CBH_PROJECT", None)
        else:
            os.environ["CBH_PROJECT"] = self._saved

    def test_resolves_from_a_directory_outside_the_workspace(self):
        # The exact condition that fired zero requests while looking like clean data.
        outside = Path(os.environ.get("TMPDIR", "/tmp")).resolve()
        got = pacing.find_project_dir(start=outside)
        self.assertIsNotNone(
            got, "CBH_PROJECT must resolve from a cwd outside the workspace tree")
        self.assertEqual(got, targets_root() / self.name)

    def test_resolves_from_the_filesystem_root(self):
        got = pacing.find_project_dir(start=Path("/"))
        self.assertEqual(got, targets_root() / self.name)

    def test_resolves_the_same_from_inside_the_engagement(self):
        inside = targets_root() / self.name
        self.assertEqual(pacing.find_project_dir(start=inside), inside)

    def test_an_unresolvable_name_still_returns_none(self):
        os.environ["CBH_PROJECT"] = "definitely-not-an-engagement-zzz"
        self.assertIsNone(pacing.find_project_dir(start=targets_root()))

    def test_bbcurl_refusal_names_the_actual_cause_and_exits_nonzero(self):
        bbcurl = REPO / "scripts" / "bbcurl"
        if not bbcurl.is_file():
            self.skipTest("scripts/bbcurl not present")
        env = dict(os.environ, CBH_PROJECT="definitely-not-an-engagement-zzz")
        p = subprocess.run(
            [sys.executable, str(bbcurl), "-s", "-o", "/dev/null",
             "--bb-dry-run", "https://example.com/"],
            capture_output=True, text=True, env=env, cwd="/", timeout=60)
        self.assertEqual(p.returncode, 3, p.stderr)
        # It must say the NAME did not resolve, not that the variable is unset.
        self.assertIn("definitely-not-an-engagement-zzz", p.stderr)
        self.assertNotIn("$CBH_PROJECT is unset", p.stderr)


if __name__ == "__main__":
    unittest.main()
