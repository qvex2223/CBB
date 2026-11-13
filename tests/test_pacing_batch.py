"""Regression: one invocation carrying N URLs must consume N slots of the budget.

`bbcurl` called `wait_turn()` once and then handed curl a whole list of URLs, which
curl fires back to back — so a multi-URL batch under-paced the programme by a factor
of N until 2026-11-04. The fix is two-sided: the broker advances the shared budget to
the END of the batch, and bbcurl injects curl's own `--rate` so the batch is spaced
internally as well.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import pacing  # noqa: E402


class BatchConsumesTheWholeBudget(unittest.TestCase):
    def _engagement(self, tmp: Path) -> pacing.Engagement:
        proj = tmp / "Targets" / "demo"
        proj.mkdir(parents=True)
        (proj / "profile.json").write_text(json.dumps({"min_interval_seconds": 0.5}))
        eng = pacing.Engagement(proj)
        eng.state_dir = tmp / "pacing"
        return eng

    def test_last_fire_is_pushed_past_the_whole_batch(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            eng = self._engagement(tmp)
            now = 1000.0
            eng.wait_turn(now=lambda: now, requests=4)
            state = json.loads((eng._state_path()).read_text())
            # 4 requests, 0.5 s apart: the next caller must wait past the 4th.
            self.assertAlmostEqual(state["last_fire"], now + 3 * 0.5, places=6)
            self.assertEqual(state["count"], 4)

    def test_single_request_is_unchanged(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            eng = self._engagement(tmp)
            now = 2000.0
            eng.wait_turn(now=lambda: now)
            state = json.loads((eng._state_path()).read_text())
            self.assertAlmostEqual(state["last_fire"], now, places=6)
            self.assertEqual(state["count"], 1)


if __name__ == "__main__":
    unittest.main()
