"""The naive agent must be able to report inside its own turn budget.

`claude -p --max-turns N` does not return a final assistant message when it hits the
cap — `result` comes back empty. So passing the prompt's stated budget straight through
as the hard cap kills the run on the very turn it was told to summarize in. Two konsol
runs (2026-10-17) lost 41 and 71 turns of fired, paced, audited probing that way, each
landing as `agent error: claude exited 1` with `items: []` and no recoverable prose.

These tests pin the two halves of the fix: the prompt still states the work budget, and
the process cap sits strictly above it.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))

import freeroam  # noqa: E402


class FreeroamTurnHeadroomTests(unittest.TestCase):
    def _run_capturing(self, turns):
        seen = {}

        def fake_run_agent(task, **kw):
            seen["task"] = task
            seen["max_turns"] = kw.get("max_turns")
            return {"result": '```json\n[]\n```', "num_turns": 1}

        with mock.patch.object(freeroam, "run_agent", fake_run_agent):
            freeroam.run("https://example.com/", project=None, turns=turns)
        return seen

    def test_hard_cap_leaves_room_to_report(self):
        for turns in (10, 30, 70):
            with self.subTest(turns=turns):
                seen = self._run_capturing(turns)
                self.assertGreater(
                    seen["max_turns"], turns,
                    "the process cap must sit above the prompt's budget, or the agent "
                    "is killed on the turn it would have emitted its JSON block")
                self.assertGreaterEqual(seen["max_turns"] - turns, 10)

    def test_prompt_still_states_the_work_budget(self):
        seen = self._run_capturing(30)
        self.assertIn("30", seen["task"])

    def test_raw_reply_survives_a_parse_failure(self):
        # A run whose closing block is missing is still work product, not a void.
        with mock.patch.object(freeroam, "run_agent",
                               lambda task, **kw: {"result": "I probed 9 endpoints.",
                                                   "error": "claude exited 1"}):
            res = freeroam.run("https://example.com/", project=None, turns=10)
        self.assertEqual(res["items"], [])
        self.assertIn("probed 9 endpoints", res["raw"])


if __name__ == "__main__":
    unittest.main()
