#!/usr/bin/env python3
"""`cbh limits` must attribute spend to one side and count one API request once.

Both failures would be silent and wrong in the operator's favour: a model-name
misclassification counts a foreign row as this plan's spend, and counting every
`assistant` row double-counts tokens, because Claude Code writes one row per
`apiBlockIndex` with the same `message.usage` attached.

Until 2026-11-13 this module carried a second ledger as well — a second provider's
credit window, its quota endpoint, the console paste and a credit estimator — because
the crew ran on that provider. The crew runs on this plan now, so the tests for that
half went out with it; what stays is the Claude side and the plan counter, which is the
only authoritative number either way.
"""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import limits  # noqa: E402


def _row(model, msg_id, ts, out=10, blk=0, session="s1"):
    return json.dumps({
        "type": "assistant", "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "sessionId": session, "uuid": f"{msg_id}-{blk}", "apiBlockIndex": blk,
        "requestRef": f"req-{msg_id}",
        "message": {"id": msg_id, "role": "assistant", "model": model,
                    "usage": {"input_tokens": 5, "output_tokens": out,
                              "cache_read_input_tokens": 1,
                              "cache_creation_input_tokens": 2}},
    })


class TestLimits(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.now = datetime.now(timezone.utc)
        d = self.root / "proj"
        d.mkdir()
        recent = self.now - timedelta(minutes=5)
        old = self.now - timedelta(days=9)
        (d / "main.jsonl").write_text("\n".join([
            _row("claude-opus-5", "m1", recent, out=100, blk=0),
            _row("claude-opus-5", "m1", recent, out=100, blk=1),   # same request, 2nd block
            _row("claude-opus-5", "m2", old, out=7),               # outside 5h/today/7d
        ]) + "\n", encoding="utf-8")
        # a row from no recognised model: it belongs to no side and is not this plan's
        (d / "other.jsonl").write_text(
            _row("<synthetic>", "x1", recent, out=20, session="w1") + "\n",
            encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _collect(self, days=30):
        return limits.collect(days=days, projects=self.root, now=self.now)

    def test_only_claude_rows_are_counted(self):
        s = self._collect()["sides"]
        self.assertEqual(["claude"], list(s))
        self.assertEqual(1, s["claude"]["5h"]["requests"])
        self.assertEqual(100, s["claude"]["5h"]["output"],
                         "an unrecognised model's row was counted as this plan's spend")

    def test_one_request_counted_once_despite_two_blocks(self):
        a = self._collect()["sides"]["claude"]["5h"]
        self.assertEqual(1, a["requests"])
        self.assertEqual(100, a["output"], "second apiBlockIndex row double-counted")

    def test_windows_widen_not_shrink(self):
        s = self._collect()["sides"]["claude"]
        self.assertEqual(1, s["7d"]["requests"])
        self.assertEqual(2, s["30d"]["requests"])

    def test_render_names_the_authoritative_source(self):
        txt = "\n".join(limits.render(self._collect(), caps={"claude": {}}))
        self.assertIn("CLAUDE", txt)
        # the measured rows are not the quota: the render must name where the real
        # number comes from (the harness, same source as the statusline and `/usage`)
        self.assertIn("/usage", txt)
        self.assertIn("PLAN COUNTER", txt)

    def test_missing_transcript_dir_is_reported_not_crashed(self):
        d = limits.collect(projects=self.root / "nope")
        self.assertIn("no transcript directory", d["error"])
        self.assertIn("limits:", limits.render(d)[0])


class TestPlanCounter(unittest.TestCase):
    """The brief line must read the plan counter, not a measured count.

    The counter is authoritative but reaches this box only through the statusline
    cache, so an uncached counter has to SAY so: a measured request count printed in
    its place reads as a quota and is not one.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved_cache = limits.CLAUDE_RL_CACHE
        limits.CLAUDE_RL_CACHE = Path(self.tmp.name) / "rl.json"
        self.saved_proj = limits.PROJECTS
        limits.PROJECTS = Path(self.tmp.name) / "empty-projects"

    def tearDown(self):
        limits.CLAUDE_RL_CACHE = self.saved_cache
        limits.PROJECTS = self.saved_proj
        self.tmp.cleanup()

    def test_claude_plan_counter_is_read_from_the_statusline_cache(self):
        limits.CLAUDE_RL_CACHE.write_text(json.dumps({
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "rate_limits": {"five_hour": {"used_percentage": 5, "resets_at": 1793178000},
                            "seven_day": {"used_percentage": 36}}}), encoding="utf-8")
        line = limits.brief_line()
        self.assertIn("claude plan 5h 95% left", line)
        self.assertIn("7d 64% left", line)

    def test_no_cache_falls_back_to_measured_and_says_so(self):
        self.assertIn("plan counter not cached yet", limits.brief_line())

    def test_epoch_and_iso_resets_both_format(self):
        self.assertTrue(limits._fmt_reset(1793178000))
        self.assertTrue(limits._fmt_reset("2026-11-02T16:00:00Z"))
        self.assertEqual("", limits._fmt_reset(None))

    def test_the_statusline_segment_adds_no_second_budget(self):
        # The harness's own statusline already draws this plan's percentages. A
        # measured count printed beside them would read as another budget.
        self.assertEqual("", limits.statusline_segment())


if __name__ == "__main__":
    unittest.main()
