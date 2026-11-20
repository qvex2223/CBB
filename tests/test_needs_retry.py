"""`cbh leads close --as needs-retry` (2026-11-17, wave 2 item 1).

The verdict that was missing. A lane that ends inconclusively because the TARGET would not
answer — a rate limit, a re-authentication, an environment that was down — had no verdict of its
own, so it was closed `refuted` or `exhausted`. Both are CLOSURE words, so the lead left the
queue permanently on evidence nobody ever gathered. `stalled` does not cover it: that means OUR
tooling did not finish.

The lead therefore stays in the queue, counted, carrying the mark, and is ranked DOWN for six
hours rather than held back — a hold would make `cbh leads`' count and its queue disagree, which
`engine/funnel.py` exists to prevent, and an immediate re-offer burns the next slot on the same
wall.
"""
import datetime as dt
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "engine"))
import lead_queue as LQ  # noqa: E402

NOW = "2026-11-17T12:00:00"


class _Pin:
    def __enter__(self):
        self._prev = os.environ.get("CBH_NOW")
        os.environ["CBH_NOW"] = NOW
        return self

    def __exit__(self, *exc):
        if self._prev is None:
            os.environ.pop("CBH_NOW", None)
        else:
            os.environ["CBH_NOW"] = self._prev
        return False


def _eng(tmp):
    root = Path(tmp) / "Targets"
    e = root / "p" / "prog"
    (e / "leads").mkdir(parents=True)
    (e / "primitives").mkdir()
    (e / "scope.md").write_text("x")
    (e / "profile.json").write_text(json.dumps({}))
    return root, e


def _write(path, text, hours_ago):
    path.write_text(text, encoding="utf-8")
    when = dt.datetime.fromisoformat(NOW).timestamp() - hours_ago * 3600
    os.utime(path, (when, when))


class ItIsNotAClosure(unittest.TestCase):
    def test_it_is_not_in_the_closure_or_blocked_word_lists(self):
        for w in LQ.CLOSURE_WORDS + LQ.BLOCKED_WORDS:
            self.assertFalse("needs-retry".startswith(w),
                             f"`needs-retry` would be swallowed by the closure word {w!r}")

    def test_it_is_a_recognised_verdict(self):
        self.assertIn("needs-retry", LQ.VERDICT_WORDS)

    def test_it_is_distinct_from_stalled(self):
        self.assertNotIn("needs-retry", LQ.STALLED_WORDS)
        self.assertNotIn("stalled", LQ.RETRY_WORDS)

    def test_the_banner_does_not_read_as_closed(self):
        text = "# L\n\n**Status:** NEEDS-RETRY (2026-11-17) — 429 on every arm\n"
        self.assertTrue(LQ._is_needs_retry(text))
        self.assertFalse(LQ._is_closed(text))
        self.assertFalse(LQ._is_blocked(text))
        self.assertFalse(LQ._is_stalled(text))

    def test_a_heading_verdict_works_too(self):
        text = "# L\n\n## NEEDS-RETRY 2026-11-17 — the environment was down\n"
        self.assertTrue(LQ._is_needs_retry(text))
        self.assertFalse(LQ._is_closed(text))

    def test_the_cli_accepts_it(self):
        src = (REPO / "engine" / "lead_queue.py").read_text(encoding="utf-8")
        self.assertIn('"needs-retry"])', src)
        self.assertIn('"needs-retry": "NEEDS-RETRY"', src)


class ItStaysInTheQueue(unittest.TestCase):
    def test_a_needs_retry_lead_is_still_offered(self):
        with tempfile.TemporaryDirectory() as t, _Pin():
            root, e = _eng(t)
            _write(e / "leads" / "rate-limited.md",
                   "# Quote on search 500s\n\n**Class:** `sqli`\n"
                   "**Status:** NEEDS-RETRY (2026-11-17) — 429 after two requests\n", 1)
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                q = LQ.scan(e)
            self.assertEqual(["leads/rate-limited.md"], [r["file"] for r in q["open"]])
            self.assertEqual(1, q["needs_retry"])
            self.assertEqual(0, q["closed"])

    def test_a_refuted_lead_in_the_same_corpus_does_leave(self):
        """The negative control: the closure path still closes."""
        with tempfile.TemporaryDirectory() as t, _Pin():
            root, e = _eng(t)
            _write(e / "leads" / "gone.md", "# L\n\n**Status:** REFUTED (2026-11-17)\n", 1)
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                q = LQ.scan(e)
            self.assertEqual([], q["open"])
            self.assertEqual(1, q["closed"])
            self.assertEqual(0, q["needs_retry"])


class TheCooldown(unittest.TestCase):
    BANNER = ("# Quote on search 500s\n\n**Class:** `sqli`\n"
              "**Status:** NEEDS-RETRY (2026-11-17) — 429 after two requests\n")

    def _scan(self, hours_ago):
        with tempfile.TemporaryDirectory() as t, _Pin():
            root, e = _eng(t)
            _write(e / "leads" / "rate-limited.md", self.BANNER, hours_ago)
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                return LQ.scan(e)["open"][0]

    def test_inside_the_cooldown_it_is_ranked_down_and_says_for_how_long(self):
        row = self._scan(hours_ago=1)
        self.assertTrue(row.get("needs_retry"))
        self.assertGreater(row.get("cooling_seconds", 0), 0)
        self.assertLessEqual(row["cooling_seconds"], LQ.RETRY_COOLDOWN_SECONDS)

    def test_after_the_cooldown_the_score_is_whole_again(self):
        hot = self._scan(hours_ago=1)
        cold = self._scan(hours_ago=7)
        self.assertNotIn("cooling_seconds", cold)
        self.assertGreater(cold["score"], hot["score"],
                           "a lead past its cooldown must outrank the same lead inside it")
        self.assertEqual(hot["score"], int(cold["score"] * LQ.RETRY_COOLDOWN_FACTOR))

    def test_the_cooldown_never_removes_it_from_the_queue(self):
        """Ranked down, not held back: the count and the queue must not disagree."""
        row = self._scan(hours_ago=0)
        self.assertTrue(row["file"].endswith("rate-limited.md"))
        self.assertGreater(row["score"], 0)

    def test_the_boundary(self):
        just_inside = self._scan(hours_ago=5.9)
        just_outside = self._scan(hours_ago=6.1)
        self.assertIn("cooling_seconds", just_inside)
        self.assertNotIn("cooling_seconds", just_outside)


class TheRenderedMark(unittest.TestCase):
    def test_the_mark_names_the_target_as_the_cause_and_is_not_the_stalled_mark(self):
        with tempfile.TemporaryDirectory() as t, _Pin():
            root, e = _eng(t)
            _write(e / "leads" / "rate-limited.md",
                   "# Quote on search 500s\n\n**Class:** `sqli`\n"
                   "**Status:** NEEDS-RETRY (2026-11-17) — 429\n", 1)
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                text = LQ.render(LQ.scan(e), top=5)
        self.assertIn("NEEDS-RETRY", text)
        self.assertIn("TARGET would not answer", text)
        self.assertNotIn("stalled in our tooling", text)

    def test_a_stalled_lead_still_gets_the_stalled_mark(self):
        with tempfile.TemporaryDirectory() as t, _Pin():
            root, e = _eng(t)
            _write(e / "leads" / "ours-broke.md",
                   "# L\n\n**Status:** STALLED (2026-11-17) — bbcurl wedged\n", 1)
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                text = LQ.render(LQ.scan(e), top=5)
        self.assertIn("stalled in our tooling", text)
        self.assertNotIn("NEEDS-RETRY", text)


class CloseAndReopen(unittest.TestCase):
    def test_close_as_needs_retry_then_the_lead_is_still_workable(self):
        with tempfile.TemporaryDirectory() as t, _Pin():
            root, e = _eng(t)
            f = e / "leads" / "rate-limited.md"
            _write(f, "# Quote on search 500s\n\n**Class:** `sqli`\n**Status:** lead\n", 1)
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                rc = LQ.close(str(f), "needs-retry", "429 after two requests")
                self.assertEqual(0, rc)
                q = LQ.scan(e)
            self.assertEqual(1, q["needs_retry"])
            self.assertEqual(1, len(q["open"]))
            self.assertEqual(0, q["closed"])


if __name__ == "__main__":
    unittest.main()
