"""decision_replay determinism (2026-11-17): the report must not be a function of the clock.

`lead_queue.scan` multiplies a lead's reward by whole DAYS of staleness, so the ranked queue
moves with the calendar. Measured: two replays of UNCHANGED code forty minutes apart printed
57142 and 60714 for the same leads — 50000 * (1 + 2/14) against 50000 * (1 + 3/14) — because a
batch of files sharing an mtime crossed the 3-day boundary between the runs, and two items
swapped rank with it. 290 report lines move between `--as-of 2026-11-10` and `--as-of
2026-11-17` on the live corpus, so a before/after diff across a day boundary reads as a
regression that never happened. `CBH_NOW` pins the clock; this guards that it keeps working.
"""
import datetime as dt
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "engine"))
import lead_queue as LQ  # noqa: E402


class _Pin:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        self._prev = os.environ.get("CBH_NOW")
        if self.value is None:
            os.environ.pop("CBH_NOW", None)
        else:
            os.environ["CBH_NOW"] = self.value
        return self

    def __exit__(self, *exc):
        if self._prev is None:
            os.environ.pop("CBH_NOW", None)
        else:
            os.environ["CBH_NOW"] = self._prev
        return False


def _aged_file(tmp, days):
    f = Path(tmp) / "x.md"
    f.write_text("# x\n")
    when = dt.datetime(2026, 11, 17).timestamp() - days * 86400
    os.utime(f, (when, when))
    return f


class Clock(unittest.TestCase):
    def test_pin_makes_age_independent_of_the_wall_clock(self):
        with tempfile.TemporaryDirectory() as t:
            f = _aged_file(t, 3.5)
            with _Pin("2026-11-17"):
                self.assertEqual(3, LQ._age_days(f))
            with _Pin("2026-11-18"):
                self.assertEqual(4, LQ._age_days(f))

    def test_pin_accepts_a_full_datetime(self):
        with tempfile.TemporaryDirectory() as t:
            f = _aged_file(t, 1.5)
            with _Pin("2026-11-17T12:00:00"):
                self.assertEqual(2, LQ._age_days(f))

    def test_unparseable_pin_falls_back_to_the_wall_clock_and_does_not_raise(self):
        """An unparseable value must never raise into a hunt."""
        with tempfile.TemporaryDirectory() as t:
            f = _aged_file(t, 1)
            with _Pin("not-a-date"):
                self.assertIsInstance(LQ._age_days(f), int)

    def test_no_pin_still_works(self):
        with tempfile.TemporaryDirectory() as t:
            f = _aged_file(t, 0)
            with _Pin(None):
                self.assertGreaterEqual(LQ._age_days(f), 0)

    def test_the_boundary_that_caused_this(self):
        """2.99 days and 3.01 days are different ranks; that is the whole defect."""
        with tempfile.TemporaryDirectory() as t:
            with _Pin("2026-11-17"):
                self.assertEqual(2, LQ._age_days(_aged_file(t, 2.99)))
            with tempfile.TemporaryDirectory() as t2, _Pin("2026-11-17"):
                self.assertEqual(3, LQ._age_days(_aged_file(t2, 3.01)))


class ScoreStability(unittest.TestCase):
    def test_scan_scores_are_stable_under_a_pin(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "Targets"
            e = root / "p" / "prog"
            (e / "leads").mkdir(parents=True)
            (e / "primitives").mkdir()
            (e / "scope.md").write_text("x")
            lead = e / "leads" / "a.md"
            lead.write_text("# A lead\n\n**Status:** lead\n")
            when = dt.datetime(2026, 11, 17).timestamp() - 2.99 * 86400
            os.utime(lead, (when, when))
            out = []
            for pin in ("2026-11-17", "2026-11-17"):
                with _Pin(pin), mock.patch.object(LQ, "_targets_root", lambda: root):
                    out.append([r["score"] for r in LQ.scan(e)["open"]])
            self.assertEqual(out[0], out[1])
            # And it genuinely moves a day later — the pin is load-bearing, not decoration.
            with _Pin("2026-11-18"), mock.patch.object(LQ, "_targets_root", lambda: root):
                later = [r["score"] for r in LQ.scan(e)["open"]]
            self.assertNotEqual(out[0], later)


if __name__ == "__main__":
    unittest.main()
