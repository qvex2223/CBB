"""Regression: a `429` must brake the next request. Nothing did.

Measured on `standoff365/mail_vk`, 2026-11-12 21:14:10-22: twelve consecutive
`429`s came back from `light.mail.ru`, `octavius.mail.ru` and `wallet.mail.ru`,
and the next request left **one second later in eleven of the twelve cases** —
four of them aimed at the host that had just refused. `grep -n '429\|Retry-After\|
backoff' engine/pacing.py scripts/bbcurl engine/request_broker.py` returned
nothing at the time: the flat `min_interval_seconds` budget is a rate, not a
brake, and it has no opinion about the target saying stop.

The fix is a per-host penalty armed from the response and honoured by the next
`wait_turn()`. The engagement rule it enforces is "respect rate limits", so
every test below is written against a measured property of that rule rather than
the implementation: the penalty exists, it grows while the target keeps
refusing, a stated `Retry-After` outranks our guess, an unthrottled host is
never slowed, and a penalty too long to sleep is REFUSED rather than slept
through (a worker turn that blocks for a quarter-hour is killed and loses its
lane; a refusal naming the host is something a lane can act on).

Positive control in both directions: a `200` must arm nothing, and an
unthrottled host must still fire while a sibling host is walled.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import pacing  # noqa: E402
import request_broker  # noqa: E402


def _engagement(tmp: Path, interval: float = 0.0) -> pacing.Engagement:
    proj = tmp / "Targets" / "demo"
    proj.mkdir(parents=True)
    (proj / "profile.json").write_text(json.dumps({"min_interval_seconds": interval}))
    eng = pacing.Engagement(proj)
    eng.state_dir = tmp / "pacing"
    return eng


class AThrottleArmsAPenalty(unittest.TestCase):
    def test_a_200_arms_nothing(self):
        """Positive control: the brake must not fire on an ordinary response."""
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td))
            self.assertIsNone(eng.note_throttle("a.example.com", 200))
            self.assertIsNone(eng.note_throttle("a.example.com", 403))
            self.assertEqual(eng.throttled_hosts(), [])

    def test_a_429_arms_the_base_penalty(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td))
            rec = eng.note_throttle("a.example.com", 429, now=lambda: 1000.0)
            self.assertEqual(rec["strikes"], 1)
            self.assertEqual(rec["penalty_seconds"], pacing.THROTTLE_BASE_SECONDS)
            self.assertEqual(rec["until"], 1000.0 + pacing.THROTTLE_BASE_SECONDS)

    def test_consecutive_strikes_double_the_penalty_up_to_the_cap(self):
        """Twelve 429s in twelve seconds is a ban forming, not a hiccup."""
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td))
            now = 1000.0
            seen = []
            for i in range(12):
                seen.append(eng.note_throttle("a.example.com", 429,
                                              now=lambda t=now + i: t))
            self.assertEqual([r["strikes"] for r in seen], list(range(1, 13)))
            self.assertEqual(seen[0]["penalty_seconds"], pacing.THROTTLE_BASE_SECONDS)
            self.assertEqual(seen[1]["penalty_seconds"], pacing.THROTTLE_BASE_SECONDS * 2)
            self.assertEqual(seen[2]["penalty_seconds"], pacing.THROTTLE_BASE_SECONDS * 4)
            self.assertEqual(seen[-1]["penalty_seconds"], pacing.THROTTLE_CAP_SECONDS)

    def test_a_quiet_gap_clears_the_strike_count(self):
        """One 429 an hour is noise; the counter must not remember it forever."""
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td))
            eng.note_throttle("a.example.com", 429, now=lambda: 1000.0)
            later = 1000.0 + pacing.THROTTLE_STRIKE_RESET + 1
            rec = eng.note_throttle("a.example.com", 429, now=lambda: later)
            self.assertEqual(rec["strikes"], 1)
            self.assertEqual(rec["penalty_seconds"], pacing.THROTTLE_BASE_SECONDS)

    def test_the_penalty_is_per_host(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td))
            eng.note_throttle("a.example.com", 429, now=lambda: 1000.0)
            rec = eng.note_throttle("b.example.com", 429, now=lambda: 1001.0)
            self.assertEqual(rec["strikes"], 1)

    def test_outside_an_engagement_nothing_is_armed(self):
        with tempfile.TemporaryDirectory() as td:
            eng = pacing.Engagement(None, state_dir=Path(td))
            self.assertIsNone(eng.note_throttle("a.example.com", 429))


class RetryAfterOutranksOurGuess(unittest.TestCase):
    def test_delta_seconds_is_honoured(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td))
            rec = eng.note_throttle("a.example.com", 429, retry_after="30",
                                    now=lambda: 1000.0)
            self.assertEqual(rec["penalty_seconds"], 30.0)
            self.assertEqual(rec["retry_after"], 30.0)

    def test_a_stated_wait_wins_even_when_it_is_shorter_than_our_backoff(self):
        """The target knows its own window better than our doubling does."""
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td))
            for _ in range(4):
                eng.note_throttle("a.example.com", 429, now=lambda: 1000.0)
            rec = eng.note_throttle("a.example.com", 429, retry_after="5",
                                    now=lambda: 1000.0)
            self.assertEqual(rec["penalty_seconds"], 5.0)

    def test_an_http_date_is_parsed_and_a_past_date_is_not_negative(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td))
            rec = eng.note_throttle("a.example.com", 429,
                                    retry_after="Wed, 21 Oct 2026 07:28:00 GMT",
                                    now=lambda: 4_000_000_000.0)
            self.assertEqual(rec["retry_after"], 0.0)

    def test_garbage_falls_back_to_the_backoff(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td))
            rec = eng.note_throttle("a.example.com", 429, retry_after="soon",
                                    now=lambda: 1000.0)
            self.assertIsNone(rec["retry_after"])
            self.assertEqual(rec["penalty_seconds"], pacing.THROTTLE_BASE_SECONDS)

    def test_a_stated_wait_over_the_cap_is_capped(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td))
            rec = eng.note_throttle("a.example.com", 429, retry_after="99999",
                                    now=lambda: 1000.0)
            self.assertEqual(rec["penalty_seconds"], pacing.THROTTLE_CAP_SECONDS)


class TheNextRequestIsBraked(unittest.TestCase):
    def test_an_unthrottled_host_is_never_slowed(self):
        """Positive control: the walled host must not wall its siblings."""
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td))
            eng.note_throttle("a.example.com", 429, now=lambda: 1000.0)
            self.assertEqual(eng.throttle_wait(["b.example.com"], now=lambda: 1001.0), 0.0)
            self.assertEqual(eng.throttle_wait([], now=lambda: 1001.0), 0.0)

    def test_a_long_penalty_refuses_instead_of_blocking_the_turn(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td))
            eng.note_throttle("a.example.com", 429,
                              retry_after=str(pacing.THROTTLE_MAX_SLEEP + 60),
                              now=lambda: 1000.0)
            with self.assertRaises(pacing.ThrottledHost) as cm:
                eng.throttle_wait(["a.example.com"], now=lambda: 1001.0)
            self.assertEqual(cm.exception.host, "a.example.com")
            self.assertIn("Nothing was sent", str(cm.exception))

    def test_wait_turn_refuses_a_throttled_host_before_charging_the_budget(self):
        """The refusal must come before the budget is spent, or the next caller
        inherits a slot that was never used."""
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td), interval=0.5)
            eng.note_throttle("a.example.com", 429,
                              retry_after=str(pacing.THROTTLE_MAX_SLEEP + 60),
                              now=lambda: 1000.0)
            with self.assertRaises(pacing.ThrottledHost):
                eng.wait_turn(now=lambda: 1001.0, hosts=["a.example.com"])
            self.assertFalse(eng._state_path().is_file())

    def test_an_expired_penalty_does_not_wait(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td))
            eng.note_throttle("a.example.com", 429, now=lambda: 1000.0)
            after = 1000.0 + pacing.THROTTLE_BASE_SECONDS + 1
            self.assertEqual(eng.throttle_wait(["a.example.com"], now=lambda: after), 0.0)

    def test_no_hosts_argument_keeps_the_old_behaviour(self):
        """Every existing caller passes no hosts and must be unaffected."""
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td), interval=0.5)
            eng.note_throttle("a.example.com", 429,
                              retry_after="900", now=lambda: 1000.0)
            self.assertEqual(eng.wait_turn(now=lambda: 1001.0), 0.0)

    def test_a_corrupt_penalty_file_does_not_raise(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _engagement(Path(td))
            eng.note_throttle("a.example.com", 429, now=lambda: 1000.0)
            eng._throttle_path().write_text("{not json")
            self.assertEqual(eng.throttle_wait(["a.example.com"], now=lambda: 1001.0), 0.0)


class TheBrokerArmsItFromAUrl(unittest.TestCase):
    def _broker(self, tmp: Path) -> request_broker.RequestBroker:
        return request_broker.RequestBroker(engagement=_engagement(tmp))

    def test_the_host_is_taken_from_the_url(self):
        with tempfile.TemporaryDirectory() as td:
            broker = self._broker(Path(td))
            rec = broker.note_throttle("https://a.example.com:8443/x?y=1", 429)
            self.assertEqual(rec["host"], "a.example.com")

    def test_a_200_through_the_broker_arms_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            broker = self._broker(Path(td))
            self.assertIsNone(broker.note_throttle("https://a.example.com/x", 200))

    def test_a_nonsense_url_arms_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            broker = self._broker(Path(td))
            self.assertIsNone(broker.note_throttle("not a url", 429))


if __name__ == "__main__":
    unittest.main()
