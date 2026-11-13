import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import program_scout as ps  # noqa: E402

NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)


def det(avg, acc, tot, last="2026-10-19T00:00:00Z", pub="2024-01-01T00:00:00Z", reward=None, text="t"):
    return {"pageProps": {"reward": reward or {"x": 1}, "scopes": [], "program": {
        "description": text, "updatedAt": "u", "publishedAt": pub, "name": "n", "terms": "only_vuln",
        "statistics": {"rewards": {"rub": {"averageBounty": avg, "max": 500000}},
                       "reportsAccepted": acc, "reportsTotal": tot, "lastAcceptedReportDate": last}}}}


class Score(unittest.TestCase):
    def test_one_big_payout_is_shrunk_toward_the_median(self):
        lucky = ps.score(det(1_500_000, 1, 9), NOW, prior_avg=30_000)["score"]
        steady = ps.score(det(60_000, 300, 900), NOW, prior_avg=30_000)["score"]
        self.assertGreater(steady, lucky)

    def test_inactive_programme_decays(self):
        a = ps.score(det(50_000, 50, 100), NOW)["score"]
        b = ps.score(det(50_000, 50, 100, last="2025-10-20T00:00:00Z"), NOW)["score"]
        self.assertGreater(a, b * 10)


class Diff(unittest.TestCase):
    def test_new_gone_and_changed(self):
        prev = {"a": det(1, 1, 1), "b": det(1, 1, 1)}
        cur = {"a": det(1, 1, 1, reward={"y": 2}), "c": det(1, 1, 1)}
        rows = dict(ps.diff(prev, cur))
        self.assertEqual(rows["c"], "NEW programme")
        self.assertTrue(rows["b"].startswith("GONE"))
        self.assertEqual(rows["a"], "changed: reward")


if __name__ == "__main__":
    unittest.main()
