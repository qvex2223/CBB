#!/usr/bin/env python3
"""Program-quality metrics: is this program worth the next week?

Technique analytics say what works. They cannot say whether the program on the other end
answers in four days or four months, returns half your work as duplicate, or quietly
downgrades every High. That data has been in hunt memory since local confirmation and the
platform's verdict were split apart; nothing read it until now.
"""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import program_quality as PQ  # noqa: E402


def row(target, result, days_ago=0, endpoint="/x", vuln="idor", **kw):
    return {"target": target, "vuln_class": vuln, "endpoint": endpoint,
            "result": result, "platform_outcome": result if result in
            {"submitted", "accepted", "paid", "na", "downgraded", "duplicate"} else None,
            "timestamp": (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat(),
            **kw}


class Metrics(unittest.TestCase):
    def test_rates_are_shares_of_judged_submissions(self):
        rows = [row("a", "accepted"), row("a", "duplicate", endpoint="/2"),
                row("a", "na", endpoint="/3"), row("a", "downgraded", endpoint="/4")]
        s = PQ.analyze(rows)["a"]
        self.assertEqual(s["judged"], 4)
        self.assertEqual(s["accepted_rate"], 25.0)
        self.assertEqual(s["duplicate_rate"], 25.0)
        self.assertEqual(s["na_rate"], 25.0)
        self.assertEqual(s["downgrade_rate"], 25.0)

    def test_local_only_results_do_not_count_as_submissions(self):
        """A confirmed finding you never submitted says nothing about the program."""
        s = PQ.analyze([row("a", "confirmed"), row("a", "rejected", endpoint="/2")])["a"]
        self.assertEqual(s["judged"], 0)
        self.assertEqual(s["submitted"], 0)

    def test_a_program_with_no_submissions_reports_unknown_not_zero(self):
        s = PQ.analyze([row("a", "confirmed")])["a"]
        self.assertIsNone(s["accepted_rate"],
                          "never submitted is not a 0% acceptance rate")

    def test_paid_counts_as_accepted_and_carries_payout(self):
        s = PQ.analyze([row("a", "paid", payout=750)])["a"]
        self.assertEqual(s["accepted"], 1)
        self.assertEqual(s["total_payout"], 750)
        self.assertEqual(s["payout_per_accepted"], 750.0)

    def test_time_to_verdict_pairs_a_submission_with_its_outcome(self):
        rows = [row("a", "submitted", days_ago=30), row("a", "accepted", days_ago=20)]
        self.assertEqual(PQ.analyze(rows)["a"]["median_days_to_verdict"], 10.0)

    def test_an_unanswered_submission_is_counted_not_dropped(self):
        """A long tail of silence is itself the program-quality signal."""
        s = PQ.analyze([row("a", "submitted", days_ago=90)])["a"]
        self.assertEqual(s["open_submissions"], 1)
        self.assertIsNone(s["median_days_to_verdict"])

    def test_outcomes_for_different_findings_are_not_paired(self):
        rows = [row("a", "submitted", days_ago=30, endpoint="/1"),
                row("a", "accepted", days_ago=20, endpoint="/2")]
        s = PQ.analyze(rows)["a"]
        self.assertIsNone(s["median_days_to_verdict"])
        self.assertEqual(s["open_submissions"], 1)

    def test_accepted_severities_are_recorded(self):
        s = PQ.analyze([row("a", "accepted", severity="high")])["a"]
        self.assertEqual(s["accepted_severities"], {"high": 1})

    def test_programs_are_separated(self):
        stats = PQ.analyze([row("a", "paid", payout=100), row("b", "na")])
        self.assertEqual(set(stats), {"a", "b"})


class Ranking(unittest.TestCase):
    def test_realized_value_leads(self):
        stats = PQ.analyze([row("rich", "paid", payout=5000),
                            row("poor", "accepted", endpoint="/2")])
        self.assertEqual(PQ.rank(stats)[0]["target"], "rich")

    def test_an_empty_record_ranks_last_not_first(self):
        stats = PQ.analyze([row("unknown", "confirmed"), row("known", "na")])
        self.assertEqual(PQ.rank(stats)[-1]["target"], "unknown",
                         "a program you never submitted to must not outrank a real one")

    def test_duplicates_and_na_pull_a_program_down(self):
        rows = [row("clean", "accepted")]
        rows += [row("noisy", "accepted")] + [row("noisy", "duplicate", endpoint=f"/{i}")
                                              for i in range(5)]
        self.assertEqual(PQ.rank(PQ.analyze(rows))[0]["target"], "clean")


class Rendering(unittest.TestCase):
    def test_empty_memory_explains_how_to_populate_it(self):
        out = PQ.render({})
        self.assertIn("/remember", out)

    def test_unknown_metrics_render_as_a_dash(self):
        self.assertIn("—", PQ.render(PQ.analyze([row("a", "confirmed")])))

    def test_json_output_is_valid(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "journal.jsonl").write_text(json.dumps(row("a", "paid", payout=10)) + "\n")
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                PQ.main(["--memdir", td, "--format", "json"])
            self.assertEqual(json.loads(buf.getvalue())["programs"][0]["target"], "a")


if __name__ == "__main__":
    unittest.main()
