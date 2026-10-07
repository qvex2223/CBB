#!/usr/bin/env python3
"""Memory schema migration, profile scrubbing, and honest analytics denominators."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import memory_migrate as MM  # noqa: E402
from memory import Memory  # noqa: E402


class MigrationRules(unittest.TestCase):
    def test_pattern_row_without_result_is_confirmed(self):
        row, changed = MM.migrate_row({"target": "a", "vuln_class": "idor"}, is_pattern=True)
        self.assertEqual(row["result"], "confirmed")
        self.assertTrue(row["locally_confirmed"])
        self.assertIn("result", changed)

    def test_journal_row_without_result_is_left_unannotated(self):
        """The whole point: an unknown attempt must never be guessed into a success."""
        row, _ = MM.migrate_row({"target": "a", "vuln_class": "idor"}, is_pattern=False)
        self.assertNotIn("locally_confirmed", row)
        self.assertNotIn("platform_outcome", row)

    def test_na_is_locally_confirmed_but_not_accepted(self):
        row, _ = MM.migrate_row({"target": "a", "result": "na"}, is_pattern=False)
        self.assertTrue(row["locally_confirmed"])
        self.assertEqual(row["platform_outcome"], "na")

    def test_rejected_is_neither(self):
        row, _ = MM.migrate_row({"target": "a", "result": "rejected"}, is_pattern=False)
        self.assertFalse(row["locally_confirmed"])
        self.assertIsNone(row["platform_outcome"])

    def test_explicit_operator_values_win(self):
        row, changed = MM.migrate_row(
            {"target": "a", "result": "rejected", "locally_confirmed": True},
            is_pattern=False)
        self.assertTrue(row["locally_confirmed"])
        self.assertNotIn("locally_confirmed", changed)

    def test_identifiers_are_normalized_through_the_writer(self):
        row, _ = MM.migrate_row(
            {"target": "a", "vuln_class": "Missing Authorization",
             "technique": "Numeric ID swap on PUT!"}, is_pattern=True)
        self.assertEqual(row["vuln_class"], "missing_authorization")
        self.assertEqual(row["technique"], "numeric_id_swap_on_put")


class MigrationSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        (self.dir / "journal.jsonl").write_text(
            json.dumps({"target": "a", "vuln_class": "Business Logic", "result": "rejected"})
            + "\n{ not json\n"
            + json.dumps({"target": "a", "vuln_class": "idor", "result": "confirmed"}) + "\n")
        (self.dir / "patterns.jsonl").write_text(
            json.dumps({"target": "a", "vuln_class": "idor", "technique": "X Y"}) + "\n")

    def _rows(self, name):
        return [x for x in (self.dir / name).read_text().splitlines() if x.strip()]

    def test_dry_run_changes_nothing_on_disk(self):
        before = (self.dir / "journal.jsonl").read_text()
        MM.main(["--memdir", str(self.dir)])
        self.assertEqual((self.dir / "journal.jsonl").read_text(), before)

    def test_apply_backs_up_and_rollback_restores_byte_for_byte(self):
        before = (self.dir / "journal.jsonl").read_text()
        report = MM.plan(self.dir)
        stamp = "TESTSTAMP"
        MM.apply(report, stamp)
        self.assertNotEqual((self.dir / "journal.jsonl").read_text(), before)
        MM.rollback(self.dir, stamp)
        self.assertEqual((self.dir / "journal.jsonl").read_text(), before)

    def test_row_count_is_preserved_and_order_is_untouched(self):
        targets_before = [json.loads(x)["target"] for x in self._rows("journal.jsonl")
                          if x.startswith("{\"")]
        MM.apply(MM.plan(self.dir), "S2")
        rows = self._rows("journal.jsonl")
        self.assertEqual(len(rows), 3, "append-only row count changed")
        self.assertIn("{ not json", rows, "a malformed line was dropped instead of preserved")
        targets_after = [json.loads(x)["target"] for x in rows if x.startswith("{\"")]
        self.assertEqual(targets_before, targets_after)

    def test_rollback_with_an_unknown_stamp_refuses(self):
        with self.assertRaises(SystemExit):
            MM.rollback(self.dir, "nope")

    def test_migration_is_idempotent(self):
        MM.apply(MM.plan(self.dir), "S3")
        first = (self.dir / "journal.jsonl").read_text()
        second_plan = MM.plan(self.dir)
        self.assertEqual(sum(f["changed_rows"] for f in second_plan["files"]), 0)
        MM.apply(second_plan, "S4")
        self.assertEqual((self.dir / "journal.jsonl").read_text(), first)


class ProfileScrubbing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.m = Memory(self.tmp.name)

    def test_identity_values_never_reach_a_target_profile(self):
        p = self.m.load_profile("acme.com")
        p["tested_endpoints"] = ["/check?iin=990101300123&contact_phone=77771234567"]
        path = self.m.save_profile(p)
        text = path.read_text()
        self.assertNotIn("990101300123", text)
        self.assertNotIn("77771234567", text)
        self.assertIn("iin=", text, "the key must survive; only the value is masked")

    def test_credentials_are_still_redacted_by_key(self):
        p = self.m.load_profile("acme.com")
        p["notes"] = {"Cookie": "session=supersecret"}
        self.assertNotIn("supersecret", self.m.save_profile(p).read_text())


class AnalyticsDenominator(unittest.TestCase):
    """A success-only corpus cannot produce a success rate. It used to print 100%."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        rows = [{"target": "a", "vuln_class": "idor", "endpoint": "/1", "result": "confirmed",
                 "technique": "numeric_id_swap", "tech_stack": ["Next.js"], "payout": 500,
                 "locally_confirmed": True, "platform_outcome": None}]
        rows += [{"target": "a", "vuln_class": "idor", "endpoint": f"/{i}", "result": "rejected",
                  "technique": "numeric_id_swap", "tech_stack": ["Next.js"], "payout": 0,
                  "locally_confirmed": False} for i in range(4)]
        (self.dir / "journal.jsonl").write_text(
            "\n".join(json.dumps(r) for r in rows) + "\n")
        (self.dir / "patterns.jsonl").write_text(json.dumps(rows[0]) + "\n")

    def _run(self, extra=()):
        r = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts" / "pattern-analytics.py"),
             "--patterns", str(self.dir / "patterns.jsonl"), "--format", "json", *extra],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout[r.stdout.index("{"):])

    def test_journal_is_the_denominator_when_present(self):
        out = self._run()
        self.assertEqual(out["denominator"], "journal")
        stats = out["stack_stats"]["next.js"]["numeric_id_swap"]
        self.assertEqual(stats["attempts"], 5)
        self.assertEqual(stats["confirmed"], 1)
        self.assertEqual(stats["success_rate"], 20.0)

    def test_without_a_journal_the_fallback_is_labelled_not_silent(self):
        out = self._run(["--journal", str(self.dir / "absent.jsonl")])
        self.assertEqual(out["denominator"], "patterns")
        self.assertEqual(
            out["stack_stats"]["next.js"]["numeric_id_swap"]["success_rate"], 100.0,
            "the fallback still reads 100% — it must be labelled, which `denominator` does")

    def test_platform_acceptance_is_tracked_apart_from_local_confirmation(self):
        rows = [{"target": "b", "vuln_class": "info-leak", "endpoint": f"/{i}",
                 "result": "na", "technique": "header_disclosure",
                 "tech_stack": ["Next.js"], "locally_confirmed": True,
                 "platform_outcome": "na"} for i in range(3)]
        (self.dir / "journal.jsonl").write_text(
            (self.dir / "journal.jsonl").read_text()
            + "\n".join(json.dumps(r) for r in rows) + "\n")
        stats = self._run()["stack_stats"]["next.js"]["header_disclosure"]
        self.assertEqual(stats["confirmed"], 3, "it did reproduce every time")
        self.assertEqual(stats["accepted_rate"], 0.0,
                         "and triage rejected it every time — that must be visible")


if __name__ == "__main__":
    unittest.main()
