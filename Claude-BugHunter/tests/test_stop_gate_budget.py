#!/usr/bin/env python3
"""The stop gate's third exit: a spent budget.

Before this the gate had two doors — a demonstrated >= medium finding, or proven
exhaustion of the vector ledger. Both are statements about the target. Neither covers
a session that has spent what the operator budgeted and has not got there, which left
the gate pushing a hunt that was no longer learning anything — and a gate that cannot
be satisfied honestly is pressure to satisfy it dishonestly.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import stop_gate as SG  # noqa: E402


class Budget(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.memdir = self.root / "hunt-memory"
        self.memdir.mkdir()
        self.project = self.root / "Targets" / "acme"
        (self.project / "findings").mkdir(parents=True)
        self._env = dict(os.environ)
        os.environ["CBH_MEMORY_DIR"] = str(self.memdir)
        self.addCleanup(self._restore)

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._env)
        self.tmp.cleanup()

    def _profile(self, **kw):
        (self.project / "profile.json").write_text(json.dumps(kw))

    def _audit(self, n, *, body_hash=None, minutes_ago=0):
        ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
        with (self.memdir / "audit.jsonl").open("a") as fh:
            for i in range(n):
                row = {"timestamp": ts.isoformat(), "engagement": "acme",
                       "urls": [f"https://acme.com/{i}"]}
                if body_hash is not None:
                    row["body_sha256"] = body_hash if isinstance(body_hash, str) else f"h{i}"
                fh.write(json.dumps(row) + "\n")

    # ------------------------------------------------------------ defaults
    def test_no_budget_configured_never_ends_a_hunt(self):
        self._profile(min_interval_seconds=0)
        self._audit(500)
        b = SG.budget(self.project, time.time() - 3600)
        self.assertFalse(b["spent"])
        self.assertFalse(SG.assess(self.project, time.time() - 3600)["allow"])

    def test_a_budget_is_spent_not_declared(self):
        """Configured but no requests fired: the hunt has spent nothing."""
        self._profile(max_requests=10)
        self.assertFalse(SG.budget(self.project, time.time())["spent"])

    # ------------------------------------------------------------ requests
    def test_request_budget_ends_the_hunt_when_actually_fired(self):
        self._profile(max_requests=5)
        self._audit(5)
        b = SG.budget(self.project, time.time() - 60)
        self.assertTrue(b["spent"])
        self.assertEqual(b["exit_condition"], "max_requests")

    def test_requests_from_other_engagements_do_not_count(self):
        self._profile(max_requests=3)
        with (self.memdir / "audit.jsonl").open("a") as fh:
            for i in range(9):
                fh.write(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(),
                                     "engagement": "other", "urls": ["https://x/"]}) + "\n")
        self.assertFalse(SG.budget(self.project, time.time() - 60)["spent"])

    def test_requests_from_an_earlier_hunt_do_not_pay_for_this_one(self):
        self._profile(max_requests=3)
        self._audit(9, minutes_ago=300)
        self.assertFalse(SG.budget(self.project, time.time() - 60)["spent"],
                         "yesterday's requests spent today's budget")

    # --------------------------------------------------------------- clock
    def test_time_budget(self):
        self._profile(max_minutes=30)
        b = SG.budget(self.project, time.time() - 31 * 60)
        self.assertTrue(b["spent"])
        self.assertEqual(b["exit_condition"], "max_minutes")

    def test_time_budget_not_yet_spent(self):
        self._profile(max_minutes=30)
        self.assertFalse(SG.budget(self.project, time.time() - 60)["spent"])

    # ---------------------------------------------------- no new information
    def test_identical_answers_across_the_window_end_the_hunt(self):
        self._profile(no_new_information_window=10)
        self._audit(10, body_hash="same")
        b = SG.budget(self.project, time.time() - 60)
        self.assertTrue(b["spent"])
        self.assertEqual(b["exit_condition"], "no_new_information_window")

    def test_varying_answers_keep_the_hunt_open(self):
        self._profile(no_new_information_window=10)
        self._audit(10, body_hash=True)          # distinct hash per request
        self.assertFalse(SG.budget(self.project, time.time() - 60)["spent"])

    def test_window_off_by_default(self):
        self._profile(min_interval_seconds=0)
        self._audit(50, body_hash="same")
        self.assertFalse(SG.budget(self.project, time.time() - 60)["spent"])

    def test_requests_without_stored_bodies_cannot_prove_stagnation(self):
        self._profile(no_new_information_window=5)
        self._audit(20)                           # no body_sha256 at all
        self.assertFalse(SG.budget(self.project, time.time() - 60)["spent"])

    # -------------------------------------------------------------- assess
    def test_assess_records_which_door_the_hunt_left_by(self):
        self._profile(max_requests=2)
        self._audit(2)
        a = SG.assess(self.project, time.time() - 60)
        self.assertTrue(a["allow"])
        self.assertEqual(a["exit_condition"], "max_requests")
        self.assertIn("budget is spent", a["reason"])

    def test_a_finding_still_outranks_a_budget(self):
        self._profile(max_requests=1)
        self._audit(50)
        a = SG.assess(self.project, time.time() - 60)
        self.assertTrue(a["allow"])
        self.assertEqual(a["exit_condition"], "max_requests")
        self.assertEqual(a["proven"], [], "no finding exists in this fixture")

    def test_block_message_shows_how_much_budget_is_left(self):
        self._profile(max_requests=100)
        self._audit(7)
        msg = SG.block_message(SG.assess(self.project, time.time() - 60))
        self.assertIn("7/100 requests", msg)
        self.assertIn("inflating a finding", msg)


if __name__ == "__main__":
    unittest.main()
