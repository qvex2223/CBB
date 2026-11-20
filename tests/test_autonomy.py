"""The closed parking list (engine/autonomy.py) and what it changed in the queues.

Operator directive 2026-11-14: a vector is parked only for a reason the operator cannot
grant, and only when the file DECLARES it. Everything else is a lane.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import autonomy  # noqa: E402
import lead_queue  # noqa: E402


class DeclarationIsTheVerdict(unittest.TestCase):
    def test_every_banner_form_declares(self):
        for text in ("**Park:** availability",
                     "**Park: other-user-data**",
                     "## Park — out-of-scope",
                     "> **Park:** human-inbox",
                     "Park: availability"):
            with self.subTest(text=text):
                self.assertEqual(autonomy.verdict(text)[0], "PARK", text)

    def test_unknown_slug_is_not_a_park(self):
        self.assertEqual(autonomy.verdict("**Park:** needs-approval"), ("ACT", None))

    def test_quoted_programme_rule_is_not_a_park(self):
        # 163 of 431 legacy files matched a prose reader on exactly this sentence, which is
        # the programme's approval rule being quoted — the rule the operator has answered.
        text = ("`scope.md`: a check that could affect other users or availability needs "
                "Kcell's prior approval. Not attempted.")
        self.assertEqual(autonomy.verdict(text), ("ACT", None))
        # It still reads as a hint, so a lane knows to read the record before firing.
        self.assertEqual(autonomy.hint(text), "other-user-data")

    def test_a_denial_is_not_its_own_trigger(self):
        # b2b-accounts-api-authorization-channel-arms parked on this sentence.
        self.assertEqual(
            autonomy.verdict("Both are read-only, carry no real credential, and target no "
                             "other user's data.")[0], "ACT")

    def test_no_declaration_means_act(self):
        for text in ("# Needs a POST to the write route",
                     "# Needs a buyer account nobody holds",
                     "# Needs Kcell's prior approval",
                     "# bbcurl cannot reach the product",
                     "**Status:** BLOCKED — waiting on the operator"):
            with self.subTest(text=text):
                self.assertEqual(autonomy.verdict(text), ("ACT", None), text)


class PerEngagementOverride(unittest.TestCase):
    def _eng(self, cfg):
        d = Path(self.tmp.name)
        (d / "profile.json").write_text(json.dumps(cfg))
        return d

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_default_is_all_four(self):
        self.assertEqual(autonomy.retained(self._eng({})),
                         ("other-user-data", "availability", "out-of-scope", "human-inbox"))

    def test_unpark_subtracts_and_overrules_the_declaration(self):
        eng = self._eng({"autonomy": {"unpark": ["human-inbox"]}})
        self.assertNotIn("human-inbox", autonomy.retained(eng))
        self.assertEqual(autonomy.verdict("**Park:** human-inbox", eng), ("ACT", None))
        self.assertEqual(autonomy.verdict("**Park:** availability", eng)[0], "PARK")

    def test_park_list_replaces_the_default(self):
        eng = self._eng({"autonomy": {"park": ["availability"]}})
        self.assertEqual(autonomy.retained(eng), ("availability",))

    def test_unknown_slug_is_reported_not_obeyed(self):
        eng = self._eng({"autonomy": {"park": ["availability", "needs-approval"]}})
        self.assertEqual(autonomy.retained(eng), ("availability",))
        self.assertEqual(autonomy.unknown_slugs(eng), ["needs-approval"])


class ClauseIsGenerated(unittest.TestCase):
    def test_clause_names_every_retained_reason_and_the_declaration(self):
        c = autonomy.clause()
        for slug in autonomy.DEFAULT_PARK:
            self.assertIn(slug, c)
        self.assertIn("**Park:**", c)
        for excuse, _ in autonomy.UNPARKED:
            self.assertIn(excuse.split("(")[0].strip()[:20], c)

    def test_role_files_carry_the_generated_clause(self):
        # The role files are the only text a worker sees; a hand-written copy drifts.
        for role in ("deep-hunter", "scout", "refuter"):
            text = (REPO / ".claude" / "agents" / f"{role}.md").read_text()
            self.assertIn("PARK A VECTOR ONLY", text, role)
            self.assertIn("**Park:**", text, role)


class QueueHoldsBackOnlyOnADeclaration(unittest.TestCase):
    def setUp(self):
        # The engagement must sit UNDER the targets root: `lead_queue.scan` reports
        # `eng.relative_to(_targets_root())`, which raises on a bare /tmp path.
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        os.environ["CBH_TARGETS_ROOT"] = self.tmp.name
        self.addCleanup(os.environ.pop, "CBH_TARGETS_ROOT", None)
        self.eng = Path(self.tmp.name) / "plat" / "prog"
        (self.eng / "leads").mkdir(parents=True)
        (self.eng / "primitives").mkdir()

    def _lead(self, name, body):
        (self.eng / "leads" / f"{name}.md").write_text(body)

    def test_blocked_banner_without_declaration_stays_workable(self):
        self._lead("a", "# A\n\n**Status:** BLOCKED — needs a POST\n")
        q = lead_queue.scan(self.eng)
        self.assertEqual(len(q["open"]), 1)
        self.assertEqual(q["blocked"], 0)
        self.assertEqual(q["undeclared_block"], 1)
        self.assertTrue(q["open"][0]["undeclared_block"])

    def test_declared_reason_holds_it_back(self):
        self._lead("b", "# B\n\n**Status:** BLOCKED\n\n**Park:** other-user-data\n")
        q = lead_queue.scan(self.eng)
        self.assertEqual(q["open"], [])
        self.assertEqual(q["blocked"], 1)

    def test_declaration_without_a_blocked_banner_does_not_park(self):
        # The banner is still what closes a row; the declaration only says WHY.
        self._lead("c", "# C\n\n**Park:** availability\n")
        self.assertEqual(len(lead_queue.scan(self.eng)["open"]), 1)

    def test_account_need_is_a_lane_marked_register_first(self):
        self._lead("d", "# D\n\n**Chain:** needs `seller-session` · gives `x`\n")
        q = lead_queue.scan(self.eng)
        self.assertEqual(q["needs_account"], {})
        self.assertEqual(len(q["open"]), 1)
        self.assertEqual(q["open"][0]["register_first"], "seller-session")

    def test_programme_forbidding_registration_still_holds_it(self):
        (self.eng / "profile.json").write_text(json.dumps({"self_registration": False}))
        self._lead("e", "# E\n\n**Chain:** needs `seller-session` · gives `x`\n")
        q = lead_queue.scan(self.eng)
        self.assertEqual(q["open"], [])
        self.assertIn("seller-session", q["needs_account"])


class Reclassification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        os.environ["CBH_TARGETS_ROOT"] = self.tmp.name
        self.addCleanup(os.environ.pop, "CBH_TARGETS_ROOT", None)
        self.eng = Path(self.tmp.name) / "plat" / "prog"
        (self.eng / "blocked-tests").mkdir(parents=True)

    def _bt(self, name, body):
        (self.eng / "blocked-tests" / f"{name}.md").write_text(body)

    def test_act_park_and_done_are_separated(self):
        self._bt("fire", "# Needs a POST\n")
        self._bt("park", "# Rung 4\n\n**Park:** other-user-data\n")
        self._bt("done", "# Old\n\n**Status:** CLOSED — answered\n")
        rows = {r["name"]: r for r in autonomy.reclassify(self.eng)}
        self.assertEqual(rows["fire"]["verdict"], "ACT")
        self.assertEqual(rows["park"]["verdict"], "PARK")
        self.assertEqual(rows["park"]["reason"], "other-user-data")
        self.assertEqual(rows["done"]["verdict"], "DONE")

    def test_reopen_writes_a_stalled_lead_and_never_overwrites(self):
        self._bt("fire", "# Needs a POST\n")
        rows = autonomy.reclassify(self.eng)
        made = autonomy.reopen(self.eng, rows)
        self.assertEqual(len(made), 1)
        text = made[0].read_text()
        self.assertIn("STALLED", text)                       # workable with a RETRY mark
        self.assertIn("blocked-tests/fire.md", text)         # points at the record
        self.assertTrue(lead_queue._is_stalled(text))
        self.assertFalse(lead_queue._is_closed(text))
        self.assertEqual(autonomy.reopen(self.eng, rows), [])

    def test_reopen_skips_a_declared_park(self):
        self._bt("park", "# Rung 4\n\n**Park:** availability\n")
        self.assertEqual(autonomy.reopen(self.eng, autonomy.reclassify(self.eng)), [])

    def test_hint_is_written_into_the_lead_not_used_to_hold_it(self):
        self._bt("quoted", "# X\n\nscope.md requires approval for anything that could "
                           "affect other users.\n")
        rows = autonomy.reclassify(self.eng)
        self.assertEqual(rows[0]["verdict"], "ACT")
        self.assertEqual(rows[0]["hint"], "other-user-data")
        text = autonomy.reopen(self.eng, rows)[0].read_text()
        self.assertIn("Read before firing", text)
        self.assertIn("**Park:** other-user-data", text)     # how to park it if it is real


if __name__ == "__main__":
    unittest.main()
