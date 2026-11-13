"""The naive agent must not be handed the engagement's own conclusions.

A konsol run on 2026-10-20 narrated "The notes reveal a lot of prior work" and
then went at a host that was not its target: it had read notes.md, so it spent
its budget re-deriving what was already written and drifted off-target. The whole
value of this agent is the item the methodology did not look for, which it cannot
produce once it has read the methodology's output.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import freeroam


class PromptKeepsItNaive(unittest.TestCase):
    def test_the_record_is_named_as_off_limits(self):
        for forbidden in ("notes.md", "hosts/", "leads/", "primitives/",
                          "findings/", "blocked-tests/", "recon/"):
            self.assertIn(forbidden, freeroam.PROMPT,
                          f"{forbidden} must be explicitly off limits")

    def test_the_two_files_it_may_read_are_named(self):
        self.assertIn("scope.md", freeroam.PROMPT)
        self.assertIn("identity.json", freeroam.PROMPT)

    def test_off_target_hosts_are_refused_explicitly(self):
        self.assertIn("not a sibling", freeroam.PROMPT.lower())


class HardCapIsOnlyARunawayStop(unittest.TestCase):
    """The turn cap must leave real headroom over the advertised work budget."""

    def test_cap_is_well_above_the_prompt_budget(self):
        for turns in (10, 30, 45, 60):
            cap = max(3 * turns, 90)
            self.assertGreaterEqual(cap, turns * 2,
                                    "a cap this close to the budget is what killed "
                                    "three runs on konsol")

    def test_small_budgets_still_get_a_floor(self):
        self.assertEqual(max(3 * 5, 90), 90)


if __name__ == "__main__":
    unittest.main()
