"""The no-Stop-hook wave protocol (2026-11-18).

An advisory is not a mechanism. `cbh autohunt` printed "continuing is YOUR obligation" on every
wave of the intigriti/1password hunt on 2026-11-18, and the session still handed the turn back to
the operator after each single lane — twice, 17 minutes idle the first time. A client with no Stop
hook gets nothing else, so the three things that actually stall it are numbered in the wave
itself: dispatch width, the spawn flake, and the hand-back.

Measured that day, and these numbers are what the text cites:
  * 05:51:18 — two lanes sent in ONE message, both ran to the end (66 and 75 tool calls).
  * 6 of 10 spawns returned `API error (status 403 Forbidden): permission-denied`, and all four
    brief texts of the day first failed and then succeeded BYTE-IDENTICAL — so neither the brief,
    its length, the role nor the model is the cause.
"""
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "engine"))
import autohunt as AH  # noqa: E402


# Reuse the fixture that already renders: every key `render` indexes on, written out rather
# than minimised, because a stub missing one raises KeyError and that reads as a broken test.
BASE = {
    "engagement": "p/e", "slots": 6, "slots_source": "test",
    "unconfirmed_findings": 0, "budget_requests_left": None,
    "budget_requests_cap": None, "budget_requests_fired": 0, "requests_per_lane": 0,
    "queue": {}, "accounts_wanted": [], "chain_hub": "", "bar_met": False,
    "walled_open_items": 0, "egress_walled_open_items": 0,
    "allow_stop": False, "stop_reason": "test", "stop_hook": False,
    "role": "deep-hunter", "role_why": "test",
}
BRIEF = {"file": "leads/x.md", "kind": "lead", "class": "idor", "title": "t",
         "reward": 0, "age_days": 0, "stalled": False, "needs": [],
         "role": "deep-hunter", "skills": [], "escalates_to": [],
         "corpus_chains": [], "chains_via": "", "operator_wall": "",
         "network_wall": "", "host_shared": "", "partners": [], "precedent": "",
         "requests": 0, "severity_claimed": "", "evidence": "",
         "refute_reason": "", "close": "c"}


class _R:
    @staticmethod
    def render(n, stop_hook=False):
        import client as client_mod
        briefs = [{**BRIEF, "file": f"leads/x{i}.md", "title": f"t{i}"} for i in range(n)]
        return AH.render({**BASE, "stop_hook": stop_hook,
                          "client": client_mod.profile("generic"), "briefs": briefs})


class ItPrintsOnlyWhereNothingElseEnforces(unittest.TestCase):
    def test_a_client_with_a_stop_hook_gets_no_protocol(self):
        """Claude Code has the Stop hook; printing this at it is noise."""
        out = _R.render(3, stop_hook=True)
        self.assertNotIn("NO STOP HOOK", out)

    def test_a_client_without_one_gets_it(self):
        out = _R.render(3, stop_hook=False)
        self.assertIn("NO STOP HOOK ON THIS CLIENT", out)

    def test_it_says_these_are_not_advice(self):
        """The 2026-11-18 failure was reading the line as a reminder."""
        out = _R.render(3)
        self.assertIn("not", out.split("NO STOP HOOK")[1][:120])
        self.assertIn("wave protocol", out)


class TheThreeSteps(unittest.TestCase):
    def test_width_step_names_the_measurement_that_proves_parallelism_works(self):
        out = _R.render(3)
        self.assertIn("DISPATCH WIDTH", out)
        self.assertIn("ONE message", out)
        self.assertIn("05:51:18", out)
        self.assertIn("66", out)

    def test_the_403_step_says_it_is_a_slot_to_resend_not_a_dead_lane(self):
        out = _R.render(3)
        self.assertIn("403", out)
        self.assertIn("BYTE-IDENTICAL", out)
        self.assertIn("six times", out)
        self.assertIn("6 of 10", out)

    def test_the_403_step_forbids_holding_the_wave_behind_one_slot(self):
        out = _R.render(3)
        tail = out.split("403s IS NOT A DEAD LANE")[1]
        self.assertIn("do not hold the rest of the wave behind it", tail)

    def test_the_handback_step_is_the_one_that_ends_the_stall(self):
        out = _R.render(3)
        self.assertIn("NEVER HAND THE TURN BACK", out)
        self.assertIn("ONLY THE OPERATOR ENDS A HUNT", out)
        self.assertIn("wait for permission", out)


class AOneLaneWaveIsNotNagged(unittest.TestCase):
    """The width step is OMITTED at n=1, not reworded: "1 together fire no faster than 1" is
    nonsense, and a one-lane wave has no width to get wrong."""

    def test_no_width_step_and_no_one_message_phrase(self):
        out = _R.render(1)
        self.assertNotIn("DISPATCH WIDTH", out)
        self.assertNotIn("ONE message", out)

    def test_but_the_other_two_still_print(self):
        """The 2026-11-18 scout was a ONE-lane wave and its spawn 403'd three times."""
        out = _R.render(1)
        self.assertIn("403s IS NOT A DEAD LANE", out)
        self.assertIn("NEVER HAND THE TURN BACK", out)

    def test_the_header_counts_the_steps_it_prints(self):
        self.assertIn("the 2 steps below", _R.render(1))
        self.assertIn("the 3 steps below", _R.render(3))


class TheStandingOrdersCarryTheSameRule(unittest.TestCase):
    """`cbh hunt-start` prints these to a client that has no UserPromptSubmit hook, so the rule
    has to be there too — a session that never re-runs autohunt would otherwise never see it."""

    ORDERS = (REPO / "scripts" / "hunt-arm.py").read_text(encoding="utf-8")

    def test_dispatch_width(self):
        self.assertIn("SEND THE WHOLE WAVE IN ONE MESSAGE", self.ORDERS)

    def test_per_slot_retry(self):
        self.assertIn("BYTE-IDENTICAL", self.ORDERS)
        self.assertIn("six times", self.ORDERS)

    def test_never_hand_back(self):
        self.assertIn("NEVER hand the turn back", self.ORDERS)

    def test_it_cites_the_stall_it_came_from(self):
        self.assertIn("2026-11-18", self.ORDERS)


if __name__ == "__main__":
    unittest.main()
