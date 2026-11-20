#!/usr/bin/env python3
"""Crew size comes from the engagement's own budget, not from a constant.

Operator instruction 2026-10-29: a hunt on one programme should start the most
workers that are actually useful there. The old number was the string "Cap is 3
concurrent workers" in scripts/hunt-arm.py — the same 3 for a programme publishing
30 rps and for one still on the 10-second default, so one of them was always wrong.
"""
import contextlib
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

_PINNED = {}


def setUpModule():
    """Pin the Claude row: these assertions are ABOUT it.

    `engine/crew.py` derives the crew from the client row, so the numbers below (the
    in-process cap of 3, the one-worker budget) are Claude's. Launched from a Grok process
    the ambient row is `generic` (crew 6) and nine of these failed for that reason alone —
    measured 2026-11-17. See the longer note in tests/test_crew_gate.py.
    """
    import os
    for k in ("CBH_AGENT", "GROK_AGENT", "GROK_SESSION_ID"):
        _PINNED[k] = os.environ.get(k)
    os.environ["CBH_AGENT"] = "claude"
    os.environ.pop("GROK_AGENT", None)
    os.environ.pop("GROK_SESSION_ID", None)


def tearDownModule():
    import os
    for k, v in _PINNED.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
sys.path.insert(0, str(REPO / "engine"))

import crew as C  # noqa: E402


class FakeEngagement:
    def __init__(self, name, interval, profile=None):
        self.name = name
        self.project_dir = Path("/tmp") / name
        self._interval = interval
        self.profile = profile or {}

    @property
    def min_interval(self):
        return self._interval


@contextlib.contextmanager
def _pinned(engagement, in_process=False, credits=95.0):
    """orders_line()/brief_line() call plan() themselves, so the engagement, the worker
    kind AND the quota have to be pinned here: reading the real plan window made the
    expected crew size depend on how much quota the operator happened to have left (seen
    2026-10-30 at 2% left: the sentence said 1 worker, the test demanded 6)."""
    orig = (C._engagement, C._in_process_workers, C._quota_pct, C.DEFAULT_HUNT_AGENTS)
    C._engagement = lambda project="", start="": engagement
    C._in_process_workers = lambda: in_process
    C._quota_pct = lambda: credits
    C.DEFAULT_HUNT_AGENTS = None  # these tests check the budget-derived wording
    try:
        yield
    finally:
        (C._engagement, C._in_process_workers, C._quota_pct, C.DEFAULT_HUNT_AGENTS) = orig


class _Patched(unittest.TestCase):
    def plan(self, interval, profile=None, credits=95.0, in_process=False, default=None):
        """`in_process` is pinned, never read from the machine: when a worker is an
        in-process `Agent` the crew is capped at IN_PROCESS_CAP (see
        InProcessWorkersCapTheCrew), which would otherwise make every budget assertion
        here depend on which client happens to be driving this test run."""
        orig, orig_r, orig_d = C._engagement, C._in_process_workers, C.DEFAULT_HUNT_AGENTS
        C._engagement = lambda project="", start="": FakeEngagement("t", interval, profile)
        C._in_process_workers = lambda: in_process
        C.DEFAULT_HUNT_AGENTS = default
        try:
            return C.plan(credits_pct=credits)
        finally:
            C._engagement, C._in_process_workers, C.DEFAULT_HUNT_AGENTS = orig, orig_r, orig_d


class DerivedFromTheBudget(_Patched):
    def test_a_ten_second_budget_feeds_exactly_one_worker(self):
        """0.1 req/s for the whole engagement: a second worker adds no request."""
        p = self.plan(10.0)
        self.assertEqual(1, p["agents"])
        self.assertEqual(1, p["budget_useful"])

    def test_a_fast_budget_is_capped_at_the_practical_ceiling(self):
        p = self.plan(0.1)
        self.assertEqual(125, p["budget_useful"])
        self.assertEqual(C.MAX_WORKERS, p["agents"])

    def test_a_middling_budget_still_reaches_the_cap(self):
        self.assertEqual(C.MAX_WORKERS, self.plan(0.4)["agents"])

    def test_the_number_rises_with_the_budget(self):
        sizes = [self.plan(i)["agents"] for i in (10.0, 1.0, 0.4, 0.1)]
        self.assertEqual(sizes, sorted(sizes), sizes)

    def test_no_pacing_at_all_still_returns_a_bounded_crew(self):
        p = self.plan(0.0)
        self.assertEqual(C.MAX_WORKERS, p["agents"])


class OperatorOverride(_Patched):
    def test_hunt_agents_wins_over_the_derivation(self):
        p = self.plan(0.1, {"hunt_agents": 2})
        self.assertEqual(2, p["agents"])
        self.assertIn("operator override", p["source"])

    def test_an_override_above_the_budget_is_kept_but_called_out(self):
        p = self.plan(10.0, {"hunt_agents": 8})
        self.assertEqual(8, p["agents"])
        self.assertTrue(any("queue on the flock" in n for n in p["notes"]))

    def test_an_override_is_still_bounded(self):
        self.assertEqual(C.HARD_MAX, self.plan(0.1, {"hunt_agents": 500})["agents"])

    def test_a_garbage_override_falls_back_to_the_derivation(self):
        p = self.plan(0.1, {"hunt_agents": "lots"})
        self.assertEqual(C.MAX_WORKERS, p["agents"])
        self.assertIn("derived", p["source"])


class QuotaShrinksTheCrew(_Patched):
    def test_a_low_window_halves_it(self):
        self.assertEqual(C.MAX_WORKERS // 2, self.plan(0.1, credits=20.0)["agents"])

    def test_a_critical_window_cuts_it_to_one(self):
        p = self.plan(0.1, credits=5.0)
        self.assertEqual(1, p["agents"])
        self.assertTrue(any("drain the quota" in n for n in p["notes"]))

    def test_an_unreadable_quota_never_blocks_a_hunt(self):
        self.assertEqual(C.MAX_WORKERS, self.plan(0.1, credits=None)["agents"])


class InProcessCapHolds(_Patched):
    def test_never_more_than_three_in_process_agents(self):
        """Measured: past three, compaction truncates one mid-run."""
        for interval in (10.0, 1.0, 0.1):
            self.assertLessEqual(self.plan(interval)["in_process_cap"], C.IN_PROCESS_CAP)

    def test_the_cap_never_exceeds_the_crew_itself(self):
        p = self.plan(10.0)
        self.assertLessEqual(p["in_process_cap"], p["agents"])


class InProcessWorkersCapTheCrew(_Patched):
    """Operator directive 2026-10-30: every worker is spawned with the `Agent` tool.

    The overflow path the sizing used to name — "run the rest as `cbh worker`" — went
    out with the second provider (2026-11-13) and is denied by scripts/agent-gate.py,
    so when workers are in-process the in-process cap IS the crew cap and the rest is
    covered by rotating roles through the queue.
    """

    def test_a_fast_budget_is_capped_at_the_in_process_cap(self):
        p = self.plan(0.1, in_process=True)
        self.assertEqual(C.IN_PROCESS_CAP, p["agents"])
        self.assertTrue(p["in_process"])
        self.assertTrue(any("rotating roles" in n for n in p["notes"]), p["notes"])

    def test_default_is_three_everywhere(self):
        """2026-11-10 (final): 3 workers on every engagement without a hunt_agents line."""
        self.assertEqual(3, C.DEFAULT_HUNT_AGENTS)
        p = self.plan(10.0, in_process=True, default=3)
        self.assertEqual(3, p["agents"])
        self.assertIn("default 3", p["source"])

    def test_operator_override_lifts_the_in_process_cap(self):
        """2026-11-10: operator chose speed — an explicit hunt_agents wins over the cap."""
        p = self.plan(0.1, profile={"hunt_agents": 6}, in_process=True)
        self.assertEqual(6, p["agents"])
        self.assertEqual(6, p["in_process_cap"])

    def test_a_client_with_its_own_subagents_still_reaches_max_workers(self):
        """Not every client runs its workers in this context; `engine/client.py` holds
        that row, and such a client is not bound by the compaction cap."""
        p = self.plan(0.1, in_process=False)
        self.assertEqual(C.MAX_WORKERS, p["agents"])
        self.assertFalse(p["in_process"])

    def test_a_small_budget_is_untouched_by_the_cap(self):
        self.assertEqual(1, self.plan(10.0, in_process=True)["agents"])

    def test_the_orders_name_the_agent_tool_and_never_the_denied_command(self):
        with _pinned(FakeEngagement("t", 0.1, None), in_process=True):
            txt = C.orders_line()
        self.assertIn("`Agent` tool", txt)
        self.assertNotIn("cbh worker", txt)


class TextForTheSession(_Patched):
    def test_the_orders_sentence_names_the_number_and_the_reason(self):
        with _pinned(FakeEngagement("t", 0.1, {}), in_process=False):
            line = C.orders_line()
        self.assertIn("6 concurrent worker(s)", line)
        self.assertIn("req/s", line)
        self.assertIn("rotate roles", line)

    def test_no_engagement_yields_no_brief_line(self):
        orig = C._engagement

        class NoEng:
            name = None
            project_dir = None
            profile = {}
            min_interval = 0.0
        C._engagement = lambda project="", start="": NoEng()
        try:
            self.assertEqual("", C.brief_line())
            self.assertIn("by default", C.orders_line())
        finally:
            C._engagement = orig


class WiredIn(unittest.TestCase):
    def test_the_standing_orders_no_longer_hardcode_three(self):
        """The ORDERS text itself, not the file: a docstring may still quote the
        old sentence to say why it went away."""
        import importlib.machinery
        import importlib.util
        loader = importlib.machinery.SourceFileLoader(
            "hunt_arm_under_test", str(REPO / "scripts" / "hunt-arm.py"))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        self.assertNotIn("Cap is 3 concurrent workers", mod.ORDERS)
        self.assertIn("{CREW}", mod.ORDERS)
        # With no engagement in the event the line is the "pickup first" variant;
        # the text for a resolved engagement is asserted in TextForTheSession.
        rendered = mod.ORDERS.replace("{SPAWN}", "").replace("{CREW}", mod._crew_line({}))
        self.assertNotIn("{CREW}", rendered)
        self.assertIn("Crew size", rendered)

    def test_the_session_brief_prints_it(self):
        text = (REPO / "scripts" / "session-brief.py").read_text(encoding="utf-8")
        self.assertIn("from crew import brief_line", text)

    def test_cbh_exposes_it(self):
        import subprocess
        r = subprocess.run([sys.executable, "-m", "cbh.cli", "crew",
                            "--project", "standoff365/yukki", "--json"],
                           capture_output=True, text=True, cwd=str(REPO), timeout=120)
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertIn('"agents"', r.stdout)


if __name__ == "__main__":
    unittest.main()


class TheEngagementNumberOutranksTheClientRow(unittest.TestCase):
    """`"hunt_agents"` in profile.json OVERRIDES any crew number — for EVERY client.

    `plan()` returned the non-Claude default before it consulted the override, so for any
    client but Claude Code the engagement's own number was silently dropped. It was
    invisible while both happened to be 6; setting an engagement to 3 to protect a fragile
    target would still have run 6 workers against it. The number is a safety knob as much
    as a speed one, so this is pinned in both directions.
    """

    def _plan(self, client_name, hunt_agents):
        profile = {"min_interval_seconds": 0.1}
        if hunt_agents is not None:
            profile["hunt_agents"] = hunt_agents
        real_client = C._client
        with _pinned(FakeEngagement("t", 0.1, profile), in_process=False):
            C._client = lambda: client_name
            try:
                return C.plan()
            finally:
                C._client = real_client

    def test_a_non_claude_client_honours_a_SMALLER_number(self):
        p = self._plan("generic", 2)
        self.assertEqual(p["agents"], 2)
        self.assertIn("hunt_agents", p["source"])

    def test_a_non_claude_client_honours_a_LARGER_number(self):
        self.assertEqual(self._plan("generic", 9)["agents"], 9)

    def test_without_an_override_the_client_default_still_applies(self):
        """Positive control: the override is what changed, not the default."""
        p = self._plan("generic", None)
        self.assertEqual(p["agents"], C.NON_CLAUDE_AGENTS)
        self.assertIn("always", p["source"])

    def test_claude_code_was_already_right_and_stays_right(self):
        self.assertEqual(self._plan("claude", 2)["agents"], 2)

    def test_the_hard_max_still_binds_whoever_asks(self):
        self.assertEqual(self._plan("generic", 10_000)["agents"], C.HARD_MAX)
