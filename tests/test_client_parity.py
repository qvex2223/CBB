"""Client parity (2026-11-17): Claude Code and Grok must DECIDE the same thing.

`engine/client.py` holds two rows — `claude` and `generic`, the one Grok takes through the
alias at `:116`. Two things differ by design (crew size, and whether the orchestrator may
send) and everything else must not. Measured the same day with
`scripts/decision_replay.py --client`: over 20 engagements, with the `wave` blocks stripped
the two reports are byte-identical but for the header, and inside a wave only the lane count
and the proportional refuter share move.

The rule these tests encode:
  * outside a wave: identical. Queue ranking, evidence status, class-proof verdict.
  * inside a wave: identical ITEM SEQUENCE, and a refuter share that is the same FRACTION of
    the crew. 1 of 3 and 2 of 6 are the same decision, not two.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "engine"))
import autohunt as AH  # noqa: E402
import class_proof as CP  # noqa: E402
import client as CL  # noqa: E402
import doctrine as DOC  # noqa: E402
import evidence as EV  # noqa: E402
import lead_queue as LQ  # noqa: E402

ROWS = ("claude", "generic")


class _AsClient:
    """Run a block as one client row. `CBH_AGENT` wins in client.detect()."""

    def __init__(self, name):
        self.name = name

    def __enter__(self):
        self._prev = os.environ.get("CBH_AGENT")
        os.environ["CBH_AGENT"] = self.name
        return self

    def __exit__(self, *exc):
        if self._prev is None:
            os.environ.pop("CBH_AGENT", None)
        else:
            os.environ["CBH_AGENT"] = self._prev
        return False


def _eng(tmp):
    root = Path(tmp) / "Targets"
    e = root / "p" / "prog"
    for tier in ("findings", "leads", "primitives"):
        (e / tier).mkdir(parents=True)
    (e / "scope.md").write_text("x")
    (e / "profile.json").write_text(json.dumps({}))
    (e / "primitives" / "idor-order-read.md").write_text(
        "# Order read across identities\n\n**Class:** `idor`\n**Status:** primitive\n"
        "**Chain:** needs `nothing` · gives `other-user-order`\n")
    (e / "leads" / "route-oracle.md").write_text(
        "# Route existence oracle\n\n**Status:** lead\n"
        "**Chain:** needs `nothing` · gives `route-oracle`\n")
    (e / "leads" / "sqli-on-search.md").write_text(
        "# Quote on search 500s\n\n**Class:** `sqli`\n**Status:** lead\n")
    return root, e


class ByDesign(unittest.TestCase):
    """The only two differences there may be."""

    def test_crew_size_differs(self):
        self.assertEqual(3, CL.crew("claude"))
        self.assertEqual(6, CL.crew("generic"))

    def test_orchestrator_may_send_differs(self):
        self.assertFalse(CL.may_send("claude"))
        self.assertTrue(CL.may_send("generic"))

    def test_grok_takes_the_generic_row(self):
        """The 01a1d946 incident: Grok was detected as Claude and ran a 3-worker crew."""
        self.assertEqual("generic", CL.profile("grok")["client"])
        self.assertEqual(6, CL.crew("grok"))

    def test_only_claude_promises_a_stop_hook(self):
        self.assertTrue(CL.profile("claude")["stop_hook"])
        self.assertFalse(CL.profile("generic")["stop_hook"])


class DetectionPrecedence(unittest.TestCase):
    """The order the tests themselves now depend on, pinned so it cannot drift.

    This is the contract four test modules rely on to pin the row they assert. It was found
    the hard way: launched from inside Grok Build the suite reported 13 failures and 3 errors
    while the same tree was green under Claude Code, because those modules popped `CBH_AGENT`
    and set `CLAUDECODE=1` — which does NOT pin Claude, since the Grok markers outrank it.
    """

    def _detect(self, **env):
        prev = {k: os.environ.get(k) for k in ("CBH_AGENT", "GROK_AGENT",
                                               "GROK_SESSION_ID", "CLAUDECODE")}
        try:
            for k in prev:
                os.environ.pop(k, None)
            os.environ.update(env)
            return CL.detect()
        finally:
            for k, v in prev.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_grok_markers_outrank_claudecode(self):
        """By design: Grok Build's compat layer leaks CLAUDECODE=1, so its own marker wins."""
        self.assertEqual("generic", self._detect(GROK_AGENT="1", CLAUDECODE="1"))
        self.assertEqual("generic", self._detect(GROK_SESSION_ID="x", CLAUDECODE="1"))

    def test_cbh_agent_outranks_everything(self):
        """The one override a test or a replay can rely on."""
        self.assertEqual("claude", self._detect(CBH_AGENT="claude", GROK_AGENT="1",
                                                CLAUDECODE="1"))
        self.assertEqual("generic", self._detect(CBH_AGENT="generic", CLAUDECODE="1"))
        self.assertEqual("generic", self._detect(CBH_AGENT="grok", CLAUDECODE="1"))

    def test_claudecode_alone_is_claude(self):
        self.assertEqual("claude", self._detect(CLAUDECODE="1"))


class DecisionsMustMatch(unittest.TestCase):
    def test_queue_ranking_is_client_independent(self):
        with tempfile.TemporaryDirectory() as t:
            root, e = _eng(t)
            out = {}
            for row in ROWS:
                with _AsClient(row), mock.patch.object(LQ, "_targets_root", lambda: root):
                    q = LQ.scan(e)
                out[row] = [r["file"] for r in q["open"]]
            self.assertEqual(out["claude"], out["generic"],
                             "the ranked queue moved with the client — parity bug")

    def test_declared_class_is_client_independent(self):
        with tempfile.TemporaryDirectory() as t:
            root, e = _eng(t)
            text = (e / "primitives" / "idor-order-read.md").read_text()
            out = {}
            for row in ROWS:
                with _AsClient(row):
                    out[row] = LQ.declared_class(text)
            self.assertEqual("idor", out["claude"])
            self.assertEqual(out["claude"], out["generic"])

    def test_known_classes_is_client_independent(self):
        out = {}
        for row in ROWS:
            with _AsClient(row):
                out[row] = sorted(LQ.known_classes())
        self.assertEqual(out["claude"], out["generic"])

    def test_evidence_status_is_client_independent(self):
        with tempfile.TemporaryDirectory() as t:
            root, e = _eng(t)
            f = e / "findings" / "nothing-behind-it.md"
            f.write_text("# A claim with no artifact\n\n**Class:** `idor`\n")
            out = {}
            for row in ROWS:
                with _AsClient(row):
                    out[row] = EV.check(f)["status"]
            self.assertEqual(out["claude"], out["generic"])

    def test_class_proof_rule_set_is_client_independent(self):
        """The per-class oracle table is `class_proof.RULES`, not `ORACLES`."""
        out = {}
        for row in ROWS:
            with _AsClient(row):
                out[row] = sorted(CP.RULES)
        self.assertEqual(out["claude"], out["generic"])
        self.assertIn("idor", out["claude"])


class WaveShape(unittest.TestCase):
    """Inside a wave, only the crew-size function may move."""

    def test_backlog_share_is_the_same_fraction_of_the_crew(self):
        """The one-third backlog cap is what scales, and it scales proportionally.

        `refuter_share` returns (refute_room, unattacked_room) and the two are different
        things, which this test originally conflated: `refute_room` is a CEILING (slots-1,
        so a hunter lane always survives) while `unattacked_room` is the one-third cap on
        never-attacked BACKLOG items. Measured 2026-11-17: (2, 1) at crew 3 and (5, 2) at
        crew 6. The replay's "1 refuter of 3, 2 of 6" is that second number.
        """
        _, b3 = AH.refuter_share(3, "", True, [])
        _, b6 = AH.refuter_share(6, "", True, [])
        self.assertEqual(1, b3)
        self.assertEqual(b3 * 2, b6,
                         f"the backlog cap is not proportional: {b3}/3 against {b6}/6")

    def test_refute_room_always_leaves_one_hunter_lane(self):
        for slots in (3, 6):
            room, _ = AH.refuter_share(slots, "", True, [])
            self.assertEqual(slots - 1, room,
                             "refute_room must be slots-1: at least one hunter lane survives")

    def test_a_named_role_fires_no_refuter(self):
        """`--role deep-hunter` and `--role scout` fire none; that holds on both crews."""
        for slots in (3, 6):
            self.assertEqual((0, 0), AH.refuter_share(slots, "auto", True, []))


class DoctrineReach(unittest.TestCase):
    def test_doctrine_text_exists(self):
        self.assertTrue(DOC.text().strip())

    def test_doctrine_is_reachable_from_the_role_files(self):
        """Item 10 landed 2026-11-17, and the decorator that marked it pending is gone.

        The doctrine moved out of every brief and into `agents/roles/*.md`, because pasting it
        per spawn re-sends a cached prefix (Strix: 97% of input tokens were re-submitted context
        across 41 subagents). What makes the move safe for Grok is the amendment in plan section
        11.2: `sync_clients.py` deploys roles ONLY to `.claude/agents`, so the `generic` row now
        tells that client to read `agents/roles/<role>.md` as a file — without it, the move would
        have deleted the doctrine from every Grok lane instead of relocating it.
        """
        marker = DOC.text().strip().splitlines()[0][:40]
        for role in ("deep-hunter", "refuter", "scout"):
            body = (REPO / "agents" / "roles" / f"{role}.md").read_text(encoding="utf-8")
            self.assertIn(marker, body, f"{role}.md does not carry the doctrine")

    def test_the_generic_row_tells_that_client_to_read_the_role_file(self):
        """The whole safety of item 10 for a client with no role registry rests on this line."""
        row = CL.profile("generic")
        self.assertIn("agents/roles/", row["subagents"])

    def test_a_brief_is_no_longer_told_to_paste_the_doctrine(self):
        """Both places that ordered the paste must stop ordering it, or the saving is undone."""
        for rel in ("AGENTS.md", "scripts/hunt-arm.py"):
            text = (REPO / rel).read_text(encoding="utf-8")
            self.assertNotIn("paste it verbatim", text, rel)

    def test_freeroam_still_gets_none_of_it(self):
        """Its value is carrying no methodology; `skills_on=False` and it reads no role file."""
        src = (REPO / "engine" / "freeroam.py").read_text(encoding="utf-8")
        self.assertNotIn("agents/roles", src)
        self.assertIn("skills_on=False", src)

    def test_the_user_scoped_registry_is_not_left_behind(self):
        """A second registry existed at `~/.claude/agents/`, last written 2026-11-12, that no
        generator touched — so the doctrine would have reached the project copies only. The
        generator now refreshes it when it exists, and never creates one where it does not."""
        gen = (REPO / "agents" / "gen_role_agents.py").read_text(encoding="utf-8")
        self.assertIn("_HOME_AGENTS", gen)
        self.assertIn("is_dir()", gen)


if __name__ == "__main__":
    unittest.main()
