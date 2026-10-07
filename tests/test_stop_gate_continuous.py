#!/usr/bin/env python3
"""Continuous mode: a finding is banked, not an exit.

The default gate treats a demonstrated Medium+ as the finish line. The operator
runs this workspace the other way round (directive 2026-09-21): keep sweeping,
drop each proven finding into `Targets/<name>/findings/`, and only the operator
ends the hunt. These tests pin both behaviours, because the switch between them
is exactly the kind of thing that silently regresses.
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import stop_gate as SG  # noqa: E402

URL = "https://acme.example.com/api/v1/orders/123"
FINDING = f"""# Orders IDOR

## Severity
High. CVSS 3.1 **7.5** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`.

## PoC
GET {URL} returns another tenant's order.
"""


class ContinuousMode(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.memdir = root / "hunt-memory"
        self.memdir.mkdir()
        self.project = root / "Targets" / "acme"
        (self.project / "findings").mkdir(parents=True)
        (self.project / "hosts").mkdir()
        self._env = dict(os.environ)
        self.addCleanup(self._restore)
        os.environ["CBH_MEMORY_DIR"] = str(self.memdir)
        os.environ.pop(SG.ENV_CONTINUOUS, None)

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._env)

    # --- fixtures ---------------------------------------------------------
    def _proven_finding(self, name="orders-idor"):
        (self.project / "findings" / f"{name}.md").write_text(FINDING, encoding="utf-8")
        (self.project / "findings" / f"{name}.result.json").write_text(json.dumps({
            "final_verdict": "PASS",
            "runs": [{"steps": [{"url": URL}], "result": {"status": 200}}],
        }), encoding="utf-8")

    def _profile(self, **kw):
        (self.project / "profile.json").write_text(json.dumps({"project": "acme", **kw}))

    def _state(self, enabled):
        SG.set_continuous(enabled, note="test", memdir=self.memdir)

    def _audit(self, n):
        ts = datetime.now(timezone.utc).isoformat()
        with (self.memdir / "audit.jsonl").open("a", encoding="utf-8") as fh:
            for i in range(n):
                fh.write(json.dumps({"timestamp": ts, "engagement": "acme",
                                     "urls": [f"https://acme.example.com/{i}"]}) + "\n")

    # --- the default is unchanged ----------------------------------------
    def test_default_mode_lets_a_proven_finding_end_the_hunt(self):
        self._proven_finding()
        verdict = SG.assess(self.project)
        self.assertTrue(verdict["allow"])
        self.assertEqual(verdict["exit_condition"], "finding")
        self.assertFalse(verdict["continuous"]["on"])
        self.assertEqual(SG.max_blocks(self.project), SG.MAX_BLOCKS)

    # --- continuous mode --------------------------------------------------
    def test_a_banked_finding_does_not_end_a_continuous_hunt(self):
        self._proven_finding()
        self._state(True)
        verdict = SG.assess(self.project)
        self.assertFalse(verdict["allow"])
        self.assertIsNone(verdict["exit_condition"])
        self.assertEqual(len(verdict["proven"]), 1)
        msg = SG.block_message(verdict)
        self.assertIn("BANKED THIS HUNT", msg)
        self.assertIn("orders-idor.md", msg)
        self.assertIn("/remember --result confirmed", msg)
        self.assertIn("--continuous off", msg)

    def test_exhaustion_means_next_host_not_the_end(self):
        self._state(True)
        (self.project / "hosts" / "shop.acme.example.com.md").write_text("# host\n")
        original = SG.exhaustion
        SG.exhaustion = lambda _pd: {"proven": True, "reason": "all vectors terminal",
                                     "vectors": 4, "open": [], "unsupported": []}
        self.addCleanup(lambda: setattr(SG, "exhaustion", original))
        verdict = SG.assess(self.project)
        self.assertFalse(verdict["allow"])
        msg = SG.block_message(verdict)
        self.assertIn("next host", msg)
        self.assertIn("shop.acme.example.com", msg)

    def test_nothing_found_still_refuses_and_keeps_the_ladder(self):
        self._state(True)
        msg = SG.block_message(SG.assess(self.project))
        self.assertIn("CONTINUOUS HUNT", msg)
        self.assertIn("vectors.py rotate", msg)
        self.assertNotIn("BANKED THIS HUNT", msg)

    def test_the_severity_bar_does_not_move(self):
        """A continuous hunt must not become a reason to write a Low up as a Medium."""
        (self.project / "findings" / "low.md").write_text(
            "# Verbose error\n\n## Severity\nLow.\n", encoding="utf-8")
        self._state(True)
        verdict = SG.assess(self.project)
        self.assertEqual(verdict["proven"], [])
        self.assertIn("never inflate a Low", SG.block_message(verdict))

    # --- switches and escapes ---------------------------------------------
    def test_env_overrides_the_state_file_in_both_directions(self):
        self._proven_finding()
        self._state(True)
        os.environ[SG.ENV_CONTINUOUS] = "off"
        self.assertTrue(SG.assess(self.project)["allow"])
        os.environ[SG.ENV_CONTINUOUS] = "on"
        self.assertFalse(SG.assess(self.project)["allow"])

    def test_profile_switch_enables_it_for_one_engagement(self):
        self._proven_finding()
        self._profile(continuous_hunt=True)
        verdict = SG.assess(self.project)
        self.assertFalse(verdict["allow"])
        self.assertIn("profile.json", verdict["continuous"]["source"])

    def test_operator_switching_it_off_restores_the_finding_door(self):
        self._proven_finding()
        self._state(True)
        self.assertFalse(SG.assess(self.project)["allow"])
        self._state(False)
        self.assertTrue(SG.assess(self.project)["allow"])

    def test_a_configured_budget_still_ends_a_continuous_hunt(self):
        self._state(True)
        self._profile(max_requests=2)
        self._audit(3)
        verdict = SG.assess(self.project)
        self.assertTrue(verdict["allow"])
        self.assertEqual(verdict["exit_condition"], "max_requests")

    def test_the_push_ceiling_is_raised_but_never_removed(self):
        self._state(True)
        self.assertEqual(SG.max_blocks(self.project), SG.CONTINUOUS_MAX_BLOCKS)
        self.assertLess(SG.MAX_BLOCKS, SG.CONTINUOUS_MAX_BLOCKS)
        self._profile(continuous_hunt=True, max_stop_blocks=3)
        self.assertEqual(SG.max_blocks(self.project), 3)


if __name__ == "__main__":
    unittest.main()
