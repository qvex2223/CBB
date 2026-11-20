#!/usr/bin/env python3
"""hunt-arm: the operator's own words arm and disarm the hunt.

Why this is tested at all: the whole push half of the workspace (skill gate, grind
nudge, stop gate) is gated on analysis mode being armed, and before this hook the
only things that armed it were a slash command or a `hunt-*` skill. "начни хантить
ozon" armed nothing, so the session was free to stop after three requests — which is
the exact failure the stop gate was built to prevent.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "scripts" / "hunt-arm.py"
sys.path.insert(0, str(ROOT / "engine"))

import hunt_mode as HM  # noqa: E402


class HuntArm(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.memdir = Path(self.tmp.name) / "hunt-memory"
        self.memdir.mkdir()
        self.env = dict(os.environ, CBH_MEMORY_DIR=str(self.memdir))
        self.env.pop("CBH_HUNT_ARM", None)
        self.env.pop("CBH_HUNT_MODE", None)
        self.env["CBH_CAIDO_AUTOSTART"] = "off"   # the suite stays offline
        self.session = "arm-test"

    def _run(self, prompt: str, session: str = "") -> str:
        payload = json.dumps({"session_id": session or self.session, "prompt": prompt})
        proc = subprocess.run([sys.executable, str(HOOK)], input=payload,
                              capture_output=True, text=True, env=self.env, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout

    def _state(self) -> dict:
        p = self.memdir / "sessions" / f"mode-{self.session}.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}

    # --- arming -----------------------------------------------------------
    def test_russian_hunt_order_arms_the_gate(self):
        out = self._run("начни хантить ozon")
        self.assertIn("HUNT MODE ARMED", out)
        self.assertTrue(self._state().get("armed"))

    def test_english_hunt_order_arms_the_gate(self):
        self._run("start hunting ozon.ru, go deep")
        self.assertTrue(self._state().get("armed"))

    def test_orders_name_the_rules_that_keep_it_going(self):
        out = self._run("продолжай хантить")
        for needle in ("bbcurl", "/remember --result confirmed", "blocked-tests/",
                       "vectors.py rotate", "cbh identity new",
                       "without asking the operator", "Severity is never inflated"):
            self.assertIn(needle, out)

    def test_orders_make_fan_out_the_default_not_an_option(self):
        """Operator directive 2026-10-16: one orchestrator, a crew of workers.

        The lane kinds are pinned by the spelling an orchestrator actually TYPES —
        `subagent_type: "deep-hunter"` — not by a capitalised prose word. Until 2026-11-17
        this asserted "Scout"/"Hunter"/"Reviewer", three words supplied by a single
        sentence ordering the doctrine to be pasted into every brief. When that sentence
        went (item 10: the doctrine moved into the role files) the pin went with it, and
        "Reviewer" turned out to name no role at all — the third role is `refuter`.
        """
        out = self._run("хантим ozon")
        for needle in ("ORCHESTRATE", "/parallel", "deep-hunter", "scout", "refuter",
                       "Freeroam", "hunt_agents"):
            self.assertIn(needle, out)

    def test_orders_carry_a_crew_size_instead_of_a_constant(self):
        """2026-10-29: the number is derived per engagement (engine/crew.py).

        The old text said "Cap is 3 concurrent workers" to every programme, whether
        it publishes 30 rps or is still on the 10-second default.
        """
        out = self._run("хантим ozon")
        self.assertIn("Crew size", out)
        self.assertNotIn("Cap is 3 concurrent", out)

    def test_orders_print_once_per_session(self):
        self.assertIn("HUNT MODE ARMED", self._run("хантим ozon"))
        self.assertEqual(self._run("дальше хантить seller.ozon.ru").strip(), "")

    # --- not arming -------------------------------------------------------
    def test_a_question_about_hunting_is_not_an_order(self):
        self.assertEqual(self._run("как работает хант мод?").strip(), "")
        self.assertFalse(self._state().get("armed"))

    def test_unrelated_work_does_not_arm(self):
        self.assertEqual(self._run("почисти логи и покажи diff").strip(), "")
        self.assertFalse(self._state().get("armed"))

    def test_pasted_material_does_not_arm(self):
        # 2026-11-20: a pasted digest saying "recon" and "hunt-loop" armed the gate on a
        # prompt that only asked for an opinion.
        prompt = ("вот думаю улучшить инструмент, скажи что стоит внимания\n\n"
                  '<pasted_content id="2610">Можно добавить в recon как сигнал. '
                  'Прямо про hunt-loop / early-stop.</pasted_content id="2610">')
        self.assertEqual(self._run(prompt).strip(), "")
        self.assertFalse(self._state().get("armed"))

    def test_an_order_next_to_a_paste_still_arms(self):
        prompt = ('начни хантить ozon, вот заметки\n<pasted_content id="7">'
                  'старые логи</pasted_content id="7">')
        self.assertIn("HUNT MODE ARMED", self._run(prompt))
        self.assertTrue(self._state().get("armed"))

    def test_a_pasted_stop_does_not_disarm(self):
        self._run("начни хантить")
        self._run('глянь лог <pasted_content id="9">stop hunting</pasted_content id="9">')
        self.assertTrue(self._state().get("armed"))

    def test_an_unclosed_paste_is_cut_to_the_end(self):
        self.assertEqual(self._run('мнение? <pasted_content id="3">recon hunt').strip(), "")
        self.assertFalse(self._state().get("armed"))

    def test_env_opt_out(self):
        self.env["CBH_HUNT_ARM"] = "off"
        self.assertEqual(self._run("начни хантить").strip(), "")
        self.assertFalse(self._state().get("armed"))

    # --- disarming --------------------------------------------------------
    def test_operator_stop_disarms(self):
        self._run("начни хантить")
        out = self._run("стоп охота")
        self.assertIn("DISARMED", out)
        self.assertFalse(self._state().get("armed"))

    def test_english_stop_disarms(self):
        self._run("start hunting")
        self._run("stop hunting for now")
        self.assertFalse(self._state().get("armed"))

    def test_stopping_the_caveman_persona_is_not_standing_down(self):
        self._run("начни хантить")
        self._run("stop caveman")
        self.assertTrue(self._state().get("armed"))


if __name__ == "__main__":
    unittest.main()
