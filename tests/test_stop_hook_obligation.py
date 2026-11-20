"""A client with no Stop hook is TOLD that continuing is its own obligation.

`engine/stop_gate.py` is a Claude Code `Stop` hook. Continuous mode — a banked Medium+
does not end the session — is therefore enforced for exactly one client. Measured
2026-11-14: 0 of the 59 sessions recorded in `hunt-memory/pacing/stop_gate.json` came from
a non-Claude client, i.e. the gate has never once run for one, and nothing told that client
so. The replacement is not a hook (there is none to install) but three texts that must all
carry the obligation: the client row, every wave's render, and the standing orders.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import autohunt  # noqa: E402
import client as client_mod  # noqa: E402


def _uncommented(text: str) -> str:
    """Source minus `#` comments: an assertion that matches a comment proves nothing.

    Twice on 2026-11-14 a test of this suite passed against its own explanatory prose.
    """
    out = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        out.append(line.split("  # ")[0])
    return "\n".join(out)


class TheRowSaysWhichClientIsKeptHunting(unittest.TestCase):
    def test_claude_has_a_stop_hook_and_generic_does_not(self):
        self.assertTrue(client_mod.stop_hook("claude"))
        self.assertFalse(client_mod.stop_hook("generic"))

    def test_every_known_client_declares_the_field_either_way(self):
        for name in client_mod.PROFILES:
            with self.subTest(client=name):
                self.assertIn("stop_hook", client_mod.PROFILES[name],
                              "an undeclared field reads as False and silently drops "
                              "the obligation for that client")

    def test_it_is_a_field_of_its_own_not_an_alias_of_gates_enforced(self):
        """Being DENIED and being KEPT GOING are different questions.

        They happen to agree for both current rows; a client could have one without the
        other, and conflating them is how the obligation would go missing for it.
        """
        src = _uncommented((REPO / "engine" / "client.py").read_text())
        self.assertIn('"stop_hook"', src)
        self.assertNotIn('gates_enforced"]\n', src.split("def stop_hook")[1][:400])

    def test_the_generic_row_states_the_obligation_in_words(self):
        text = client_mod.brief("generic")
        self.assertIn("cbh autohunt", text)
        self.assertIn("Stop gate:", text)
        for must in ("NO Stop hook", "operator ends a hunt"):
            self.assertIn(must, text)

    def test_the_claude_row_does_not_claim_the_hunt_is_the_clients_job(self):
        self.assertNotIn("NO Stop hook", client_mod.brief("claude"))


class EveryWavePrintsTheVerdict(unittest.TestCase):
    """The ALLOW is the dangerous verdict for a hookless client, so both must print."""

    BASE = {
        "engagement": "p/e", "slots": 1, "slots_source": "test", "briefs": [],
        "unconfirmed_findings": 0, "budget_requests_left": None,
        "budget_requests_cap": None, "budget_requests_fired": 0, "requests_per_lane": 0,
        "queue": {}, "accounts_wanted": [], "chain_hub": "", "bar_met": False,
        "walled_open_items": 0, "egress_walled_open_items": 0,
        # The real row, not a hand-rolled stub: render indexes several of its keys hard,
        # and a stub drifts from that the first time render reads one more.
        "client": client_mod.profile("generic"),
        "role": "deep-hunter", "role_why": "test",
    }

    def _render(self, **over):
        return autohunt.render({**self.BASE, **over})

    def test_a_deny_prints_keep_hunting_and_the_reason(self):
        out = self._render(allow_stop=False, stop_reason="continuous mode", stop_hook=True)
        self.assertIn("Stop gate:", out)
        self.assertIn("KEEP HUNTING", out)
        self.assertIn("continuous mode", out)

    def test_an_allow_still_prints_rather_than_vanishing(self):
        out = self._render(allow_stop=True, stop_reason="nothing left", stop_hook=True)
        self.assertIn("Stop gate:", out)
        self.assertIn("may stop", out)

    def test_a_hookless_client_is_told_the_line_is_its_only_mechanism(self):
        """The wording changed on 2026-11-18 and the obligation got stronger, not weaker.

        It used to read "advisory for this client". That is exactly how it was read: the line
        printed on every wave of the intigriti/1password hunt and the session still handed the
        turn back to the operator after each single lane, twice, 17 minutes idle the first time.
        It is now a numbered wave protocol, and `tests/test_autohunt_wave_protocol.py` pins the
        steps. This test keeps pinning what it always pinned — that a hookless client is told
        this line is the whole mechanism it gets.
        """
        out = self._render(allow_stop=True, stop_reason="nothing left", stop_hook=False)
        self.assertIn("NO STOP HOOK ON THIS CLIENT", out)
        self.assertIn("not", out.split("NO STOP HOOK")[1][:120])
        self.assertIn("cbh autohunt", out)
        self.assertIn("--demote", out)

    def test_a_hooked_client_is_not_told_that(self):
        out = self._render(allow_stop=False, stop_reason="continuous mode", stop_hook=True)
        self.assertNotIn("NO STOP HOOK", out)
        self.assertNotIn("advisory for this client", out)

    def test_a_missing_reason_does_not_render_an_empty_verdict(self):
        out = self._render(allow_stop=False, stop_reason="", stop_hook=True)
        self.assertIn("no reason recorded", out)

    def test_the_wave_dict_carries_the_field_so_render_never_guesses(self):
        src = _uncommented((REPO / "engine" / "autohunt.py").read_text())
        self.assertIn('"stop_hook": client_mod.stop_hook()', src)


class TheStandingOrdersCarryIt(unittest.TestCase):
    def test_the_client_map_tells_a_hookless_client_to_re_run_autohunt(self):
        from hunt_start import CLIENT_MAP  # noqa: PLC0415
        text = CLIENT_MAP.format(client="generic")
        for must in ("cbh autohunt", "Stop gate:", "stop_gate.py", "--demote"):
            with self.subTest(must=must):
                self.assertIn(must, text)

    def test_the_shared_orders_queue_continuing_behind_the_proof(self):
        orders = (REPO / "scripts" / "hunt-arm.py").read_text()
        orders = orders[orders.index("ORDERS = "):]
        for must in ("CONFIRM FIRST", "--demote", "Stop gate:"):
            with self.subTest(must=must):
                self.assertIn(must, orders)


if __name__ == "__main__":
    unittest.main()
