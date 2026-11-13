"""Regression: what a brief tells a worker about its budget, and what counts as an item.

Both defects were found by replaying every engagement's wave through
`scripts/decision_replay.py` on 2026-11-13 rather than by reading the code.

1. `stop_gate.assess()["budget"]["requests"]` is the count of requests this hunt has
   ALREADY FIRED. `wave()` used it as the remaining allowance and `render()` printed it
   as "N request(s) left". No current engagement sets `max_requests`, so 8 of 12
   engagements opened every brief with "0 request(s) left, 0 per lane" — a spent budget,
   to a worker reading it — and mail_vk announced 1710 left, which was its fired count.
   An absent cap is not a cap of zero.

2. `leads/README.md` and `primitives/README.md` are a tier's instructions. `lead_queue`
   ranked them as items at DEFAULT_REWARD, and on rowi one of three lanes went to
   "hunt the README". `stop_gate` had always skipped them.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import autohunt  # noqa: E402
import lead_queue  # noqa: E402
import stop_gate  # noqa: E402

PRIM = ("# PRIMITIVE — a credential-free route oracle\n\n**Status:** CONFIRMED\n\n"
        "**Chain:** needs `a-thing` · gives `a-capability`\n")


class _Eng(unittest.TestCase):
    def setUp(self):
        self.eng = Path(tempfile.mkdtemp())
        for tier in ("findings", "primitives", "leads"):
            (self.eng / tier).mkdir()

    def write(self, rel, body=PRIM):
        p = self.eng / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        return p


class TheBudgetABriefAnnounces(_Eng):
    def _wave(self, budget: dict, slots=3):
        q = {"engagement": "t/t", "open": [
            {"file": "primitives/open0.md", "kind": "primitive", "class": "", "needs": [],
             "title": "Primitive — an open item on api.example.com", "reward": 0,
             "age_days": 1}],
            "closed": [], "blocked": [], "stalled": [], "needs_account": {}}
        a = dict(stop_gate.assess(self.eng))
        a["budget"] = budget
        orig = (lead_queue.resolve_engagement, lead_queue.scan, stop_gate.assess)
        lead_queue.resolve_engagement = lambda *_: self.eng
        lead_queue.scan = lambda *_: q
        stop_gate.assess = lambda *_a, **_k: a
        try:
            return autohunt.wave("t/t", slots, "")
        finally:
            (lead_queue.resolve_engagement, lead_queue.scan, stop_gate.assess) = orig

    def test_no_cap_configured_is_not_a_spent_budget(self):
        w = self._wave({"requests": 1710, "limits": {}})
        self.assertIsNone(w["budget_requests_left"])
        self.assertEqual(w["budget_requests_cap"], 0)
        self.assertEqual(w["budget_requests_fired"], 1710)
        text = autohunt.render(w)
        self.assertIn("1710 request(s) fired this hunt", text)
        self.assertIn("no `max_requests` in profile.json", text)
        self.assertNotIn("request(s) left", text)

    def test_a_lane_with_no_cap_says_so_instead_of_zero(self):
        w = self._wave({"requests": 0, "limits": {}})
        self.assertIn("no request cap", autohunt.render(w))
        self.assertNotIn("· 0 request(s) ---", autohunt.render(w))

    def test_a_configured_cap_is_what_is_left_not_what_was_fired(self):
        w = self._wave({"requests": 40, "limits": {"max_requests": 100}}, slots=3)
        self.assertEqual(w["budget_requests_left"], 60)
        self.assertEqual(w["requests_per_lane"], 20)
        self.assertIn("60 of 100 request(s) left (40 fired), 20 per lane",
                      autohunt.render(w))

    def test_a_spent_cap_reads_as_zero_left(self):
        w = self._wave({"requests": 140, "limits": {"max_requests": 100}})
        self.assertEqual(w["budget_requests_left"], 0)
        self.assertEqual(w["requests_per_lane"], 0)

    def test_a_malformed_cap_does_not_crash_the_wave(self):
        w = self._wave({"requests": 10, "limits": {"max_requests": "lots"}})
        self.assertEqual(w["budget_requests_cap"], 0)
        self.assertIsNone(w["budget_requests_left"])

    def test_render_survives_a_wave_dict_without_the_budget_keys(self):
        # render() is a formatter and is called on partial dicts (the other suites stub
        # one); a missing key must not raise.
        w = self._wave({"requests": 5, "limits": {}})
        for k in ("budget_requests_fired", "budget_requests_cap", "budget_requests_left",
                  "requests_per_lane"):
            w.pop(k, None)
        self.assertIn("budget", autohunt.render(w))


class WhatCountsAsAnItemInATier(unittest.TestCase):
    def setUp(self):
        # `scan()` reports the engagement relative to the corpus root, so the fixture has
        # to sit under one. `paths.targets_root()` reads the override on every call.
        self.root = Path(tempfile.mkdtemp()) / "Targets"
        self.eng = self.root / "plat" / "prog"
        for tier in ("findings", "primitives", "leads"):
            (self.eng / tier).mkdir(parents=True)
        self.saved = os.environ.get("CBH_TARGETS_ROOT")
        os.environ["CBH_TARGETS_ROOT"] = str(self.root)

    def tearDown(self):
        if self.saved is None:
            os.environ.pop("CBH_TARGETS_ROOT", None)
        else:
            os.environ["CBH_TARGETS_ROOT"] = self.saved

    def write(self, rel, body=PRIM):
        p = self.eng / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        return p

    def test_a_tiers_own_readme_is_not_a_lead(self):
        self.write("leads/README.md", "# leads/ — one file per untested hypothesis\n")
        self.write("primitives/README.md", "# primitives/ — one file per capability\n")
        q = lead_queue.scan(self.eng)
        self.assertEqual([i["file"] for i in q["open"]], [])

    def test_a_real_item_beside_it_is_still_listed(self):
        self.write("primitives/README.md", "# primitives/ — one file per capability\n")
        self.write("primitives/route-oracle.md")
        q = lead_queue.scan(self.eng)
        self.assertEqual([Path(i["file"]).name for i in q["open"]], ["route-oracle.md"])

    def test_an_item_whose_name_merely_contains_readme_is_kept(self):
        # The skip is on the file NAME being README.md, not on the word appearing in it.
        self.write("leads/readme-exposes-internal-paths.md",
                   "# LEAD — the published README exposes internal paths\n")
        q = lead_queue.scan(self.eng)
        self.assertEqual([Path(i["file"]).name for i in q["open"]],
                         ["readme-exposes-internal-paths.md"])

    def test_the_count_a_wave_prints_drops_the_readmes_too(self):
        self.write("leads/README.md", "# leads/\n")
        self.write("primitives/route-oracle.md")
        self.assertEqual(len(lead_queue.scan(self.eng)["open"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
