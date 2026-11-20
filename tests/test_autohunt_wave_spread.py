"""How a wave is sized and spread — engine/autohunt.py.

All three pinned here were found on 2026-11-14 when standoff365/hh was widened from 3 lanes
to 6 on operator directive. At three slots every one of them was invisible; widening the
crew is what exposed them.

  1. `wave()` sized itself from the CLIENT row (`client_mod.crew()`), so `"hunt_agents": 6`
     in profile.json — which root AGENTS.md calls an override of any crew number, and which
     `scripts/agent-gate.py` already honours for the cap it enforces — did not reach the
     wave. The cap said 6, the wave emitted 3, and nothing printed the disagreement.
  2. The refuter pass and the deep-hunter pass did not dedupe against each other, so
     `primitives/hh.ru-account-otp-email.md` came back as lane 1 (refuter) AND lane 5
     (deep-hunter): one record, two roles, one trying to kill the claim while the other
     tried to prove it. The two passes also carry paths in different shapes, absolute from
     `stop_gate` and engagement-relative from `lead_queue`, so a raw string compare would
     not have caught it either.
  3. `_host_of()` read the host from the item's TITLE only. `spread()` skips a collision
     only between two items that BOTH report a host, so the items whose titles name a
     surface rather than a hostname reported `""`, collided with nothing, and the
     "no two lanes share a host" rule silently did not apply to them.
"""
import os
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import autohunt  # noqa: E402


class HostOfAnItem(unittest.TestCase):
    def test_the_funnel_filing_answers_when_the_title_does_not(self):
        for file, want in (
            ("leads/talantix.ru-ats.md", "talantix.ru"),
            ("leads/hh.ru-oauth-ato.md", "hh.ru"),
            ("primitives/hh.ru-account-otp-email.md", "hh.ru"),
            ("primitives/api.hh.ru-similar-vacancies-unauth.md", "api.hh.ru"),
            ("leads/dev.hh.ru-oauth-apps.md", "dev.hh.ru"),
            ("leads/setka.ru-chats-accounts-authz.md", "setka.ru"),
        ):
            with self.subTest(file=file):
                self.assertEqual(autohunt._host_of({"file": file, "title": "ATS vacancies"}), want)

    def test_the_slug_is_not_swallowed_into_the_host(self):
        # HOST_RE's class holds both `.` and `-`, so reusing it matched `talantix.ru-ats`
        # whole. FILE_HOST_RE's `-|$` boundary is what stops it.
        self.assertEqual(autohunt._host_of({"file": "leads/talantix.ru-ats.md"}), "talantix.ru")

    def test_a_payload_host_in_the_title_does_not_become_the_lanes_host(self):
        # leads/dev.hh.ru-backurl.md is titled around a backUrl arm pointing at github.com,
        # which is not even in scope. Filing wins over the title for exactly this reason.
        item = {"file": "leads/dev.hh.ru-backurl.md",
                "title": "dev.hh.ru backUrl accepts https://github.com/ — open redirect"}
        self.assertEqual(autohunt._host_of(item), "dev.hh.ru")

    def test_the_title_is_still_the_fallback(self):
        item = {"file": "leads/some-unfiled-note.md", "title": "api.setka.ru krakend mobile API"}
        self.assertEqual(autohunt._host_of(item), "api.setka.ru")

    def test_no_host_anywhere_is_empty_not_a_guess(self):
        self.assertEqual(autohunt._host_of({"file": "leads/notes.md", "title": "misc"}), "")


class NormaliseFileKey(unittest.TestCase):
    def test_absolute_and_relative_shapes_collapse_onto_one_key(self):
        a = "/home/qvex/x/Targets/standoff365/hh/primitives/hh.ru-account-otp-email.md"
        b = "primitives/hh.ru-account-otp-email.md"
        self.assertEqual(autohunt._norm_file(a), autohunt._norm_file(b))
        self.assertEqual(autohunt._norm_file(b), "primitives/hh.ru-account-otp-email.md")

    def test_a_different_tier_is_a_different_item(self):
        self.assertNotEqual(autohunt._norm_file("leads/x.md"), autohunt._norm_file("primitives/x.md"))


class Spread(unittest.TestCase):
    def _items(self, *files):
        return [{"file": f, "title": "", "needs": []} for f in files]

    def test_one_host_per_lane_while_distinct_hosts_remain(self):
        got = autohunt.spread(self._items(
            "leads/a.example-1.md", "leads/a.example-2.md", "leads/b.example-1.md"), 2)
        self.assertEqual([autohunt._host_of(i) for i in got], ["a.example", "b.example"])

    def test_a_claimed_record_is_never_handed_out_again(self):
        taken = {"/abs/Targets/p/e/primitives/hh.ru-otp.md"}
        got = autohunt.spread(self._items("primitives/hh.ru-otp.md", "leads/b.example-1.md"),
                              2, taken_files=taken)
        self.assertEqual([i["file"] for i in got], ["leads/b.example-1.md"])

    def test_a_claimed_record_is_not_even_used_as_filler(self):
        # The leftover pass fills empty slots; it must not fill one with a duplicate.
        taken = {"primitives/hh.ru-otp.md"}
        got = autohunt.spread(self._items("primitives/hh.ru-otp.md"), 3, taken_files=taken)
        self.assertEqual(got, [])

    def test_a_claimed_host_is_a_soft_collision_and_gets_marked(self):
        got = autohunt.spread(self._items("leads/a.example-1.md"), 1,
                              taken_hosts={"a.example"})
        self.assertEqual(len(got), 1, "an idle slot is worse than a shared host")
        self.assertEqual(got[0]["host_shared"], "a.example")

    def test_a_filled_slot_beats_an_idle_one_but_says_so(self):
        got = autohunt.spread(self._items(
            "leads/a.example-1.md", "leads/a.example-2.md", "leads/a.example-3.md"), 3)
        self.assertEqual(len(got), 3)
        self.assertFalse(got[0].get("host_shared"))
        self.assertTrue(all(i.get("host_shared") == "a.example" for i in got[1:]))


class SlotsComeFromCrewPy(unittest.TestCase):
    def test_wave_delegates_sizing_and_does_not_read_the_client_row_directly(self):
        src = (REPO / "engine" / "autohunt.py").read_text()
        body = src[src.index("def wave("):src.index("\ndef ", src.index("def wave(") + 10)]
        # Strip comments first: the fix's own comment QUOTES the call it replaced, and
        # matching the raw text read that comment as code — the same substring-in-prose
        # trap this file exists to pin (see _host_of and engine/client.py).
        code = "\n".join(re.sub(r"#.*$", "", ln) for ln in body.splitlines())
        self.assertNotIn("client_mod.crew()", code,
                         "wave() must size via _crew_slots -> engine/crew.py, not the client row")
        self.assertIn("_crew_slots(eng)", code)

    def test_crew_slots_falls_back_to_the_client_row_rather_than_zero(self):
        n, src = autohunt._crew_slots(Path("/nonexistent/engagement"))
        self.assertGreater(n, 0, "a broken profile must cost the override, never the wave")
        self.assertTrue(src)

    def test_the_render_names_where_the_number_came_from(self):
        src = (REPO / "engine" / "autohunt.py").read_text()
        self.assertIn("slots_source", src)


class TheWaveDemandsOneMessage(unittest.TestCase):
    """Dispatching one lane and waiting is invisible from inside the session.

    Every lane still succeeds and the hunt still progresses — it just runs at a fraction of
    its budget. Measured 2026-11-14 on a 3.4 h Grok hunt of standoff365/hh: `cbh autohunt`
    emitted 6 briefs every wave, the orchestrator ran 3-4 lanes concurrently for the first
    hour and exactly ONE for the last 50 minutes — ~8 lanes/hour against a capacity of ~45,
    and 9.96 requests/min against a paced budget of 600.
    """

    BASE = {
        "engagement": "p/e", "slots": 6, "slots_source": "test",
        "unconfirmed_findings": 0, "budget_requests_left": None,
        "budget_requests_cap": None, "budget_requests_fired": 0, "requests_per_lane": 0,
        "queue": {}, "accounts_wanted": [], "chain_hub": "", "bar_met": False,
        "walled_open_items": 0, "egress_walled_open_items": 0,
        "allow_stop": False, "stop_reason": "test", "stop_hook": False,
        "role": "deep-hunter", "role_why": "test",
    }

    # Every key `render` indexes on a brief. Written out rather than minimised: a stub
    # missing one raises KeyError, which reads as a broken test instead of a missing field.
    BRIEF = {"file": "leads/x.md", "kind": "lead", "class": "idor", "title": "t",
             "reward": 0, "age_days": 0, "stalled": False, "needs": [],
             "role": "deep-hunter", "skills": [], "escalates_to": [],
             "corpus_chains": [], "chains_via": "", "operator_wall": "",
             "network_wall": "", "host_shared": "", "partners": [], "precedent": "",
             "requests": 0, "severity_claimed": "", "evidence": "",
             "refute_reason": "", "close": "c"}

    def _render(self, n_briefs):
        import client as client_mod
        briefs = [{**self.BRIEF, "file": f"leads/x{i}.md", "title": f"t{i}"}
                  for i in range(n_briefs)]
        return autohunt.render({**self.BASE, "client": client_mod.profile("generic"),
                                "briefs": briefs})

    def test_a_multi_lane_wave_says_one_message_and_counts_the_waste(self):
        out = self._render(6)
        self.assertIn("ONE message", out)
        self.assertIn("wastes 5/6", out)

    def test_the_count_follows_the_wave_rather_than_being_hardcoded(self):
        self.assertIn("wastes 2/3", self._render(3))

    def test_a_single_lane_wave_does_not_nag(self):
        """Positive control: with one brief there is nothing to parallelise."""
        self.assertNotIn("ONE message", self._render(1))

    def test_it_says_concurrency_does_not_raise_the_request_rate(self):
        """Or the rule reads as permission to go faster than the programme allows."""
        out = self._render(6)
        self.assertIn("no faster than 1", out)


if __name__ == "__main__":
    unittest.main()


class ItemNameNeverShadowsTheSlug(unittest.TestCase):
    """engine/funnel.py — the item's identity comes from the folder, not from a generic
    markdown name. Measured 2026-11-14: two distinct refuter lanes both printed `finding`,
    so a six-lane wave read as if it repeated a record."""

    def test_all_four_documented_forms(self):
        import funnel
        for path, want in (
            ("leads/host-reflects-origin.md", "host-reflects-origin"),          # flat
            ("leads/host-reflects-origin/README.md", "host-reflects-origin"),   # <slug>/README.md
            ("findings/slug-x/slug-x.md", "slug-x"),                           # <slug>/<slug>.md
            ("primitives/chat-prod-basketuid/finding.md", "chat-prod-basketuid"),  # single .md
            ("blocked-tests/some-wall.md", "some-wall"),
            # A flat item does not always sit in a directory funnel recognises; its own
            # name is still the slug. A structural "parent wins" rule broke exactly here.
            ("/tmp/tmpqcxaitkm/some-finding-slug.md", "some-finding-slug"),
            ("/tmp/tmpl3fo6o4q/url-minifier-s.acme.com.md", "url-minifier-s.acme.com"),
        ):
            with self.subTest(path=path):
                self.assertEqual(funnel.item_name(path), want)

    def test_two_folder_items_sharing_a_markdown_name_stay_distinct(self):
        import funnel
        a = "findings/www-android-deeplink-callback-javascript-scheme-xss/finding.md"
        b = "primitives/chat-prod-unauth-support-chat-readable-by-client-chosen-basketuid/finding.md"
        self.assertNotEqual(funnel.item_name(a), funnel.item_name(b))
        self.assertEqual(funnel.item_name(a), "www-android-deeplink-callback-javascript-scheme-xss")


class ConfirmBeforeMovingOn(unittest.TestCase):
    """Operator directive 2026-11-14: a finding is banked and the hunt continues — but it is
    CONFIRMED before the crew opens new surface.

    "если даже нашёл, пусть просто дальше продолжает искать, но уже после того как полностью
    подтвердил находку."

    Half of that was already enforced: `stop_gate` continuous mode banks a Medium+ and never
    lets a finding be a reason to stop. The other half was not — nothing checked the banked
    claim was finished, so the crew kept opening surface while its own claim sat unproven.
    """

    def test_an_unconfirmed_finding_may_take_the_whole_wave(self):
        self.assertEqual(autohunt.refuter_share(6, "", True, 0), (5, 2),
                         "with everything confirmed, one hunter lane is still guaranteed")
        self.assertEqual(autohunt.refuter_share(6, "", True, 1)[0], 6,
                         "an unconfirmed finding drops the hunter floor")
        self.assertEqual(autohunt.refuter_share(6, "", True, 9)[0], 6)

    def test_the_backlog_share_is_not_raised_by_it(self):
        # 400-odd never-attacked primitives must not swallow every wave forever.
        self.assertEqual(autohunt.refuter_share(6, "", True, 3)[1], 2)
        self.assertEqual(autohunt.refuter_share(9, "", True, 3)[1], 3)

    def test_a_named_role_still_overrides(self):
        self.assertEqual(autohunt.refuter_share(6, "deep-hunter", True, 5), (0, 0))
        self.assertEqual(autohunt.refuter_share(6, "scout", True, 5), (0, 0))
        self.assertEqual(autohunt.refuter_share(6, "refuter", True, 0), (6, 6))

    def test_hunting_resumes_in_the_same_wave_once_confirmation_runs_out(self):
        # Confirmation lanes are finite: one per unconfirmed finding. "Continue searching" is
        # preserved — it queues behind the proof rather than being cancelled by it.
        room, _ = autohunt.refuter_share(6, "", True, 2)
        self.assertEqual(room, 6)          # may take all
        self.assertLess(2, room)           # but only 2 exist, so 4 slots go to hunting


class ContinuousModeIsTheDefault(unittest.TestCase):
    """A finding must never be a reason to stop. Measured 2026-11-14: the workspace state file
    had continuous mode OFF since 2026-11-12 with an empty note, so a demonstrated Medium+
    would have opened the stop door on the next Stop hook."""

    def test_the_code_default_is_on(self):
        import stop_gate
        self.assertTrue(stop_gate.CONTINUOUS_DEFAULT)

    def test_the_live_workspace_state_is_on(self):
        import stop_gate
        cfg = stop_gate.continuous_config()
        self.assertTrue(cfg["on"], f"continuous mode is OFF (source: {cfg.get('source')})")

    def test_a_disable_must_carry_a_reason(self):
        # The 2026-11-12 disable left `note: ""`, so nothing recorded who turned it off or why.
        import stop_gate
        cfg = stop_gate.continuous_config()
        if not cfg["on"]:
            self.assertTrue((cfg.get("note") or "").strip(),
                            "continuous mode is off with no note saying why")


class TheHeaderNamesTheLanesThatExist(unittest.TestCase):
    """`pick_role` predicts; `spread` decides. The header must follow the decision.

    An unattacked claim in `primitives/` is BOTH an open queue item and a refuter
    candidate. The refuter lane takes the record, `spread` then refuses to reissue it as a
    hunter lane (correct — one record, one lane), and the prediction is stale. Measured on
    the 2026-11-14 decision replay: `standoff365/hh` printed `lead role deep-hunter — 1
    workable lead(s)/primitive(s) in the queue` above one refuter and two scout briefs,
    with no hunter lane at all. A worker reads that header first.
    """

    def test_no_wave_in_the_replay_corpus_names_a_role_it_did_not_emit(self):
        import autohunt
        root = os.environ.get("CBH_TARGETS_ROOT") or str(REPO / "Targets")
        if not Path(root).is_dir():  # Targets/ is git-ignored
            self.skipTest("no corpus in this checkout")
        checked = 0
        for prof in sorted(Path(root).glob("*/*/profile.json"))[:12]:
            eng = prof.parent
            try:
                w = autohunt.wave(f"{eng.parent.name}/{eng.name}", 3, "")
            except Exception:  # noqa: BLE001 - a broken engagement is not this test's subject
                continue
            if w.get("error") or not w.get("briefs"):
                continue
            checked += 1
            mix = [b["role"] for b in w["briefs"]]
            with self.subTest(engagement=w["engagement"]):
                self.assertIn(w["role"], mix,
                              f"header says {w['role']}, lanes are {sorted(set(mix))}")
        if not checked:
            self.skipTest("no engagement in the corpus produced a wave")

    def test_the_reason_says_so_rather_than_quietly_swapping_the_role(self):
        """A silent swap would read as the plan having been right all along."""
        src = (REPO / "engine" / "autohunt.py").read_text()
        self.assertIn("went to another lane", src)

    def test_a_forced_role_is_never_reconciled_away(self):
        src = (REPO / "engine" / "autohunt.py").read_text()
        where = src.index("if not role and lanes:")
        self.assertIn("not role", src[where:where + 40],
                      "--role is the operator's word and outranks the mix")


if __name__ == "__main__":
    unittest.main()
