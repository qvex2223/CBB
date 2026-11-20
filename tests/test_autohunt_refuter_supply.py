"""Regression: every wave fires a kill attempt while an unattacked claim exists.

Measured over the 2026-11-12 wildberries/mail_vk session: 125 lanes went out as
`deep-hunter` and 1 as `refuter`. The cause was the lane SUPPLY, not the ranking.
`stop_gate.assess()["claimed_but_unproven"]` was the only thing that ever produced
a refuter lane, and it holds exactly the findings written in THIS hunt that have no
PASSing PoC. Three whole populations were therefore unreachable by the role:

  * a finding that got its PoC — it lands in `proven`, and proof is precisely when a
    kill attempt is worth firing, because that is the claim about to be submitted;
  * a finding from an earlier hunt — it lands in `older_findings`;
  * every primitive, the tier whose whole purpose is to supply capabilities to a
    chain, so an unattacked one is what the next chain gets built on.

Counted on disk 2026-11-13: 11 of 16 live findings and 395 of 408 live primitives
carried no `.refute.json` at all.

The fix adds `stop_gate.unrefuted()` as a second source and a share rule. Positive
controls in both directions, because a wave that is all refuter is the same bug
mirrored: a wave with other work must keep a hunter lane, and a `--role deep-hunter`
wave the operator asked for by name must fire no refuter lane at all.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import autohunt  # noqa: E402
import stop_gate  # noqa: E402

CHAIN = "**Chain:** needs `a-thing` · gives `a-capability`\n"
PRIM = "# PRIMITIVE — a credential-free route oracle\n\n**Status:** CONFIRMED\n\n" + CHAIN
FINDING = ("## Title\n\nUnauthenticated route oracle on api.example.com returns 401 for a "
           "real id and 404 for a synthetic one\n\n- **Severity:** High\n")


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

    def record(self, item: Path, verdict="SURVIVED", why="nothing killed it"):
        rec = item.with_name(item.stem + ".refute.json")
        rec.write_text(json.dumps({"verdict": verdict, "why": why}), encoding="utf-8")
        return rec


class WhatCountsAsNeverAttacked(_Eng):
    def test_a_primitive_with_no_record_is_listed(self):
        self.write("primitives/oracle.md")
        rows = stop_gate.unrefuted(self.eng)
        self.assertEqual([r["name"] for r in rows], ["oracle.md"])
        self.assertIn("ever been fired", rows[0]["why"])

    def test_a_primitive_with_a_record_is_not(self):
        """Positive control: the gate must go quiet once a kill attempt ran."""
        self.record(self.write("primitives/oracle.md"))
        self.assertEqual(stop_gate.unrefuted(self.eng), [])

    def test_an_incomplete_verdict_is_listed_again(self):
        p = self.write("primitives/oracle.md")
        self.record(p, verdict="INCOMPLETE", why="the controls did not reach the claim")
        rows = stop_gate.unrefuted(self.eng)
        self.assertEqual(len(rows), 1)
        self.assertIn("INCOMPLETE", rows[0]["why"])
        self.assertIn("did not reach the claim", rows[0]["why"])

    def test_a_record_older_than_the_claim_is_listed_again(self):
        import os
        p = self.write("primitives/oracle.md")
        rec = self.record(p)
        os.utime(rec, (1_700_000_000, 1_700_000_000))
        rows = stop_gate.unrefuted(self.eng)
        self.assertEqual(len(rows), 1)
        self.assertIn("edited after it was refuted", rows[0]["why"])

    def test_an_unparseable_record_is_listed_again(self):
        p = self.write("primitives/oracle.md")
        p.with_name("oracle.refute.json").write_text("{not json", encoding="utf-8")
        self.assertIn("does not parse", stop_gate.unrefuted(self.eng)[0]["why"])

    def test_a_killed_item_is_never_proposed(self):
        """Same rule as `funnel`: a recorded kill is a refutation, not pending work."""
        self.write("primitives/dead.md", "# PRIMITIVE\n\n**Status:** REFUTED\n\n"
                                        "**Refuted:** the oracle is a shared placeholder\n")
        self.assertEqual([r["name"] for r in stop_gate.unrefuted(self.eng)], [])

    def test_a_finding_with_a_passing_poc_is_still_proposed(self):
        """The population the old supply could not reach at all."""
        self.write("findings/route-oracle/finding.md", FINDING)
        self.assertEqual([r["tier"] for r in stop_gate.unrefuted(self.eng)], ["findings"])

    def test_a_folder_form_primitive_is_seen(self):
        self.write("primitives/slug/README.md")
        self.assertEqual([r["name"] for r in stop_gate.unrefuted(self.eng)], ["slug"])

    def test_the_findings_index_is_not_a_claim(self):
        self.write("findings/README.md", "# Findings\n\nOne line per finding.\n")
        self.assertEqual(stop_gate.unrefuted(self.eng), [])

    def test_findings_outrank_primitives_and_severity_orders_the_rest(self):
        self.write("primitives/p.md")
        self.write("findings/low.md", "## Title\n\nA claim about something measurable here\n\n"
                                      "- **Severity:** Low\n")
        self.write("findings/high.md", FINDING)
        rows = stop_gate.unrefuted(self.eng)
        self.assertEqual([r["name"] for r in rows], ["high.md", "low.md", "p.md"])

    def test_the_list_is_capped(self):
        for i in range(30):
            self.write(f"primitives/p{i:02d}.md")
        self.assertEqual(len(stop_gate.unrefuted(self.eng, limit=5)), 5)

    def test_assess_carries_it(self):
        self.write("primitives/oracle.md")
        self.assertEqual(len(stop_gate.assess(self.eng)["unrefuted"]), 1)


class TheShareOfAWave(unittest.TestCase):
    def test_a_six_slot_wave_with_other_work_keeps_both(self):
        room, unattacked = autohunt.refuter_share(6, "", other_work=True)
        self.assertEqual((room, unattacked), (5, 2))

    def test_a_crew_of_three_still_fires_one(self):
        self.assertEqual(autohunt.refuter_share(3, "", other_work=True)[1], 1)

    def test_a_single_slot_wave_with_other_work_hunts(self):
        """A never-attacked claim is not worth the only lane there is."""
        self.assertEqual(autohunt.refuter_share(1, "", other_work=True)[1], 0)

    def test_nothing_else_to_do_gives_refutation_the_wave(self):
        self.assertEqual(autohunt.refuter_share(6, "", other_work=False), (6, 6))

    def test_a_forced_refuter_wave_is_all_refuter(self):
        self.assertEqual(autohunt.refuter_share(6, "refuter", other_work=True), (6, 6))

    def test_a_forced_hunter_wave_fires_no_refuter_lane(self):
        """Positive control the other way: --role deep-hunter means that role."""
        self.assertEqual(autohunt.refuter_share(6, "deep-hunter", other_work=True), (0, 0))
        self.assertEqual(autohunt.refuter_share(6, "scout", other_work=True), (0, 0))


class ThePickedRole(unittest.TestCase):
    def test_an_unproven_claim_still_outranks_everything(self):
        role, why = autohunt.pick_role({"claimed_but_unproven": [{"file": "f.md"}]},
                                       {"open": [{"file": "p.md"}]})
        self.assertEqual(role, "refuter")
        self.assertIn("PASSing PoC", why)

    def test_a_finding_awaiting_its_kill_attempt_also_leads_the_wave(self):
        """The second half of "not fully confirmed" must reach the HEADER, not just the mix.

        `refuter_share` hands the whole wave to confirmation for either half, but the lead
        role was picked from `claimed_but_unproven` alone. Measured on the 2026-11-14
        decision replay: `tumar/freedom` printed `lead role deep-hunter — 68 workable
        lead(s)/primitive(s) in the queue` above three refuter briefs, so the header
        contradicted every brief under it.
        """
        role, why = autohunt.pick_role(
            {}, {"open": [{"file": "p.md"}] * 68},
            unrefuted_findings=[{"file": "findings/a.md", "tier": "findings"},
                                {"file": "findings/b.md", "tier": "findings"}])
        self.assertEqual(role, "refuter")
        self.assertIn("no current kill attempt", why)
        self.assertIn("2 finding", why)

    def test_an_unproven_claim_still_outranks_a_finding_awaiting_refutation(self):
        role, why = autohunt.pick_role(
            {"claimed_but_unproven": [{"file": "f.md"}]}, {},
            unrefuted_findings=[{"file": "findings/a.md", "tier": "findings"}])
        self.assertIn("PASSing PoC", why)

    def test_a_never_attacked_BACKLOG_claim_does_not_take_the_header(self):
        """Positive control: the one-third cap exists so 400 old primitives cannot.

        Only the findings tier is confirm-first. A primitive that never faced an arm is
        backlog, and backlog never outranks workable leads.
        """
        role, _ = autohunt.pick_role({}, {"open": [{"file": "p.md"}]},
                                     unrefuted_findings=[])
        self.assertEqual(role, "deep-hunter")

    def test_the_default_keeps_every_existing_caller_working(self):
        role, _ = autohunt.pick_role({}, {"open": [{"file": "p.md"}]})
        self.assertEqual(role, "deep-hunter")

    def test_an_open_queue_outranks_a_never_attacked_claim(self):
        """Positive control: hunting is still the default when there is work."""
        role, _ = autohunt.pick_role({"unrefuted": [{"file": "p.md"}]},
                                     {"open": [{"file": "p.md"}]})
        self.assertEqual(role, "deep-hunter")

    def test_an_empty_queue_with_no_hosts_refutes_instead_of_re_reading_the_ledger(self):
        role, why = autohunt.pick_role({"unrefuted": [{"file": "p.md"}, {"file": "q.md"}]}, {})
        self.assertEqual(role, "refuter")
        self.assertIn("2 claim(s)", why)

    def test_an_empty_engagement_asks_for_the_ledger(self):
        role, why = autohunt.pick_role({}, {})
        self.assertEqual(role, "deep-hunter")
        self.assertIn("re-read the ledger", why)


class TheLanesAWaveActuallyEmits(_Eng):
    """`wave()` with the engagement's state stubbed, so the arithmetic is what is read."""

    def _wave(self, slots=6, role="", open_items=2, unproven=0, hosts=()):
        import lead_queue
        q = {"engagement": "t/t", "open": [
            {"file": f"primitives/open{i}.md", "kind": "primitive", "class": "",
             "needs": [], "title": f"Primitive — open item {i} on api.example.com",
             "reward": 0, "age_days": 1} for i in range(open_items)],
            "closed": [], "blocked": [], "stalled": [], "needs_account": {}}
        a = dict(stop_gate.assess(self.eng))
        a["claimed_but_unproven"] = [{"file": str(self.write(f"findings/unproven{i}.md", FINDING)),
                                      "severity": "high", "evidence": "UNCHECKED"}
                                     for i in range(unproven)]
        if unproven:  # the same files must not also arrive as never-attacked
            a["unrefuted"] = [r for r in stop_gate.unrefuted(self.eng)
                              if r["file"] not in {f["file"] for f in a["claimed_but_unproven"]}]
        a["next_hosts"] = list(hosts)
        a["budget"] = {"requests": 600}
        orig = (lead_queue.resolve_engagement, lead_queue.scan, stop_gate.assess)
        lead_queue.resolve_engagement = lambda *_: self.eng
        lead_queue.scan = lambda *_: q
        stop_gate.assess = lambda *_a, **_k: a
        try:
            return autohunt.wave("t/t", slots, role)
        finally:
            (lead_queue.resolve_engagement, lead_queue.scan, stop_gate.assess) = orig

    def _roles(self, w):
        from collections import Counter
        return Counter(b["role"] for b in w["briefs"])

    def test_a_never_attacked_primitive_now_gets_a_lane(self):
        self.write("primitives/oracle.md")
        w = self._wave()
        self.assertEqual(self._roles(w)["refuter"], 1)
        self.assertEqual(self._roles(w)["deep-hunter"], 2)

    def test_the_refuter_lane_names_a_primitive_and_closes_it_as_one(self):
        self.write("primitives/oracle.md")
        b = next(x for x in self._wave()["briefs"] if x["role"] == "refuter")
        self.assertEqual(b["kind"], "primitive")
        self.assertIn("cbh refute", b["close"])
        self.assertIn("--as refuted", b["close"])
        self.assertIn("ever been fired", b["refute_reason"])

    def test_a_finding_lane_closes_through_the_evidence_gate(self):
        self.write("findings/route-oracle/finding.md", FINDING)
        b = next(x for x in self._wave()["briefs"] if x["role"] == "refuter")
        self.assertEqual(b["kind"], "finding")
        self.assertIn("cbh evidence", b["close"])

    def test_many_never_attacked_claims_never_take_more_than_a_third(self):
        for i in range(20):
            self.write(f"primitives/p{i:02d}.md")
        self.assertEqual(self._roles(self._wave(slots=6))["refuter"], 2)

    def test_many_unproven_findings_take_the_whole_wave(self):
        """Operator directive 2026-11-14 replaced the hunter floor with confirm-first.

        This test used to assert the mirror of the 2026-11-12 bug: 11 unproven claims had to
        leave one hunter lane (`refuter=5, deep-hunter=1`), so a pile of unproven claims could
        not empty the wave. The directive — "если даже нашёл, пусть просто дальше продолжает
        искать, но уже после того как полностью подтвердил находку" — inverts that priority:
        an unproven claim cannot be submitted, so finishing it outranks opening new surface,
        and the wave may go entirely to confirmation.

        The floor is NOT gone, it moved: it still applies when nothing is unconfirmed
        (`test_a_confirmed_hunt_still_guarantees_a_hunter_lane`), and the never-attacked
        BACKLOG still gets only a third of the wave, so 400-odd old primitives cannot swallow
        every wave forever.
        """
        w = self._wave(slots=6, unproven=11)
        self.assertEqual(self._roles(w)["refuter"], 6)
        self.assertEqual(self._roles(w).get("deep-hunter", 0), 0)

    def test_a_confirmed_hunt_still_guarantees_a_hunter_lane(self):
        """With nothing unconfirmed, the backlog may never take the last slot."""
        w = self._wave(slots=6, unproven=0)
        self.assertGreaterEqual(self._roles(w).get("deep-hunter", 0), 1)

    def test_an_unproven_claim_is_briefed_before_a_never_attacked_one(self):
        self.write("primitives/oracle.md")
        briefs = self._wave(slots=6, unproven=1)["briefs"]
        self.assertEqual(briefs[0]["role"], "refuter")
        self.assertIn("no PASSing PoC", briefs[0]["refute_reason"])

    def test_the_same_file_is_never_briefed_twice(self):
        w = self._wave(slots=6, unproven=1)
        files = [b["file"] for b in w["briefs"] if b["role"] == "refuter"]
        self.assertEqual(len(files), len(set(files)))

    def test_a_forced_hunter_wave_emits_no_refuter_lane(self):
        for i in range(5):
            self.write(f"primitives/p{i}.md")
        w = self._wave(slots=6, role="deep-hunter", unproven=3)
        self.assertEqual(self._roles(w)["refuter"], 0)

    def test_a_forced_refuter_wave_emits_only_refuter_lanes(self):
        for i in range(8):
            self.write(f"primitives/p{i}.md")
        w = self._wave(slots=6, role="refuter")
        self.assertEqual(list(self._roles(w)), ["refuter"])
        self.assertEqual(len(w["briefs"]), 6)

    def test_an_empty_queue_spends_the_wave_on_refutation(self):
        for i in range(8):
            self.write(f"primitives/p{i}.md")
        w = self._wave(slots=6, open_items=0)
        self.assertEqual(self._roles(w)["refuter"], 6)

    def test_a_scout_wave_is_not_displaced_by_refutation(self):
        """Hosts never censused are other work, so the share rule applies to them too."""
        for i in range(8):
            self.write(f"primitives/p{i}.md")
        w = self._wave(slots=6, open_items=0, hosts=[f"h{i}.example.com" for i in range(6)])
        self.assertEqual(self._roles(w)["refuter"], 2)
        # One census lane carrying every host, not one lane per host
        # (tests/test_autohunt_census_batch.py): the census is not displaced, it is batched.
        scouts = [b for b in w["briefs"] if b["role"] == "scout"]
        self.assertEqual(len(scouts), 1)
        self.assertEqual(scouts[0]["hosts"], [f"h{i}.example.com" for i in range(6)])

    def test_nothing_unrefuted_leaves_the_wave_as_it_was(self):
        """Positive control: with every claim attacked, the wave is all hunters."""
        self.record(self.write("primitives/oracle.md"))
        self.assertEqual(list(self._roles(self._wave())), ["deep-hunter"])


if __name__ == "__main__":
    unittest.main()
