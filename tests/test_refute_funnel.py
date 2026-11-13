#!/usr/bin/env python3
"""The disproving half of the pipeline, and the funnel tiers below findings/.

Everything else here is built to confirm a finding. These cover the parts built to
knock one back: the controls `engine/refute.py` derives, the precedence its verdict
has over a passing exploit, and the fact that a control artifact can never be read
as evidence for some other finding.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import evidence  # noqa: E402
import refute  # noqa: E402

# The second arm. `evidence.py` now asks what the CLASS of a claim needs, and an
# ownership claim needs two identities in one artifact (engine/class_proof.py). Without
# this spec the fixture is a single authenticated request to /users/124 — exactly what the
# class gate exists to catch. It is scaffolding for the question each test below actually
# asks, so it carries the arm a real IDOR PoC would carry.
IDOR_SPEC = {"steps": [
    {"name": "owner", "method": "GET", "url": "https://api.acme.com/users/124",
     "headers": {"Authorization": "Bearer owner-token"}},
    {"name": "other-account", "method": "GET", "url": "https://api.acme.com/users/124",
     "headers": {"Authorization": "Bearer attacker-token"}}]}

import stop_gate  # noqa: E402

SPEC = {
    "note": "IDOR — read 124 as 123",
    "method": "GET",
    "url": "https://api.acme.com/users/124",
    "headers": {"Cookie": "session=abc", "X-Bug-Bounty": "qvex"},
    "refute": {"attack": "124", "control": "123"},
    "expect": {"status": 200, "body_contains": ['"id":124']},
}


def by_name(controls):
    return {c["name"]: c for c in controls}


class Controls(unittest.TestCase):
    def test_credentials_removed_keeps_the_programs_mandatory_header(self):
        """Stripping X-Bug-Bounty would make the control violate the program's rules."""
        c = by_name(refute.build_controls(SPEC))["credentials-removed"]
        self.assertNotIn("Cookie", c["spec"]["headers"])
        self.assertEqual(c["spec"]["headers"]["X-Bug-Bounty"], "qvex")
        self.assertTrue(c["runnable"])

    def test_control_value_swaps_the_request_but_never_the_expectation(self):
        """The whole point: does the ORIGINAL expectation still hold without the attack?"""
        c = by_name(refute.build_controls(SPEC))["control-value"]
        self.assertEqual(c["spec"]["url"], "https://api.acme.com/users/123")
        self.assertEqual(c["spec"]["expect"]["body_contains"], ['"id":124'])

    def test_control_value_is_skipped_when_the_spec_declares_no_attack_value(self):
        spec = {k: v for k, v in SPEC.items() if k != "refute"}
        c = by_name(refute.build_controls(spec))["control-value"]
        self.assertFalse(c["runnable"])
        self.assertIn('"refute"', c["skip_reason"])

    def test_exploit_removed_drops_the_attack_step_and_keeps_login_and_verify(self):
        spec = {"steps": [
            {"name": "login", "url": "https://api.acme.com/login", "method": "POST"},
            {"name": "exploit", "url": "https://api.acme.com/transfer", "method": "POST"},
            {"name": "verify", "url": "https://api.acme.com/balance"}]}
        c = by_name(refute.build_controls(spec))["exploit-removed"]
        self.assertTrue(c["runnable"])
        self.assertEqual([s["name"] for s in c["spec"]["steps"]], ["login", "verify"])

    def test_credentials_removed_also_drops_the_login_step_of_a_chain(self):
        spec = {"steps": [
            {"name": "login", "url": "https://api.acme.com/login", "method": "POST"},
            {"name": "exploit", "url": "https://api.acme.com/users/124",
             "headers": {"Cookie": "s=1"}}]}
        c = by_name(refute.build_controls(spec))["credentials-removed"]
        self.assertEqual([s["name"] for s in c["spec"]["steps"]], ["exploit"])
        self.assertEqual(c["spec"]["steps"][0]["headers"], {})

    def test_a_single_request_poc_cannot_have_its_exploit_step_removed(self):
        c = by_name(refute.build_controls(SPEC))["exploit-removed"]
        self.assertFalse(c["runnable"])


class Judgement(unittest.TestCase):
    def row(self, name, verdict, means):
        return {"name": name, "verdict": verdict, "pass_means": means,
                "pass_text": "because"}

    def test_a_passing_killer_control_kills_it(self):
        out = refute.judge([self.row("control-value", "PASS", refute.KILLED)], [], None)
        self.assertEqual(out["verdict"], refute.KILLED)

    def test_credentials_removed_passing_is_mis_framed_not_killed(self):
        """Unauthenticated access may still be a bug — just not the one written up."""
        out = refute.judge([self.row("credentials-removed", "PASS", refute.MISFRAMED)], [], None)
        self.assertEqual(out["verdict"], refute.MISFRAMED)

    def test_controls_that_fail_let_the_finding_survive(self):
        out = refute.judge([self.row("control-value", "FAIL", refute.KILLED),
                            self.row("credentials-removed", "FAIL", refute.MISFRAMED)], [], None)
        self.assertEqual(out["verdict"], refute.SURVIVED)

    def test_a_constant_decisive_field_kills_a_survivor_with_no_request(self):
        out = refute.judge([self.row("control-value", "FAIL", refute.KILLED)], [],
                           {"decisive": ["match"], "responses": 9, "path": "/check"})
        self.assertEqual(out["verdict"], refute.KILLED)
        self.assertIn("never changed", out["why"])

    def test_no_runnable_control_is_incomplete_not_a_pass(self):
        self.assertEqual(refute.judge([], [{"name": "x", "skip_reason": "y"}], None)["verdict"],
                         refute.INCOMPLETE)


class EvidencePrecedence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name) / "Targets" / "acme"
        (self.project / "findings").mkdir(parents=True)
        self.finding = self.project / "findings" / "idor.md"
        self.finding.write_text("# IDOR\n\nSeverity: High\n\nhttps://api.acme.com/users/124\n")
        (self.project / "findings" / "idor.poc.json").write_text(json.dumps(IDOR_SPEC))
        (self.project / "findings" / "idor.result.json").write_text(json.dumps({
            "spec_file": "idor.poc.json",
            "final_verdict": "PASS",
            "runs": [{"steps": [], "result": {"final_url": "https://api.acme.com/users/124",
                                              "status": 200}}]}))

    def test_without_a_refutation_a_passing_poc_is_demonstrated(self):
        self.assertEqual(evidence.check(self.finding)["status"], "DEMONSTRATED")

    def test_a_refutation_outranks_the_exploits_own_pass(self):
        (self.project / "findings" / "idor.refute.json").write_text(json.dumps(
            {"verdict": "KILLED", "why": "the answer never moved"}))
        rep = evidence.check(self.finding)
        self.assertEqual(rep["status"], "REFUTED")
        self.assertIn("never moved", rep["reason"])
        self.assertIn("demote", evidence.gate_line(rep))

    def test_a_survived_refutation_changes_nothing(self):
        (self.project / "findings" / "idor.refute.json").write_text(json.dumps(
            {"verdict": "SURVIVED", "why": "controls failed"}))
        self.assertEqual(evidence.check(self.finding)["status"], "DEMONSTRATED")

    def test_a_passing_control_is_never_evidence_for_a_finding(self):
        """refutations/ holds requests built to pass when the finding is WRONG."""
        d = self.project / "refutations" / "other"
        d.mkdir(parents=True)
        (d / "control-value.poc.result.json").write_text(json.dumps({
            "final_verdict": "PASS",
            "runs": [{"steps": [], "result": {"final_url": "https://api.acme.com/users/124",
                                              "status": 200}}]}))
        (self.project / "findings" / "idor.result.json").unlink()
        rep = evidence.check(self.finding)
        self.assertEqual(rep["status"], "NO-EVIDENCE", rep)
        self.assertEqual(rep["artifacts"], [])


class Funnel(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name) / "Targets" / "acme"
        for sub in ("findings", "leads", "primitives"):
            (self.project / sub).mkdir(parents=True)

    def test_a_lead_is_never_a_finding(self):
        (self.project / "leads" / "a.md").write_text("# Maybe an IDOR\n\nSeverity: Critical\n")
        self.assertEqual(stop_gate.qualifying_findings(self.project), [])

    def test_an_unfired_lead_is_reported_separately(self):
        (self.project / "leads" / "a.md").write_text(
            "# Maybe an IDOR\n\n## Fired so far\nnothing yet\n")
        (self.project / "leads" / "b.md").write_text(
            "# Open redirect\n\n## Fired so far\nGET /x?u= returned 302\n")
        fn = stop_gate.funnel(self.project)
        self.assertEqual(fn["counts"]["leads"], 2)
        self.assertEqual([r["name"] for r in fn["untested_leads"]], ["a.md"])

    def test_the_tier_readmes_are_not_counted_as_items(self):
        (self.project / "primitives" / "README.md").write_text("# primitives/\n")
        self.assertEqual(stop_gate.funnel(self.project)["counts"]["primitives"], 0)

    def _triage_demote(self, finding: Path):
        r = subprocess.run([sys.executable, "-B", str(ROOT / "scripts" / "cbh.py"),
                            "triage", str(finding), "--demote"],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(finding.exists())
        return r.stdout + r.stderr

    def test_triage_demote_moves_the_finding_and_its_artifact_out_of_findings(self):
        """A KILL with a fired-request artifact behind it is a primitive, not a lead.

        The tier used to be read from the verdict alone, so every KILL landed in `leads/`.
        On 2026-11-11 a finding with three fired POSTs and a captured response behind it was
        filed there and had to be moved by hand: the capability was proven, only the impact
        was not, which is the definition of a primitive.
        """
        f = self.project / "findings" / "x.md"
        f.write_text("# Something\n\nSeverity: High\n")
        (self.project / "findings" / "x.result.json").write_text('{"final_verdict": "FAIL"}')
        out = self._triage_demote(f)
        moved = self.project / "primitives" / "x.md"
        self.assertTrue(moved.is_file(), out)
        self.assertFalse((self.project / "leads" / "x.md").exists())
        self.assertIn("Demoted from findings/", moved.read_text())
        self.assertIn("requests were fired", moved.read_text())
        self.assertTrue((self.project / "primitives" / "x.result.json").is_file())
        self.assertEqual(stop_gate.qualifying_findings(self.project), [])

    def test_a_kill_with_nothing_fired_is_a_lead(self):
        f = self.project / "findings" / "guess.md"
        f.write_text("# Read from the bundle\n\nSeverity: High\n")
        out = self._triage_demote(f)
        self.assertTrue((self.project / "leads" / "guess.md").is_file(), out)
        self.assertIn("no fired-request artifact", (self.project / "leads" / "guess.md").read_text())

    def test_the_house_index_name_does_not_collide_in_the_destination_tier(self):
        """`findings/<slug>/finding.md` is this workspace's layout. Demoting two of them used
        to produce `primitives/finding.md` twice, the second renamed with a timestamp, so the
        slug — the name every tracker uses — was lost."""
        for slug in ("unauth-toggle-read", "unauth-config-read"):
            d = self.project / "findings" / slug
            d.mkdir(parents=True)
            (d / "finding.md").write_text(f"# {slug}\n\nSeverity: Low\n")
            (d / "finding.wire.txt").write_text("POST /v1/evaluate HTTP/1.1\n")
            self._triage_demote(d / "finding.md")
        self.assertTrue((self.project / "primitives" / "unauth-toggle-read.md").is_file())
        self.assertTrue((self.project / "primitives" / "unauth-config-read.md").is_file())
        self.assertFalse((self.project / "primitives" / "finding.md").exists())

    def test_artifact_subdirectories_travel_with_the_file(self):
        """`evidence/`, `cdp/`, `report/` were globbed as files only and stayed in findings/."""
        d = self.project / "findings" / "deeplink-xss"
        (d / "evidence").mkdir(parents=True)
        (d / "finding.md").write_text("# deeplink\n\nSeverity: High\n")
        (d / "evidence" / "proof.png").write_bytes(b"\x89PNG\r\n")
        (d / "finding.result.json").write_text('{"final_verdict": "FAIL"}')
        self._triage_demote(d / "finding.md")
        carried = self.project / "primitives" / "deeplink-xss-evidence" / "proof.png"
        self.assertTrue(carried.is_file(),
                        "the screenshot was orphaned in findings/ where nothing reads it")
        self.assertFalse(d.exists(), "the empty finding folder was left behind")


if __name__ == "__main__":
    unittest.main()
