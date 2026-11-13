"""Regression: a refutation must say which hops of the claim it actually attacked.

Measured 2026-11-12 on a live engagement. The write-up is held back here — it is
an unfixed third-party issue — so only the shape of the defect is recorded, and the
engagement's own copy is replayed from disk by the last class below.

The claim was a consent-scope mismatch: a consent screen stating the application
cannot act on a resource, and the token that same flow issues then acting on it.
Its `**Vulnerable URL:**` line named three hops — the authorize endpoint, the
identity provider's login hop, and the API the token is spent against.

`cbh refute` found exactly one spec in the folder, and it covers the FIRST hop: an
unauthenticated `302` whose `Location` carries the over-broad scope. The arm that
carries the claim — the authenticated call against the third hop — had no spec at
all. So:

  * one control fired (`control-value`) and failed, as a control should;
  * `credentials-removed` was SKIPPED with "the exploit spec carries no credential
    header ... this finding is already an unauthenticated claim" — true of the
    spec, false of the finding;
  * `exploit-removed` was SKIPPED as a single-request PoC;
  * the verdict written to `finding.refute.json` was **SURVIVED**.

Every sentence there was accurate and the result was misleading: "nothing killed
it" is a statement about the whole finding, made from a spec that covered a third
of it. The fix compares the write-up's own declared claim line against the spec's
own URLs and downgrades SURVIVED to INCOMPLETE, naming the untested hop.

Positive controls, in both directions, because a coverage gate that fires on
everything is worse than none: a spec that reaches every declared hop must still
reach SURVIVED, a KILLED verdict must never be downgraded (a control that passed
on one hop really did refute that hop), and a write-up with no declared claim
line must leave the verdict alone rather than guess.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import refute  # noqa: E402

CLAIM = """# Consent screen denies mail send while the token sends

- **Severity:** Medium
- **Vulnerable URL:** `https://ai.example.com/oauth/authorize` -> `https://o2.example.com/xlogin` -> MCP `https://ai.example.com/mcp`
- **Host:** ai.example.com

## 2. Steps to reproduce

1. `GET https://ai.example.com/oauth/authorize?...`
4. `POST https://ai.example.com/mcp` with `Authorization: Bearer mcp_at_v1...`

## 5. Precedent

See https://hackerone.com/reports/341876 and https://portswigger.net/research/x.
"""

FIRST_HOP_SPEC = {"url": "https://ai.example.com/oauth/authorize?response_type=code",
                  "method": "GET", "expect": {"status": 302}}
ALL_HOPS_SPEC = {
    "steps": [
        {"name": "authorize", "url": "https://ai.example.com/oauth/authorize"},
        {"name": "login", "url": "https://o2.example.com/xlogin"},
        {"name": "exploit", "url": "https://ai.example.com/mcp",
         "headers": {"Authorization": "Bearer x"}},
    ],
    "expect": {"status": 200},
}


def _finding(tmp: Path, doc: str = CLAIM) -> Path:
    folder = tmp / "findings" / "demo"
    folder.mkdir(parents=True)
    (folder / "finding.md").write_text(doc, encoding="utf-8")
    return folder


def _results(verdict="FAIL", pass_means=refute.KILLED):
    return [{"name": "control-value", "verdict": verdict, "pass_means": pass_means,
             "pass_text": "the oracle is a stub"}]


class CoverageIsReadFromTheClaimLine(unittest.TestCase):
    def test_a_one_hop_spec_over_a_three_hop_claim_is_partial(self):
        with tempfile.TemporaryDirectory() as td:
            cov = refute.claim_coverage(_finding(Path(td)), FIRST_HOP_SPEC)
            self.assertTrue(cov["checked"])
            self.assertEqual(len(cov["claim_hops"]), 3)
            self.assertEqual(cov["spec_hops"], ["https://ai.example.com/oauth/authorize"])
            self.assertEqual(cov["untested_hops"],
                             ["https://o2.example.com/xlogin", "https://ai.example.com/mcp"])

    def test_a_spec_reaching_every_hop_is_complete(self):
        """Positive control: full coverage must report nothing untested."""
        with tempfile.TemporaryDirectory() as td:
            cov = refute.claim_coverage(_finding(Path(td)), ALL_HOPS_SPEC)
            self.assertEqual(cov["untested_hops"], [])

    def test_precedent_and_platform_links_are_not_claim_hops(self):
        """The write-up cites two research URLs; neither is an arm of the claim."""
        with tempfile.TemporaryDirectory() as td:
            cov = refute.claim_coverage(_finding(Path(td)), ALL_HOPS_SPEC)
            joined = " ".join(cov["claim_hops"])
            self.assertNotIn("hackerone.com", joined)
            self.assertNotIn("portswigger.net", joined)

    def test_the_query_string_does_not_make_a_hop_look_untested(self):
        """A spec carries the live code_challenge the write-up does not."""
        with tempfile.TemporaryDirectory() as td:
            spec = {"url": "https://ai.example.com/oauth/authorize?code_challenge=abc&state=1"}
            cov = refute.claim_coverage(_finding(Path(td)), spec)
            self.assertNotIn("https://ai.example.com/oauth/authorize", cov["untested_hops"])

    def test_a_template_placeholder_still_identifies_the_hop(self):
        with tempfile.TemporaryDirectory() as td:
            spec = {"url": "https://ai.example.com/mcp{{suffix}}"}
            cov = refute.claim_coverage(_finding(Path(td)), spec)
            self.assertNotIn("https://ai.example.com/mcp", cov["untested_hops"])

    def test_a_trailing_slash_is_the_same_hop(self):
        with tempfile.TemporaryDirectory() as td:
            cov = refute.claim_coverage(_finding(Path(td)), {"url": "https://ai.example.com/mcp/"})
            self.assertNotIn("https://ai.example.com/mcp", cov["untested_hops"])

    def test_no_write_up_means_not_checked_rather_than_a_guess(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "findings" / "bare"
            folder.mkdir(parents=True)
            cov = refute.claim_coverage(folder, FIRST_HOP_SPEC)
            self.assertFalse(cov["checked"])

    def test_a_write_up_with_no_claim_line_means_not_checked(self):
        with tempfile.TemporaryDirectory() as td:
            folder = _finding(Path(td), "# Finding\n\nNo declared claim line here.\n")
            cov = refute.claim_coverage(folder, FIRST_HOP_SPEC)
            self.assertFalse(cov["checked"])
            self.assertIn("Vulnerable URL", cov["reason"])

    def test_a_write_up_from_another_finding_is_never_read(self):
        """Same confinement rule as find_spec: two .md files -> no guess."""
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "findings" / "demo"
            folder.mkdir(parents=True)
            (folder / "a.md").write_text(CLAIM, encoding="utf-8")
            (folder / "b.md").write_text(CLAIM, encoding="utf-8")
            self.assertFalse(refute.claim_coverage(folder, FIRST_HOP_SPEC)["checked"])


class TheAuthenticatedArmIsFlaggedWhenItsControlCouldNotRun(unittest.TestCase):
    def test_a_credential_free_spec_under_an_authenticated_claim_is_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            folder = _finding(Path(td))
            controls = refute.build_controls(FIRST_HOP_SPEC)
            cov = refute.claim_coverage(folder, FIRST_HOP_SPEC, controls)
            self.assertTrue(cov["auth_claim_unrefuted"])
            self.assertIn("bearer", cov["auth_markers"])

    def test_a_spec_that_does_carry_a_credential_is_not_flagged(self):
        """Positive control: the credential control ran, so there is nothing to flag."""
        with tempfile.TemporaryDirectory() as td:
            folder = _finding(Path(td))
            controls = refute.build_controls(ALL_HOPS_SPEC)
            cov = refute.claim_coverage(folder, ALL_HOPS_SPEC, controls)
            self.assertFalse(cov["auth_claim_unrefuted"])

    def test_an_unauthenticated_claim_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            doc = ("# Open redirect\n\n- **Vulnerable URL:** `https://ai.example.com/go`\n\n"
                   "Unauthenticated GET, no session of any kind.\n")
            folder = _finding(Path(td), doc)
            spec = {"url": "https://ai.example.com/go"}
            cov = refute.claim_coverage(folder, spec, refute.build_controls(spec))
            self.assertFalse(cov["auth_claim_unrefuted"])


class PartialCoverageDowngradesSurvivedOnly(unittest.TestCase):
    def test_survived_over_a_partial_spec_becomes_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            folder = _finding(Path(td))
            cov = refute.claim_coverage(folder, FIRST_HOP_SPEC,
                                        refute.build_controls(FIRST_HOP_SPEC))
            out = refute.judge(_results(), [], None, cov)
            self.assertEqual(out["verdict"], refute.INCOMPLETE)
            self.assertIn("https://ai.example.com/mcp", out["why"])
            self.assertIn("did not reach the claim", out["why"])

    def test_survived_over_a_complete_spec_stays_survived(self):
        """Positive control. Without this the gate would make SURVIVED unreachable."""
        with tempfile.TemporaryDirectory() as td:
            folder = _finding(Path(td))
            cov = refute.claim_coverage(folder, ALL_HOPS_SPEC,
                                        refute.build_controls(ALL_HOPS_SPEC))
            out = refute.judge(_results(), [], None, cov)
            self.assertEqual(out["verdict"], refute.SURVIVED)

    def test_killed_is_never_downgraded(self):
        """A control that passed on one hop really did refute that hop."""
        with tempfile.TemporaryDirectory() as td:
            folder = _finding(Path(td))
            cov = refute.claim_coverage(folder, FIRST_HOP_SPEC,
                                        refute.build_controls(FIRST_HOP_SPEC))
            out = refute.judge(_results(verdict="PASS", pass_means=refute.KILLED), [], None, cov)
            self.assertEqual(out["verdict"], refute.KILLED)

    def test_misframed_is_never_downgraded(self):
        with tempfile.TemporaryDirectory() as td:
            folder = _finding(Path(td))
            cov = refute.claim_coverage(folder, FIRST_HOP_SPEC,
                                        refute.build_controls(FIRST_HOP_SPEC))
            out = refute.judge(_results(verdict="PASS", pass_means=refute.MISFRAMED),
                               [], None, cov)
            self.assertEqual(out["verdict"], refute.MISFRAMED)

    def test_an_unchecked_coverage_leaves_the_verdict_alone(self):
        out = refute.judge(_results(), [], None, {"checked": False, "reason": "no write-up"})
        self.assertEqual(out["verdict"], refute.SURVIVED)

    def test_no_coverage_argument_keeps_the_old_behaviour(self):
        """Every existing caller of judge() passes three arguments."""
        self.assertEqual(refute.judge(_results(), [], None)["verdict"], refute.SURVIVED)

    def test_the_coverage_record_is_written_into_the_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            folder = _finding(Path(td))
            cov = refute.claim_coverage(folder, FIRST_HOP_SPEC)
            out = refute.judge(_results(), [], None, cov)
            self.assertEqual(out["coverage"]["untested_hops"], cov["untested_hops"])
            json.dumps(out)  # the artifact must stay serialisable


class TheMeasuredCaseIsCaught(unittest.TestCase):
    """The engagement's own record on disk, replayed through the gate.

    Engagement folders are not in this repository (`.gitignore`: unfixed
    third-party detail stays local), so this reads a folder named by
    `CBH_MEASURED_FINDING` and skips when it is unset. Nothing about the target is
    asserted — only that a spec covering one hop of a three-hop claim used to reach
    SURVIVED and now reaches INCOMPLETE.
    """

    def test_a_partial_refutation_on_the_real_record_is_incomplete(self):
        import os
        folder = os.environ.get("CBH_MEASURED_FINDING", "")
        if not folder or not Path(folder).is_dir():
            self.skipTest("set CBH_MEASURED_FINDING=<findings/<slug>/> to replay the real record")
        folder = Path(folder)
        spec_file = refute.find_spec(folder)
        self.assertTrue(spec_file, "the folder holds no single unambiguous PoC spec")
        spec = json.loads(Path(spec_file).read_text(encoding="utf-8"))
        cov = refute.claim_coverage(folder, spec, refute.build_controls(spec))
        self.assertTrue(cov["checked"])
        self.assertTrue(cov["untested_hops"], "this record's spec already covers every hop")
        rec = next(iter(folder.glob("*.refute.json")), None)
        self.assertIsNotNone(rec, "no refutation was ever recorded for this finding")
        recorded = json.loads(rec.read_text(encoding="utf-8"))
        self.assertEqual(recorded["verdict"], refute.SURVIVED)  # what it said
        self.assertEqual(
            refute.judge(recorded["controls"], recorded["skipped"], None, cov)["verdict"],
            refute.INCOMPLETE)  # what it says now


if __name__ == "__main__":
    unittest.main()
