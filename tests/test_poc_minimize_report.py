#!/usr/bin/env python3
"""The triager-facing reproduction, and its path into `cbh report`.

A technically valid finding gets closed when the repro is twenty steps long or never
shows a final state change. poc_minimize is the fix — but only if it keeps the step
that causes the bug, and only if the report path actually calls it.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import poc_minimize as PM  # noqa: E402


def names(steps):
    return [s.get("name") for s in steps]


class Minimization(unittest.TestCase):
    CHAIN = {"steps": [
        {"name": "login", "method": "POST", "url": "https://a/login",
         "capture": {"tok": "$.token"}},
        {"name": "noise", "method": "GET", "url": "https://a/dashboard"},
        {"name": "exploit", "method": "POST", "url": "https://a/orders/999/refund",
         "headers": {"X-T": "{{tok}}"}},
        {"name": "verify", "method": "GET", "url": "https://a/orders/999",
         "expect": {"body_contains": "refunded"}},
    ]}

    def test_the_exploit_survives_minimization(self):
        """The regression: minimizing on capture-dependencies alone dropped it.

        `verify` reads state back, so it references nothing; nothing references
        `exploit`'s output either. A repro of login -> verify shows no bug at all.
        """
        self.assertIn("exploit", names(PM.required_steps(self.CHAIN)))

    def test_the_verification_step_is_always_last_and_kept(self):
        self.assertEqual(names(PM.required_steps(self.CHAIN))[-1], "verify")

    def test_irrelevant_steps_are_dropped(self):
        self.assertNotIn("noise", names(PM.required_steps(self.CHAIN)))

    def test_capture_dependencies_are_pulled_in_transitively(self):
        spec = {"steps": [
            {"name": "a", "method": "GET", "url": "https://a/1", "capture": {"x": "$.x"}},
            {"name": "b", "method": "GET", "url": "https://a/2?x={{x}}",
             "capture": {"y": "$.y"}},
            {"name": "c", "method": "POST", "url": "https://a/3", "body": "{{y}}"},
            {"name": "d", "method": "GET", "url": "https://a/4"},
        ]}
        self.assertEqual(names(PM.required_steps(spec)), ["a", "b", "c", "d"])

    def test_a_single_step_spec_is_returned_unchanged(self):
        spec = {"method": "GET", "url": "https://a/x"}
        self.assertEqual(PM.required_steps(spec), [spec])

    def test_render_shows_the_verdict_and_every_step(self):
        result = {"spec_file": "x.poc.json", "final_verdict": "PASS",
                  "runs": [{"steps": [{"name": "exploit", "result": {"status": 200},
                                       "verdict": "PASS"}]}]}
        md = PM.render(self.CHAIN, result)
        self.assertIn("PASS", md)
        self.assertIn("/orders/999/refund", md)
        self.assertIn("Impact", md)


class ReportIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        (self.d / "idor.md").write_text(
            "# IDOR on refund\n\nSeverity: High\n\n## Summary\nCross-account refund.\n")
        (self.d / "idor.poc.json").write_text(json.dumps(Minimization.CHAIN))

    def _result(self, verdict="PASS"):
        (self.d / "idor.poc.result.json").write_text(json.dumps({
            "spec_file": "idor.poc.json", "final_verdict": verdict,
            "runs": [{"steps": [{"name": "exploit", "result": {"status": 200},
                                 "verdict": verdict}]}]}))

    def _report(self, *extra):
        r = subprocess.run(
            [sys.executable, "-B", str(ROOT / "cbh" / "cli.py"), "report",
             str(self.d / "idor.md"), "--platform", "h1", *extra],
            capture_output=True, text=True, timeout=60, cwd=str(self.d))
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_a_passing_poc_is_embedded_as_a_short_reproduction(self):
        self._result("PASS")
        out = self._report()
        self.assertIn("Minimal reproduction", out)
        self.assertIn("/orders/999/refund", out, "the exploit step is missing from the report")
        self.assertIn("Full evidence (appendix)", out,
                      "the verbose artifact must stay attached, not be replaced")

    def test_a_failing_poc_is_never_rendered_as_proof(self):
        self._result("FAIL")
        out = self._report()
        self.assertNotIn("Minimal reproduction", out,
                         "a FAIL artifact was rendered as reproduction steps")

    def test_no_artifact_still_produces_a_draft(self):
        out = self._report()
        self.assertIn("IDOR on refund", out)
        self.assertNotIn("Minimal reproduction", out)

    def test_another_findings_evidence_is_never_pasted_in(self):
        """Found by this suite: the first version scanned the tree for any artifact.

        `evidence.collect()` rglobs the engagement, so a finding with no PoC of its own
        got a *different* bug's reproduction steps rendered under its title — the exact
        MISMATCH that gets reports closed. Only the sibling artifact counts.
        """
        other = self.d / "unrelated"
        other.mkdir()
        (other / "sqli.poc.json").write_text(json.dumps(
            {"steps": [{"name": "exploit", "method": "POST",
                        "url": "https://elsewhere/sqli"}]}))
        (other / "sqli.poc.result.json").write_text(json.dumps(
            {"spec_file": "sqli.poc.json", "final_verdict": "PASS", "runs": [{"steps": []}]}))
        out = self._report()
        self.assertNotIn("elsewhere/sqli", out)
        self.assertNotIn("Minimal reproduction", out)

    def test_opt_out_flag(self):
        self._result("PASS")
        self.assertNotIn("Minimal reproduction", self._report("--no-repro"))


if __name__ == "__main__":
    unittest.main()
