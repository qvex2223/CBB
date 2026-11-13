#!/usr/bin/env python3
"""
What a class of bug has to show before the gate calls it demonstrated.

`evidence.py` grades that a request was fired and matched its `expect`. These tests lock
the second question — whether the artifacts hold the oracle that makes the class's effect
observable — and they lock it in BOTH directions, because a gate that only ever says no
is as useless as one that only ever says yes:

  * the oracle fired  -> the finding still reaches DEMONSTRATED
  * no class detected -> nothing is downgraded
  * no rule for the class -> nothing is downgraded, and the report says "not checked"
  * the oracle is missing -> CLASS-UNPROVEN, and only when a PoC actually passed

The fixtures are synthetic: `example.test` and invented markers, never a real target.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import class_proof  # noqa: E402
import evidence  # noqa: E402


def _result(folder: Path, name: str = "finding", *, verdict: str = "PASS",
            url: str = "https://example.test/api/v1/orders/7",
            steps: list | None = None, body: str = "ok", status: int = 200,
            elapsed: float = 120.0, headers: dict | None = None,
            redirects: list | None = None) -> Path:
    """A poc_runtime artifact and the spec beside it, as `evidence.collect` expects."""
    spec_path = folder / f"{name}.poc.json"
    spec_steps = steps if steps is not None else [
        {"name": "fetch", "method": "GET", "url": url,
         "headers": {"Authorization": "Bearer owner-token"}}]
    spec_path.write_text(json.dumps({"steps": spec_steps}), encoding="utf-8")
    run_steps = []
    for st in spec_steps:
        run_steps.append({
            "step": len(run_steps) + 1, "name": st.get("name", ""),
            "url": st.get("url", url), "method": st.get("method", "GET"),
            "verdict": "PASS",
            "result": {"ok": True, "status": status, "url": st.get("url", url),
                       "final_url": st.get("url", url), "body": body,
                       "headers": headers or {}, "redirects": redirects or [],
                       "elapsed_ms": elapsed}})
    out = folder / f"{name}.poc.result.json"
    out.write_text(json.dumps({
        "spec_file": str(spec_path), "final_verdict": verdict,
        "runs": [{"steps": run_steps,
                  "result": {"ok": True, "status": status, "url": url,
                             "final_url": url, "body": body,
                             "headers": headers or {}, "redirects": redirects or [],
                             "elapsed_ms": elapsed}}]}), encoding="utf-8")
    return out


def _finding(folder: Path, title: str, *, declared: str = "",
             url: str = "https://example.test/api/v1/orders/7") -> Path:
    body = f"# {title}\n\n"
    if declared:
        body += f"**Class:** {declared}\n\n"
    body += f"**Vulnerable URL:** {url}\n\n**Victim:** another user loses their order data\n"
    f = folder / "finding.md"
    f.write_text(body, encoding="utf-8")
    return f


class TheClassOfAClaim(unittest.TestCase):
    def test_a_declared_class_wins_over_the_title(self):
        text = "# an open redirect sends visitors off-origin from the shortener\n\n**Class:** ssrf\n"
        self.assertEqual(class_proof.classify(text), ("ssrf", "declared"))

    def test_the_declaration_is_read_from_lowercased_text(self):
        # evidence.check() lowercases a finding before grading it.
        self.assertEqual(class_proof.classify("**class:** `xss`\n"), ("xss", "declared"))

    def test_the_title_is_the_fallback(self):
        cls, src = class_proof.classify(
            "# a reflected marker reaches an html sink on the search page\n")
        self.assertEqual((cls, src), ("xss", "guessed"))

    def test_prose_far_from_the_title_does_not_classify(self):
        # A write-up that argues about redirects while claiming something else must not
        # classify itself off its body: only the first claim-shaped heading is read.
        text = ("# unauthenticated read of kyc records on the identification subsystem\n\n"
                "The service also redirects, and the redirect is a redirect, redirect.\n")
        self.assertEqual(class_proof.classify(text)[0], "data-exposure")

    def test_nothing_matched_is_not_an_error(self):
        self.assertEqual(class_proof.classify("# a thing happened\n", "notes"), ("", ""))


class AClassWithNoRuleIsNotDowngraded(unittest.TestCase):
    def test_grade_passes_and_says_it_did_not_check(self):
        rep = class_proof.grade("**Class:** info-leak\n", [], REPO / "tests")
        self.assertTrue(rep["ok"])
        self.assertFalse(rep["checked"])
        self.assertIn("info-leak", rep["reason"])

    def test_an_unclassified_finding_passes_and_says_so(self):
        rep = class_proof.grade("# something\n", [], REPO / "tests")
        self.assertTrue(rep["ok"])
        self.assertFalse(rep["checked"])
        self.assertIn("no class", rep["reason"])

    def test_the_line_marks_an_unchecked_class(self):
        self.assertIn("not checked",
                      class_proof.line(class_proof.grade("# something\n", [], REPO / "tests")))


class ExecutionNotReflection(unittest.TestCase):
    def test_a_byte_record_alone_does_not_prove_execution(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, body="<p>MARKER7731</p>")
            f = _finding(d, "reflected marker reaches an html sink", declared="xss")
            rep = class_proof.grade(f.read_text().lower(), [art], d, f.stem)
            self.assertFalse(rep["ok"])
            self.assertIn("sink", rep["reason"])

    def test_a_screenshot_beside_the_finding_proves_it(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, body="<p>MARKER7731</p>")
            (d / "evidence").mkdir()
            (d / "evidence" / "proof-alert.png").write_bytes(b"\x89PNG\r\n")
            f = _finding(d, "reflected marker reaches an html sink", declared="xss")
            rep = class_proof.grade(f.read_text().lower(), [art], d, f.stem)
            self.assertTrue(rep["ok"], rep["reason"])
            self.assertIn("proof-alert.png", rep["reason"])

    def test_a_subfolder_is_searched(self):
        # One folder per finding: the artifact sits in evidence/ or cdp/, not at the top.
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d)
            (d / "cdp").mkdir()
            (d / "cdp" / "console.json").write_text("[]", encoding="utf-8")
            f = _finding(d, "a marker reaches an html sink", declared="xss")
            self.assertTrue(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])

    def test_the_script_that_makes_the_proof_is_not_the_proof(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d)
            (d / "native-alert-proof.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            (d / "browser-poc.mjs").write_text("// drive it\n", encoding="utf-8")
            f = _finding(d, "a marker reaches an html sink", declared="xss")
            self.assertFalse(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])


class ADatabaseOrADelay(unittest.TestCase):
    def test_a_passing_request_is_not_an_injection(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, body="Internal Server Error", status=500)
            f = _finding(d, "a quote reaches the query", declared="sqli")
            rep = class_proof.grade(f.read_text().lower(), [art], d, f.stem)
            self.assertFalse(rep["ok"])
            self.assertIn("500", rep["reason"])

    def test_the_drivers_own_error_proves_it(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, body='{"error":"SQLSTATE[42601] syntax error at or near \\"\'\\""}')
            f = _finding(d, "a quote reaches the query", declared="sqli")
            self.assertTrue(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])

    def test_a_time_delta_across_steps_proves_it(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            steps = [{"name": "fast", "method": "GET", "url": "https://example.test/s?q=1"},
                     {"name": "slow", "method": "GET", "url": "https://example.test/s?q=2"}]
            art = _result(d, steps=steps)
            doc = json.loads(art.read_text())
            doc["runs"][0]["steps"][0]["result"]["elapsed_ms"] = 110.0
            doc["runs"][0]["steps"][1]["result"]["elapsed_ms"] = 5200.0
            art.write_text(json.dumps(doc), encoding="utf-8")
            f = _finding(d, "a sleep reaches the query", declared="sqli")
            rep = class_proof.grade(f.read_text().lower(), [art], d, f.stem)
            self.assertTrue(rep["ok"], rep["reason"])
            self.assertIn("time delta", rep["reason"])

    def test_a_delta_that_only_edges_past_the_fast_arm_does_not(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            steps = [{"name": "a", "method": "GET", "url": "https://example.test/s?q=1"},
                     {"name": "b", "method": "GET", "url": "https://example.test/s?q=2"}]
            art = _result(d, steps=steps)
            doc = json.loads(art.read_text())
            doc["runs"][0]["steps"][0]["result"]["elapsed_ms"] = 4000.0
            doc["runs"][0]["steps"][1]["result"]["elapsed_ms"] = 6100.0  # +2100 ms, but 1.5x
            art.write_text(json.dumps(doc), encoding="utf-8")
            f = _finding(d, "a sleep reaches the query", declared="sqli")
            self.assertFalse(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])


class AnOutboundRequestNeedsAListener(unittest.TestCase):
    def test_a_200_from_the_fetcher_is_not_an_outbound_request(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, body='{"status":"queued"}')
            f = _finding(d, "the image optimizer fetches a url we choose", declared="ssrf")
            rep = class_proof.grade(f.read_text().lower(), [art], d, f.stem)
            self.assertFalse(rep["ok"])
            self.assertIn("oob-responder.py", rep["reason"])

    def test_a_hit_log_proves_it(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d)
            (d / "oob.jsonl").write_text(
                '{"ts":"2026-11-13T10:00:00Z","path":"/MARKER7731","ua":"Go-http-client/2.0"}\n',
                encoding="utf-8")
            f = _finding(d, "the optimizer fetches a url we choose", declared="ssrf")
            self.assertTrue(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])

    def test_an_empty_hit_log_proves_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d)
            (d / "oob.jsonl").write_text("", encoding="utf-8")
            f = _finding(d, "the optimizer fetches a url we choose", declared="ssrf")
            self.assertFalse(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])

    def test_xxe_asks_for_the_same_oracle(self):
        self.assertEqual(class_proof.RULES["xxe"][1], class_proof.RULES["ssrf"][1])


class TwoIdentitiesInOneArtifact(unittest.TestCase):
    def test_one_identity_cannot_show_an_ownership_boundary(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, body='{"order":{"id":7,"total":1200}}')
            f = _finding(d, "another user's order is readable", declared="idor")
            rep = class_proof.grade(f.read_text().lower(), [art], d, f.stem)
            self.assertFalse(rep["ok"])
            self.assertIn("two", rep["reason"])

    def test_an_owner_arm_and_an_anonymous_arm_are_two(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            steps = [{"name": "owner", "method": "GET", "url": "https://example.test/api/v1/orders/7",
                      "headers": {"Authorization": "Bearer owner-token"}},
                     {"name": "nobody", "method": "GET", "url": "https://example.test/api/v1/orders/7",
                      "headers": {"Accept": "application/json"}}]
            art = _result(d, steps=steps)
            f = _finding(d, "another user's order is readable", declared="idor")
            rep = class_proof.grade(f.read_text().lower(), [art], d, f.stem)
            self.assertTrue(rep["ok"], rep["reason"])
            self.assertIn("2 identities", rep["reason"])

    def test_two_different_credentials_are_two(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            steps = [{"name": "a", "method": "GET", "url": "https://example.test/api/v1/orders/7",
                      "headers": {"Cookie": "sid=aaa"}},
                     {"name": "b", "method": "GET", "url": "https://example.test/api/v1/orders/7",
                      "headers": {"Cookie": "sid=bbb"}}]
            art = _result(d, steps=steps)
            f = _finding(d, "another user's order is readable", declared="idor")
            self.assertTrue(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])

    def test_the_same_credential_twice_is_one(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            steps = [{"name": "a", "method": "GET", "url": "https://example.test/api/v1/orders/7",
                      "headers": {"Cookie": "sid=aaa"}},
                     {"name": "b", "method": "GET", "url": "https://example.test/api/v1/orders/8",
                      "headers": {"Cookie": "sid=aaa"}}]
            art = _result(d, steps=steps)
            f = _finding(d, "another user's order is readable", declared="idor")
            self.assertFalse(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])


class AHopThatLeavesTheOrigin(unittest.TestCase):
    def test_a_200_is_not_a_redirect(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, url="https://example.test/go?to=https://evil.example")
            f = _finding(d, "the shortener sends visitors off-origin",
                         declared="open-redirect",
                         url="https://example.test/go?to=https://evil.example")
            self.assertFalse(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])

    def test_a_location_to_another_host_proves_it(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, url="https://example.test/go?to=https://evil.example",
                          status=302, headers={"location": "https://evil.example/landing"})
            f = _finding(d, "the shortener sends visitors off-origin",
                         declared="open-redirect",
                         url="https://example.test/go?to=https://evil.example")
            rep = class_proof.grade(f.read_text().lower(), [art], d, f.stem)
            self.assertTrue(rep["ok"], rep["reason"])
            self.assertIn("evil.example", rep["reason"])

    def test_a_same_host_location_does_not(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, url="https://example.test/go?to=/account",
                          status=302, headers={"location": "https://example.test/account"})
            f = _finding(d, "the shortener sends visitors off-origin",
                         declared="open-redirect", url="https://example.test/go?to=/account")
            self.assertFalse(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])


class FileBytesAndCommandOutput(unittest.TestCase):
    def test_a_differential_404_is_not_a_file_read(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, body="Not Found", status=404)
            f = _finding(d, "a path parameter traverses out of the template root",
                         declared="lfi")
            rep = class_proof.grade(f.read_text().lower(), [art], d, f.stem)
            self.assertFalse(rep["ok"])
            self.assertIn("primitive", rep["reason"])

    def test_the_files_own_bytes_prove_it(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, body="root:x:0:0:root:/root:/bin/bash\n")
            f = _finding(d, "a path parameter traverses out of the template root",
                         declared="lfi")
            self.assertTrue(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])

    def test_a_timeout_is_not_execution(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, body="Gateway Timeout", status=504, elapsed=30000.0)
            f = _finding(d, "a template argument reaches the shell", declared="rce")
            self.assertFalse(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])

    def test_command_output_proves_it(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, body="uid=33(www-data) gid=33(www-data) groups=33(www-data)")
            f = _finding(d, "a template argument reaches the shell", declared="rce")
            self.assertTrue(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])

    def test_an_oob_callback_also_proves_execution(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, body="queued")
            (d / "interactsh.jsonl").write_text('{"protocol":"dns","q":"MARKER7731.oob.test"}\n',
                                                encoding="utf-8")
            f = _finding(d, "a template argument reaches the shell", declared="rce")
            self.assertTrue(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])


class ACrossOriginDocument(unittest.TestCase):
    def test_a_curl_that_carries_the_cookie_is_not_a_forged_request(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, steps=[{"name": "post", "method": "POST",
                                     "url": "https://example.test/account/email",
                                     "headers": {"Cookie": "sid=aaa"}}])
            f = _finding(d, "the email change accepts a cross-site request", declared="csrf",
                         url="https://example.test/account/email")
            self.assertFalse(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])

    def test_an_html_poc_proves_it(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            art = _result(d, steps=[{"name": "post", "method": "POST",
                                     "url": "https://example.test/account/email",
                                     "headers": {"Cookie": "sid=aaa"}}])
            (d / "poc.html").write_text("<form method=post action=...>", encoding="utf-8")
            f = _finding(d, "the email change accepts a cross-site request", declared="csrf",
                         url="https://example.test/account/email")
            self.assertTrue(class_proof.grade(f.read_text().lower(), [art], d, f.stem)["ok"])


class TheGateVerdict(unittest.TestCase):
    """The branch only fires where a PoC already passed, and only downgrades that case."""

    def test_a_passing_poc_without_the_oracle_is_class_unproven(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = _finding(d, "a reflected marker reaches an html sink on the search page",
                         declared="xss", url="https://example.test/search?q=MARKER7731")
            _result(d, name="finding", url="https://example.test/search?q=MARKER7731",
                    body="<p>MARKER7731</p>")
            rep = evidence.check(f)
            self.assertEqual(rep["status"], "CLASS-UNPROVEN")
            self.assertIn("execution", rep["reason"])
            self.assertIn("Q1/Q6 backed for the REQUEST", evidence.gate_line(rep))

    def test_the_same_finding_with_its_oracle_is_demonstrated(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = _finding(d, "a reflected marker reaches an html sink on the search page",
                         declared="xss", url="https://example.test/search?q=MARKER7731")
            _result(d, name="finding", url="https://example.test/search?q=MARKER7731",
                    body="<p>MARKER7731</p>")
            (d / "evidence").mkdir()
            (d / "evidence" / "proof.png").write_bytes(b"\x89PNG\r\n")
            self.assertEqual(evidence.check(f)["status"], "DEMONSTRATED")

    def test_a_class_with_no_rule_still_reaches_demonstrated(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = _finding(d, "an unauthenticated read returns personal data",
                         declared="data-exposure",
                         url="https://example.test/api/v1/orders/7")
            _result(d, name="finding", body='{"name":"A","phone":"+70000000000"}')
            rep = evidence.check(f)
            self.assertEqual(rep["status"], "DEMONSTRATED")
            self.assertFalse(rep["class_proof"]["checked"])

    def test_a_failing_poc_keeps_its_own_verdict(self):
        # CLASS-UNPROVEN must not mask NOT-PROVEN: nothing passed, so the first question
        # is still unanswered and the advice has to say so.
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = _finding(d, "a reflected marker reaches an html sink on the search page",
                         declared="xss", url="https://example.test/search?q=MARKER7731")
            _result(d, name="finding", verdict="FAIL",
                    url="https://example.test/search?q=MARKER7731", body="")
            self.assertEqual(evidence.check(f)["status"], "NOT-PROVEN")

    def test_a_refutation_still_outranks_everything(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = _finding(d, "a reflected marker reaches an html sink on the search page",
                         declared="xss", url="https://example.test/search?q=MARKER7731")
            _result(d, name="finding", url="https://example.test/search?q=MARKER7731",
                    body="<p>MARKER7731</p>")
            (d / "finding.refute.json").write_text(
                json.dumps({"verdict": "KILLED", "why": "the control-value arm passed"}),
                encoding="utf-8")
            self.assertEqual(evidence.check(f)["status"], "REFUTED")

    def test_the_exit_code_is_recoverable_not_fatal(self):
        # 1, like WIRE-UNPROVEN: one artifact away from reportable, not "nothing fired".
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = _finding(d, "a reflected marker reaches an html sink on the search page",
                         declared="xss", url="https://example.test/search?q=MARKER7731")
            _result(d, name="finding", url="https://example.test/search?q=MARKER7731",
                    body="<p>MARKER7731</p>")
            self.assertEqual(evidence.main([str(f)]), 1)

    def test_an_unimportable_class_proof_cannot_wall_a_finding(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = _finding(d, "a reflected marker reaches an html sink on the search page",
                         declared="xss", url="https://example.test/search?q=MARKER7731")
            _result(d, name="finding", url="https://example.test/search?q=MARKER7731",
                    body="<p>MARKER7731</p>")
            saved = sys.modules.pop("class_proof", None)
            sys.modules["class_proof"] = None  # import raises
            try:
                self.assertEqual(evidence.check(f)["status"], "DEMONSTRATED")
            finally:
                if saved is not None:
                    sys.modules["class_proof"] = saved
                else:
                    del sys.modules["class_proof"]


if __name__ == "__main__":
    unittest.main(verbosity=2)
