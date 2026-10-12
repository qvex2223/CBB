#!/usr/bin/env python3
"""Regression tests for the response corpus and the evidence rules that read it.

These exist because both bugs this workspace shipped in the enforcement layer —
a skill-gate that demanded the wrong skill, a PoC runner that reported a redirect
as a 200 — were found on a live target instead of here. Run:

    python3 -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import responses  # noqa: E402
import evidence  # noqa: E402


class Corpus(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mem = Path(self.tmp.name) / "hunt-memory"
        (self.mem).mkdir(parents=True)
        os.environ["CBH_MEMORY_DIR"] = str(self.mem)

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("CBH_MEMORY_DIR", None)

    def _body(self, data: bytes) -> Path:
        p = Path(self.tmp.name) / "body.bin"
        p.write_bytes(data)
        return p

    def test_identical_bodies_collapse_to_one_file(self):
        a = responses.save("t", self._body(b'{"x":1}'), memdir=self.mem)
        b = responses.save("t", self._body(b'{"x":1}'), memdir=self.mem)
        self.assertEqual(a["body_sha256"], b["body_sha256"])
        self.assertEqual(len(list((self.mem / "responses" / "t").glob("*.txt"))), 1)

    def test_hash_covers_the_whole_body_even_when_stored_truncated(self):
        big = b"A" * (responses.MAX_STORE + 100)
        out = responses.save("t", self._body(big), memdir=self.mem)
        self.assertEqual(out["body_bytes"], len(big))
        self.assertTrue(out["truncated"])
        stored = (self.mem / "responses" / "t" / f"{out['body_sha256']}.txt").read_bytes()
        self.assertLess(len(stored), len(big))
        self.assertIn(b"truncated", stored)

    def test_credentials_never_reach_disk(self):
        argv = ["-H", "Authorization: Bearer LIVE-TOKEN", "-H", "Accept: */*",
                "-u", "user:pass", "-b", "session=abc", "https://x/api"]
        red = responses.redact(argv)
        blob = " ".join(red)
        for secret in ("LIVE-TOKEN", "user:pass", "session=abc"):
            self.assertNotIn(secret, blob)
        self.assertIn("Accept: */*", blob)  # non-secret headers survive intact

    def test_subscriber_identity_never_reaches_disk(self):
        """The hole this closes: redact() only ever matched credential-shaped HEADERS,
        so `?iin=<national id>&contact_phone=<number>` in a URL, the same pair in a JSON
        body, and an `msisdn:` header all landed in audit.jsonl verbatim on a live telecom
        program. Found 2026-09-11 while answering "what happens to my data if I hand you
        a real IIN".
        """
        argv = ["-H", "msisdn: 7770000001", "-H", "X-platform: WEB",
                "-d", '{"iin":"900101500009","msisdn":"7770000001","languageId":1}',
                "https://www.activ.kz/api/v1/x?iin=900101500009&contact_phone=7770000001"]
        blob = " ".join(responses.redact(argv))
        for pii in ("900101500009", "7770000001"):
            self.assertNotIn(pii, blob)
        self.assertIn("X-platform: WEB", blob)      # benign headers survive
        self.assertIn("languageId", blob)           # non-PII body fields survive
        self.assertIn("iin=", blob)                 # the KEY stays, so the shape is readable

    def test_identity_inside_a_returned_url_is_masked_too(self):
        """The response to the Aitu link minter repeats the IIN and phone INSIDE the URL
        it hands back, so scrubbing only the request would have left both on disk anyway.
        """
        body = ('{"link":"https://passport.aitu.io/oauth2/auth?client_id=abc'
                '&iin=900101500009&phone=%2B77770000001&scope=openid","requestId":"r1"}')
        out = responses.scrub_text(body)
        self.assertNotIn("900101500009", out)
        self.assertNotIn("77770000001", out)
        self.assertIn("client_id=abc", out)         # a public OAuth param is not PII
        self.assertIn("requestId", out)

    def test_stored_body_is_scrubbed_but_hash_still_identifies_the_original(self):
        raw = b'{"iin":"900101500009","count_msisdn":1}'
        p = Path(self.tmp.name) / "b.json"
        p.write_bytes(raw)
        meta = responses.save("kcell", p, memdir=self.mem)
        import hashlib
        self.assertEqual(meta["body_sha256"], hashlib.sha256(raw).hexdigest())
        disk = responses.load("kcell", meta["body_sha256"], memdir=self.mem)
        self.assertNotIn("900101500009", disk)
        self.assertIn("count_msisdn", disk)
        self.assertIn("masked before storage", disk)  # the file says it was scrubbed

    def test_identical_run_counts_distinct_answers(self):
        rows = [{"body_sha256": "a"}] * 9 + [{"body_sha256": "b"}]
        stats = responses.identical_run(rows)
        self.assertEqual((stats["requests"], stats["distinct"]), (10, 2))
        self.assertEqual(stats["identical_ratio"], 0.8)

    def _audit(self, rows):
        with (self.mem / "audit.jsonl").open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    def test_repeat_alert_fires_on_a_wall_of_sameness(self):
        self._audit([{"body_sha256": "a" * 64, "urls": ["https://t/x"], "http_code": 403,
                      "body_bytes": 12, "engagement": "t"} for _ in range(8)])
        alert = responses.repeat_alert(memdir=self.mem)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["repeats"], 8)
        self.assertEqual(alert["hosts"], ["t"])

    def test_repeat_alert_silent_when_answers_differ(self):
        self._audit([{"body_sha256": f"{i:064d}", "urls": ["https://t/x"]} for i in range(8)])
        self.assertIsNone(responses.repeat_alert(memdir=self.mem))


class FieldVariance(unittest.TestCase):
    """The phantom oracle: many requests, varied inputs, one answer that never moves."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mem = Path(self.tmp.name) / "hunt-memory"
        (self.mem / "responses" / "t").mkdir(parents=True)
        os.environ["CBH_MEMORY_DIR"] = str(self.mem)
        self.rows = []

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("CBH_MEMORY_DIR", None)

    def _capture(self, url, body):
        import hashlib
        raw = body.encode()
        sha = hashlib.sha256(raw).hexdigest()
        (self.mem / "responses" / "t" / f"{sha}.txt").write_bytes(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + raw)
        self.rows.append({"engagement": "t", "urls": [url], "body_sha256": sha,
                          "http_code": 200, "source": "bbcurl"})

    def _write_audit(self):
        with (self.mem / "audit.jsonl").open("w", encoding="utf-8") as fh:
            for r in self.rows:
                fh.write(json.dumps(r) + "\n")

    def test_constant_decision_field_is_flagged_even_when_bodies_differ(self):
        # Bodies all differ — they echo the input back — but `match` never moves.
        for i in range(8):
            self._capture(f"https://t/api/lookup2?phone=777000000{i}&id=99010130012{i}",
                          json.dumps({"match": False, "checked": True,
                                      "echo": {"phone": f"777000000{i}"}}))
        self._write_audit()
        alert = responses.constant_field_alert(memdir=self.mem)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["path"], "https://t/api/lookup2")
        self.assertIn("match", alert["decisive_fields"])
        self.assertEqual(alert["constant_fields"]["match"], "false")
        self.assertEqual(alert["responses"], 8)

    def test_a_field_that_tracks_the_input_is_not_flagged(self):
        for i in range(8):
            self._capture(f"https://t/api/lookup?phone=777000000{i}",
                          json.dumps({"match": i % 2 == 0, "echo": i}))
        self._write_audit()
        alert = responses.constant_field_alert(memdir=self.mem)
        self.assertIsNone(alert)

    def test_same_request_repeated_is_not_a_phantom_oracle(self):
        # One URL fired eight times proves nothing about input sensitivity.
        for _ in range(8):
            self._capture("https://t/api/lookup2?phone=1&id=2",
                          json.dumps({"match": False, "checked": True}))
        self._write_audit()
        self.assertIsNone(responses.constant_field_alert(memdir=self.mem))

    def test_field_variance_reports_per_field_movement(self):
        for i in range(3):
            self._capture(f"https://t/api/x?i={i}", json.dumps({"const": 1, "moves": i}))
        var = responses.field_variance(self.rows, memdir=self.mem)
        self.assertEqual(var["parsed"], 3)
        self.assertTrue(var["fields"]["const"]["constant"])
        self.assertFalse(var["fields"]["moves"]["constant"])
        self.assertEqual(var["fields"]["moves"]["distinct"], 3)


class WireEvidence(unittest.TestCase):
    """A wire-level claim needs wire-level bytes — the rule, and its escape hatches."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.mem = self.dir / "hunt-memory"
        (self.mem / "responses" / "t").mkdir(parents=True)
        os.environ["CBH_MEMORY_DIR"] = str(self.mem)
        (self.dir / "f.result.json").write_text(json.dumps({
            "spec_file": "f.json", "final_verdict": "PASS",
            "runs": [{"verdict": "PASS",
                      "result": {"ok": True, "status": 200,
                                 "final_url": "https://x.example.com/api/v1/session"}}]}))
        self.claim = ("# Session fixation on https://x.example.com/api/v1/session\n"
                      "The response redirects to /login and the session cookie is replaced.\n")

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("CBH_MEMORY_DIR", None)

    def _store(self, raw: bytes) -> str:
        import hashlib
        sha = hashlib.sha256(raw).hexdigest()
        (self.mem / "responses" / "t" / f"{sha}.txt").write_bytes(raw)
        return sha

    def _check(self, text: str) -> str:
        f = self.dir / "f.md"
        f.write_text(text, encoding="utf-8")
        return evidence.check(f)["status"]

    def test_single_shot_artifact_is_not_wire_proof(self):
        self.assertEqual(self._check(self.claim), "WIRE-UNPROVEN")

    def test_cited_capture_with_headers_is_wire_proof(self):
        sha = self._store(b"HTTP/1.1 302 Found\r\nLocation: /login\r\n"
                          b"Set-Cookie: session=deleted; Max-Age=0\r\n\r\n")
        self.assertEqual(self._check(self.claim + f"\ncaptured: sha256 {sha}\n"), "DEMONSTRATED")

    def test_cited_body_without_headers_proves_nothing_about_the_wire(self):
        sha = self._store(b'{"just":"a body"}')
        self.assertEqual(self._check(self.claim + f"\ncaptured: sha256 {sha}\n"), "WIRE-UNPROVEN")

    def test_citing_a_hash_the_corpus_does_not_have_changes_nothing(self):
        self.assertEqual(self._check(self.claim + "\ncaptured: sha256 " + "0" * 64 + "\n"),
                         "WIRE-UNPROVEN")


if __name__ == "__main__":
    unittest.main()


class StopGate(unittest.TestCase):
    """The hunt may end when it has something to report — not when it runs out of momentum.

    These cover the DEFAULT gate, so continuous mode is pinned off for them: whether the
    operator has the workspace-wide sweep switched on must not decide whether this suite
    passes (it did, the first time continuous mode was turned on). Continuous behaviour has
    its own file: tests/test_stop_gate_continuous.py.
    """

    def setUp(self):
        sys.path.insert(0, str(ROOT / "engine"))
        import stop_gate  # noqa: PLC0415
        self.sg = stop_gate
        self._prev = os.environ.get(stop_gate.ENV_CONTINUOUS)
        os.environ[stop_gate.ENV_CONTINUOUS] = "off"
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = Path(self.tmp.name) / "Targets" / "acme"
        (self.proj / "findings").mkdir(parents=True)

    def tearDown(self):
        if self._prev is None:
            os.environ.pop(self.sg.ENV_CONTINUOUS, None)
        else:
            os.environ[self.sg.ENV_CONTINUOUS] = self._prev
        self.tmp.cleanup()

    def _finding(self, name, text, artifact_verdict=None):
        f = self.proj / "findings" / name
        f.write_text(text, encoding="utf-8")
        if artifact_verdict:
            f.with_name(f.stem + ".result.json").write_text(json.dumps({
                "spec_file": "x.json", "final_verdict": artifact_verdict,
                "runs": [{"verdict": artifact_verdict,
                          "result": {"ok": True, "status": 200,
                                     "final_url": "https://acme.example.com/api/v1/x"}}]}))
        return f

    def test_cvss_version_is_not_read_as_the_score(self):
        self.assertEqual(self.sg.severity_of("CVSS 3.1 `AV:N/AC:L` = **8.2**"), "high")
        self.assertEqual(self.sg.severity_of("CVSS 3.1: `AV:N` = **5.3**"), "medium")

    def test_russian_and_letter_bands_parse(self):
        self.assertEqual(self.sg.severity_of("Критичность: В"), "high")
        self.assertEqual(self.sg.severity_of("Критичность: Н"), "low")

    def test_demonstrated_medium_lets_the_hunt_stop(self):
        self._finding("f.md", "Severity: Medium\nhttps://acme.example.com/api/v1/x\n", "PASS")
        self.assertTrue(self.sg.assess(self.proj)["allow"])

    def test_claimed_but_unproven_does_not(self):
        self._finding("f.md", "Severity: High\nhttps://acme.example.com/api/v1/x\n")
        v = self.sg.assess(self.proj)
        self.assertFalse(v["allow"])
        self.assertEqual(len(v["claimed_but_unproven"]), 1)

    def test_demonstrated_low_does_not(self):
        self._finding("f.md", "Severity: Low\nhttps://acme.example.com/api/v1/x\n", "PASS")
        self.assertFalse(self.sg.assess(self.proj)["allow"])

    def test_an_old_finding_does_not_pay_for_todays_hunt(self):
        f = self._finding("f.md", "Severity: High\nhttps://acme.example.com/api/v1/x\n", "PASS")
        old = f.stat().st_mtime
        self.assertTrue(self.sg.assess(self.proj, since_ts=old - 60)["allow"])
        v = self.sg.assess(self.proj, since_ts=old + 60)
        self.assertFalse(v["allow"])
        self.assertEqual(len(v["older_findings"]), 1)

    def test_block_message_names_the_bar_and_forbids_inflation(self):
        self._finding("f.md", "Severity: Low\n", "PASS")
        msg = self.sg.block_message(self.sg.assess(self.proj))
        self.assertIn("severity >= medium", msg)
        self.assertIn("inflating a Low into a Medium", msg)
        self.assertIn("Honest exit", msg)


class CredentialScrubbing(unittest.TestCase):
    """A secret quoted inside a RESPONSE BODY used to walk past every redactor.

    SECRET_HEADER_RE only ever matched a header *name* on a command line, so when
    m.egov.kz echoed its own outbound `Authorization` header back to an anonymous
    caller, the live OpenAI key had to be masked by hand in the stored artifact.
    """

    LEAK = (r'{"error":"{\"config\":{\"headers\":{\"Authorization\":'
            r'\"Bearer sk-proj-sb_oUpTWAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH\"}}}"}')

    def test_api_key_inside_a_response_body_is_masked(self):
        out = responses.scrub_text(self.LEAK)
        self.assertNotIn("AAAABBBBCCCC", out)
        self.assertIn("redacted", out)

    def test_identifying_prefix_survives_so_the_owner_knows_which_key_to_rotate(self):
        out = responses.scrub_text(self.LEAK)
        self.assertIn("sk-proj-", out)

    def test_opaque_and_jwt_bearer_tokens_are_masked_too(self):
        for tok in ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmno",
                    "qvex-obviously-invalid-key-0123456789"):
            out = responses.scrub_text(f"Authorization: Bearer {tok}")
            self.assertNotIn(tok, out, tok)

    def test_prose_mentioning_bearer_tokens_is_left_alone(self):
        s = "no secrets here, just prose about bearer tokens"
        self.assertEqual(responses.scrub_text(s), s)

    def test_identity_masking_still_works_alongside_it(self):
        out = responses.scrub_text("iin=123456789012&contact_phone=77011234567")
        self.assertNotIn("123456789012", out)
        self.assertNotIn("77011234567", out)

    def test_owner_prefixed_identity_keys_are_masked(self):
        """`company_email` is the same PII as `email`.

        The anchored key list matched only the bare spellings, so a real person's work
        address and phone reached hunt-memory/responses/ and a findings/*.md through
        `company_email` / `company_telephone_number` on
        register-accpt.portofantwerpbruges.com (2026-10-08).
        """
        body = ('{"company_email":"someone@example.org",'
                '"company_telephone_number":"03 246 02 30",'
                '"telephone_number":"03 246 02 30","name":"LSP IRPTEST NHS"}')
        out = responses.scrub_text(body)
        self.assertNotIn("someone@example.org", out)
        self.assertNotIn("03 246 02 30", out)
        # the key itself, and non-identity fields, survive
        self.assertIn("company_email", out)
        self.assertIn("LSP IRPTEST NHS", out)

    def test_owner_prefixed_identity_keys_are_masked_in_a_query_string_too(self):
        out = responses.scrub_text("/x?company_email=someone@example.org&user_phone=32470000000")
        self.assertNotIn("someone@example.org", out)
        self.assertNotIn("32470000000", out)

    def test_oauth_token_response_body_is_masked_but_scope_survives(self):
        """An OAuth token endpoint's JSON body carries live credentials.

        The header/prefix/Bearer patterns never matched a bare JSON key, so
        {"access_token": "...", "refresh_token": "..."} went to disk intact. A live
        Atlassian refresh token (~90 day lifetime) reached hunt-memory/responses/ that
        way on 2026-10-09. The `scope` value must survive - on that finding it IS the
        evidence.
        """
        body = ('{"access_token":"eyJraWQiOiJhdXRoLmF0bGFzc2lhbi5jb20tQUNDRVNT.a.b",'
                '"token_type":"bearer","expires_in":3600,'
                '"refresh_token":"eyJraWQiOiJSRUZSRVNI.x.y",'
                '"scope":"offline_access read:servicedesk-request write:servicedesk-request"}')
        out = responses.scrub_text(body)
        self.assertNotIn("eyJraWQ", out)
        self.assertIn("access_token", out)
        self.assertIn("write:servicedesk-request", out)

    def test_client_secret_in_a_json_body_is_masked_too(self):
        out = responses.scrub_text('{"client_id":"public-id","client_secret":"s3cr3t-value-here"}')
        self.assertNotIn("s3cr3t-value-here", out)
        self.assertIn("public-id", out)
