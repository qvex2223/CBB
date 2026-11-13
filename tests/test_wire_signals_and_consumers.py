"""Regression tests for the 2026-11-02 crit/high lessons layer.

Source: docs/disclosed-reports/HIGH-CRIT-LESSONS-2026-11.md. Covers the advisory
wire signals (body on a 3xx, data in a refusal, a secret in a body), the new vector
classes, the oracle ladder on blind classes and the consumer table.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import responses  # noqa: E402
import vectors  # noqa: E402


class WireSignals(unittest.TestCase):
    def kinds(self, stats, raw):
        return [s["signal"] for s in responses.wire_signals(stats, raw)]

    def test_redirect_with_page_body_is_flagged(self):
        body = b"<html><h1>Admin dashboard</h1>" + b"x" * 2000 + b"</html>"
        self.assertIn("body-on-redirect", self.kinds({"http_code": 302}, body))

    def test_bare_redirect_stub_is_not_flagged(self):
        self.assertEqual(self.kinds({"http_code": 302}, b"<a href='/login'>Moved</a>"), [])

    def test_followed_redirect_landing_200_is_not_flagged(self):
        self.assertNotIn("body-on-redirect", self.kinds({"http_code": 200}, b"x" * 5000))

    def test_refusal_carrying_data_fields_is_flagged(self):
        raw = json.dumps({"error": "forbidden", "object": {"email": "a@b.c", "id": 7}}).encode()
        sig = responses.wire_signals({"http_code": 422}, raw)
        self.assertEqual(sig[0]["signal"], "data-in-denial")
        self.assertEqual(sig[0]["keys"], ["email"])

    def test_plain_refusal_is_quiet(self):
        raw = json.dumps({"error": "forbidden", "code": 403, "message": "no"}).encode()
        self.assertEqual(self.kinds({"http_code": 403}, raw), [])

    def test_secret_in_body_reports_only_a_prefix(self):
        key = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
        sig = responses.wire_signals({"http_code": 200}, f'{{"t":"{key}"}}'.encode())
        self.assertEqual(sig[0]["signal"], "secret-in-body")
        self.assertNotIn(key, json.dumps(sig))
        self.assertTrue(sig[0]["prefix"].startswith("ghp_"))

    def test_garbage_never_raises(self):
        self.assertEqual(responses.wire_signals({"http_code": "abc"}, None), [])
        self.assertEqual(responses.wire_signals({}, b"\x00\xff" * 10), [])

    def test_last_signals_reads_the_last_audit_row(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "audit.jsonl"
            p.write_text(json.dumps({"x": 1}) + "\n" +
                         json.dumps({"signals": [{"signal": "body-on-redirect"}]}) + "\n")
            self.assertEqual(responses.last_signals(Path(d))[0]["signal"], "body-on-redirect")
            self.assertEqual(responses.last_signals(Path(d) / "missing"), [])


class VectorLessons(unittest.TestCase):
    def test_new_classes_exist_with_skills(self):
        for c in ("sibling-interface", "secret-exposure", "filter-injection", "parser-differential"):
            self.assertIn(c, vectors.CATALOG)
            self.assertTrue((ROOT / "skills" / vectors.CATALOG[c]["skill"] / "SKILL.md").exists(), c)
            self.assertTrue(vectors.CLASS_MUTATIONS.get(c), c)

    def test_blind_classes_carry_the_oracle_ladder(self):
        for c in ("sqli", "ssti", "rce", "xxe", "deserialization"):
            self.assertTrue(any("build an oracle" in m for m in vectors.mutations_for(c)), c)

    def test_original_mutations_kept_in_order(self):
        # additive only: the first entries a ledger may already reference are unchanged
        self.assertTrue(vectors.mutations_for("idor")[0].startswith("increment/decrement"))
        self.assertTrue(vectors.mutations_for("ssrf")[0].startswith("127.0.0.1"))

    def test_consumers_table(self):
        self.assertTrue(any("OAuth" in c for c in vectors.consumers_for("open-redirect")))
        self.assertEqual(vectors.consumers_for("no-such-class"), [])

    def test_blind_vector_cannot_die_before_the_oracle(self):
        with tempfile.TemporaryDirectory() as d:
            md = Path(d)
            vectors.save(vectors.seed("t", ["/q"], ["sqli"], memdir=md), memdir=md)
            vid = vectors.vector_id("sqli", "/q")
            for m in vectors.mutations_for("sqli"):
                if "oracle" in m or "timing pair" in m:
                    continue
                vectors.mark("t", vid, "active", mutation=m, requests=1, memdir=md)
            with self.assertRaises(SystemExit) as cm:
                vectors.mark("t", vid, "dead", memdir=md)
            self.assertIn("oracle", str(cm.exception))

    def test_manifest_function_authorization_seeds_sibling_interface(self):
        self.assertIn("sibling-interface", vectors.HINT_CLASSES["function-authorization"])


if __name__ == "__main__":
    unittest.main()
