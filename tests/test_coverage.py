#!/usr/bin/env python3
"""Coverage is which dimension moved, not how many requests were sent.

The workspace already lost a session to an all-200 path sweep that was an nginx
SPA fallback. A request is not a test; these tests pin the distinction so a
scoreboard cannot quietly replace it.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import coverage as CV  # noqa: E402


def _row(url, method="GET", headers=None, body=None, status=200, sha=None,
         engagement="acme"):
    return {"url": url, "method": method, "headers": headers or {},
            "body": body, "status": status, "body_sha256": sha,
            "engagement": engagement}


class CoverageFromAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mem = Path(self.tmp.name) / "hunt-memory"
        self.mem.mkdir()
        self._env = dict(os.environ)
        self.addCleanup(self._restore)
        os.environ["CBH_MEMORY_DIR"] = str(self.mem)

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._env)

    def _write(self, rows):
        with open(self.mem / "audit.jsonl", "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    def test_one_request_is_observed_not_tested(self):
        self._write([_row("https://api.example.com/v1/users/1", sha="a" * 64)])
        result = CV.summarize("acme")
        self.assertEqual(result["counts"]["paths"], 1)
        self.assertEqual(result["rows"][0]["verdict"],
                         "OBSERVED — one request is not a test")

    def test_second_input_is_the_dimension_that_counts(self):
        self._write([
            _row("https://api.example.com/v1/users/1", sha="a" * 64),
            _row("https://api.example.com/v1/users/1?q=x", sha="b" * 64),
        ])
        result = CV.summarize("acme")
        row = result["rows"][0]
        self.assertIn("second-input", row["dimensions_varied"])
        self.assertNotIn("second-input", result["gaps"]["never-second-input"])

    def test_same_path_different_ids_collapse(self):
        self._write([
            _row("https://api.example.com/v1/users/1", sha="a" * 64),
            _row("https://api.example.com/v1/users/2", sha="b" * 64),
        ])
        result = CV.summarize("acme")
        self.assertEqual(result["counts"]["paths"], 1)

    def test_stub_shaped_when_many_requests_one_body(self):
        self._write([_row(f"https://api.example.com/v1/users/{i}?q={i}",
                          sha="a" * 64) for i in range(8)])
        result = CV.summarize("acme")
        self.assertIn("STUB-SHAPED", result["rows"][0]["verdict"])

    def test_principal_contrast_needs_both_directions(self):
        self._write([
            _row("https://api.example.com/v1/orders", sha="a" * 64,
                 headers={"Authorization": "Bearer t"}),
            _row("https://api.example.com/v1/orders", sha="b" * 64, headers={}),
        ])
        result = CV.summarize("acme")
        self.assertIn("principal-contrast", result["rows"][0]["dimensions_varied"])

    def test_identity_and_override_headers_recognised(self):
        self._write([
            _row("https://api.example.com/v1/me", sha="a" * 64,
                 headers={"X-MSISDN": "7770001234", "X-Original-URL": "/admin"}),
            _row("https://api.example.com/v1/me", sha="b" * 64,
                 headers={"X-MSISDN": "7770009999"}),
        ])
        dims = CV.summarize("acme")["rows"][0]["dimensions_varied"]
        self.assertIn("identity-header", dims)
        self.assertIn("override-header", dims)

    def test_garbage_input_detected(self):
        self._write([
            _row("https://api.example.com/v1/users?id=abc", sha="a" * 64),
            _row("https://api.example.com/v1/users?id=%27+OR+1%3D1--", sha="b" * 64),
            _row("https://api.example.com/v1/users?id=null", sha="c" * 64),
        ])
        dims = CV.summarize("acme")["rows"][0]["dimensions_varied"]
        self.assertIn("garbage-input", dims)

    def test_method_swap_is_a_dimension(self):
        self._write([
            _row("https://api.example.com/v1/orders", method="POST", body="{}", sha="a" * 64),
            _row("https://api.example.com/v1/orders", method="GET", sha="b" * 64),
        ])
        dims = CV.summarize("acme")["rows"][0]["dimensions_varied"]
        self.assertIn("method", dims)

    def test_gaps_list_is_honest(self):
        # Same input every time: three requests, one input shape — never tested.
        self._write([_row(f"https://api.example.com/v1/users/{i}?q=same",
                          sha="a" * 64) for i in range(3)])
        gaps = CV.summarize("acme")["gaps"]
        self.assertIn("/v1/users/{id}", gaps["never-second-input"])
        self.assertIn("/v1/users/{id}", gaps["never-auth-contrasted"])

    def test_engagement_filter(self):
        self._write([
            _row("https://api.example.com/a", sha="a" * 64, engagement="acme"),
            _row("https://api.example.com/b", sha="b" * 64, engagement="other"),
        ])
        self.assertEqual(CV.summarize("acme")["counts"]["paths"], 1)
        self.assertEqual(CV.summarize("other")["counts"]["paths"], 1)
        self.assertEqual(CV.summarize("")["counts"]["paths"], 2)

    def test_markdown_says_the_rule(self):
        self._write([_row("https://api.example.com/a", sha="a" * 64)])
        text = CV.to_markdown(CV.summarize("acme"))
        self.assertIn("A request is not a test", text)

    def test_empty_audit_is_not_a_crash(self):
        result = CV.summarize("acme")
        self.assertEqual(result["counts"]["paths"], 0)


if __name__ == "__main__":
    unittest.main()
