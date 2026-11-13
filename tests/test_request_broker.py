#!/usr/bin/env python3
"""Integration tests for the shared outbound-request policy.

Both enforcement bugs this workspace shipped were found on a live target instead
of on a bench, so every transport that can put a packet on the wire gets its
contract checked here: scope deny, default deny with no scope, mandatory headers,
the global pacing budget, the audit row, and the stored response body.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

from pacing import Engagement, MissingRequiredHeader  # noqa: E402
from request_broker import RequestBlocked, RequestBroker, is_local_url  # noqa: E402
from scope import Scope  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b'{"ok":true,"path":"' + self.path.encode() + b'"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Echo-Bounty", self.headers.get("X-Bug-Bounty", ""))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


class BrokerFixture(unittest.TestCase):
    """One temp engagement + one temp memory dir per test."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.memdir = self.root / "hunt-memory"
        self.memdir.mkdir()
        self.project = self.root / "Targets" / "acme"
        self.project.mkdir(parents=True)
        self._env = dict(os.environ)
        os.environ["CBH_MEMORY_DIR"] = str(self.memdir)
        self.addCleanup(self._restore)

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._env)
        self.tmp.cleanup()

    def broker(self, *, profile=None, scope=None, **kw):
        eng = Engagement(self.project, profile=profile if profile is not None else {},
                         state_dir=self.memdir / "pacing")
        return RequestBroker(engagement=eng, scope=scope, source="test", **kw)

    def audit_rows(self):
        path = self.memdir / "audit.jsonl"
        if not path.exists():
            return []
        return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


class TestScopeGate(BrokerFixture):
    def test_out_of_scope_host_is_refused(self):
        b = self.broker(scope=Scope(in_scope=["*.acme.com"], out_of_scope=[]))
        with self.assertRaises(RequestBlocked) as cm:
            b.validate(["https://evil.example.com/x"])
        self.assertIn("OUT-OF-SCOPE", str(cm.exception))

    def test_deny_wins_over_allow(self):
        b = self.broker(scope=Scope(in_scope=["*.acme.com"], out_of_scope=["secret.acme.com"]))
        b.validate(["https://api.acme.com/x"])          # allowed
        with self.assertRaises(RequestBlocked):
            b.validate(["https://secret.acme.com/x"])

    def test_no_scope_source_defaults_to_deny_for_remote(self):
        b = self.broker(scope=None)
        with self.assertRaises(RequestBlocked) as cm:
            b.validate(["https://api.acme.com/x"])
        self.assertIn("no authoritative scope", str(cm.exception))

    def test_local_urls_are_never_gated(self):
        b = self.broker(scope=None)
        self.assertEqual(b.validate(["http://127.0.0.1:8000/x"]), [])
        self.assertTrue(is_local_url("http://localhost:1/"))
        self.assertFalse(is_local_url("https://acme.com/"))

    def test_ungated_opt_out_is_explicit(self):
        b = self.broker(scope=None, allow_ungated=True)
        self.assertEqual(b.validate(["https://api.acme.com/x"]), [])

    def test_one_bad_url_blocks_the_whole_batch(self):
        b = self.broker(scope=Scope(in_scope=["*.acme.com"], out_of_scope=[]))
        with self.assertRaises(RequestBlocked):
            b.validate(["https://api.acme.com/a", "https://elsewhere.net/b"])


class TestRequiredHeaders(BrokerFixture):
    def test_mandatory_header_is_injected(self):
        b = self.broker(profile={"required_headers": {"X-Bug-Bounty": "qvex"}})
        self.assertEqual(b.prepare_headers({"Accept": "*/*"})["X-Bug-Bounty"], "qvex")

    def test_explicit_value_wins(self):
        b = self.broker(profile={"required_headers": {"X-Bug-Bounty": "qvex"}})
        self.assertEqual(b.prepare_headers({"X-Bug-Bounty": "other"})["X-Bug-Bounty"], "other")

    def test_unset_required_header_refuses_to_fire(self):
        b = self.broker(profile={"required_headers": {"X-Bug-Bounty": "TODO"}})
        with self.assertRaises(MissingRequiredHeader):
            b.prepare_headers({})


class TestPacing(BrokerFixture):
    def test_budget_is_global_across_broker_instances(self):
        profile = {"min_interval_seconds": 0.4}
        self.broker(profile=profile).wait_turn()
        started = time.time()
        waited = self.broker(profile=profile).wait_turn()
        elapsed = time.time() - started
        self.assertGreater(waited, 0.0, "second request did not queue behind the first")
        self.assertGreaterEqual(round(elapsed, 2), 0.2)

    def test_before_request_validates_then_paces(self):
        b = self.broker(profile={"min_interval_seconds": 0.0,
                                 "required_headers": {"X-Bug-Bounty": "qvex"}},
                        scope=Scope(in_scope=["*.acme.com"], out_of_scope=[]))
        headers, waited = b.before_request("https://api.acme.com/x", {"Accept": "*/*"})
        self.assertEqual(headers["X-Bug-Bounty"], "qvex")
        self.assertGreaterEqual(waited, 0.0)

    def test_before_request_refuses_before_pacing_an_out_of_scope_url(self):
        b = self.broker(profile={"min_interval_seconds": 30},
                        scope=Scope(in_scope=["*.acme.com"], out_of_scope=[]))
        started = time.time()
        with self.assertRaises(RequestBlocked):
            b.before_request("https://evil.example.com/x")
        self.assertLess(time.time() - started, 5, "paced before checking scope")


class TestAuditAndResponseCorpus(BrokerFixture):
    def test_audit_row_carries_engagement_and_source(self):
        b = self.broker()
        b.audit({"urls": ["https://api.acme.com/x"], "http_code": 200})
        row = self.audit_rows()[-1]
        self.assertEqual(row["source"], "test")
        self.assertEqual(row["engagement"], "acme")
        self.assertIn("timestamp", row)

    def test_response_is_hashed_stored_and_audited(self):
        b = self.broker()
        entry = b.record_response("https://api.acme.com/x", "get", 200, b'{"a":1}',
                                  {"Content-Type": "application/json"}, 12.5)
        self.assertEqual(entry["method"], "GET")
        self.assertEqual(entry["http_code"], 200)
        self.assertEqual(len(entry["body_sha256"]), 64)
        stored = self.memdir / "responses" / "acme" / f"{entry['body_sha256']}.txt"
        self.assertTrue(stored.exists(), "response body was not stored")
        self.assertIn('{"a":1}', stored.read_text())
        self.assertEqual(self.audit_rows()[-1]["body_sha256"], entry["body_sha256"])

    def test_identical_bodies_deduplicate_to_one_file(self):
        b = self.broker()
        a = b.record_response("https://api.acme.com/1", "GET", 200, b"same", {})
        c = b.record_response("https://api.acme.com/2", "GET", 200, b"same", {})
        self.assertEqual(a["body_sha256"], c["body_sha256"])
        self.assertEqual(len(list((self.memdir / "responses" / "acme").glob("*.txt"))), 1)
        self.assertEqual(len(self.audit_rows()), 2, "both requests must still be audited")

    def test_an_error_response_is_recorded_not_dropped(self):
        b = self.broker()
        entry = b.record_response("https://api.acme.com/x", "POST", 500, b"boom", {})
        self.assertEqual(entry["http_code"], 500)
        self.assertEqual(self.audit_rows()[-1]["http_code"], 500)

    def test_response_store_can_be_disabled(self):
        os.environ["CBH_NO_RESPONSE_STORE"] = "1"
        try:
            b = self.broker()
            entry = b.record_response("https://api.acme.com/x", "GET", 200, b"secret", {})
            self.assertNotIn("body_sha256", entry)
            self.assertFalse((self.memdir / "responses").exists())
            self.assertEqual(len(self.audit_rows()), 1, "audit must survive opt-out")
        finally:
            os.environ.pop("CBH_NO_RESPONSE_STORE", None)


class TestTransports(BrokerFixture):
    """The gate is only real if the programs that ship packets honour it."""

    def _write_scope(self, body):
        (self.project / "scope.md").write_text(body)

    def _write_profile(self, profile):
        (self.project / "profile.json").write_text(json.dumps(profile))

    def _run(self, argv, **kw):
        env = dict(os.environ, CBH_MEMORY_DIR=str(self.memdir), CBH_PROJECT="acme")
        env["PYTHONPATH"] = str(ROOT / "engine")
        return subprocess.run(argv, capture_output=True, text=True, timeout=90,
                              cwd=str(self.project), env=env, **kw)

    def test_bbcurl_refuses_an_out_of_scope_url(self):
        self._write_scope("# Scope\n\n## In scope\n- `*.acme.com`\n")
        self._write_profile({"min_interval_seconds": 0})
        r = self._run([str(ROOT / "scripts" / "bbcurl"), "--bb-dry-run",
                       "https://evil.example.com/x"])
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("OUT-OF-SCOPE", r.stdout + r.stderr)

    def test_bbcurl_injects_the_mandatory_header(self):
        self._write_scope("# Scope\n\n## In scope\n- `*.acme.com`\n")
        self._write_profile({"min_interval_seconds": 0,
                             "required_headers": {"X-Bug-Bounty": "qvex"}})
        r = self._run([str(ROOT / "scripts" / "bbcurl"), "--bb-dry-run",
                       "https://api.acme.com/x"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("X-Bug-Bounty: qvex", r.stdout + r.stderr)

    def test_poc_runtime_gates_scope_and_stores_the_response(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        spec = {"name": "broker-contract", "method": "GET",
                "url": f"http://127.0.0.1:{port}/ping", "expect": {"status": 200}}
        spec_path = self.project / "t.poc.json"
        spec_path.write_text(json.dumps(spec))
        r = self._run([sys.executable, "-B", str(ROOT / "engine" / "poc_runtime.py"),
                       str(spec_path), "--no-scope-check"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        result = json.loads((self.project / "t.poc.result.json").read_text())
        self.assertEqual(result["final_verdict"], "PASS")
        rows = self.audit_rows()
        self.assertTrue(rows, "poc_runtime fired without writing an audit row")
        self.assertEqual(rows[-1]["source"], "poc_runtime")

    def test_poc_runtime_refuses_a_remote_url_with_no_scope_source(self):
        spec = {"name": "ungated", "method": "GET", "url": "https://api.acme.com/x",
                "expect": {"status": 200}}
        spec_path = self.project / "u.poc.json"
        spec_path.write_text(json.dumps(spec))
        r = self._run([sys.executable, "-B", str(ROOT / "engine" / "poc_runtime.py"),
                       str(spec_path)])
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_recon_get_returns_the_block_reason_instead_of_fetching(self):
        sys.path.insert(0, str(ROOT / "engine"))
        import recon  # noqa: PLC0415
        b = self.broker(scope=Scope(in_scope=["*.acme.com"], out_of_scope=[]))
        body, final, headers = recon._get("https://evil.example.com/x", broker=b)
        self.assertEqual(body, "")
        self.assertIn("OUT-OF-SCOPE", headers.get("x-cbh-blocked", ""))
        self.assertEqual(self.audit_rows(), [], "a blocked request must not be audited as sent")


if __name__ == "__main__":
    unittest.main()
