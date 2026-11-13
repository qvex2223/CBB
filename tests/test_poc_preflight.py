#!/usr/bin/env python3
"""PoC specs must resolve their credential references and refuse to fire unready.

The generator (authorization_matrix) writes `Bearer {{env:ACTOR_TOKEN}}` headers,
but poc_runtime's substitution used to understand only `{{name}}` — so the
recommended `export` left the string in place and the "authenticated" request went
out anonymous. Preflight now refuses an unready spec before anything leaves, and
substitute() resolves env references at fire time, in this process, never to disk.
"""
import json
import os
import sys
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import authorization_matrix as AZ  # noqa: E402
import poc_runtime as P  # noqa: E402


class EnvSubstitution(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)
        self.addCleanup(self._restore)

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_env_reference_resolves_at_fire_time(self):
        os.environ["CBH_TEST_TOKEN"] = "tok-123"
        self.assertEqual(P.substitute("Bearer {{env:CBH_TEST_TOKEN}}", {}), "Bearer tok-123")

    def test_env_reference_is_never_blanked(self):
        os.environ.pop("CBH_TEST_TOKEN", None)
        out = P.substitute("Bearer {{env:CBH_TEST_TOKEN}}", {})
        self.assertEqual(out, "Bearer {{env:CBH_TEST_TOKEN}}",
                         "an unset env reference became an empty credential")

    def test_regular_vars_still_work_alongside_env(self):
        os.environ["CBH_TEST_TOKEN"] = "t"
        doc = {"headers": {"Authorization": "{{env:CBH_TEST_TOKEN}}"},
               "url": "http://x/orders/{{oid}}"}
        out = P.substitute(doc, {"oid": "42"})
        self.assertEqual(out["headers"]["Authorization"], "t")
        self.assertEqual(out["url"], "http://x/orders/42")


class Preflight(unittest.TestCase):
    def _clean(self):
        os.environ.pop("CBH_TEST_TOKEN", None)

    def setUp(self):
        self._env = dict(os.environ)
        self._clean()
        self.addCleanup(self._restore)

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_unset_env_var_blocks_the_spec(self):
        spec = {"url": "http://x/o/1", "headers": {"Authorization": "{{env:CBH_TEST_TOKEN}}"}}
        errors = P.preflight(spec)
        self.assertTrue(any("CBH_TEST_TOKEN" in e for e in errors), errors)

    def test_set_env_var_unblocks_the_spec(self):
        os.environ["CBH_TEST_TOKEN"] = "t"
        spec = {"url": "http://x/o/1", "headers": {"Authorization": "{{env:CBH_TEST_TOKEN}}"}}
        self.assertEqual(P.preflight(spec), [])

    def test_unfilled_object_id_blocks_the_spec(self):
        spec = {"url": "http://x/o/{{OBJECT_ID}}"}
        self.assertTrue(any("OBJECT_ID" in e for e in P.preflight(spec)))

    def test_capture_from_an_earlier_step_is_not_a_blocker(self):
        spec = {"steps": [
            {"name": "login", "url": "http://x/login",
             "capture": {"csrf": {"from": "body", "regex": "\"csrf\":\"([^\"]+)\""}}},
            {"name": "act", "url": "http://x/act?csrf={{csrf}}"},
        ]}
        self.assertEqual(P.preflight(spec), [])

    def test_a_placeholder_no_step_produces_still_blocks(self):
        spec = {"steps": [
            {"name": "first", "url": "http://x/a"},
            {"name": "second", "url": "http://x/b/{{nope}}", "capture": {}},
        ]}
        errors = P.preflight(spec)
        self.assertTrue(any("nope" in e for e in errors), errors)


class _AuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = json.dumps({
            "auth": self.headers.get("Authorization", ""),
            "path": self.path,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class GeneratedSpecFires(unittest.TestCase):
    """The full loop: matrix plan -> spec skeleton -> operator fills -> fires."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "hunt-memory").mkdir()
        self._env = dict(os.environ)
        os.environ["CBH_MEMORY_DIR"] = str(self.root / "hunt-memory")
        os.environ["CBH_TEST_ALICE"] = "alice-token-zzz"
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _AuthHandler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._restore)

    def _restore(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        os.environ.clear()
        os.environ.update(self._env)
        self.tmp.cleanup()

    def _generated_spec(self):
        principals = {"principals": [
            {"name": "alice", "token_env": "CBH_TEST_ALICE"},
            {"name": "bob", "token_env": "CBH_TEST_BOB"},
        ]}
        port = self.server.server_address[1]
        manifest = {"operations": [
            {"id": "op", "method": "GET", "url": f"http://127.0.0.1:{port}/orders/{{id}}",
             "risk_hints": ["object-authorization"]}]}
        plan = AZ.plan(manifest, principals)
        test = next(t for t in plan["tests"]
                    if t["actor"] == "alice" and t["object_owner"] == "bob")
        return AZ.to_poc_spec(test)

    def run_main(self, spec: dict) -> int:
        spec_path = self.root / "case.poc.json"
        spec_path.write_text(json.dumps(spec))
        return P.main([str(spec_path), "--no-pacing", "--no-scope-check"])

    def test_a_fresh_skeleton_refuses_to_fire(self):
        import contextlib, io
        spec = self._generated_spec()
        os.environ.pop("CBH_TEST_BOB", None)
        with contextlib.redirect_stdout(io.StringIO()):
            # preflight must refuse BEFORE any request: the OBJECT_ID placeholder
            # is unresolved. No evidence file may appear on disk.
            code = self.run_main(spec)
        self.assertEqual(code, 2)
        self.assertFalse((self.root / "case.poc.result.json").exists(),
                         "a blocked spec still left evidence on disk")

    def test_the_prepared_spec_fires_with_the_real_credential(self):
        import contextlib, io
        spec = self._generated_spec()
        spec["url"] = spec["url"].replace("{{OBJECT_ID}}", "7")
        with contextlib.redirect_stdout(io.StringIO()):
            code = self.run_main(spec)
        self.assertNotEqual(code, 2, "a prepared spec was still blocked")
        result = json.loads((self.root / "case.poc.result.json").read_text())
        # The header the server actually saw must be the resolved env value —
        # proof the token never went through the spec file.
        body = json.loads(result["runs"][-1]["result"]["body"])
        self.assertEqual(body["auth"], "Bearer alice-token-zzz")
        raw = (self.root / "case.poc.result.json").read_text()
        self.assertNotIn("alice-token-zzz", raw.split('"body"')[0],
                         "the credential leaked into the request side of the evidence file")


if __name__ == "__main__":
    unittest.main()
