"""sweep: placeholders, write gating, verdict rules. No network: fire_fn is injected."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import sweep  # noqa: E402


class Broker:
    def __init__(self, writes=False):
        self.allow_writes = writes


def op(method="GET", path="/api/v1/items", secured=True, **kw):
    d = {"id": "o1", "method": method, "host": "t.example", "path": path,
         "url": f"https://t.example{path}", "secured": secured, "risk_hints": [], "fields": [], "parameters": []}
    d.update(kw)
    return d


def resp(status, body=""):
    return {"status": status, "headers": {}, "body": body, "bytes": len(body), "ms": 1}


class Sweep(unittest.TestCase):
    def test_resolve_needs_env(self):
        spec = {"method": "GET", "url": "https://x/a", "headers": {"Authorization": "Bearer {{TOKEN}}"}, "body": None}
        got, missing = sweep.resolve(spec, env={})
        self.assertIsNone(got)
        self.assertEqual(missing, ["TOKEN"])
        got, _ = sweep.resolve(spec, env={"CBH_TOKEN": "abc"})
        self.assertEqual(got["headers"]["Authorization"], "Bearer abc")

    def test_auth_strip_hit(self):
        hit = sweep.classify("auth-strip", resp(200, '{"a":1}'), resp(200, '{"a":1}'))
        self.assertEqual(hit["kind"], "AUTH-NOT-ENFORCED")
        self.assertIsNone(sweep.classify("auth-strip", resp(200, "x"), resp(401, "no")))

    def test_error_disclosure_wins(self):
        hit = sweep.classify("garbage-input", resp(200, "ok"), resp(500, "Traceback (most recent call last)"))
        self.assertEqual(hit["kind"], "ERROR-DISCLOSURE")

    def test_old_version(self):
        self.assertEqual(sweep.classify("path-version", resp(404), resp(200, "{}"))["kind"], "OLD-VERSION-REACHABLE")

    def test_writes_skipped_without_profile_flag(self):
        calls = []
        res = sweep.run({"operations": [op("GET")]}, axes=["method-swap"], broker=Broker(False),
                        fire_fn=lambda s: calls.append(s) or resp(200))
        self.assertNotIn("POST", [c["method"] for c in calls])  # state-changing probe never sent
        self.assertEqual([c["method"] for c in calls], ["OPTIONS"])

    def test_writes_allowed_but_destructive_path_still_skipped(self):
        calls = []
        sweep.run({"operations": [op("GET", "/api/delete-account")]}, axes=["method-swap"], broker=Broker(True),
                  fire_fn=lambda s: calls.append(s) or resp(200))
        self.assertNotIn("POST", [c["method"] for c in calls])

    def test_unresolved_placeholder_never_fires(self):
        calls = []
        res = sweep.run({"operations": [op()]}, axes=["principal-swap"], broker=Broker(),
                        fire_fn=lambda s: calls.append(s) or resp(200))
        self.assertEqual(calls, [])  # literal {{TOKEN_A}} must never reach the wire
        self.assertTrue(res["needs_input"])

    def test_anomaly_reported_for_unauth_axis(self):
        def fake(spec):
            return resp(404) if "/v2/" in spec["url"] else resp(200, "{}")
        res = sweep.run({"operations": [op("GET", "/api/v2/items")]}, axes=["path-version"],
                        broker=Broker(), fire_fn=fake)
        kinds = [a["kind"] for a in res["anomalies"]]
        self.assertIn("OLD-VERSION-REACHABLE", kinds, res)


if __name__ == "__main__":
    unittest.main()


class NoCredentials(unittest.TestCase):
    def test_unauth_data_with_control(self):
        def fake(spec):
            if "cbh-nx-" in spec["url"]:
                return resp(404, "not found")
            return {"status": 200, "headers": {"Content-Type": "application/json"},
                    "body": '{"users":[{"id":1,"email":"a@b.c"}]}', "bytes": 40, "ms": 1}
        res = sweep.run({"operations": [op("GET", "/api/users")]}, axes=["auth-strip"], broker=Broker(), fire_fn=fake)
        self.assertEqual([a["kind"] for a in res["anomalies"]], ["UNAUTH-DATA"])

    def test_catch_all_shell_is_not_a_finding(self):
        shell = {"status": 200, "headers": {"Content-Type": "application/json"},
                 "body": '{"ok":true,"padding":"xxxxxxxxxxxxxxxx"}', "bytes": 40, "ms": 1}
        res = sweep.run({"operations": [op("GET", "/api/users")]}, axes=["auth-strip"], broker=Broker(),
                        fire_fn=lambda s: dict(shell))
        self.assertEqual(res["anomalies"], [])

    def test_options_substitutes_for_blocked_write_probe(self):
        sent = []

        def fake(spec):
            sent.append(spec["method"])
            return {"status": 200, "headers": {"Allow": "GET, PUT, DELETE"}, "body": "", "bytes": 0, "ms": 1}
        res = sweep.run({"operations": [op("GET", "/api/items")]}, axes=["method-swap"], broker=Broker(False), fire_fn=fake)
        self.assertEqual(sent, ["OPTIONS"])
        self.assertEqual(res["anomalies"][0]["kind"], "METHODS-ADVERTISED")


class FromAudit(unittest.TestCase):
    def test_method_comes_from_traffic_and_filters_apply(self):
        import os
        import tempfile
        import json
        d = tempfile.mkdtemp()
        os.environ["CBH_MEMORY_DIR"] = d
        rows = [
            {"engagement": "e", "urls": ["https://t.example/api/v1/feedback"], "method": "POST", "http_code": 200,
             "body_sha256": "a", "req": ["-d", '{"name":"x","email":"y"}']},
            {"engagement": "e", "urls": ["https://t.example/api/v1/feedback"], "method": "POST", "http_code": 200, "body_sha256": "b"},
            {"engagement": "e", "urls": ["https://t.example/api/v1/camunda/x"], "method": "GET", "http_code": 200, "body_sha256": "c"},
            {"engagement": "e", "urls": ["https://t.example/static/app.js"], "method": "GET", "http_code": 200, "body_sha256": "d"},
            {"engagement": "e", "urls": ["https://t.example/api/v1/items?id=3"], "method": "GET", "http_code": 200, "body_sha256": "e"},
        ]
        Path(d, "audit.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
        m = sweep.manifest_from_audit("e")
        self.assertEqual([(o["method"], o["path"]) for o in m["operations"]], [("POST", "/api/v1/feedback")])
        self.assertEqual(m["operations"][0]["fields"], ["email", "name"])


class Credentials(unittest.TestCase):
    def test_env_file_loaded_and_loose_perms_refused(self):
        import os
        import tempfile
        d = Path(tempfile.mkdtemp())
        f = d / ".sweep-env"
        f.write_text("TOKEN_A=abc\n# c\nCBH_TOKEN_B='def'\n")
        os.chmod(f, 0o644)
        with self.assertRaises(SystemExit):
            sweep.load_env_file(f)
        os.chmod(f, 0o600)
        for k in ("CBH_TOKEN_A", "CBH_TOKEN_B"):
            os.environ.pop(k, None)
        self.assertEqual(sweep.load_env_file(f), ["CBH_TOKEN_A", "CBH_TOKEN_B"])
        self.assertEqual(os.environ["CBH_TOKEN_B"], "def")

    def test_tls_verified_by_default(self):
        self.assertIs(sweep._opener(False), sweep._OPENER)
        self.assertIsNot(sweep._opener(True), sweep._OPENER)
