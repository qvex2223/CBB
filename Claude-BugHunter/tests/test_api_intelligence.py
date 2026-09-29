#!/usr/bin/env python3
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import api_manifest
import authorization_matrix
import poc_minimize
import recon_delta
import report_intel
import workflow_graph
from pacing import Engagement
from request_broker import RequestBlocked, RequestBroker
from scope import Scope


OPENAPI = {
    "openapi": "3.0.0", "servers": [{"url": "https://api.example.com"}],
    "security": [{"bearer": []}],
    "paths": {
        "/v1/orders/{orderId}": {
            "patch": {"operationId": "updateOrder", "parameters": [
                {"name": "orderId", "in": "path", "schema": {"type": "string"}}],
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object", "properties": {"status": {"type": "string"},
                                                       "owner_id": {"type": "string"},
                                                       "price": {"type": "number"}}}}}}}
        },
        "/v1/public": {"get": {"security": [], "responses": {"200": {}}}},
    },
}


class ApiManifestTests(unittest.TestCase):
    def test_openapi_extracts_sensitive_fields_and_risks(self):
        ops = api_manifest.from_openapi(OPENAPI)
        order = next(o for o in ops if o["operation_name"] == "updateOrder")
        self.assertEqual(order["method"], "PATCH")
        self.assertTrue({"owner_id", "price", "status"}.issubset(order["fields"]))
        self.assertTrue({"object-authorization", "property-authorization", "business-flow"}
                        .issubset(order["risk_hints"]))

    def test_har_and_openapi_merge_same_operation(self):
        har = {"log": {"entries": [{"request": {"method": "PATCH",
                "url": "https://api.example.com/v1/orders/123", "queryString": [],
                "postData": {"text": '{"status":"paid"}'}}, "response": {"status": 200}}]}}
        merged = api_manifest.merge_operations([api_manifest.from_openapi(OPENAPI),
                                                 api_manifest.from_har(har)])
        order = next(o for o in merged if o["method"] == "PATCH")
        self.assertEqual(order["sources"], ["har", "openapi"])


class AuthorizationTests(unittest.TestCase):
    def test_plan_rejects_inline_credentials(self):
        with self.assertRaises(ValueError):
            authorization_matrix.plan({"operations": []}, {"principals": [{"name": "a", "token": "secret"}]})

    def test_cross_user_write_requires_state_verification(self):
        result = authorization_matrix.evaluate([{"actor": "b", "object_owner": "a",
            "expected": "deny", "method": "PATCH", "status": 200, "state_changed": False}])
        self.assertEqual(result["results"][0]["verdict"], "INCONCLUSIVE")
        result = authorization_matrix.evaluate([{"actor": "b", "object_owner": "a",
            "expected": "deny", "method": "PATCH", "status": 200, "state_changed": True}])
        self.assertEqual(result["results"][0]["verdict"], "VIOLATION")

    def test_plan_creates_cross_principal_rows(self):
        manifest = {"operations": api_manifest.from_openapi(OPENAPI)}
        principals = {"principals": [{"name": "a", "token_env": "TOKEN_A"},
                                      {"name": "b", "token_env": "TOKEN_B"}]}
        result = authorization_matrix.plan(manifest, principals)
        self.assertTrue(any(t["actor"] == "b" and t["object_owner"] == "a" for t in result["tests"]))


class OfflineIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {"operations": api_manifest.from_openapi(OPENAPI)}

    def test_workflow_prioritizes_cross_principal_and_hidden_fields(self):
        graph = workflow_graph.build(self.manifest)
        kinds = {h["kind"] for h in graph["hypotheses"]}
        self.assertIn("cross-principal", kinds)
        self.assertIn("hidden-field", kinds)

    def test_recon_delta_reports_new_sensitive_operation(self):
        delta = recon_delta.compare({"operations": []}, self.manifest)
        self.assertEqual(delta["counts"]["operations_added"], 2)
        self.assertGreaterEqual(delta["operations_added"][0]["risk_score"], 80)

    def test_report_search_is_bounded_and_relevant(self):
        rows = [{"id": 1, "title": "IDOR in order API", "severity": "high", "bounty": 1000},
                {"id": 2, "title": "XSS in profile", "severity": "medium"}]
        got = report_intel.search(rows, "order idor authorization", limit=5)
        self.assertEqual([x["id"] for x in got], [1])

    def test_poc_minimizer_keeps_capture_dependency_and_final_verify(self):
        spec = {"steps": [
            {"name": "login", "url": "https://x/login", "capture": {"csrf": {}}},
            {"name": "noise", "url": "https://x/help"},
            {"name": "verify", "url": "https://x/object?csrf={{csrf}}"}]}
        self.assertEqual([s["name"] for s in poc_minimize.required_steps(spec)], ["login", "verify"])


class BrokerTests(unittest.TestCase):
    def test_scope_and_headers_share_one_policy(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td) / "Targets" / "acme"; project.mkdir(parents=True)
            eng = Engagement(project, profile={"min_interval_seconds": 0,
                                               "required_headers": {"X-Bug-Bounty": "h"}},
                             state_dir=Path(td) / "state")
            broker = RequestBroker(eng, Scope(["example.com"]), allow_ungated=False)
            self.assertEqual(broker.prepare_headers({})["X-Bug-Bounty"], "h")
            broker.validate(["https://example.com/x"])
            with self.assertRaises(RequestBlocked):
                broker.validate(["https://evil.example/x"])


if __name__ == "__main__":
    unittest.main()
