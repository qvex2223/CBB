#!/usr/bin/env python3
"""API-manifest import depth.

Each of these parsers looked like it worked and returned almost nothing useful:
OpenAPI bodies are `$ref` far more often than inline, Burp exports recorded only
method/URL/status, GraphQL recorded a field name and no arguments' contents, and
Postman collections collapsed to one host called placeholder.invalid. No fields means
no `property-authorization` risk hint, which means the mass-assignment and
excessive-data-exposure candidates — the best thing a spec can hand you — were invisible.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import api_manifest as AM  # noqa: E402


class OpenApiRefs(unittest.TestCase):
    DOC = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.acme.com"}],
        "paths": {
            "/v1/orders": {
                "post": {
                    "operationId": "createOrder",
                    "requestBody": {"content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/Order"}}}},
                    "responses": {"200": {"content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/OrderView"}}}}},
                },
            },
        },
        "components": {"schemas": {
            "Order": {"type": "object", "properties": {
                "amount": {"type": "number"},
                "customer": {"$ref": "#/components/schemas/Customer"}}},
            "Customer": {"type": "object", "properties": {
                "ownerId": {"type": "string"}, "email": {"type": "string"}}},
            "OrderView": {"type": "object", "properties": {
                "internalNotes": {"type": "string"}}},
        }},
    }

    def setUp(self):
        self.ops = AM.from_openapi(self.DOC)
        self.op = self.ops[0]

    def test_a_referenced_request_schema_yields_its_fields(self):
        self.assertIn("amount", self.op["fields"])

    def test_nested_refs_are_followed(self):
        self.assertIn("ownerId", self.op["fields"],
                      "a $ref inside a $ref was not resolved")

    def test_response_schemas_count_too(self):
        self.assertIn("internalNotes", self.op["fields"],
                      "a field the server returns but the client never sends is "
                      "exactly where excessive data exposure lives")

    def test_sensitive_fields_produce_the_risk_hint(self):
        self.assertIn("property-authorization", self.op["risk_hints"])

    def test_a_recursive_schema_does_not_hang(self):
        doc = {"openapi": "3.0.0", "paths": {"/x": {"get": {
                   "requestBody": {"content": {"application/json": {
                       "schema": {"$ref": "#/components/schemas/Node"}}}}}}},
               "components": {"schemas": {"Node": {"properties": {
                   "child": {"$ref": "#/components/schemas/Node"}, "name": {}}}}}}
        self.assertIn("child", AM.from_openapi(doc)[0]["fields"])

    def test_a_remote_ref_is_not_followed(self):
        """Offline means offline: an OpenAPI doc on a target is untrusted input."""
        self.assertEqual(AM._resolve_ref("https://evil.example/schema.json", {}), None)
        self.assertEqual(AM._resolve_ref("./other.yaml#/X", {}), None)

    def test_a_dangling_ref_is_survivable(self):
        doc = {"openapi": "3.0.0", "paths": {"/x": {"get": {
            "requestBody": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Missing"}}}}}}}}
        self.assertEqual(AM.from_openapi(doc)[0]["fields"], [])


class BurpImport(unittest.TestCase):
    def _xml(self, request_blob, b64=False):
        import base64 as b
        from xml.sax.saxutils import escape
        payload = (b.b64encode(request_blob.encode()).decode() if b64
                   else escape(request_blob))
        xml = f"""<?xml version="1.0"?><items><item>
          <url>https://api.acme.com/v1/orders?expand=customer&amp;fields=all</url>
          <method>POST</method><status>200</status>
          <request base64="{'true' if b64 else 'false'}">{payload}</request>
          </item></items>"""
        d = tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False)
        d.write(xml); d.close()
        self.addCleanup(lambda: Path(d.name).unlink(missing_ok=True))
        return AM.from_burp_xml(Path(d.name))

    RAW = ("POST /v1/orders HTTP/1.1\r\nHost: api.acme.com\r\n"
           "Content-Type: application/json\r\nCookie: s=abc\r\n\r\n"
           '{"amount": 5, "ownerId": "u-1"}')

    def test_query_parameters_are_imported(self):
        op = self._xml(self.RAW)[0]
        self.assertEqual(op["parameters"], ["expand", "fields"])

    def test_json_body_field_names_are_imported(self):
        op = self._xml(self.RAW)[0]
        self.assertIn("amount", op["fields"])
        self.assertIn("ownerId", op["fields"])

    def test_body_values_are_never_imported(self):
        """Names are signal; values are somebody's live session and order data."""
        blob = json.dumps(self._xml(self.RAW)[0])
        self.assertNotIn("u-1", blob)
        self.assertNotIn("abc", blob, "a captured cookie reached the manifest")

    def test_form_encoded_bodies(self):
        raw = ("POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded"
               "\r\n\r\nuser=alice&pass=hunter2")
        op = self._xml(raw)[0]
        self.assertEqual(sorted(op["fields"]), ["pass", "user"])
        self.assertNotIn("hunter2", json.dumps(op))

    def test_base64_encoded_requests_are_decoded(self):
        op = self._xml(self.RAW, b64=True)[0]
        self.assertIn("ownerId", op["fields"])

    def test_credentialed_requests_are_marked_secured(self):
        self.assertTrue(self._xml(self.RAW)[0]["secured"])

    def test_a_request_with_no_body_still_imports(self):
        op = self._xml("GET /v1/orders HTTP/1.1\r\nHost: a\r\n\r\n")[0]
        self.assertEqual(op["fields"], [])


class GraphQLImport(unittest.TestCase):
    DOC = {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "fields": [
                {"name": "node", "args": [{"name": "id", "type": {"name": "ID"}}],
                 "type": {"name": "Node"}},
            ]},
            {"name": "Mutation", "fields": [
                {"name": "updateUser",
                 "args": [{"name": "input", "type": {"kind": "NON_NULL", "ofType": {
                     "name": "UpdateUserInput"}}}],
                 "type": {"name": "User"}},
            ]},
            {"name": "UpdateUserInput", "inputFields": [
                {"name": "role", "type": {"name": "String"}},
                {"name": "email", "type": {"name": "String"}}]},
            {"name": "User", "fields": [
                {"name": "id", "type": {"name": "ID"}},
                {"name": "isAdmin", "type": {"name": "Boolean"}}]},
            {"name": "Node", "fields": [{"name": "id", "type": {"name": "ID"}}]},
        ]}}

    def setUp(self):
        self.ops = {o["operation_name"]: o
                    for o in AM.from_graphql(self.DOC, "https://api.acme.com/graphql")}

    def test_input_object_members_are_walked(self):
        self.assertIn("role", self.ops["updateUser"]["fields"],
                      "the mutation's input object was recorded as one opaque argument")

    def test_return_type_fields_are_recorded(self):
        self.assertIn("isAdmin", self.ops["updateUser"]["fields"])

    def test_sensitive_input_fields_raise_the_authorization_hint(self):
        self.assertIn("property-authorization", self.ops["updateUser"]["risk_hints"])

    def test_a_mutation_is_a_state_change(self):
        self.assertIn("state-change", self.ops["updateUser"]["risk_hints"])
        self.assertNotIn("state-change", self.ops["node"]["risk_hints"])

    def test_an_id_argument_is_an_object_reference(self):
        self.assertIn("object-authorization", self.ops["node"]["risk_hints"])

    def test_relay_node_is_flagged(self):
        self.assertIn("relay-global-id", self.ops["node"]["risk_hints"])

    def test_resolver_group_is_recorded(self):
        self.assertEqual(self.ops["updateUser"]["metadata"]["return_type"], "User")

    def test_wrapped_types_are_unwrapped(self):
        self.assertEqual(AM._gql_type_name(
            {"kind": "NON_NULL", "ofType": {"kind": "LIST", "ofType": {"name": "Order"}}}),
            "Order")


class PostmanImport(unittest.TestCase):
    DOC = {"info": {"name": "acme"},
           "variable": [{"key": "baseUrl", "value": "https://api.acme.com"},
                        {"key": "authToken", "value": "eyJsecret"}],
           "item": [{"name": "Orders", "item": [
               {"name": "create order",
                "request": {"method": "POST",
                            "url": {"raw": "{{baseUrl}}/v1/orders?expand=all",
                                    "query": [{"key": "expand", "value": "all"}]},
                            "header": [{"key": "Authorization", "value": "Bearer {{authToken}}"}],
                            "body": {"raw": '{"amount": 1, "ownerId": "x"}'}}}]}]}

    def setUp(self):
        self.op = AM.from_postman(self.DOC)[0]

    def test_variables_are_substituted_into_the_url(self):
        self.assertEqual(self.op["host"], "api.acme.com")
        self.assertEqual(self.op["path"], "/v1/orders")

    def test_secret_variable_values_are_never_carried(self):
        self.assertNotIn("eyJsecret", json.dumps(AM.from_postman(self.DOC)))
        self.assertNotIn("authToken", AM.postman_variables(self.DOC))

    def test_query_and_body_fields_are_imported(self):
        self.assertEqual(self.op["parameters"], ["expand"])
        self.assertIn("ownerId", self.op["fields"])

    def test_an_auth_header_marks_the_operation_secured(self):
        self.assertTrue(self.op["secured"])

    def test_an_unresolved_variable_never_becomes_a_real_hostname(self):
        doc = {"info": {}, "item": [{"name": "x", "request": {
            "method": "GET", "url": {"raw": "{{unknownHost}}/v1/thing"}}}]}
        self.assertEqual(AM.from_postman(doc)[0]["host"], "placeholder.invalid")

    def test_environment_file_variables_are_merged(self):
        doc = {"info": {}, "item": [{"name": "x", "request": {
            "method": "GET", "url": {"raw": "{{host}}/v1/thing"}}}]}
        env = {"values": [{"key": "host", "value": "https://staging.acme.com"}]}
        self.assertEqual(AM.from_postman(doc, env)[0]["host"], "staging.acme.com")

    def test_disabled_variables_are_ignored(self):
        doc = {"variable": [{"key": "a", "value": "1", "disabled": True}]}
        self.assertNotIn("a", AM.postman_variables(doc))


if __name__ == "__main__":
    unittest.main()


class WorkflowMaterial(unittest.TestCase):
    """Hypotheses should carry the object ids the target already handed back.

    "perform refund as user B against user A's order" is not actionable without an
    order id, and sourcing one by hand is where a cross-principal test gets abandoned.
    The corpus already holds every response body; the ids are in there.
    """

    def setUp(self):
        sys.path.insert(0, str(ROOT / "engine"))
        import workflow_graph as WG
        self.WG = WG
        self.manifest = {"operations": [
            AM.make_operation("POST", "https://api.acme.com/v1/orders/{id}/refund",
                              "openapi", fields=["amount"]),
        ]}

    def test_observed_ids_reach_the_cross_principal_hypothesis(self):
        observed = {"/v1/orders": ["ord_1", "ord_2"]}
        wf = self.WG.build(self.manifest, observed)
        cross = [h for h in wf["hypotheses"] if h["kind"] == "cross-principal"][0]
        self.assertEqual(cross["material"], ["ord_1", "ord_2"])
        self.assertEqual(wf["counts"]["hypotheses_with_material"], 1)

    def test_a_hypothesis_with_material_outranks_the_same_one_without(self):
        with_ids = self.WG.build(self.manifest, {"/v1/orders": ["ord_1"]})
        without = self.WG.build(self.manifest, {})
        def p(wf):
            return [h for h in wf["hypotheses"] if h["kind"] == "cross-principal"][0]["priority"]
        self.assertGreater(p(with_ids), p(without))

    def test_entities_carry_their_observed_ids(self):
        wf = self.WG.build(self.manifest, {"/v1/orders": ["ord_9"]})
        node = [n for n in wf["nodes"] if n["id"] == "orders"][0]
        self.assertEqual(node["observed_ids"], ["ord_9"])

    def test_no_corpus_still_builds(self):
        wf = self.WG.build(self.manifest)
        self.assertTrue(wf["hypotheses"])
        self.assertEqual(wf["counts"]["hypotheses_with_material"], 0)

    def test_only_id_shaped_values_are_lifted(self):
        """Names, emails and free text are somebody's data, not test material."""
        import tempfile, json as _json, os
        with tempfile.TemporaryDirectory() as td:
            memdir = Path(td)
            body = _json.dumps({"id": "ord_1", "customerName": "Alice Smith",
                                "email": "a@b.c", "owner_id": "u_7",
                                "note": "please refund my order now"})
            (memdir / "responses" / "acme").mkdir(parents=True)
            import hashlib
            digest = hashlib.sha256(body.encode()).hexdigest()
            (memdir / "responses" / "acme" / f"{digest}.txt").write_text(body)
            (memdir / "audit.jsonl").write_text(_json.dumps({
                "engagement": "acme", "urls": ["https://api.acme.com/v1/orders"],
                "body_sha256": digest}) + "\n")
            found = self.WG.observed_identifiers("acme", memdir)
        values = [v for ids in found.values() for v in ids]
        self.assertIn("ord_1", values)
        self.assertIn("u_7", values)
        self.assertNotIn("a@b.c", values)
        self.assertFalse(any("Alice" in v for v in values))
