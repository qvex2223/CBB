#!/usr/bin/env python3
"""The class-agnostic track: incoherence, not a vulnerability name.

What must hold: an anomaly is never a finding, a random UUID never settles
authz-before-lookup, and a finding that fits no class stays unclassified rather
than being forced into a nearby one.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import anomaly as AN  # noqa: E402
import technique_classifier as TC  # noqa: E402


MANIFEST = {
    "schema_version": "2.0",
    "operations": [
        {"id": "POST api.example.com/orders", "method": "POST",
         "url": "https://api.example.com/orders",
         "host": "api.example.com", "path": "/orders",
         "fields": ["owner_id", "status", "amount"], "parameters": [],
         "secured": True, "risk_hints": ["business-flow"]},
        {"id": "GET api.example.com/admin/backup", "method": "GET",
         "url": "https://api.example.com/admin/backup",
         "host": "api.example.com", "path": "/admin/backup",
         "fields": [], "parameters": [], "secured": False, "risk_hints": []},
        {"id": "GET api.example.com/users/{id}", "method": "GET",
         "url": "https://api.example.com/v2/users/124",
         "host": "api.example.com", "path": "/v2/users/124",
         "fields": ["role", "email"], "parameters": ["id"], "secured": True,
         "risk_hints": ["object-authorization"]},
        {"id": "GET api.example.com/v1/users/{id}", "method": "GET",
         "url": "https://api.example.com/v1/users/124",
         "host": "api.example.com", "path": "/v1/users/124",
         "fields": ["email"], "parameters": ["id"], "secured": True,
         "risk_hints": []},
    ],
}


class AnomalyIsNotAFinding(unittest.TestCase):
    def test_every_row_says_so(self):
        result = AN.analyze(MANIFEST)
        self.assertGreater(result["counts"]["anomalies"], 0)
        for a in result["anomalies"]:
            self.assertIn("not_a_finding_until", a)
            self.assertIn("fired request", a["not_a_finding_until"])
        for a in result["assumptions"]:
            self.assertIn("not_a_finding_until", a)
        for i in result["invariants"]:
            self.assertIn("not_a_finding_until", i)


class Detectors(unittest.TestCase):
    def setUp(self):
        self.result = AN.analyze(MANIFEST)
        self.kinds = {a["kind"] for a in self.result["anomalies"]}

    def test_client_supplied_identity_flags_belief_fields(self):
        rows = [a for a in self.result["anomalies"]
                if a["kind"] == "client-supplied-identity"]
        self.assertTrue(rows)
        self.assertIn("owner_id", rows[0]["fields"])

    def test_money_and_state_are_their_own_kinds(self):
        self.assertIn("client-supplied-value", self.kinds)
        self.assertIn("client-driven-state-machine", self.kinds)

    def test_internal_surface_flagged(self):
        rows = [a for a in self.result["anomalies"]
                if a["kind"] == "internal-looking-surface"]
        self.assertTrue(rows)
        self.assertIn("admin", rows[0]["path"])

    def test_identity_header_oracle_on_principal_path(self):
        rows = [a for a in self.result["anomalies"]
                if a["kind"] == "identity-header-oracle"]
        self.assertTrue(rows)

    def test_version_skew_between_v1_and_v2(self):
        rows = [a for a in self.result["anomalies"] if a["kind"] == "version-skew"]
        self.assertTrue(rows)

    def test_probe_carries_a_note(self):
        for a in self.result["anomalies"]:
            self.assertTrue(a["probe"].get("note"))


class AssumptionsAndInvariants(unittest.TestCase):
    def test_authz_assumption_is_present_and_flags_real_id(self):
        rows = [a for a in AN.analyze(MANIFEST)["assumptions"]
                if a["id"] == "authz-before-lookup"]
        self.assertTrue(rows)
        self.assertTrue(rows[0]["needs_real_id"])
        self.assertIn("random uuid", rows[0]["invert"].lower())

    def test_money_invariants_appear_on_a_money_surface(self):
        ids = {i["id"] for i in AN.analyze(MANIFEST)["invariants"]}
        self.assertIn("total-equals-lines", ids)
        self.assertIn("balance-never-negative", ids)

    def test_analyze_is_pure(self):
        self.assertEqual(AN.analyze(MANIFEST), AN.analyze(MANIFEST))


class NoveltyContract(unittest.TestCase):
    def test_classifier_marks_generic_as_novel(self):
        out = TC.classify_finding_ex({"notes": "something we have never seen, zqxwv plorf"})
        self.assertTrue(out["novel"])
        self.assertEqual(out["technique"], "generic")
        self.assertIn("unclassified__", out["reason"])

    def test_classifier_keeps_string_contract(self):
        self.assertEqual(
            TC.classify_finding({"notes": "totally unrelated zqxwv"}), "generic")

    def test_operator_supplied_unclassified_slug_is_novel(self):
        out = TC.classify_finding_ex({
            "notes": "nothing matches here",
            "technique": "unclassified__header-supplied-identity"})
        self.assertTrue(out["novel"])
        self.assertEqual(out["technique"], "unclassified__header-supplied-identity")

    def test_known_technique_is_not_novel(self):
        self.assertFalse(TC.is_novel_technique(next(iter(TC.TECHNIQUE_PATTERNS))))
        self.assertTrue(TC.is_novel_technique("generic"))
        self.assertTrue(TC.is_novel_technique("something_brand_new"))


class MarkdownAndCLI(unittest.TestCase):
    def test_markdown_reminds_about_classes(self):
        text = AN.to_markdown(AN.analyze(MANIFEST))
        self.assertIn("do not name a vulnerability class", text.lower())
        self.assertIn("needs a real id", text.lower())

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            mpath = tmp / "manifest.json"
            mpath.write_text(json.dumps(MANIFEST), encoding="utf-8")
            out = tmp / "an.json"
            rc = AN.main([str(mpath), "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertIn("anomalies", data)


if __name__ == "__main__":
    unittest.main()
