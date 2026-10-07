#!/usr/bin/env python3
"""The differential plan is a comparison queue, not a payload sweep.

Pinned here because the two failure modes this module exists to prevent are
exactly the ones that regress silently: a plan row that pretends to be a
finding, and a "coverage" report that counts a request as a test.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import diff_matrix as DM  # noqa: E402


MANIFEST = {
    "schema_version": "2.0",
    "operations": [
        {"id": "GET api.example.com/users/{id}", "method": "GET",
         "url": "https://api.example.com/v2/users/124",
         "host": "api.example.com", "path": "/v2/users/124",
         "parameters": ["id"], "fields": [], "secured": True,
         "risk_hints": ["object-authorization"]},
        {"id": "POST api.example.com/orders", "method": "POST",
         "url": "https://api.example.com/orders",
         "host": "api.example.com", "path": "/orders",
         "parameters": [], "fields": ["amount", "status", "owner_id"],
         "secured": True, "risk_hints": ["business-flow"]},
        {"id": "GET api.example.com/health", "method": "GET",
         "url": "https://api.example.com/health",
         "host": "api.example.com", "path": "/health",
         "parameters": [], "fields": [], "secured": False, "risk_hints": []},
    ],
}


class PlanIsAHypothesis(unittest.TestCase):
    def test_every_row_carries_the_not_a_finding_clause(self):
        result = DM.plan(MANIFEST)
        self.assertGreater(result["counts"]["comparisons"], 0)
        for row in result["comparisons"]:
            self.assertIn("not_a_finding_until", row)
            self.assertIn("fired request", row["not_a_finding_until"])

    def test_comparison_is_a_pair(self):
        for row in DM.plan(MANIFEST)["comparisons"]:
            self.assertIn("baseline", row)
            self.assertIn("probe", row)
            self.assertIn("axis", row)
            self.assertIn("why", row)

    def test_plan_is_pure_and_reproducible(self):
        a = DM.plan(MANIFEST)
        b = DM.plan(MANIFEST)
        self.assertEqual(a["comparisons"], b["comparisons"])


class AxisSelection(unittest.TestCase):
    def test_auth_strip_skips_declared_public(self):
        rows = [r for r in DM.plan(MANIFEST)["comparisons"]
                if r["axis"] == "auth-strip"]
        # only the two secured operations
        self.assertEqual(len(rows), 2)

    def test_path_version_fires_on_v2_only(self):
        rows = [r for r in DM.plan(MANIFEST)["comparisons"]
                if r["axis"] == "path-version"]
        self.assertEqual(len(rows), 1)
        self.assertIn("/v1/", rows[0]["probe"]["url"])

    def test_hidden_field_targets_state_changing_call(self):
        rows = [r for r in DM.plan(MANIFEST)["comparisons"]
                if r["axis"] == "hidden-field"]
        self.assertEqual(len(rows), 1)
        body = json.loads(rows[0]["probe"]["body"])
        self.assertTrue(any(k in body for k in ("role", "is_admin", "status",
                                                "owner_id", "price")))

    def test_axis_filter(self):
        result = DM.plan(MANIFEST, axes=["auth-strip"])
        self.assertTrue(all(r["axis"] == "auth-strip" for r in result["comparisons"]))
        self.assertEqual(result["counts"]["by_axis"], {"auth-strip": 2})

    def test_host_filter(self):
        empty = {"schema_version": "2.0", "operations": []}
        result = DM.plan(MANIFEST, only_hosts=["nope.example.com"])
        self.assertEqual(result["counts"]["comparisons"], 0)
        self.assertEqual(DM.plan(empty)["counts"]["comparisons"], 0)

    def test_limit_orders_by_impact(self):
        full = DM.plan(MANIFEST)
        top = DM.plan(MANIFEST, limit=2)
        self.assertEqual(len(top["comparisons"]), 2)
        self.assertEqual(top["comparisons"], full["comparisons"][:2])


class NegativeSpace(unittest.TestCase):
    def test_every_operation_is_mapped(self):
        result = DM.plan(MANIFEST)
        self.assertEqual(len(result["negative_space"]), 3)

    def test_health_check_has_little_planned(self):
        result = DM.plan(MANIFEST)
        row = next(r for r in result["negative_space"] if r["path"] == "/health")
        self.assertLessEqual(len(row["axes_planned"]), 2)

    def test_audit_marks_already_fired(self):
        result = DM.plan(MANIFEST, audit_urls=["https://api.example.com/v2/users/124"])
        rows = [r for r in result["comparisons"] if r["path"] == "/v2/users/124"]
        self.assertTrue(rows)
        for r in rows:
            self.assertTrue(r.get("already_fired"))
        other = [r for r in result["comparisons"] if r["path"] == "/orders"]
        for r in other:
            self.assertFalse(r.get("already_fired"))


class MarkdownAndCLI(unittest.TestCase):
    def test_markdown_names_the_rule(self):
        text = DM.to_markdown(DM.plan(MANIFEST))
        self.assertIn("not a finding until", text.lower())
        self.assertIn("negative space", text.lower())

    def test_cli_writes_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            mpath = tmp / "manifest.json"
            mpath.write_text(json.dumps(MANIFEST), encoding="utf-8")
            out = tmp / "plan.json"
            rc = DM.main([str(mpath), "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertIn("comparisons", data)

    def test_cli_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            mpath = tmp / "manifest.json"
            mpath.write_text(json.dumps(MANIFEST), encoding="utf-8")
            out = tmp / "plan.md"
            rc = DM.main([str(mpath), "--format", "md", "--out", str(out)])
            self.assertEqual(rc, 0)
            self.assertIn("Differential oracle plan", out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
