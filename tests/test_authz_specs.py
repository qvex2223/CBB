#!/usr/bin/env python3
"""The authorization matrix must emit runnable specs, not just a plan.

The plan is the easy half. Leaving execution to hand-rolled curl is how access-control
testing dies here: a hand-rolled request skips the scope gate, the pacing budget and the
audit row, so whatever it finds cannot back a report. These skeletons go through
poc_runtime like everything else.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import api_manifest as AM  # noqa: E402
import authorization_matrix as AZ  # noqa: E402

PRINCIPALS = {"principals": [
    {"name": "alice", "role": "user", "tenant": "t1", "token_env": "ALICE_TOKEN"},
    {"name": "bob", "role": "user", "tenant": "t2", "token_env": "BOB_TOKEN"},
]}

MANIFEST = {"operations": [
    AM.make_operation("GET", "https://api.acme.com/v1/orders/{id}", "openapi",
                      parameters=["id"]),
    AM.make_operation("DELETE", "https://api.acme.com/v1/orders/{id}", "openapi",
                      parameters=["id"]),
    AM.make_operation("PATCH", "https://api.acme.com/v1/orders/{id}", "openapi",
                      fields=["amount", "status"]),
]}


class Credentials(unittest.TestCase):
    def test_an_inline_credential_is_refused(self):
        for bad in ("token", "cookie", "authorization"):
            with self.assertRaises(ValueError, msg=f"{bad} was accepted inline"):
                AZ.plan(MANIFEST, {"principals": [{"name": "a", bad: "secret-value"}]})

    def test_specs_reference_env_names_never_values(self):
        plan = AZ.plan(MANIFEST, PRINCIPALS)
        blob = json.dumps([AZ.to_poc_spec(t) for t in plan["tests"]])
        self.assertIn("{{env:ALICE_TOKEN}}", blob)
        self.assertNotIn("Bearer ey", blob)


class SpecSemantics(unittest.TestCase):
    def setUp(self):
        self.plan = AZ.plan(MANIFEST, PRINCIPALS)
        self.specs = [AZ.to_poc_spec(t) for t in self.plan["tests"]]
        self.cross = [s for s in self.specs if s["is_finding_if_passes"]]

    def test_a_pass_always_means_the_vulnerability_is_demonstrated(self):
        """engine/evidence.py and the stop gate both read PASS as 'demonstrated'.

        A spec that PASSes when the server correctly denies would hand every hardened
        endpoint a green artifact and let the stop gate wave a hunt through on it.
        """
        for spec in self.cross:
            step = (spec.get("steps") or [spec])[0]
            self.assertEqual(step["expect"]["status"], 200,
                             "a deny-expected test must assert the FINDING condition")
            self.assertIn("missing", step["pass_means"])

    def test_owner_control_requests_are_marked_as_baseline_not_finding(self):
        owner = [s for s in self.specs if not s["is_finding_if_passes"]]
        for spec in owner:
            self.assertIn("baseline", json.dumps(spec).lower())

    def test_every_write_test_verifies_state_as_the_owner(self):
        for spec in self.cross:
            if "steps" not in spec:
                continue
            verify = spec["steps"][-1]
            self.assertEqual(verify["name"], "verify")
            self.assertIn("BOB_TOKEN" if "ALICE_TOKEN" in json.dumps(spec["steps"][0])
                          else "ALICE_TOKEN", json.dumps(verify),
                          "verification used the attacker's own credentials, which the "
                          "same broken authorization would satisfy")

    def test_delete_verifies_the_object_is_gone(self):
        spec = next(s for s in self.cross
                    if s.get("steps") and s["steps"][0]["method"] == "DELETE")
        self.assertEqual(spec["steps"][-1]["expect"]["status"], 404,
                         "asserting the object is still readable inverts the proof")

    def test_a_read_test_demands_owner_attributable_data(self):
        spec = next(s for s in self.cross if "steps" not in s)
        self.assertIn("2xx alone is not the finding", spec["verification_required"])

    def test_object_ids_are_placeholders_never_invented(self):
        for spec in self.cross:
            blob = json.dumps(spec)
            self.assertIn(AZ.OBJECT_ID_PLACEHOLDER, blob)
            self.assertTrue(spec["fill_in"], "nothing told the operator what to fill in")

    def test_a_missing_owner_token_is_called_out_not_silently_wrong(self):
        plan = AZ.plan(MANIFEST, {"principals": [
            {"name": "alice", "token_env": "ALICE_TOKEN"}, {"name": "bob"}]})
        spec = next(AZ.to_poc_spec(t) for t in plan["tests"]
                    if t["object_owner"] == "bob" and t["requires_state_verification"])
        self.assertTrue(any("WARNING" in x for x in spec["fill_in"]))


class EvaluateReads(unittest.TestCase):
    """A deny-expected read must not turn missing evidence into a VIOLATION."""

    def _verdict(self, **obs):
        row = {"actor": "bob", "object_owner": "alice", "expected": "deny",
               "method": "GET", "status": 200}
        row.update(obs)
        return AZ.evaluate([row])["results"][0]

    def test_missing_ownership_evidence_is_inconclusive_not_a_violation(self):
        v = self._verdict(body={})
        self.assertEqual(v["verdict"], "INCONCLUSIVE",
                         "None == None made an empty response look like data exposure")

    def test_both_owners_none_is_not_a_match(self):
        v = self._verdict(response_owner=None, object_owner=None)
        self.assertEqual(v["verdict"], "INCONCLUSIVE")

    def test_empty_strings_are_not_a_match(self):
        v = self._verdict(response_owner="", object_owner="", body={})
        self.assertEqual(v["verdict"], "INCONCLUSIVE")

    def test_one_sided_ownership_is_not_a_match(self):
        self.assertEqual(self._verdict(response_owner="alice", object_owner=None)["verdict"],
                         "INCONCLUSIVE")
        self.assertEqual(self._verdict(response_owner=None)["verdict"], "INCONCLUSIVE")

    def test_valid_matching_owners_are_a_violation(self):
        v = self._verdict(response_owner="alice", object_owner="alice")
        self.assertEqual(v["verdict"], "VIOLATION")

    def test_mismatching_owners_are_not_a_violation(self):
        v = self._verdict(response_owner="carol", object_owner="alice")
        self.assertEqual(v["verdict"], "INCONCLUSIVE")

    def test_sensitive_data_flag_still_proves_exposure(self):
        v = self._verdict(body={"ssn": "…"}, sensitive_data=True)
        self.assertEqual(v["verdict"], "VIOLATION")

    def test_correct_deny_still_passes(self):
        v = self._verdict(status=403)
        self.assertEqual(v["verdict"], "PASS")


class Emission(unittest.TestCase):
    def test_specs_are_written_one_per_test_and_nothing_fires(self):
        with tempfile.TemporaryDirectory() as td:
            plan = AZ.plan(MANIFEST, PRINCIPALS)
            paths = AZ.emit_specs(plan, Path(td))
            self.assertEqual(len(paths), len(plan["tests"]))
            for path in paths:
                spec = json.loads(path.read_text())
                self.assertTrue(spec["name"].startswith("authz_"))
                self.assertTrue(path.name.endswith(".poc.json"))

    def test_limit_is_honoured(self):
        with tempfile.TemporaryDirectory() as td:
            plan = AZ.plan(MANIFEST, PRINCIPALS)
            self.assertEqual(len(AZ.emit_specs(plan, Path(td), limit=2)), 2)


if __name__ == "__main__":
    unittest.main()
