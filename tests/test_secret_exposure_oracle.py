"""`secret-exposure` class proof (2026-11-17, wave 2 item 8).

A leaked credential is proven by USING it. The class already existed everywhere — `CATALOG`,
`CLASS_WORDS`, `skill_map`, a 300 000 band — and had no oracle, so `cbh triage` graded it
"not checked": the class whose artifact is most often a grep hit rather than a request.

Evidence for the rule: ARTEX reported a planted fake secret as genuine on 30 of 120 tasks
(arXiv 2611.07611). A planted, revoked or expired key is indistinguishable from a live one until
it is used.

Note the shape the oracle must REFUSE: `cbh refute`'s `credentials-removed` control passes by
construction on an unauthenticated-exposure claim, since the request carried no credential. It
shows the endpoint answers WITHOUT the secret — the opposite claim.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "engine"))
import class_proof as CP  # noqa: E402

URL = "https://api.example.test/v1/me"
OTHER = "https://api.example.test/v1/public"


def _artifact(tmp, steps_and_codes, url_per_step=None):
    """The real two-file layout: `<stem>.poc.json` holds the request, `.result.json` the run.

    This matters and a first version of this fixture got it wrong. `class_proof._spec_of` loads
    the spec from the SIBLING file (`doc["spec_file"]`, else `<stem>.poc.json`), never from a key
    inside the result document — and a real `poc_runtime` result step carries `url`, `method`,
    `result`, and NOT `headers`. So the credential arm's headers exist only in the spec, which is
    why this rule reads identities from `ctx.specs` exactly as `_idor` does.
    """
    spec_steps, doc_steps = [], []
    for i, (headers, code) in enumerate(steps_and_codes):
        u = (url_per_step or [URL] * len(steps_and_codes))[i]
        spec_steps.append({"url": u, "method": "GET", "headers": headers,
                           "expect": {"status": code}})
        doc_steps.append({"step": i + 1, "url": u, "method": "GET", "verdict": "PASS",
                          "result": {"status": code, "body": "", "elapsed_ms": 10}})
    spec = Path(tmp) / "leak.poc.json"
    spec.write_text(json.dumps({"steps": spec_steps}), encoding="utf-8")
    res = Path(tmp) / "leak.poc.result.json"
    res.write_text(json.dumps({
        "spec_file": str(spec), "final_verdict": "PASS",
        "runs": [{"steps": doc_steps, "result": {"status": steps_and_codes[-1][1]}}],
    }), encoding="utf-8")
    return res


def _grade(tmp, path, text="# Finding\n\n**Class:** `secret-exposure`\n"):
    return CP.grade(text, [path], Path(tmp), name="leak")


class ThePositiveArm(unittest.TestCase):
    def test_credential_2xx_against_no_credential_401_on_one_url_passes(self):
        with tempfile.TemporaryDirectory() as t:
            a = _artifact(t, [({"Authorization": "Bearer FOUND"}, 200), ({}, 401)])
            got = _grade(t, a)
            self.assertTrue(got["ok"], got["reason"])
            self.assertIn("authenticated", got["reason"])

    def test_an_api_key_header_counts_too(self):
        with tempfile.TemporaryDirectory() as t:
            a = _artifact(t, [({"X-API-Key": "FOUND"}, 200), ({}, 403)])
            self.assertTrue(_grade(t, a)["ok"])

    def test_the_arms_may_come_in_either_order(self):
        with tempfile.TemporaryDirectory() as t:
            a = _artifact(t, [({}, 401), ({"Authorization": "Bearer FOUND"}, 204)])
            self.assertTrue(_grade(t, a)["ok"])


class TheNegativeArms(unittest.TestCase):
    def test_finding_the_secret_without_using_it_is_not_proof(self):
        with tempfile.TemporaryDirectory() as t:
            a = _artifact(t, [({}, 200)])
            got = _grade(t, a)
            self.assertFalse(got["ok"])
            self.assertIn("found, not used", got["reason"])

    def test_the_credentials_removed_shape_is_refused(self):
        """Both arms uncredentialed and both 2xx: that is the refute control, not this proof."""
        with tempfile.TemporaryDirectory() as t:
            a = _artifact(t, [({}, 200), ({}, 200)])
            got = _grade(t, a)
            self.assertFalse(got["ok"])
            self.assertIn("credentials-removed", got["reason"])

    def test_two_different_urls_prove_nothing(self):
        """The same-url guard: a 2xx here beside a 401 there is two routes differing."""
        with tempfile.TemporaryDirectory() as t:
            a = _artifact(t, [({"Authorization": "Bearer FOUND"}, 200), ({}, 401)],
                          url_per_step=[URL, OTHER])
            got = _grade(t, a)
            self.assertFalse(got["ok"], "the same-url guard did not hold")

    def test_credential_arm_that_is_also_denied_is_not_proof(self):
        """A revoked or planted key: it carries the credential and still gets 401."""
        with tempfile.TemporaryDirectory() as t:
            a = _artifact(t, [({"Authorization": "Bearer PLANTED"}, 401), ({}, 401)])
            self.assertFalse(_grade(t, a)["ok"])

    def test_both_arms_succeeding_is_not_proof(self):
        """If the url answers 2xx without the credential, the credential proved nothing."""
        with tempfile.TemporaryDirectory() as t:
            a = _artifact(t, [({"Authorization": "Bearer FOUND"}, 200), ({}, 200)])
            self.assertFalse(_grade(t, a)["ok"])

    def test_no_artifact_at_all(self):
        with tempfile.TemporaryDirectory() as t:
            got = CP.grade("# F\n\n**Class:** `secret-exposure`\n", [], Path(t), name="leak")
            self.assertFalse(got["ok"])


class ItIsWiredIntoTheGate(unittest.TestCase):
    def test_the_class_has_a_rule_now(self):
        self.assertIn("secret-exposure", CP.RULES)

    def test_the_rule_states_what_the_oracle_is(self):
        need, _fn = CP.RULES["secret-exposure"]
        self.assertIn("authenticating", need)

    def test_the_refusal_names_the_header_arm_and_the_query_parameter_case(self):
        with tempfile.TemporaryDirectory() as t:
            a = _artifact(t, [({}, 200)])
            reason = _grade(t, a)["reason"]
            self.assertIn("identity", reason)
            self.assertIn("query parameter", reason)


class DeclaringItMustNotDemoteTheLead(unittest.TestCase):
    """The wave-1 defect, re-checked on this class and its synonym."""

    def test_both_spellings_have_a_band(self):
        import lead_queue as LQ
        for cls in ("secret-exposure", "secret"):
            self.assertIn(cls, LQ.known_classes())
            self.assertIn(cls, LQ.DEFAULT_WEIGHTS, f"declaring `{cls}` would demote the lead")
            self.assertGreater(LQ.DEFAULT_WEIGHTS[cls], LQ.DEFAULT_REWARD)


if __name__ == "__main__":
    unittest.main()
