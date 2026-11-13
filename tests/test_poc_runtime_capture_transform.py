"""The capture transform exists so a chain can SPEND a disclosed credential.

Timeweb's login route takes HTTP Basic only (`{"login":..,"password":..}` is
rejected `400 property password should not exist`), so proving that a disclosed
password is a working credential needs base64("<login>:<captured>") built from a
value that only exists mid-run. Without this, the only way to write that step was
to paste the credential into the versioned .poc.json spec — which this workspace
forbids. A regression here silently pushes PoC authors back to that.
"""
import base64
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "engine"))
from poc_runtime import capture_vars  # noqa: E402

BODY = '{"token":{"password":"s3cr3t-value","user":"ch061558"}}'
RULE = {"from": "body", "regex": r'"password":"([^"]+)"'}


class CaptureTransform(unittest.TestCase):
    def test_no_transform_still_returns_the_raw_value(self):
        out, errors = capture_vars({"body": BODY}, {"pw": dict(RULE)})
        self.assertEqual(errors, [])
        self.assertEqual(out["pw"], "s3cr3t-value")

    def test_basic_transform_builds_the_http_basic_credential(self):
        out, errors = capture_vars(
            {"body": BODY}, {"pw": dict(RULE, transform="basic:ch061558")})
        self.assertEqual(errors, [])
        self.assertEqual(
            base64.b64decode(out["pw"]).decode(), "ch061558:s3cr3t-value")

    def test_b64_transform_encodes_the_value_alone(self):
        out, errors = capture_vars({"body": BODY}, {"pw": dict(RULE, transform="b64")})
        self.assertEqual(errors, [])
        self.assertEqual(base64.b64decode(out["pw"]).decode(), "s3cr3t-value")

    def test_basic_with_no_username_is_an_error_not_a_colon_prefix(self):
        out, errors = capture_vars({"body": BODY}, {"pw": dict(RULE, transform="basic:")})
        self.assertNotIn("pw", out)
        self.assertTrue(any("needs a username" in e for e in errors), errors)

    def test_unknown_transform_is_an_error_not_a_silent_passthrough(self):
        out, errors = capture_vars({"body": BODY}, {"pw": dict(RULE, transform="rot13")})
        self.assertNotIn("pw", out)
        self.assertTrue(any("unknown transform" in e for e in errors), errors)

    def test_a_capture_that_matches_nothing_is_still_an_error_with_a_transform(self):
        out, errors = capture_vars(
            {"body": "{}"}, {"pw": dict(RULE, transform="basic:ch061558")})
        self.assertNotIn("pw", out)
        self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
