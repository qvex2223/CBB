"""Regression: a captured response body must not leave subscriber identities on disk.

Found live 2026-09-14 — a PASS artifact for /api/v1/optionals/public/fraud-numbers kept
60 304 real MSISDNs, because the scrubber ran on the serialised JSON where the body's
own quotes are escaped (\"msisdn\":\"7…\") and the key/value regex never matched.
"""
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "engine"))
import poc_runtime  # noqa: E402


class ArtifactScrubTest(unittest.TestCase):
    def test_identity_inside_a_captured_body_is_masked(self):
        doc = {"runs": [{"result": {"body": '{"blockList":[{"msisdn":"77771234567"}]}'}}]}
        out = json.dumps(poc_runtime._scrub_doc(doc))
        self.assertNotIn("77771234567", out)
        self.assertIn("msisdn", out)

    def test_plain_fields_still_scrubbed(self):
        doc = {"url": "https://x/api?iin=900101500009&msisdn=77771234567"}
        out = json.dumps(poc_runtime._scrub_doc(doc))
        self.assertNotIn("900101500009", out)
        self.assertNotIn("77771234567", out)


if __name__ == "__main__":
    unittest.main()
