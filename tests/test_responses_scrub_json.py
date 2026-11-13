"""Regression: scrub_text must not break JSON escaping.

scrub_text runs over the FINISHED json.dumps output in poc_runtime, so a PII-keyed value
sitting right before an escaped quote used to swallow the escape backslash and produce an
unparseable .result.json — which made `cbh evidence` report NO-EVIDENCE for a finding whose
PoC had actually fired (www.wildberries.ru, 2026-11-03).
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
from responses import scrub_text  # noqa: E402


class ScrubKeepsJsonParseable(unittest.TestCase):
    def test_escaped_quote_after_pii_value_survives(self):
        body = '<meta name="format-detection" content="telephone=no"> rest'
        doc = json.dumps({"body": body, "status": 200})
        scrubbed = scrub_text(doc)
        json.loads(scrubbed)  # must not raise
        self.assertIn("telephone=<redacted>", scrubbed)

    def test_real_identity_values_are_still_masked(self):
        self.assertEqual(scrub_text("?contact_phone=79990001122&x=1"),
                         "?contact_phone=<redacted>&x=1")
        self.assertEqual(scrub_text('{"iin": "123456789012"}'),
                         '{"iin": "<redacted>"}')


if __name__ == "__main__":
    unittest.main()
