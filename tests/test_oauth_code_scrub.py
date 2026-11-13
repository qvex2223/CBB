"""OAuth/OIDC authorization codes and bare passwords in a query string or form body.

Why these exist: `_TOKEN_QUERY_RE` lists `authorization_code` but NOT the parameter the
RFC actually names, `code=`, and `pwd=` was in no pattern at all. `bbcurl` logs its full
argv into `hunt-memory/audit.jsonl`, so an audited credentialed request wrote both
one-time IDM codes of the mail_vk VK Teams lane (48 hex each) plus a consumed yoomoney
oauth code and a Russian ESIA authorization code from two other engagements into the log
in cleartext — 28 occurrences across two generations, found on 2026-11-13 only because
the lane that minted the codes reported its own exposure. Nothing was published
(`hunt-memory/` is git-ignored) and every code was already dead, but a code on an
endpoint that does exchange is a live credential for its whole TTL.

A workspace marker is exempt on purpose: our own invented values (`cbhmk...`, `qvex...`)
are the load-bearing evidence of which control a refute lane fired, and `cbh refute`
requires the attack value to stay visible. A scrubber that ate `code=qvexnope4417` would
destroy the record it is meant to protect.

The last test pins the regex SHAPE, not just behaviour: the `code` rule carries a star
inside a negative lookahead, so its worst case is asserted with a clock. A scrubber that
its own input can stall is a scrubber that fails open.
"""
from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))

from responses import REDACTED, scrub_text  # noqa: E402

IDM_CODE = "12440d0471777fc693caf1bab0ef3bfbf4fd049337363830"
ESIA_CODE = "0173fff2-9446-4097-8f1f-094bf5315841"


class TestOAuthCodeScrub(unittest.TestCase):
    def test_real_code_is_masked_in_either_query_position(self):
        for sep in ("?", "&"):
            url = f"https://u.myteam.mail.ru/api/v1/idm/auth/token{sep}code={IDM_CODE}"
            out = scrub_text(url)
            self.assertNotIn(IDM_CODE, out)
            self.assertIn(f"code={REDACTED}", out)

    def test_uuid_shaped_code_is_masked(self):
        out = scrub_text(f"https://x/api/callbacks/esia?code={ESIA_CODE}&state=78e9")
        self.assertNotIn(ESIA_CODE, out)
        self.assertIn("state=78e9", out, "a non-credential sibling parameter must survive")

    def test_workspace_marker_survives_so_a_refute_control_stays_auditable(self):
        for marker in ("qvexnope4417", "cbhmk4z7k9", "cbh-dummy-code", "qvexinvented1"):
            out = scrub_text(f"https://x/cb?code={marker}&state=a")
            self.assertIn(marker, out, f"marker {marker} must stay readable")

    def test_short_non_credential_code_survives(self):
        for value in ("ru", "404", "EN", "0"):
            out = scrub_text(f"https://x/err?code={value}&other=1")
            self.assertIn(f"code={value}", out)

    def test_pwd_is_masked_at_any_length(self):
        # The VK Teams auth/clientLogin second leg posts a 6-digit OTP as pwd=.
        for value in ("483921", "notarealpassword", "a"):
            out = scrub_text(f"pwd={value}")
            self.assertEqual(out, f"pwd={REDACTED}")

    def test_key_with_a_code_suffix_is_not_clobbered(self):
        out = scrub_text("https://x/q?qrcode=12440d0471777fc693caf1bab")
        self.assertIn("qrcode=12440d0471777fc693caf1bab", out,
                      "the left word boundary must stop qrcode/barcode/zipcode matching")

    def test_scrubbed_audit_row_stays_parseable(self):
        # scrub_text runs over an already serialized audit line (memory._append), so the
        # value class must not swallow the closing `"]` of a urls array.
        row = json.dumps({"urls": [f"https://x/cb?code={IDM_CODE}"], "http_code": 400})
        out = scrub_text(row)
        self.assertNotIn(IDM_CODE, out)
        parsed = json.loads(out)
        self.assertEqual(parsed["http_code"], 400)
        self.assertIn(f"code={REDACTED}", parsed["urls"][0])

    def test_no_catastrophic_backtracking(self):
        hostile = "https://x/cb?code=" + "a" * 20000 + "!" + "b" * 20000
        start = time.monotonic()
        scrub_text(hostile)
        self.assertLess(time.monotonic() - start, 2.0,
                        "the lookahead star must not backtrack exponentially")


if __name__ == "__main__":
    unittest.main()
