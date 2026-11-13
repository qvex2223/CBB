"""Credential-shaped cookie values in a stored response's header block.

Why these exist: `SECRET_HEADER_RE` masks a header by NAME, which covers `set-cookie:`
on a command line. But a stored response's header block is scrubbed as free text, so the
cookie NAME *inside* a `Set-Cookie` line never matched and the value survived — two
corpus files kept `__Secure-access-token=` / `__Secure-refresh-token=` in cleartext on
2026-10-16. That jar was an anonymous subject-0 one, so no real session was exposed; the
next one would not be, since the operator's own session was authorized for use the same
day.

The last test pins the regex SHAPE, not just its behaviour. The first version of the rule
nested a quantifier over an overlapping character class and backtracked exponentially,
which hung the entire suite on a long header block. A scrubber that its own input can
stall is a scrubber that fails open, so the worst case is asserted with a clock.
"""
from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))

from responses import SECRET_HEADER_RE, scrub_text  # noqa: E402


class CookieValueScrubTests(unittest.TestCase):
    def test_credential_cookies_lose_their_value_and_keep_their_name(self):
        for line in (
            "Set-Cookie: __Secure-access-token=12.0.TBc5G24RjC0nvQNW5rwA.23.blob; HttpOnly",
            "Set-Cookie: __Secure-refresh-token=12.0.AAAABBBB.23.other; Secure",
            "Set-Cookie: __Secure-sid=aVeryLongSessionHandleValue123456; Secure",
            "Set-Cookie: ozonid-auth-tokens=abcdefghijklmnopqrst; Secure",
        ):
            with self.subTest(line=line):
                out = scrub_text(line)
                self.assertIn("<redacted>", out)
                # The name has to survive: a stored exchange that no longer says WHICH
                # cookie was set is not readable evidence.
                name = line.split(":", 1)[1].split("=", 1)[0].strip()
                self.assertIn(name, out)

    def test_fields_that_decide_a_finding_are_not_touched(self):
        # `user-id` is the decisive field in the anonymous-jar analysis, the antibot
        # cookie is what makes a lane reproducible, and `content-disposition` is the
        # header a whole file-serving finding turns on. Masking any of them would
        # destroy evidence rather than protect anyone.
        keeps = (
            ("Set-Cookie: __Secure-user-id=0; Domain=ozon.ru", "__Secure-user-id=0"),
            ("Set-Cookie: __obank_tc=6a1f9c2b4d; Secure", "__obank_tc=6a1f9c2b4d"),
            ("x-o3-trace-id: fe1b811a6a841605", "fe1b811a6a841605"),
            ("websocket-connection-id: db533fa6-c939-11f1-ae46-bec063b0a144",
             "db533fa6-c939-11f1-ae46-bec063b0a144"),
            ("content-disposition: attachment; filename=report.pdf", "attachment"),
        )
        for line, must_survive in keeps:
            with self.subTest(line=line):
                self.assertIn(must_survive, scrub_text(line))

    def test_header_names_ending_in_token_or_tokens_are_credentials(self):
        for name in ("ozon-id-token", "ozonid-auth-tokens", "x-refresh-tokens",
                     "authorization", "set-cookie"):
            with self.subTest(name=name):
                self.assertTrue(SECRET_HEADER_RE.search(name), name)
        for name in ("x-o3-trace-id", "websocket-connection-id", "x-o3-app-handler",
                     "content-disposition"):
            with self.subTest(name=name):
                self.assertFalse(SECRET_HEADER_RE.search(name), name)

    def test_scrubbing_a_serialized_audit_row_leaves_valid_json(self):
        """The regression that cost 5 audit rows (konsol, 2026-10-17).

        `memory._append` scrubs the already-serialized line, so the cookie-value class
        has to stop at JSON punctuation. It stopped only at `;`/`,`/whitespace, so
        `"urls": ["https://app.konsol.pro/?auth_token=XYZ"]` lost its closing `"]` and
        the row no longer parsed: a request that was fired, paced and logged could no
        longer back a report. A scrubber may remove a value; it may never corrupt the
        record around it.
        """
        row = {
            "urls": ["https://app.konsol.pro/?auth_token=SECRETVALUE123"],
            "exit_code": 0,
            "req": ["-H", "Cookie: _prime_session=abcdefghijklmnopqrst", "-X", "POST"],
            "note": "partner_session=aVeryLongHandleValue99 inside free text",
        }
        line = json.dumps(row)
        out = scrub_text(line)
        parsed = json.loads(out)  # the whole point: still a row
        self.assertIn("<redacted>", out)
        self.assertNotIn("SECRETVALUE123", out)
        self.assertNotIn("abcdefghijklmnopqrst", out)
        # structure around the masked value survives intact
        self.assertEqual(parsed["exit_code"], 0)
        self.assertEqual(len(parsed["urls"]), 1)
        self.assertTrue(parsed["urls"][0].startswith("https://app.konsol.pro/?auth_token="))
        self.assertEqual(parsed["req"][-2:], ["-X", "POST"])

    def test_scrubbing_cannot_be_stalled_by_its_own_input(self):
        adversarial = "a" * 4000 + "-token=" + "b" * 4000
        started = time.monotonic()
        scrub_text(adversarial)
        self.assertLess(time.monotonic() - started, 1.0,
                        "scrub_text backtracked — check for a nested quantifier")


if __name__ == "__main__":
    unittest.main()
