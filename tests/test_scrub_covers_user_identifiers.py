"""A buyer session puts the operator's own user id on every request line.

`scrub_text()` covered `login`/`email`/`account`/`username`/`owner` but not the
identifier keys an authenticated engagement actually carries, so on 2026-11-09 the
operator's own `wb_user_id` landed verbatim in audit rows and stored bodies. Contained
(everything under hunt-memory/ and Targets/ is gitignored), but the key list was one
word short.
"""
import sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
from responses import scrub_text  # noqa: E402


class ScrubCoversUserIdentifiers(unittest.TestCase):
    def test_identifier_keys_are_masked_in_urls_and_bodies(self):
        for text in (
            "?userId=12345678&x=1",
            '{"user_id": "12345678"}',
            "uid=12345678",
            "wbUserId: 12345678",
            '{"wb_user_id":"12345678"}',
            '{"globalUserId": "12345678"}',
            '{"user": "12345678"}',
            "subscriber_id=12345678",
        ):
            with self.subTest(text=text):
                out = scrub_text(text)
                self.assertNotIn("12345678", out, f"identifier survived scrubbing: {out!r}")
                self.assertIn("<redacted>", out)

    def test_the_key_itself_survives_so_the_shape_stays_readable(self):
        self.assertIn("user_id", scrub_text('{"user_id": "12345678"}'))

    def test_non_identifier_numbers_are_left_alone(self):
        # Counters and amounts are what makes a body worth diffing; do not mask them.
        for text in ("?order_count=22", '{"total_purchase_percent": 73}', "?limit=20"):
            with self.subTest(text=text):
                self.assertEqual(scrub_text(text), text)


if __name__ == "__main__":
    unittest.main()
