"""An item's CURRENT `Chain:` line is the last one, not the first.

House style on a re-measured item is to append an `## UPDATE <date>` block carrying a
corrected `Chain:` line and leave the original in place as the observation trail. `load()`
used `CHAIN_RE.search()`, so the stale first line won. Hit on yukki-lk 2026-10-28: the
image-optimizer primitive's first line spelled both capabilities out as prose inside the
backticks, which `CAP_RE` cannot match, so the strongest capability on the engagement
contributed nothing to the graph in either direction and the ranking was built without it --
silently, with a cheerful "27 annotated item(s)" line above it.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import chain_graph  # noqa: E402


class LastChainLineWins(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.eng = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, rel, body):
        p = self.eng / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    def test_the_update_blocks_line_is_the_one_used(self):
        body = ("# PRIMITIVE\n\n**Status:** capability CONFIRMED\n\n"
                "**Chain:** needs `old-need` · gives `old-gives`\n\n"
                "## UPDATE — re-measured\n\n"
                "**Chain:** needs `new-need` · gives `new-gives`\n")
        self._write("primitives/x.md", body)
        items = chain_graph.load(self.eng)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["needs"], ["new-need"])
        self.assertEqual(items[0]["gives"], ["new-gives"])

    def test_a_first_line_written_as_prose_does_not_blank_the_item(self):
        """The exact yukki-lk shape: prose in the backticks, corrected slugs appended."""
        body = ("# PRIMITIVE\n\n**Status:** capability CONFIRMED\n\n"
                "**Chain:** needs `a *.ykky.ru redirector with an attacker-chosen Location`"
                " · gives `unauthenticated server-side HTTP fetch of any *.ykky.ru URL`\n\n"
                "## UPDATE 2026-10-28\n\n"
                "**Chain:** needs `a-body-channel` · gives `unauth-ssrf-into-rfc1918`\n")
        self._write("primitives/x.md", body)
        items = chain_graph.load(self.eng)
        self.assertEqual(items[0]["gives"], ["unauth-ssrf-into-rfc1918"])
        res = chain_graph.analyse(items)
        self.assertIn("a-body-channel", {m["cap"] for m in res["missing"]})

    def test_a_dead_marker_on_the_last_line_still_kills_the_item(self):
        body = ("# PRIMITIVE\n\n**Status:** capability CONFIRMED\n\n"
                "**Chain:** needs `old-need` · gives `old-gives`\n\n"
                "## UPDATE\n\n**Chain:** DEAD\n")
        self._write("primitives/x.md", body)
        self.assertEqual(chain_graph.load(self.eng), [])


if __name__ == "__main__":
    unittest.main()
