"""The chain graph must not count a refuted item, and must see folder-form items.

Two defects, both silent:
  1. `load()` read only the `Chain:` line. A refuted primitive keeps that line — the record
     of a kill is kept rather than deleted — so a dead supplier went on feeding the ranking
     and the stop gate went on recommending chains built on it. Hit on yukki-lk 2026-10-27,
     where the ЕСИА chain was measured dead and its two primitives were still being ranked.
  2. The tier glob was `*.md`, so `findings/<slug>/README.md` — the layout this workspace
     actually uses — contributed nothing and nothing said so.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import chain_graph  # noqa: E402

CHAIN = "**Chain:** needs `a-thing` · gives `a-capability`\n"


class DeadAndFolders(unittest.TestCase):
    def setUp(self):
        self.eng = Path(tempfile.mkdtemp())
        (self.eng / "primitives").mkdir()
        (self.eng / "leads").mkdir()

    def _write(self, rel, body):
        p = self.eng / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        return p

    def test_live_item_is_counted(self):
        self._write("primitives/live.md", "# PRIMITIVE\n\n**Status:** capability CONFIRMED.\n\n" + CHAIN)
        self.assertEqual([i["file"] for i in chain_graph.load(self.eng)], ["primitives/live.md"])

    def test_the_house_style_primitive_header_stays_live(self):
        """`primitives/` items are written "Not a finding yet" BY TEMPLATE.

        An earlier version of this check listed "NOT A FINDING" as a death marker, which
        would have silently emptied the tier of every correctly-written item. Live-but-
        unproven is what the tier is for.
        """
        for value in ("capability CONFIRMED by fired requests. **Impact NOT demonstrated.** "
                      "Not a finding yet.",
                      "capability CONFIRMED. Impact NOT demonstrated.",
                      "the Госуслуги ask is MOOT, not blocking — capability still live"):
            with self.subTest(value=value):
                self._write("primitives/x.md", f"# PRIMITIVE\n\n**Status:** {value}\n\n" + CHAIN)
                self.assertEqual(len(chain_graph.load(self.eng)), 1,
                                 f"{value!r} is a live primitive, not a dead one")

    def test_refuted_status_is_excluded(self):
        for value in ("REFUTED by its own control", "DEAD — premise was wrong",
                      "KILLED 2026-10-27", "closed negative",
                      "WITHDRAWN"):
            with self.subTest(value=value):
                self._write("primitives/x.md", f"# PRIMITIVE\n\n**Status:** {value}\n\n" + CHAIN)
                self.assertEqual(chain_graph.load(self.eng), [],
                                 f"{value!r} must not supply capabilities")

    def test_superseded_heading_is_excluded(self):
        self._write("primitives/x.md", "# SUPERSEDED — merged into another file\n\n" + CHAIN)
        self.assertEqual(chain_graph.load(self.eng), [])

    def test_chain_line_literally_dead_is_excluded(self):
        self._write("leads/x.md", "# LEAD\n\n**Chain:** DEAD\n")
        self.assertEqual(chain_graph.load(self.eng), [])

    def test_include_dead_still_returns_them_flagged(self):
        self._write("primitives/x.md", "# PRIMITIVE\n\n**Status:** REFUTED\n\n" + CHAIN)
        items = chain_graph.load(self.eng, include_dead=True)
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["dead"])

    def test_folder_form_readme_is_seen(self):
        self._write("primitives/a-slug/README.md", "# PRIMITIVE\n\n**Status:** CONFIRMED\n\n" + CHAIN)
        self.assertEqual([i["file"] for i in chain_graph.load(self.eng)],
                         ["primitives/a-slug/README.md"])

    def test_folder_form_refuted_is_also_excluded(self):
        self._write("primitives/a-slug/README.md", "# PRIMITIVE\n\n**Status:** DEAD\n\n" + CHAIN)
        self.assertEqual(chain_graph.load(self.eng), [])

    def test_prose_mentioning_a_kill_is_not_enough(self):
        """Only a marker counts. A write-up that discusses killing a hypothesis stays live."""
        body = ("# PRIMITIVE\n\n**Status:** capability CONFIRMED by fired requests.\n\n"
                "## A hypothesis I formed and then killed\n\nIt is not that. Not a finding. "
                "Do not write it up.\n\n" + CHAIN)
        self._write("primitives/x.md", body)
        self.assertEqual(len(chain_graph.load(self.eng)), 1,
                         "prose about a killed sub-hypothesis must not kill the whole item")


if __name__ == "__main__":
    unittest.main()
