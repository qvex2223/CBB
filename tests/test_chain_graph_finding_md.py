"""Regression: chain_graph must see a folder-form finding named finding.md.

`_tier_files` only looked for `findings/<slug>/README.md`, while `stop_gate.py` reads
`findings/<slug>/finding.md`. A CONFIRMED finding written in the finding.md form was
therefore invisible to the graph: the capability it supplies still ranked as MISSING with
"nothing on file supplies it" (www.wildberries.ru XSS → `xss-on-trusted-origin`, 2026-11-03).
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import chain_graph  # noqa: E402


class FolderFormFindingIsSeen(unittest.TestCase):
    def _eng(self, root: Path, filename: str) -> None:
        d = root / "findings" / "some-slug"
        d.mkdir(parents=True)
        (d / filename).write_text(
            "# A confirmed thing\n\n**Chain:** needs `nothing` · gives `cap-alpha`\n")
        for tier in ("leads", "primitives"):
            (root / tier).mkdir()

    def test_finding_md_supplies_its_capability(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._eng(root, "finding.md")
            items = chain_graph.load(root)
            gives = {g for it in items for g in it["gives"]}
            self.assertIn("cap-alpha", gives)

    def test_readme_md_still_works(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._eng(root, "README.md")
            items = chain_graph.load(root)
            gives = {g for it in items for g in it["gives"]}
            self.assertIn("cap-alpha", gives)


if __name__ == "__main__":
    unittest.main()
