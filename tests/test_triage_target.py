#!/usr/bin/env python3
"""`cbh triage` must accept the layout the funnel actually writes.

Operator directive 2026-11-12: every candidate finding goes through the gate the moment
its write-up exists. The house layout is one folder per finding (`findings/<slug>/` with
its own evidence beside the write-up), so the gate is routinely pointed at the DIRECTORY
— and it answered `IsADirectoryError`, i.e. the one mandatory gate refused the one layout
the funnel uses. `engine/evidence.py` already tolerated a directory; `cbh/cli.py` now
resolves one to the write-up inside it, and says which markdown it picked.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cbh.cli import _triage_writeup  # noqa: E402


class TriageTarget(unittest.TestCase):
    def test_file_passes_through(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "x.md"
            f.write_text("x", encoding="utf-8")
            self.assertEqual(_triage_writeup(f), f)

    def test_directory_resolves_finding_md(self):
        """The real layout: findings/<slug>/finding.md next to its artifacts."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "ai-workspace-consent-scope-mismatch"
            d.mkdir()
            (d / "finding.md").write_text("x", encoding="utf-8")
            (d / "finding.poc.result.json").write_text("{}", encoding="utf-8")
            self.assertEqual(_triage_writeup(d).name, "finding.md")

    def test_slug_named_writeup_wins_over_readme(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "slug"
            d.mkdir()
            (d / "slug.md").write_text("x", encoding="utf-8")
            (d / "README.md").write_text("x", encoding="utf-8")
            self.assertEqual(_triage_writeup(d).name, "slug.md")

    def test_single_markdown_is_unambiguous(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "slug"
            d.mkdir()
            (d / "write-up.md").write_text("x", encoding="utf-8")
            self.assertEqual(_triage_writeup(d).name, "write-up.md")

    def test_ambiguous_directory_refuses(self):
        """Two candidate write-ups: guessing would triage the wrong claim."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "slug"
            d.mkdir()
            (d / "a.md").write_text("x", encoding="utf-8")
            (d / "b.md").write_text("x", encoding="utf-8")
            self.assertIsNone(_triage_writeup(d))

    def test_empty_directory_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "slug"
            d.mkdir()
            self.assertIsNone(_triage_writeup(d))


if __name__ == "__main__":
    unittest.main()
