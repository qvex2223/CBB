"""The stop gate's refusal message must not propose work already measured dead.

A kill is recorded inside the file rather than deleted, so a reader that looks only at the
tier directory keeps counting refuted primitives and keeps naming them as the cheapest next
move. Observed on yukki-lk 2026-10-27: the gate went on listing two ЕСИА primitives whose
chain a worker had measured dead, in the same refusal that told the agent to chain them.
Second half: the tier glob missed `<tier>/<slug>/README.md`, the layout actually in use.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import stop_gate  # noqa: E402

CHAIN = "**Chain:** needs `a-thing` · gives `a-capability`\n"


def _funnel(project_dir):
    for name in ("funnel_state", "funnel", "pending_funnel", "leads_and_primitives"):
        fn = getattr(stop_gate, name, None)
        if callable(fn):
            return fn(project_dir)
    raise AssertionError("funnel reader not found in stop_gate")


class SkipsRefuted(unittest.TestCase):
    def setUp(self):
        self.eng = Path(tempfile.mkdtemp())
        (self.eng / "primitives").mkdir()
        (self.eng / "leads").mkdir()

    def _write(self, rel, body):
        p = self.eng / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    def test_live_primitive_is_counted(self):
        self._write("primitives/live.md", "# PRIMITIVE\n\n**Status:** CONFIRMED\n\n" + CHAIN)
        out = _funnel(self.eng)
        self.assertEqual(out["counts"]["primitives"], 1)

    def test_refuted_primitive_is_not_counted_or_suggested(self):
        self._write("primitives/dead.md", "# PRIMITIVE\n\n**Status:** REFUTED 2026-10-27\n\n" + CHAIN)
        out = _funnel(self.eng)
        self.assertEqual(out["counts"]["primitives"], 0)
        self.assertEqual(out["primitives"], [])

    def test_folder_form_primitive_is_seen_and_named_by_its_slug(self):
        self._write("primitives/a-real-slug/README.md",
                    "# PRIMITIVE — something\n\n**Status:** CONFIRMED\n\n" + CHAIN)
        out = _funnel(self.eng)
        self.assertEqual(out["counts"]["primitives"], 1)
        self.assertEqual(out["primitives"][0]["name"], "a-real-slug",
                         "a refusal message naming 'README.md' tells the reader nothing")

    def test_folder_form_refuted_is_skipped_too(self):
        self._write("primitives/dead-slug/README.md",
                    "# PRIMITIVE\n\n**Status:** DEAD — premise was wrong\n\n" + CHAIN)
        self.assertEqual(_funnel(self.eng)["counts"]["primitives"], 0)

    def test_tier_readme_is_still_not_an_item(self):
        self._write("primitives/README.md", "# primitives/ — one file per capability\n")
        self.assertEqual(_funnel(self.eng)["counts"]["primitives"], 0)

    def test_mixed_tier_counts_only_the_live_ones(self):
        self._write("primitives/a.md", "# P\n\n**Status:** CONFIRMED\n\n" + CHAIN)
        self._write("primitives/b.md", "# P\n\n**Status:** REFUTED\n\n" + CHAIN)
        self._write("primitives/c-slug/README.md", "# P\n\n**Status:** CONFIRMED\n\n" + CHAIN)
        out = _funnel(self.eng)
        self.assertEqual(out["counts"]["primitives"], 2)
        self.assertEqual(sorted(r["name"] for r in out["primitives"]), ["a.md", "c-slug"])


if __name__ == "__main__":
    unittest.main()
