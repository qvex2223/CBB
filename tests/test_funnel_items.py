#!/usr/bin/env python3
"""
What counts as an item in a funnel tier.

Every counter and every queue in the workspace used to answer this differently, so the
rule now lives in `engine/funnel.py` and this file is what holds it still. The three
things measured on the live corpus on 2026-11-13, in order of how badly they misdirected
a hunt:

  * a tier's own `README.md` was ranked as work, and on rowi one of three lanes was
    briefed to hunt `primitives/README.md`;
  * `lead_queue` globbed `*.md`, so a folder-per-item write-up never entered the queue the
    lanes are picked from -- 10 of yukki-lk's 22 primitives;
  * `stop_gate` looked only for `<slug>/README.md`, which is 4 of the 9 folder-form items
    on disk; the rest name their write-up `<slug>.md` or are the single markdown in the
    folder.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

import funnel  # noqa: E402


def write(p: Path, text: str = "x\n") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


class WhatIsAnItem(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tier = Path(self.tmp.name) / "primitives"
        self.tier.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def names(self):
        return [p.name for p in funnel.tier_items(self.tier)]

    def rel(self):
        return [str(p.relative_to(self.tier)) for p in funnel.tier_items(self.tier)]

    def test_a_flat_markdown_file_is_an_item(self):
        write(self.tier / "host-reflects-origin.md")
        self.assertEqual(self.names(), ["host-reflects-origin.md"])

    def test_the_tiers_own_readme_is_not_an_item(self):
        write(self.tier / "README.md", "how to use this tier\n")
        write(self.tier / "real-lead.md")
        self.assertEqual(self.names(), ["real-lead.md"])

    def test_the_tier_readme_is_skipped_in_any_case(self):
        write(self.tier / "readme.md", "lowercase on disk\n")
        self.assertEqual(self.names(), [])

    def test_an_item_whose_own_name_contains_readme_is_kept(self):
        write(self.tier / "readme-exposes-internal-paths.md")
        self.assertEqual(self.names(), ["readme-exposes-internal-paths.md"])

    def test_a_folder_items_readme_is_its_write_up(self):
        write(self.tier / "idor-on-invoice" / "README.md")
        self.assertEqual(self.rel(), ["idor-on-invoice/README.md"])

    def test_a_folder_item_named_after_its_folder(self):
        write(self.tier / "open-redirect" / "open-redirect.md")
        self.assertEqual(self.rel(), ["open-redirect/open-redirect.md"])

    def test_readme_wins_over_the_folder_named_file(self):
        write(self.tier / "dup" / "README.md")
        write(self.tier / "dup" / "dup.md")
        self.assertEqual(self.rel(), ["dup/README.md"])

    def test_the_single_markdown_in_a_folder_is_the_item(self):
        """4 of 9 folder items on disk use README; the others are this shape."""
        write(self.tier / "token-leak" / "report.md")
        self.assertEqual(self.rel(), ["token-leak/report.md"])

    def test_a_folder_with_two_unnamed_write_ups_is_not_an_item(self):
        """`leads/refuted/` holds two closed write-ups. Briefing a worker to attack an
        archive is worse than not counting it, so it is skipped, never guessed at."""
        write(self.tier / "refuted" / "cors-allowlist-refuted.md")
        write(self.tier / "refuted" / "merged-into-sms-init.md")
        self.assertEqual(self.rel(), [])
        self.assertIsNone(funnel.item_write_up(self.tier / "refuted"))

    def test_evidence_beside_the_write_up_does_not_multiply_the_item(self):
        write(self.tier / "xss" / "README.md")
        write(self.tier / "xss" / "evidence" / "proof.md")
        write(self.tier / "xss" / "poc.sh", "#!/bin/sh\n")
        self.assertEqual(self.rel(), ["xss/README.md"])

    def test_a_folder_with_no_markdown_is_not_an_item(self):
        write(self.tier / "captures" / "run.har", "{}\n")
        self.assertEqual(self.rel(), [])

    def test_flat_items_come_before_folder_items_and_both_are_sorted(self):
        write(self.tier / "b-lead.md")
        write(self.tier / "a-lead.md")
        write(self.tier / "z-folder" / "README.md")
        write(self.tier / "m-folder" / "README.md")
        self.assertEqual(
            self.rel(),
            ["a-lead.md", "b-lead.md", "m-folder/README.md", "z-folder/README.md"],
        )

    def test_a_missing_tier_yields_nothing_rather_than_raising(self):
        self.assertEqual(list(funnel.tier_items(self.tier.parent / "findings")), [])

    def test_items_walks_every_tier(self):
        eng = self.tier.parent
        write(eng / "findings" / "proven.md")
        write(eng / "primitives" / "prim.md")
        write(eng / "leads" / "lead" / "README.md")
        self.assertEqual(
            [p.name for p in funnel.items(eng)], ["proven.md", "prim.md", "README.md"]
        )


class BothEnginesReadTheSameRule(unittest.TestCase):
    """The point of the shared collector: the queue and the stop gate agree on the count."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name) / "Targets"
        self.eng = root / "plat" / "prog"
        write(self.eng / "primitives" / "README.md", "tier instructions\n")
        write(
            self.eng / "primitives" / "flat-one.md",
            "**Class:** idor\n\n**Status:** open\n",
        )
        write(
            self.eng / "primitives" / "folder-form" / "report.md",
            "**Class:** xss\n\n**Status:** open\n",
        )
        write(self.eng / "leads" / "refuted" / "a.md", "closed\n")
        write(self.eng / "leads" / "refuted" / "b.md", "closed\n")
        self.prev = os.environ.get("CBH_TARGETS_ROOT")
        os.environ["CBH_TARGETS_ROOT"] = str(root)

    def tearDown(self):
        if self.prev is None:
            os.environ.pop("CBH_TARGETS_ROOT", None)
        else:
            os.environ["CBH_TARGETS_ROOT"] = self.prev
        self.tmp.cleanup()

    def test_the_queue_sees_the_folder_form_item(self):
        import lead_queue

        got = {Path(i["file"]).name for i in lead_queue.scan(self.eng)["open"]}
        self.assertIn("flat-one.md", got)
        self.assertIn("report.md", got)
        self.assertNotIn("README.md", got)

    def test_the_stop_gate_counts_the_same_two(self):
        import stop_gate

        got = [p for p in stop_gate._tier_item_files(self.eng / "primitives")]
        self.assertEqual(
            sorted(str(p.relative_to(self.eng / "primitives")) for p in got),
            ["flat-one.md", "folder-form/report.md"],
        )


if __name__ == "__main__":
    unittest.main()
