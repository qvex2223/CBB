#!/usr/bin/env python3
"""Tests for engine/dedup.py — same-run duplicate signals.

The duplicate that costs money is against yourself: two findings of one
engagement describing the same broken control, submitted separately. These
tests pin the extraction and the verdict routing so `cbh dedup` keeps
surfacing candidates deterministically.

    python3 -m unittest tests.test_dedup -v
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import dedup  # noqa: E402


FINDING_IDOR_A = """# IDOR in /api/v2/orders allows reading victim orders

## Classification
- CWE: CWE-639
- Severity: High

## Steps
```http
GET /api/v2/orders/9901 HTTP/1.1
Host: shop.example.com
Authorization: Bearer ATTACKER
```
"""

FINDING_IDOR_B = """# [ЧЕРНОВИК] IDOR: orders export leaks another user's data

## Title
IDOR on the order export endpoint

Description: `GET /api/v1/orders/9901/export` with the attacker session
returns the victim's order document from shop.example.com.
"""

FINDING_XSS = """# Stored XSS in the ticket comment box

## Steps
POST /api/v2/tickets/432/comments with `<svg onload=alert(1)>` —
the comment renders on https://shop.example.com/tickets/432.
"""


class Extract(unittest.TestCase):
    def test_class_and_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "a.md"
            f.write_text(FINDING_IDOR_A, encoding="utf-8")
            got = dedup.extract(f)
        self.assertEqual(got["class"], "idor")
        self.assertEqual(got["cwe"], "CWE-639")
        self.assertIn("/api/v*/orders/9901", got["paths"])  # version collapsed

    def test_version_segments_collapse(self):
        self.assertEqual(dedup.normalize_path("/api/v2/Orders/1?x=2"), "/api/v*/orders/1")


class Compare(unittest.TestCase):
    def _findings(self, tmp, *texts):
        paths = []
        for i, text in enumerate(texts):
            p = Path(tmp) / f"f{i}.md"
            p.write_text(text, encoding="utf-8")
            paths.append(p)
        return paths

    def test_same_endpoint_same_class_is_likely(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = self._findings(tmp, FINDING_IDOR_A, FINDING_IDOR_B)
            out = dedup.run(b)
        self.assertEqual(out["verdict"], "LIKELY_DUPLICATE")
        self.assertTrue(any(m["verdict"] == "LIKELY_DUPLICATE" for m in out["matches"]))

    def test_different_class_and_endpoint_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = self._findings(tmp, FINDING_IDOR_A, FINDING_XSS)
            out = dedup.run(b)
        self.assertEqual(out["verdict"], "NOT_DUPLICATE")

    def test_uncertainty_is_possible_never_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = self._findings(
                tmp,
                FINDING_IDOR_A,
                FINDING_IDOR_A.replace("/api/v2/orders/9901", "/api/v2/invoices/9901"),
            )
            out = dedup.run(b)
        # same class, disjoint endpoints: identity unresolved → POSSIBLE, not clean
        self.assertEqual(out["verdict"], "POSSIBLE_DUPLICATE")

    def test_park_files_are_not_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = self._findings(tmp, FINDING_IDOR_A, FINDING_IDOR_B)
            (Path(tmp) / "b.park.md").write_text("Prerequisite: victim UUID", encoding="utf-8")
            out = dedup.run(b)
        self.assertEqual(out["checked"], 1)  # a.md only; b.park.md skipped

    def test_killed_drafts_are_not_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = self._findings(tmp, FINDING_IDOR_A, FINDING_IDOR_B)
            killed = Path(tmp) / "c.md"
            killed.write_text(
                "# [KILL]\n<!-- TRIAGE -->\nDecision: KILL\nReason: telemetry\n"
                "GET /api/v2/orders/9901 …", encoding="utf-8")
            out = dedup.run(b)
        self.assertEqual(out["checked"], 1)  # the killed draft must not compete

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = self._findings(tmp, FINDING_IDOR_A, FINDING_IDOR_B)
            self.assertEqual(dedup.main([str(b)]), 1)               # likely
            self.assertEqual(dedup.main([str(a), "--dir", str(a.parent)]), 1)
        with tempfile.TemporaryDirectory() as tmp:
            a, b = self._findings(tmp, FINDING_IDOR_A, FINDING_XSS)
            self.assertEqual(dedup.main([str(b)]), 0)               # clean


if __name__ == "__main__":
    unittest.main()
