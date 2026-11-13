"""A remediated finding must stop supplying capabilities.

Measured on Wildberries 2026-11-05: a confirmed XSS on a slide-v3 trusted origin was
submitted, reproduced by the vendor and patched, but its `findings/` file still carried
`gives xss-on-trusted-origin`. `cbh chain-graph` therefore listed that capability as held
and ranked the 1,000,000 RUB chain built on it as already unblocked.

A fixed finding was never wrong, so marking it REFUTED would be false. It needs its own
marker, and the marker must be a phrase that cannot appear negated.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import chain_graph  # noqa: E402


class RemediatedSuppliesNothing(unittest.TestCase):
    def test_fix_confirmed_marks_it_dead(self):
        self.assertTrue(chain_graph.is_dead(
            "# Finding\n\n**Status:** confirmed · submitted 2026-11-03 · FIX CONFIRMED 2026-11-04\n"))

    def test_fixed_by_vendor_marks_it_dead(self):
        self.assertTrue(chain_graph.is_dead(
            "**Status:** high, demonstrated, FIXED BY VENDOR on 2026-11-04\n"))

    def test_remediated_marks_it_dead(self):
        self.assertTrue(chain_graph.is_dead("**Status:** remediated\n"))

    def test_bare_not_fixed_does_NOT_kill_a_live_item(self):
        """The negation trap: substring matching on "FIXED" would kill this."""
        self.assertFalse(chain_graph.is_dead(
            "**Status:** primitive — the guard is broken and not fixed yet\n"))

    def test_unpatched_does_NOT_kill_a_live_item(self):
        self.assertFalse(chain_graph.is_dead(
            "**Status:** lead — the host is unpatched, so the advisory applies\n"))

    def test_refuted_still_works(self):
        self.assertTrue(chain_graph.is_dead("**Status:** REFUTED by its own controls\n"))

    def test_plain_live_status_is_not_dead(self):
        self.assertFalse(chain_graph.is_dead(
            "**Status:** primitive — capability confirmed, impact NOT demonstrated\n"))


if __name__ == "__main__":
    unittest.main()
