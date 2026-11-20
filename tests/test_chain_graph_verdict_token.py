"""A bare DEAD_WORD in narrative prose must not kill a live item.

Measured on rteam/activ 2026-11-13. `is_dead` substring-matched the WHOLE `**Status:**`
value, which in this workspace is a long narrative paragraph. A sweep of the engagement
flagged 47 items dead, of which at least 6 were false -- each killed by one incidental word
while the item's own leading verdict token said EXHAUSTED, STALLED, BLOCKED or "capability
proven".

The consequence was not cosmetic: `chain_graph` output is what the orchestrator reads to pick
lanes and write briefs, and `stop_gate` imports `is_dead` too. A partially-refuted primitive
that explicitly "keeps supplying" three slugs vanished from `have:`, its capability read as
MISSING with "nothing supplies it", and the next wave would have spent a lane re-deriving a
capability already on disk. A STALLED lead flagged RETRY disappeared instead of being retried.

The hazard was already known for FIXED/PATCHED (see the comment above REMEDIATED_WORDS) and
solved there by requiring a PHRASE, which cannot appear negated. That mitigation was never
applied to the bare words. These tests pin both halves: phrases still match anywhere, bare
verdict words match only as the leading token.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import chain_graph  # noqa: E402


class BareWordInProseDoesNotKill(unittest.TestCase):
    """Each string below is the real status line of an item that was wrongly classified."""

    def test_stalled_lead_saying_not_a_dead_host(self):
        # leads/alpha.activ.kz-staging-graphql-host.md -- said the OPPOSITE of dead
        self.assertFalse(chain_graph.is_dead(
            "**Status:** STALLED (2026-11-13) - curl exit 7 on 443 and exit 56 on 80. Our own "
            "channel never carried HTTP to this host, so this is our tooling and vantage, not "
            "the target refusing a test and not a dead host: port 80 still completes the TCP "
            "handshake. Needs a different channel or vantage, flagged RETRY.\n"))

    def test_exhausted_primitive_that_keeps_supplying(self):
        # primitives/web-kcell-external-camunda-workers-unauthenticated-route-map.md
        self.assertFalse(chain_graph.is_dead(
            "**Status:** EXHAUSTED (2026-11-13) - Route map stands PROVEN and keeps supplying "
            "route-map/unauth-reachable-api-handler/internal-service-name; what is closed is "
            "its arm 1. Second-parameter-position hypothesis REFUTED: 9 identity headers all "
            "left the route at the byte-identical 401.\n"))

    def test_capability_proven_impact_refuted(self):
        # primitives/web.kcell.kz-graphql-suggestions-public-title-only.md
        self.assertFalse(chain_graph.is_dead(
            "**Status:** capability proven, impact REFUTED. No named victim. Not a finding.\n"))

    def test_exhausted_with_capability_kept(self):
        # primitives/leasing-kcell-cors-arbitrary-origin-credentialed.md
        self.assertFalse(chain_graph.is_dead(
            "**Status:** EXHAUSTED (2026-11-13) - Credentialed half REFUTED by measurement, "
            "capability kept. Reflection is unconditional and rides on body-carrying "
            "responses.\n"))

    def test_exhausted_split_re_proved(self):
        # primitives/acpa-sandbox-prod-backend-split.md
        self.assertFalse(chain_graph.is_dead(
            "**Status:** EXHAUSTED (2026-11-13) - Split re-proved on three layers and nothing "
            "behind it: the OPTIONS-405-means-file-exists oracle fired and refuted on "
            "/favicon.ico /robots.txt /index.html.\n"))

    def test_blocked_lead_held_for_the_operator(self):
        # leads/web.kcell.kz-graphql-current-customer-msisdn.md -- BLOCKED, not dead
        self.assertFalse(chain_graph.is_dead(
            "**Status:** BLOCKED (2026-11-13) - Unauthenticated form REFUTED: four header "
            "spellings all return the byte-identical 26 B {\"data\":{\"Profile\":null}}. The "
            "ownership question needs one valid bearer token the operator does not have.\n"))


class LeadingVerdictTokenStillKills(unittest.TestCase):
    """The fix must not make the gate useless -- a real verdict still marks an item dead."""

    def test_leading_refuted_with_a_date(self):
        self.assertTrue(chain_graph.is_dead(
            "**Status:** REFUTED (2026-11-13) - the premise was measured false.\n"))

    def test_leading_dead_bullet_separated(self):
        self.assertTrue(chain_graph.is_dead("**Status:** DEAD · superseded by a newer lane\n"))

    def test_leading_killed_lowercase(self):
        self.assertTrue(chain_graph.is_dead("**Status:** killed by its own control arm\n"))

    def test_leading_superseded(self):
        self.assertTrue(chain_graph.is_dead("**Status:** SUPERSEDED: see the merged record\n"))

    def test_leading_withdrawn(self):
        self.assertTrue(chain_graph.is_dead("**Status:** WITHDRAWN, duplicate of another item\n"))

    def test_phrase_still_matches_mid_line(self):
        """A phrase cannot be negated, so it keeps matching anywhere -- the FIX CONFIRMED case."""
        self.assertTrue(chain_graph.is_dead(
            "**Status:** confirmed, submitted 2026-11-03, FIX CONFIRMED 2026-11-04\n"))

    def test_dead_heading_still_wins(self):
        self.assertTrue(chain_graph.is_dead("# REFUTED - the whole premise\n\nbody\n"))


if __name__ == "__main__":
    unittest.main()
