"""Paid precedent must arrive without a dataset path and without an invented query.

Measured 2026-11-11 in session a0053cc0's transcript: `cbh report-intel` was named in 103
worker briefs and run 0 times. These tests hold the two things that made it unused — the
path argument and the query — out of the caller's hands, and hold retrieval off the queue's
critical path (a broken corpus costs the hint, not the lane).
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))
import precedent as pc  # noqa: E402
import lead_queue as lq  # noqa: E402

REPORTS = [
    {"id": "a", "source_url": "https://example.test/a", "severity": "critical",
     "bounty": "$12,000", "classes": ["rce", "graphql"],
     "first_signal": "GraphQL filter argument described as a free-form JSON object",
     "mechanic": "filter JSON reaches sift() and compiles a $where via new Function",
     "impact_proof": "id returned uid=1000", "lesson": "filter-operator",
     "keywords": ["graphql", "sift", "filter"]},
    {"id": "b", "source_url": "https://example.test/b", "severity": "high",
     "bounty": "$3,000", "classes": ["oauth", "auth-bypass"],
     "first_signal": "The interstitial text itself; he replayed the underlying form POST",
     "mechanic": "email verification enforced in the UI only",
     "impact_proof": "logged in unverified", "lesson": "sibling-interface",
     "keywords": ["oauth", "interstitial", "replay"]},
]


class Corpus(unittest.TestCase):
    def _root(self, *corpora):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: None)
        for i, rows in enumerate(corpora):
            c = d / "docs" / "disclosed-reports" / f"corpus-{i}"
            c.mkdir(parents=True)
            (c / "corpus.json").write_text(json.dumps(
                {"meta": {"source": f"s{i}", "licence": "public"}, "reports": rows}))
        pc._LOAD_CACHE.clear()
        pc._DF_CACHE.clear()
        return d

    def test_every_corpus_is_merged_without_a_path_argument(self):
        root = self._root(REPORTS[:1], REPORTS[1:])
        ds = pc.load(root)
        self.assertEqual(len(ds["reports"]), 2)
        self.assertEqual(len(ds["meta"]["corpora"]), 2)

    def test_the_same_report_in_two_corpora_is_counted_once(self):
        root = self._root(REPORTS, REPORTS[:1])
        self.assertEqual(len(pc.load(root)["reports"]), 2)

    def test_the_real_corpus_loads_and_declares_provenance(self):
        pc._LOAD_CACHE.clear()
        ds = pc.load()
        self.assertGreater(len(ds["reports"]), 100)
        for m in ds["meta"]["corpora"]:
            self.assertTrue(m.get("source"), m)

    def test_a_broken_corpus_file_does_not_raise(self):
        root = self._root(REPORTS)
        (root / "docs" / "disclosed-reports" / "corpus-0" / "corpus.json").write_text("{not json")
        pc._LOAD_CACHE.clear()
        self.assertEqual(pc.load(root)["reports"], [])


class Query(unittest.TestCase):
    def setUp(self):
        pc._LOAD_CACHE.clear()
        pc._DF_CACHE.clear()
        self.ds = pc.load()

    def test_workspace_vocabulary_never_reaches_the_query(self):
        q = pc.query_from_text("# a lead\n\nCBH_PROJECT=x bbcurl https://a.example/api/v1/x\n"
                               "poc_runtime spec, audit row, scope.md\n", dataset=self.ds)
        for w in ("bbcurl", "cbh_project", "poc_runtime", "scope", "audit"):
            self.assertNotIn(w, q.split(), q)

    def test_a_term_the_corpus_never_saw_is_dropped(self):
        q = pc.query_from_text("# zzqqxx\n\nzzqqxx zzqqxx zzqqxx jwt signature\n", dataset=self.ds)
        self.assertNotIn("zzqqxx", q.split())
        self.assertIn("jwt", q.split())

    def test_the_title_outweighs_the_body(self):
        q = pc.query_from_text("# deserialization pickle\n\n" + ("redirect " * 4), dataset=self.ds)
        terms = q.split()
        self.assertIn("pickle", terms)
        self.assertLess(terms.index("pickle"), terms.index("redirect"))

    def test_a_jwt_lead_retrieves_a_signature_precedent(self):
        text = ("# adn v1 sync parses an attacker-supplied JWT and names a user id\n\n"
                "The endpoint accepts a bearer token whose alg is none and whose signature "
                "is invalid, and still resolves the user claim.\n")
        hits = pc.match(pc.query_from_text(text, dataset=self.ds), limit=3)
        blob = json.dumps(hits).lower()
        self.assertTrue(any(w in blob for w in ("jwt", "signature", "alg")), blob[:300])


class Signals(unittest.TestCase):
    def test_a_body_matching_a_disclosed_opening_is_reported(self):
        ds = {"meta": {}, "reports": REPORTS}
        hits = pc.signals("the graphql endpoint takes a filter argument as a free-form "
                          "json object and calls sift", dataset=ds)
        self.assertTrue(hits)
        self.assertEqual(hits[0]["report"]["id"], "a")
        self.assertGreaterEqual(hits[0]["score"], 2)

    def test_one_shared_term_is_not_a_match(self):
        ds = {"meta": {}, "reports": REPORTS}
        self.assertEqual(pc.signals("nothing here but graphql", dataset=ds), [])


class QueueIntegration(unittest.TestCase):
    def test_a_missing_lead_file_costs_the_hint_not_the_lane(self):
        self.assertEqual(lq._precedent("leads/does-not-exist.md"), "")

    def test_the_hint_is_one_line_per_report(self):
        pc._LOAD_CACHE.clear()
        line = pc.lane_line("# oauth redirect_uri accepts a sibling host\n", limit=1)
        self.assertEqual(len([x for x in line.splitlines() if x.strip()]), 1)
        self.assertIn("precedent:", line)
        self.assertIn("FIRST SIGNAL", line)

    def test_an_exploding_retrieval_still_renders_the_queue(self):
        import unittest.mock as mock
        with mock.patch.object(pc, "lane_line", side_effect=RuntimeError("boom")):
            self.assertEqual(lq._precedent("leads/x.md"), "")


if __name__ == "__main__":
    unittest.main()


class OneLineIsReadable(unittest.TestCase):
    """21 of the 155 reports predate the corpus rebuild and carry no `first_signal`.

    `wu-09`'s is `None`, so the lane line read `FIRST SIGNAL:` followed by its `source_url`
    — the prose note `https://simonkoeck blog (site and title only; slug lost to
    compaction)` — as if the precedent were a dead link, and its `$90,000` printed as
    `90000.0` because `report_intel.search` normalises the field to a float.
    """

    def test_a_numeric_bounty_is_printed_as_money(self):
        self.assertEqual("$90,000", pc._money(90000.0))
        self.assertEqual("$617", pc._money(617))
        self.assertEqual("$50,000", pc._money("$50,000"))
        self.assertEqual("—", pc._money(None))

    def test_the_opening_falls_back_to_the_mechanic_then_the_first_step(self):
        self.assertEqual("FIRST SIGNAL: a header", pc._opening({"first_signal": "a header"}))
        self.assertEqual("MECHANIC: an internal admin API",
                         pc._opening({"first_signal": None, "mechanic": "an internal admin API"}))
        self.assertEqual("STEP 1: authenticate",
                         pc._opening({"mechanic": "", "chain": ["authenticate", "call"]}))
        self.assertEqual("", pc._opening({"chain": []}))

    def test_a_source_with_spaces_is_not_offered_as_a_link(self):
        self.assertEqual("https://hackerone.com/reports/1087489",
                         pc._source({"source_url": "https://hackerone.com/reports/1087489"}))
        self.assertIn("unresolved source",
                      pc._source({"url": "https://simonkoeck blog (slug lost to compaction)"}))
        self.assertEqual("", pc._source({}))

    def test_a_row_with_no_opening_at_all_is_not_emitted(self):
        ds = {"meta": {}, "reports": [
            {"id": "empty", "severity": "critical", "bounty": 1.0, "classes": ["ssrf"],
             "mechanic": "", "chain": [], "first_signal": None,
             "title": "ssrf fetcher allowlist bypass"},
            {"id": "usable", "severity": "high", "bounty": 2.0, "classes": ["ssrf"],
             "first_signal": "an ssrf fetcher that follows redirects",
             "title": "ssrf fetcher allowlist bypass"}]}
        line = "\n".join(f"        precedent: {pc._one_line(r)}  {pc._source(r)}".rstrip()
                         for r in ds["reports"] if pc._opening(r))
        self.assertIn("an ssrf fetcher", line)
        self.assertEqual(1, len(line.splitlines()), "the signal-less row took a slot")

    def test_the_live_line_for_the_declared_ozon_lead_has_no_bare_note(self):
        line = pc.lane_line("262 server-side micro-frontend render endpoints taking a "
                            "client-supplied route-url, missing_authorization on _mf/context")
        if not line:
            self.skipTest("corpus not present")
        self.assertNotIn("FIRST SIGNAL: https://", line)
        self.assertNotIn("90000.0", line)
