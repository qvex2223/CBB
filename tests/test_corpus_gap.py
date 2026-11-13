"""An ingested technique with no landed check must FAIL, loudly.

Written 2026-11-13. `docs/disclosed-reports/corpus-2026-11-13/known-urls.txt` had held 155
research URLs since the day it was built, and a measurement that day found 8 of 10
techniques from the operator's digest with no check in any skill — `filename*`, the RSC
Flight framing, the cached-OAuth-302 chain and the CSS token-limit stitching had zero
occurrences under `skills/`. Questions 1-3 of `corpus_gap` could not see that: they read
the whole toolkit, so a keyword that lives anywhere scores, and both arms of a before/after
measurement returned 100% technique coverage. Question 4 (`landed_in`) reads only the file
the record names, which is what makes a deleted or never-written check fail.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))
import corpus_gap as cg  # noqa: E402

CORPUS = REPO / "docs" / "disclosed-reports" / "corpus-2026-11-13" / "corpus.json"


class LandedField(unittest.TestCase):
    def test_a_record_naming_no_file_is_unlanded_not_failed(self):
        """161 of the 171 records here predate the field; one mark cannot cover both
        "the check was deleted" and "this record never named one"."""
        r = cg.landed_check({"id": "x"}, REPO, ["anything"])
        self.assertIsNone(r["landed_ok"])
        self.assertEqual(r["landed_reason"], "no landed_in field")

    def test_paths_come_out_of_the_prose(self):
        r = {"landed_in": "skills/hunt-dom/SKILL.md (Phase 7) + engine/vectors.py"}
        self.assertEqual(cg.landed_paths(r), ["engine/vectors.py", "skills/hunt-dom/SKILL.md"])

    def test_a_named_file_that_is_gone_fails(self):
        r = cg.landed_check({"landed_in": "skills/hunt-not-a-skill/SKILL.md"}, REPO, ["k"])
        self.assertFalse(r["landed_ok"])
        self.assertIn("not in this checkout", r["landed_reason"])

    def test_the_keywords_are_read_in_that_file_only(self):
        d = Path(tempfile.mkdtemp())
        (d / "skills" / "hunt-x").mkdir(parents=True)
        (d / "skills" / "hunt-x" / "SKILL.md").write_text("the marker phrase lives here", encoding="utf-8")
        (d / "skills" / "hunt-y").mkdir(parents=True)
        (d / "skills" / "hunt-y" / "SKILL.md").write_text("the marker phrase drifted here", encoding="utf-8")
        rec = {"landed_in": "skills/hunt-x/SKILL.md"}
        self.assertTrue(cg.landed_check(rec, d, ["marker phrase"])["landed_ok"])
        drifted = {"landed_in": "skills/hunt-y/SKILL.md"}
        self.assertTrue(cg.landed_check(drifted, d, ["marker phrase"])["landed_ok"])
        (d / "skills" / "hunt-x" / "SKILL.md").write_text("the check was deleted", encoding="utf-8")
        self.assertFalse(cg.landed_check(rec, d, ["marker phrase"])["landed_ok"])


class TheShippedTechniqueCorpus(unittest.TestCase):
    """The 2026-11-13 digest: every record must still be in the skill it names."""

    def setUp(self):
        self.assertTrue(CORPUS.exists(), f"{CORPUS} is the record of what was ingested")
        self.doc = json.loads(CORPUS.read_text(encoding="utf-8"))

    def test_every_record_names_a_file_and_its_check_is_still_there(self):
        rep = cg.run(CORPUS, REPO)
        self.assertEqual(rep["landed_failures"], [],
                         "a technique was ingested and its check is not in the skill it names")
        self.assertEqual(rep["unlanded"], 0, "every record in this corpus names its file")

    def test_the_keywords_are_specific_not_general_security_vocabulary(self):
        """A keyword set that scores on any skill measures vocabulary, not a check.

        `_hit` counts 60% of a phrase's words anywhere in the file, so a descriptive
        keyword ('crlf injection' in a CRLF skill) passes before the check exists —
        measured 2026-11-13, when both arms of a before/after run returned 100%. These
        sets are checked against skills none of this work touched.
        """
        controls = ["skills/hunt-sqli/SKILL.md", "skills/hunt-ssrf/SKILL.md",
                    "skills/hunt-idor/SKILL.md"]
        texts = [(c, (REPO / c).read_text(encoding="utf-8").lower()) for c in controls]
        for r in self.doc["reports"]:
            kws = r["keywords"]
            for name, text in texts:
                hits = [k for k in kws if cg._hit(k, text)]
                self.assertLess(len(hits) / len(kws), 0.34,
                                f"{r['id']}: {hits} score in {name}, which holds none of these checks")

    def test_no_url_is_invented(self):
        known = (CORPUS.parent / "known-urls.txt").read_text(encoding="utf-8")
        for r in self.doc["reports"]:
            if r.get("ref_url"):
                self.assertIn(r["ref_url"], known,
                              f"{r['ref_url']} is not in this folder's known-urls.txt")

    def test_the_dedupe_key_is_left_free(self):
        """`precedent.load` dedupes by `source_url`; five of these URLs already have a
        record in another corpus, so a URL here would have dropped one of the two."""
        for r in self.doc["reports"]:
            self.assertIsNone(r.get("source_url"), f"{r['id']}: use ref_url, not source_url")

    def test_a_technique_record_claims_no_bounty(self):
        for r in self.doc["reports"]:
            self.assertIsNone(r.get("bounty"), f"{r['id']}: a technique write-up has no bounty to cite")


if __name__ == "__main__":
    unittest.main()
