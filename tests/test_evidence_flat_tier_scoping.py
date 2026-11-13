"""A write-up in a flat tier directory must not adopt a sibling's artifacts.

Measured on the Wildberries engagement, 2026-11-05: a `primitives/` entry with no
artifacts of its own came back REFUTED. `collect()` climbed to `parent.parent` and
pooled the whole engagement (four PASS artifacts from other hosts, each reported
"[endpoint not mentioned in the finding]"), and the refutation lookup adopted every
`*.refute.json` in the directory because the `own` set was empty — so the KILLED was
read out of a different finding's refutation.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import evidence  # noqa: E402


def _result(path: Path, url: str, verdict: str = "PASS") -> None:
    path.write_text(json.dumps({"verdict": verdict, "url": url,
                                "status": 200, "final_url": url}), encoding="utf-8")


class FlatTierScoping(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.prims = self.root / "primitives"
        self.prims.mkdir()
        # The write-up under test: prose only, no artifact of its own.
        self.mine = self.prims / "mine.md"
        self.mine.write_text("# Primitive\n\nGET https://mine.example/api/thing\n",
                             encoding="utf-8")
        # A sibling write-up that DOES own a spec, a result and a KILLED refutation.
        (self.prims / "other.md").write_text(
            "# Other primitive\n\nGET https://other.example/api/else\n", encoding="utf-8")
        _result(self.prims / "other.result.json", "https://other.example/api/else")
        # The `.poc` infix form, which is how poc_runtime actually names them.
        _result(self.prims / "other.poc.result.json", "https://other.example/api/else")
        (self.prims / "other.refute.json").write_text(
            json.dumps({"spec_file": "other.json", "verdict": "KILLED"}), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_sibling_owned_result_is_not_pooled(self):
        got = evidence.collect(self.mine)
        self.assertNotIn(self.prims / "other.result.json", got,
                         "an artifact named after a sibling write-up was adopted")

    def test_sibling_poc_infix_result_is_not_pooled(self):
        got = evidence.collect(self.mine)
        self.assertNotIn(self.prims / "other.poc.result.json", got,
                         "a sibling's `<slug>.poc.result.json` was adopted")

    def test_engagement_root_is_not_swept(self):
        findings = self.root / "findings" / "elsewhere"
        findings.mkdir(parents=True)
        _result(findings / "elsewhere.result.json", "https://elsewhere.example/x")
        got = evidence.collect(self.mine)
        self.assertEqual([], [p for p in got if "elsewhere" in str(p)],
                         "collect() climbed above the tier directory")

    def test_sibling_refutation_is_not_adopted(self):
        cands = evidence._refute_candidates(self.mine)
        self.assertNotIn(self.prims / "other.refute.json", cands,
                         "a sibling's refutation was credited to this write-up")

    def test_own_folder_evidence_still_found(self):
        own = self.prims / "mine"
        own.mkdir()
        _result(own / "proof.result.json", "https://mine.example/api/thing")
        got = evidence.collect(self.mine)
        self.assertIn(own / "proof.result.json", got,
                      "a finding's own evidence folder must still be searched")


if __name__ == "__main__":
    unittest.main()


class OrphanedArtifactsAreNotEvidence(unittest.TestCase):
    """The false-DEMONSTRATED direction, which is the dangerous one.

    After a first fix excluded only artifacts owned by a sibling `.md`, an ORPHANED
    artifact (no matching write-up at all, from another host entirely) stayed in the pool,
    matched on a URL token, and a primitive whose own text says impact is NOT demonstrated
    came back as "Q1/Q6 backed by a fired PoC".
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.prims = Path(self.tmp.name) / "primitives"
        self.prims.mkdir(parents=True)
        self.mine = self.prims / "mine.md"
        self.mine.write_text(
            "# Primitive\n\nGET https://mine.example/api/v1/thing — impact NOT demonstrated.\n",
            encoding="utf-8")
        # An orphan: named after no write-up in this directory, and for another host.
        _result(self.prims / "someone-elses-probe.poc.result.json",
                "https://other-host.example/api/v1/thing")

    def tearDown(self):
        self.tmp.cleanup()

    def test_orphaned_artifact_is_not_pooled(self):
        got = evidence.collect(self.mine)
        self.assertEqual([], got,
                         "an orphaned artifact from another host was offered as this "
                         "write-up's evidence")
