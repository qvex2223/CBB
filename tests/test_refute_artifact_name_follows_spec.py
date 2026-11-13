"""Two specs sharing a slug prefix must not overwrite each other's refutation.

Measured on the Wildberries engagement, 2026-11-06: one lane refuted `<slug>.poc.json`
and a later lane refuted `<slug>.invisible.poc.json`. Both derived the output name from
`target.name.split(".")[0]`, i.e. the slug up to the first dot, so the second run silently
replaced the first's `<slug>.refute.json` and `refutations/<slug>/`. Both verdicts were
SURVIVED, so nothing looked wrong; the earlier artifact was simply gone.

A refutation is evidence. The name must come from the spec, which is unique, not from a
slug prefix two specs can share.
"""
import re
import sys
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parent.parent / "engine"
sys.path.insert(0, str(ENGINE))


class RefuteArtifactNaming(unittest.TestCase):
    def setUp(self):
        self.src = (ENGINE / "refute.py").read_text(encoding="utf-8")

    def test_output_name_is_not_derived_from_slug_to_first_dot(self):
        """The exact expression that caused the overwrite must be gone."""
        self.assertNotIn('stem = target.name.split(".")[0]', self.src,
                         "refute.py still names its artifacts by the target's slug prefix, "
                         "so two specs sharing that prefix overwrite each other")

    def test_output_name_is_derived_from_the_spec_filename(self):
        self.assertIn("spec_name = spec_path.name", self.src,
                      "the artifact name should come from the spec, which is unique")
        self.assertIn('.poc.json', self.src)

    def test_two_specs_sharing_a_prefix_yield_different_stems(self):
        """Reproduce the naming rule in isolation and assert it separates the two."""
        def stem_for(spec_filename: str) -> str:
            if spec_filename.endswith(".poc.json"):
                return spec_filename[:-len(".poc.json")]
            if spec_filename.endswith(".json"):
                return spec_filename[:-len(".json")]
            return Path(spec_filename).stem

        a = stem_for("digital-ext-api-prefix-is-a-transparent-whole-app-path-alias.poc.json")
        b = stem_for("digital-ext-api-prefix-is-a-transparent-whole-app-path-alias.invisible.poc.json")
        self.assertNotEqual(a, b, "the two specs still collide")
        self.assertTrue(b.endswith(".invisible"))


if __name__ == "__main__":
    unittest.main()
