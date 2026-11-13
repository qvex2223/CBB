"""Regression: a SPEC's evidence must be its own, never a neighbour's.

`collect()` widened from a spec file to its whole directory (and the grandparent), so with
two lanes sharing `primitives/` one lane's `cbh evidence` returned the OTHER lane's
.result.json — and that lane's KILLED refutation with it, reporting REFUTED for a spec that
had actually survived (measured 2026-11-05). A finding file may still fall back to the
directory: it names its endpoint in prose and the caller matches on that.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import evidence  # noqa: E402


class SpecEvidenceIsSpecScoped(unittest.TestCase):
    def _shared_dir(self, tmp: Path) -> Path:
        d = tmp / "primitives"
        d.mkdir()
        (d / "mine.poc.json").write_text('{"method":"GET","url":"https://mine.example/x"}')
        (d / "mine.poc.result.json").write_text('{"verdict":"PASS"}')
        (d / "other.poc.result.json").write_text('{"verdict":"FAIL"}')
        return d

    def test_spec_gets_only_its_own_result(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._shared_dir(Path(td))
            names = [p.name for p in evidence.collect(d / "mine.poc.json")]
            self.assertEqual(names, ["mine.poc.result.json"])

    def test_spec_without_its_own_result_does_not_borrow_silently(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._shared_dir(Path(td))
            (d / "mine.poc.result.json").unlink()
            names = [p.name for p in evidence.collect(d / "mine.poc.json")]
            self.assertNotIn("mine.poc.result.json", names)

    def test_a_directory_still_collects_everything_in_it(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._shared_dir(Path(td))
            names = {p.name for p in evidence.collect(d)}
            self.assertIn("mine.poc.result.json", names)
            self.assertIn("other.poc.result.json", names)


if __name__ == "__main__":
    unittest.main()
