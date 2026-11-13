"""A mutation label the caller typed must either register or be refused.

`mark --mutation` recorded the raw string while the `dead` guard compared
against the exact matrix text, so every shorthand label silently registered
nothing and the refusal printed a count that contradicted its own "next one".
Found on a live target (HUNTER-LK-ALFA, 2026-10-27), not on a bench.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import vectors  # noqa: E402


class ResolveMutation(unittest.TestCase):
    def test_exact_matrix_string_resolves_to_itself(self):
        m = vectors.GENERIC_MUTATIONS[0]
        self.assertEqual(vectors.resolve_mutation("idor", m), m)

    def test_one_based_index_resolves(self):
        matrix = vectors.mutations_for("idor")
        self.assertEqual(vectors.resolve_mutation("idor", "1"), matrix[0])
        self.assertEqual(vectors.resolve_mutation("idor", str(len(matrix))), matrix[-1])

    def test_index_out_of_range_is_not_resolved(self):
        matrix = vectors.mutations_for("idor")
        self.assertIsNone(vectors.resolve_mutation("idor", str(len(matrix) + 1)))
        self.assertIsNone(vectors.resolve_mutation("idor", "0"))

    def test_unambiguous_prefix_resolves_case_insensitively(self):
        got = vectors.resolve_mutation("idor", "Method Swap")
        self.assertIsNotNone(got)
        self.assertTrue(got.startswith("method swap"))

    def test_label_matching_nothing_is_not_resolved(self):
        self.assertIsNone(vectors.resolve_mutation("idor", "qvexmarker99813"))

    def test_ambiguous_label_is_refused_rather_than_guessed(self):
        # "auth " prefixes both "auth removal" and "auth downgrade".
        self.assertIsNone(vectors.resolve_mutation("idor", "auth "))


class UntriedCount(unittest.TestCase):
    def test_count_comes_from_the_matrix_not_the_list_length(self):
        matrix = vectors.mutations_for("idor")
        vec = {"class": "idor", "mutations_tried": ["junk"] * len(matrix)}
        # Every label is unrecognised, so nothing is actually burned.
        self.assertEqual(len(vectors.untried_mutations(vec)), len(matrix))
        self.assertEqual(vectors.untried_mutations(vec)[0], vectors.next_mutation(vec))

    def test_guard_count_and_next_one_agree(self):
        matrix = vectors.mutations_for("idor")
        vec = {"class": "idor", "mutations_tried": list(matrix[:3])}
        untried = vectors.untried_mutations(vec)
        self.assertEqual(len(untried), len(matrix) - 3)
        self.assertEqual(untried[0], vectors.next_mutation(vec))


class MarkRefusesUnrecognisedLabels(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.memdir = Path(self.tmp.name)
        ledger = vectors.seed("uni2.example.test", endpoints=["/"],
                              classes=["idor"], memdir=self.memdir)
        vectors.save(ledger, self.memdir)
        self.ledger = vectors.load("uni2.example.test", self.memdir)
        self.vid = self.ledger["vectors"][0]["id"]
        self.vclass = self.ledger["vectors"][0]["class"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_unrecognised_label_is_refused_and_prints_the_matrix(self):
        with self.assertRaises(SystemExit) as cm:
            vectors.mark("uni2.example.test", self.vid, "active",
                         mutation="shorthand-nobody-defined", memdir=self.memdir)
        msg = str(cm.exception)
        self.assertIn("unrecognised mutation label", msg)
        self.assertIn("1. ", msg)

    def test_a_number_registers_the_canonical_string(self):
        v = vectors.mark("uni2.example.test", self.vid, "active",
                         mutation="1", requests=1, memdir=self.memdir)
        self.assertEqual(v["mutations_tried"], [vectors.mutations_for(self.vclass)[0]])

    def test_same_mutation_twice_is_recorded_once(self):
        vectors.mark("uni2.example.test", self.vid, "active",
                     mutation="1", requests=1, memdir=self.memdir)
        v = vectors.mark("uni2.example.test", self.vid, "active",
                         mutation=vectors.mutations_for(self.vclass)[0],
                         requests=1, memdir=self.memdir)
        self.assertEqual(len(v["mutations_tried"]), 1)


if __name__ == "__main__":
    unittest.main()
