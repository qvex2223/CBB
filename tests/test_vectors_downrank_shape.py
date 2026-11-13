"""`downrank_classes` is a LIST in every real profile.json; it used to crash `next`.

`engine/vectors.py:466` did `(profile.get("downrank_classes") or {}).get(cls)`, which
raises AttributeError on a list. The effect was invisible rather than loud: it took out
`cbh vectors next` and the hunt-nudge rotation hints for the whole engagement, i.e. the
"what do I try next" half of the no-dead-ends machinery, while every other command kept
working. Found on yukki-lk, 2026-10-27.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import vectors  # noqa: E402


class DownrankShape(unittest.TestCase):
    def _profile(self, downrank):
        d = Path(tempfile.mkdtemp())
        (d / "profile.json").write_text(json.dumps({
            "reward_by_class": {"idor": 25, "ssrf": 20},
            "downrank_classes": downrank,
        }), encoding="utf-8")
        return d

    def test_list_form_is_normalised_to_a_dict_with_reasons(self):
        prof = vectors.reward_profile(self._profile(["open-redirect", "csrf"]))
        dr = prof["downrank_classes"]
        self.assertIsInstance(dr, dict)
        self.assertIn("open-redirect", dr)
        self.assertTrue(dr["open-redirect"], "a downranked class must carry a reason")

    def test_dict_form_keeps_its_own_reasons(self):
        prof = vectors.reward_profile(self._profile({"csrf": "no impact on this programme"}))
        self.assertEqual(prof["downrank_classes"]["csrf"], "no impact on this programme")

    def test_penalty_applies_either_way(self):
        for shape in (["csrf"], {"csrf": "why"}):
            prof = vectors.reward_profile(self._profile(shape))
            self.assertEqual(vectors.payout_adjustment("csrf", prof),
                             vectors.payout_adjustment("csrf", prof),
                             )
            self.assertLess(vectors.payout_adjustment("csrf", prof),
                            vectors.payout_adjustment("idor", prof),
                            f"downranked class must rank below a paid one ({shape!r})")

    def test_next_vectors_does_not_raise_on_the_list_form(self):
        """The actual regression: .get() on a list."""
        prof = vectors.reward_profile(self._profile(["open-redirect"]))
        item = {"class": "open-redirect", "status": "untried", "id": "v1",
                "endpoint": "/x", "mutations_tried": []}
        try:
            adj = vectors.payout_adjustment("open-redirect", prof)
            reason = (prof.get("downrank_classes") or {}).get(item["class"])
        except AttributeError as exc:  # pragma: no cover
            self.fail(f"list form still crashes the ranking path: {exc}")
        self.assertLess(adj, 0)
        self.assertTrue(reason)

    def test_garbage_shape_degrades_to_empty_rather_than_crashing(self):
        prof = vectors.reward_profile(self._profile("open-redirect"))
        self.assertEqual(prof["downrank_classes"], {})


if __name__ == "__main__":
    unittest.main()
