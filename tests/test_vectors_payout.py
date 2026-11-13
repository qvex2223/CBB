import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import vectors as v  # noqa: E402


class PayoutRanking(unittest.TestCase):
    def test_no_profile_keeps_old_order(self):
        rows = [{"class": "xss", "status": "untried"}, {"class": "rce", "status": "untried"}]
        self.assertEqual([r["class"] for r in v.rank(rows)], ["rce", "xss"])

    def test_downranked_class_drops_below_a_paid_one(self):
        prof = {"reward_by_class": {"csrf": 100000},
                "downrank_classes": {"open-redirect": "excluded without impact"}}
        rows = [{"class": "open-redirect", "status": "untried"},
                {"class": "csrf", "status": "untried"}]
        self.assertEqual(v.rank(rows)[0]["class"], "csrf")          # 50 > 40 already
        rows[1]["status"] = "active"                                 # csrf 50+10 vs redirect 40+20
        self.assertEqual(v.rank(rows)[0]["class"], "open-redirect")  # tie-ish without profile
        self.assertEqual(v.rank(rows, prof)[0]["class"], "csrf")     # programme decides

    def test_reward_profile_reads_profile_json(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "profile.json").write_text(json.dumps({"reward_by_class": {"rce": 10}}))
            self.assertEqual(v.reward_profile(Path(t))["reward_by_class"], {"rce": 10})
            self.assertEqual(v.payout_adjustment("rce", v.reward_profile(Path(t))), v.REWARD_BONUS_MAX)


if __name__ == "__main__":
    unittest.main()
