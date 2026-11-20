"""Regression: a census is ONE scout lane over up to 30 hosts, never one lane per host.

Measured on Grok session 01a1e937 (hackerone/wolt, 2026-11-17). `wave()` dealt
`next_hosts` across every free slot with `hosts[i::free][:8]`, so six uncensused hosts and
six free slots came out as six scout lanes of one host each (`census batch:
corporate.wolt.com`, `census batch: consumer-api.wolt.com`, ...). Pacing is one flock'd
budget per engagement, so those six lanes fired no more requests per minute than one; each
only added a full worker context. Single-host lanes took 221M of the 428M tokens the
workers spent that session, for 0 findings.

Positive controls both ways: the census still covers every host it was handed (nothing is
dropped to save tokens), and a list longer than one batch still opens a second lane.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import autohunt  # noqa: E402
import lead_queue  # noqa: E402
import stop_gate  # noqa: E402


class CensusBatching(unittest.TestCase):
    def setUp(self):
        self.eng = Path(tempfile.mkdtemp())
        for tier in ("findings", "primitives", "leads"):
            (self.eng / tier).mkdir()

    def _wave(self, hosts, slots=6, open_items=0, wide=None):
        q = {"engagement": "t/t", "open": [
            {"file": f"leads/h{i}.example.com-x.md", "kind": "lead", "class": "",
             "needs": [], "title": f"Lead {i}", "reward": 0, "age_days": 1}
            for i in range(open_items)],
            "closed": [], "blocked": [], "stalled": [], "needs_account": {}}
        a = dict(stop_gate.assess(self.eng))
        a["claimed_but_unproven"] = []
        a["unrefuted"] = []
        a["next_hosts"] = list(hosts)[:6]          # what assess() hands over: capped at 6
        a["budget"] = {"requests": 0}
        seen = {}

        def fake_next_hosts(_eng, limit=6):
            seen["limit"] = limit
            return list(wide if wide is not None else hosts)[:limit]

        orig = (lead_queue.resolve_engagement, lead_queue.scan, stop_gate.assess,
                stop_gate.next_hosts)
        lead_queue.resolve_engagement = lambda *_: self.eng
        lead_queue.scan = lambda *_: q
        stop_gate.assess = lambda *_a, **_k: a
        stop_gate.next_hosts = fake_next_hosts
        try:
            w = autohunt.wave("t/t", slots, "")
        finally:
            (lead_queue.resolve_engagement, lead_queue.scan, stop_gate.assess,
             stop_gate.next_hosts) = orig
        w["_limit"] = seen.get("limit")
        return w

    @staticmethod
    def _scouts(w):
        return [b for b in w["briefs"] if b["role"] == "scout"]

    def test_six_hosts_six_slots_is_one_lane_not_six(self):
        hosts = [f"h{i}.example.com" for i in range(6)]
        s = self._scouts(self._wave(hosts))
        self.assertEqual(len(s), 1)
        self.assertEqual(s[0]["hosts"], hosts)

    def test_the_lane_is_widened_past_the_stop_gates_six(self):
        hosts = [f"h{i}.example.com" for i in range(25)]
        w = self._wave(hosts)
        s = self._scouts(w)
        self.assertEqual(len(s), 1)
        self.assertEqual(len(s[0]["hosts"]), 25)
        self.assertGreaterEqual(w["_limit"], 30)

    def test_more_than_one_batch_opens_a_second_lane_and_drops_nothing(self):
        hosts = [f"h{i}.example.com" for i in range(45)]
        s = self._scouts(self._wave(hosts))
        self.assertEqual(len(s), 2)
        got = sorted(h for b in s for h in b["hosts"])
        self.assertEqual(got, sorted(hosts))
        self.assertTrue(all(len(b["hosts"]) <= autohunt.SCOUT_BATCH_MAX for b in s))

    def test_never_more_than_the_wave_cap_of_census_lanes(self):
        hosts = [f"h{i}.example.com" for i in range(200)]
        s = self._scouts(self._wave(hosts))
        self.assertEqual(len(s), autohunt.SCOUT_LANES_MAX)

    def test_a_failing_widen_keeps_the_six_in_hand(self):
        hosts = [f"h{i}.example.com" for i in range(6)]
        s = self._scouts(self._wave(hosts, wide=[]))
        self.assertEqual(s[0]["hosts"], hosts)

    def test_idle_slots_are_counted_and_said_out_loud(self):
        w = self._wave([f"h{i}.example.com" for i in range(3)], slots=6, open_items=1)
        self.assertEqual(len(w["briefs"]), 2)
        self.assertEqual(w["idle_slots"], 4)
        text = autohunt.render(w)
        self.assertIn("IDLE", text)
        self.assertIn("Do NOT write new leads to fill them", text)

    def test_a_full_wave_prints_no_idle_line(self):
        w = self._wave([], slots=2, open_items=2)
        self.assertEqual(w["idle_slots"], 0)
        self.assertNotIn("  IDLE ", autohunt.render(w))

    def test_render_lists_every_host_even_past_the_title_cut(self):
        hosts = [f"a-long-hostname-{i}.example.com" for i in range(30)]
        text = autohunt.render(self._wave(hosts))
        for h in hosts:
            self.assertIn(h, text)


class WorkerReadingRule(unittest.TestCase):
    def test_every_role_tells_the_worker_not_to_read_notes_whole(self):
        sys.path.insert(0, str(ROOT / "agents"))
        import gen_role_agents
        for path, text in gen_role_agents.plan().items():
            self.assertIn("Do not read `notes.md` whole", text, path)
            self.assertIn("hosts/<host>.md", text, path)
            self.assertIn("is NOT yours: no `cbh client`", text, path)


if __name__ == "__main__":
    unittest.main()
