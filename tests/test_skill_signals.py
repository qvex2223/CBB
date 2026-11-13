#!/usr/bin/env python3
"""Regressions for the URL -> skill table that two hooks enforce.

Both cases below shipped as bugs and were found on live targets:
  * a repeated URL fell through to a lower-priority pattern, so the gate demanded
    a skill the URL never called for;
  * heredoc bodies were read as command lines, so writing a patch or a test file
    that merely mentioned a request was treated as firing one.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import skill_signals as ss  # noqa: E402


class Signals(unittest.TestCase):
    def test_one_url_can_contribute_multiple_relevant_skills(self):
        cmd = ("bbcurl -s https://t/api/v1/camunda-workers/external/x ; "
               "bbcurl -s https://t/api/v1/camunda-workers/external/x")
        skills = [s for _c, s, _b in ss.signals_for(cmd)]
        self.assertEqual(skills, ["hunt-auth-bypass", "hunt-api-misconfig"])

    def test_token_route_matches_oauth(self):
        skills = [s for _c, s, _b in ss.signals_for("bbcurl https://t/token")]
        self.assertIn("hunt-oauth", skills)

    def test_order_object_keeps_logic_idor_and_api_signals(self):
        skills = [s for _c, s, _b in ss.signals_for("bbcurl https://t/api/v1/orders/123")]
        self.assertEqual(skills, ["hunt-business-logic", "hunt-idor", "hunt-api-misconfig"])

    def test_distinct_urls_each_contribute(self):
        cmd = "bbcurl https://t/graphql ; bbcurl https://t/login"
        skills = {s for _c, s, _b in ss.signals_for(cmd)}
        self.assertEqual(skills, {"hunt-graphql", "hunt-auth-bypass"})

    def test_heredoc_body_is_not_a_command_line(self):
        cmd = ("cat > f.py <<'EOF'\n"
               "# bbcurl https://t/graphql is described here, not run\n"
               "EOF\necho done")
        self.assertFalse(ss.sends_request(cmd))
        self.assertEqual(ss.urls_in(cmd), [])

    def test_a_real_request_next_to_a_heredoc_still_gates(self):
        cmd = ("cat > f.md <<'EOF'\nhttps://t/api/v1/notes\nEOF\n"
               "bbcurl -s https://t/graphql")
        self.assertTrue(ss.sends_request(cmd))
        self.assertEqual([s for _c, s, _b in ss.signals_for(cmd)], ["hunt-graphql"])

    def test_gate_is_satisfied_once_the_named_skill_is_loaded(self):
        cmd = "bbcurl -s https://t/graphql"
        ok, missing = ss.satisfied(cmd, set())
        self.assertFalse(ok)
        self.assertEqual([s for _c, s in missing], ["hunt-graphql"])
        ok, missing = ss.satisfied(cmd, {"hunt-graphql"})
        self.assertTrue(ok)
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
