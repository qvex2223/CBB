"""Caido records every programme into ONE shared project, and nothing breaks when it is down.

Operator directive 2026-11-18: one project (`bughunter`) for every programme. Before it,
nothing chose the project, and the wolt and 1password hunts filed into a project named
after a programme that was not being hunted. These cases run offline: Caido unreachable or
unauthenticated must be a reported state, never an exception into a hook or a browser start.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))


class SharedProject(unittest.TestCase):
    def _run(self, *args, **env):
        e = dict(os.environ, **env)
        return subprocess.run([sys.executable, str(ROOT / "engine" / "caido_project.py"), *args],
                              capture_output=True, text=True, timeout=30, env=e)

    def test_one_name_for_every_programme(self):
        import caido_project
        self.assertEqual(caido_project.SHARED_PROJECT, "bughunter")

    def test_caido_down_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as d:
            tok = Path(d) / "token.json"
            tok.write_text('{"accessToken": "x"}')
            r = self._run("--ensure", CBH_CAIDO_URL="http://127.0.0.1:9", CAIDO_URL="",
                          CBH_CAIDO_TOKEN=str(tok))
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("Caido unreachable", r.stdout)
        self.assertNotIn("Traceback", r.stderr)

    def test_no_token_is_reported_not_raised(self):
        r = self._run("--ensure", CBH_CAIDO_TOKEN="/nonexistent/token.json")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no Caido token", r.stdout)

    def test_an_engagement_argument_is_accepted_and_ignored(self):
        r = self._run("intigriti/1password", CBH_CAIDO_TOKEN="/nonexistent/token.json")
        self.assertIn("want `bughunter`", r.stdout)


class RolesCarryTheWireRule(unittest.TestCase):
    def test_every_role_says_when_and_how(self):
        sys.path.insert(0, str(ROOT / "agents"))
        import gen_role_agents
        for path, text in gen_role_agents.plan().items():
            self.assertIn("## Browser + Caido: when, and how", text, path)
            self.assertIn('req.host.cont:"<domain>"', text, path)
            self.assertIn("`requestId` + `host`", text, path)


if __name__ == "__main__":
    unittest.main()
