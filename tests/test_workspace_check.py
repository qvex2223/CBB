import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import workspace_check as wc  # noqa: E402


def _settings(tmp, scripts):
    hooks = {}
    for s in scripts:
        event, matcher = wc.HOOKS[s]
        g = {"hooks": [{"type": "command", "command": f"python3 {wc.REPO}/scripts/{s}"}]}
        if matcher:
            g["matcher"] = matcher + (".*" if matcher.endswith("_") else "")
        hooks.setdefault(event, []).append(g)
    p = Path(tmp) / "settings.json"
    p.write_text(json.dumps({"hooks": hooks}))
    return p


class HooksCheck(unittest.TestCase):
    def test_no_hooks_is_a_fail(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "settings.json"
            p.write_text("{}")
            r = wc.check_hooks(p)
            self.assertEqual(r[0]["status"], "FAIL")
            self.assertIn("mcp-gate.py", r[0]["detail"])

    def test_all_hooks_ok(self):
        with tempfile.TemporaryDirectory() as t:
            r = wc.check_hooks(_settings(t, wc.HOOKS))
            self.assertEqual([x["status"] for x in r], ["OK"])

    def test_wrong_matcher_counts_as_missing(self):
        with tempfile.TemporaryDirectory() as t:
            p = _settings(t, [s for s in wc.HOOKS if s != "mcp-gate.py"])
            s = json.loads(p.read_text())
            s["hooks"]["PreToolUse"].append({"matcher": "Bash", "hooks": [
                {"type": "command", "command": f"python3 {wc.REPO}/scripts/mcp-gate.py"}]})
            p.write_text(json.dumps(s))
            r = wc.check_hooks(p)
            self.assertEqual(r[0]["status"], "FAIL")
            self.assertIn("mcp-gate.py", r[0]["detail"])


class CopyCheck(unittest.TestCase):
    def test_stale_copy_fails(self):
        with tempfile.TemporaryDirectory() as t:
            repo, home = Path(t) / "repo", Path(t) / "home"
            (repo / "skills" / "a").mkdir(parents=True)
            (home / "skills" / "a").mkdir(parents=True)
            (repo / "skills" / "a" / "SKILL.md").write_text("new")
            (home / "skills" / "a" / "SKILL.md").write_text("old")
            r = wc.check_skill_copies(repo, home)
            self.assertEqual(r[0]["status"], "FAIL")
            (home / "skills" / "a" / "SKILL.md").write_text("new")
            self.assertEqual(wc.check_skill_copies(repo, home)[0]["status"], "OK")


class RewardCheck(unittest.TestCase):
    def test_zero_band_without_verdict_warns(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / "plat" / "prog"
            d.mkdir(parents=True)
            (d / "scope.md").write_text("## Reward bands (RUB)\n| Severity | Min | Max |\n"
                                        "|---|---|---|\n| medium | 0 | 0 |\n")
            self.assertEqual(wc.check_reward_models(t)[0]["status"], "WARN")
            (d / "scope.md").write_text("## Reward model (RUB)\n| medium | 0 | 0 |\n"
                                        "`onlyMaxPayment: true`\n")
            self.assertEqual(wc.check_reward_models(t)[0]["status"], "OK")


class BriefLines(unittest.TestCase):
    def test_only_fails_reach_the_brief(self):
        res = [wc._r("OK", "a", "x"), wc._r("WARN", "b", "y"), wc._r("FAIL", "c", "z", "do it")]
        lines = wc.brief_lines(res)
        self.assertEqual(len(lines), 1)
        self.assertIn("[c]", lines[0])


if __name__ == "__main__":
    unittest.main()
