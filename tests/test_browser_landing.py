#!/usr/bin/env python3
"""A followed redirect is the one outbound hop nothing else here can see.

`scripts/mcp-gate.py` is a PreToolUse hook: it checks the URL handed to
`browser_navigate` and then the response is invisible to it. Measured 2026-11-12 on
standoff365/mail_vk, a navigation to the in-scope `https://e.mail.ru/` was redirected to
`id.vk.ru` — a host the engagement is NOT allowed to fetch — and no gate said a word.
`engine/poc_runtime.py` closed the same hole for specs by reading the redirect chain;
the browser can only be checked after the fact, so `scripts/mcp-hint.py` reads the
landing out of the tool result, says so loudly and writes it down. It cannot un-send the
request, and the notice says that too.

It must fail OPEN: an unreadable scope file is a workspace problem, and a hook that
invents an out-of-scope claim would be worse than the gap it closes.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "scripts" / "mcp-hint.py"
sys.path.insert(0, str(ROOT / "scripts"))


def _run(tool: str, text: str, memdir: str, project: str = ""):
    ev = {"tool_name": tool, "tool_response": {"content": [{"type": "text", "text": text}]}}
    env = dict(os.environ, CBH_MEMORY_DIR=memdir)
    env.pop("CBH_PROJECT", None)
    if project:
        env["CBH_PROJECT"] = project
    return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(ev),
                          capture_output=True, text=True, env=env, timeout=120)


class BrowserLanding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mem = self.tmp.name
        self.addCleanup(self.tmp.cleanup)

    def test_off_scope_landing_is_reported_and_logged(self):
        """The host nobody's scope.md admits: notice on stderr, row on disk."""
        r = _run("mcp__playwright__browser_navigate",
                 "- Page URL: https://landing-test.invalid/auth?x=1\n- Page Title: x",
                 self.mem)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("OFF-SCOPE LANDING", r.stderr)
        self.assertIn("landing-test.invalid", r.stderr)
        # The notice must not claim it blocked anything — it cannot.
        self.assertIn("already been sent", r.stderr)
        rows = (Path(self.mem) / "browser-landings.jsonl").read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(rows), 1)
        row = json.loads(rows[0])
        self.assertEqual(row["verdict"], "OUT-OF-SCOPE")
        self.assertIn("landing-test.invalid", row["landed_url"])

    def test_browser_control_url_is_silent(self):
        """about:blank fetches nothing; mcp-gate passes it and so must this."""
        r = _run("mcp__playwright__browser_navigate", "- Page URL: about:blank", self.mem)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((Path(self.mem) / "browser-landings.jsonl").exists())

    def test_non_browser_tool_is_silent(self):
        """A Caido listing that happens to quote a URL is not a landing."""
        r = _run("mcp__caido__caido_list_requests",
                 "- Page URL: https://landing-test.invalid/", self.mem)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_in_scope_landing_is_silent(self):
        """An engagement that admits the host gets no notice."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("mcp_hint", HOOK)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(mod._landing_notice("mcp__playwright__browser_navigate",
                                             "- Page URL: about:blank"), "")

    def test_scope_unreadable_fails_open(self):
        """No scope.md readable at all => no claim about the target."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("mcp_hint2", HOOK)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as empty:
            orig = sys.modules.get("paths")
            try:
                import paths  # type: ignore
                old = paths.targets_root
                paths.targets_root = lambda: empty  # no scope.md anywhere
                try:
                    self.assertTrue(mod._in_scope("https://landing-test.invalid/"))
                finally:
                    paths.targets_root = old
            except ImportError:
                self.skipTest("engine/paths.py not importable")
            finally:
                if orig is not None:
                    sys.modules["paths"] = orig


if __name__ == "__main__":
    unittest.main()
