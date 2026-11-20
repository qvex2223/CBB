"""Which agent CLI is driving the session — engine/client.py.

Measured 2026-11-14 on Grok Build session 01a1d946: `cbh client` answered
"Claude Code (claude) — detected by process ancestry" to a Grok session. It then ran a
3-worker crew instead of 6 and was told "you do NOT fire requests"; neither is Grok's row.
Two causes, both fixed here and both pinned below:

  1. `_PROC_MARKERS` matched the bare substring `claude` against twelve ancestor command
     lines, and this workspace puts that string in paths everywhere — the repo's own
     `Claude-BugHunter` symlink, `/tmp/claude-1000/...` scratchpads, `~/.claude/` config.
  2. `_from_env` knew only `CLAUDECODE`, while `runtime/inline-gate.mjs` and
     `runtime/playwright-mcp.mjs` resolve `GROK_*` FIRST — because Grok Build's compat
     layer leaks `CLAUDECODE=1`. Three detectors, one doctrine sentence claiming one.
"""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import client  # noqa: E402


class Tokens(unittest.TestCase):
    def test_basename_and_each_path_component_are_tokens(self):
        t = client._tokens("/usr/bin/claude --flag")
        self.assertIn("claude", t)
        self.assertIn("usr", t)
        self.assertIn("--flag", t)

    def test_the_near_misses_that_caused_the_incident_are_not_tokens(self):
        for line in (
            # the repo's own compatibility symlink
            "python3 /home/qvex/security-research/Claude-BugHunter/cbh/cli.py client",
            # a Claude scratchpad path, which any client can be handed
            "python3 /tmp/claude-1000/-home-qvex-x/abc/scratchpad/p.py",
            # shared config that Grok also reads (it loads plugins from ~/.claude/)
            "/bin/bash -c source /home/qvex/.claude/shell-snapshots/snapshot-bash-1.sh",
            # the model name, which appears in env and in briefs
            "worker --model claude-opus-5",
        ):
            with self.subTest(line=line):
                self.assertNotIn("claude", client._tokens(line), line)

    def test_a_real_launcher_path_still_tokenises(self):
        # `claude-code` is a marker in its own right, so an npm-style launch is recognised.
        t = client._tokens("node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js")
        self.assertIn("claude-code", t)
        self.assertNotIn("claude", t)


class FromProc(unittest.TestCase):
    def _anc(self, *lines):
        return mock.patch.object(client, "_ancestry", lambda: list(lines))

    def test_bare_substring_no_longer_identifies_a_client(self):
        with self._anc("python3 /tmp/claude-1000/x/p.py", "/usr/bin/bash"):
            self.assertEqual(client._from_proc(), "")

    def test_the_claude_binary_identifies_claude(self):
        with self._anc("python3 /tmp/x/p.py", "claude "):
            self.assertEqual(client._from_proc(), "claude")

    def test_the_grok_binary_takes_the_generic_row(self):
        with self._anc("python3 /tmp/x/p.py", "grok ", "/usr/bin/bash"):
            self.assertEqual(client._from_proc(), "generic")

    def test_nearest_ancestor_wins(self):
        # A far ancestor must not outvote the process actually driving the session.
        with self._anc("grok ", "claude "):
            self.assertEqual(client._from_proc(), "generic")
        with self._anc("claude ", "grok "):
            self.assertEqual(client._from_proc(), "claude")


class FromEnv(unittest.TestCase):
    def _env(self, **kw):
        return mock.patch.dict(os.environ, kw, clear=True)

    def test_grok_markers_win_over_a_leaked_claudecode(self):
        # The documented reason, from runtime/playwright-mcp.mjs: "Grok Build's compat layer
        # leaks CLAUDECODE=1 into MCP, so GROK_AGENT / GROK_SESSION_ID still win."
        with self._env(GROK_AGENT="1", CLAUDECODE="1"):
            self.assertEqual(client._from_env(), "generic")
        with self._env(GROK_SESSION_ID="01a1d946", CLAUDECODE="1"):
            self.assertEqual(client._from_env(), "generic")

    def test_claudecode_alone_is_claude(self):
        with self._env(CLAUDECODE="1"):
            self.assertEqual(client._from_env(), "claude")

    def test_nothing_set_is_no_verdict(self):
        with self._env():
            self.assertEqual(client._from_env(), "")


class Detect(unittest.TestCase):
    def test_explicit_override_beats_everything(self):
        with mock.patch.dict(os.environ, {"CBH_AGENT": "claude", "GROK_AGENT": "1"}, clear=True):
            self.assertEqual(client.detect(), "claude")

    def test_a_grok_session_in_a_claude_shaped_tree_is_generic(self):
        """The incident, end to end."""
        with mock.patch.dict(os.environ, {"GROK_AGENT": "1"}, clear=True), \
             mock.patch.object(client, "_ancestry", lambda: [
                 "python3 /home/qvex/security-research/Claude-BugHunter/cbh/cli.py client",
                 "/bin/bash -c source /home/qvex/.claude/shell-snapshots/s.sh",
                 "grok ",
             ]):
            self.assertEqual(client.detect(), "generic")
            row = client.profile(client.detect())
            self.assertEqual(row["crew"], 6)
            self.assertTrue(row["orchestrator_may_send"])
            self.assertFalse(row["gates_enforced"])

    def test_a_claude_session_is_still_claude(self):
        with mock.patch.dict(os.environ, {"CLAUDECODE": "1"}, clear=True):
            self.assertEqual(client.detect(), "claude")
            row = client.profile("claude")
            self.assertEqual(row["crew"], 3)
            self.assertFalse(row["orchestrator_may_send"])

    def test_unknown_client_falls_back_to_generic(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(client, "_ancestry", lambda: ["/usr/bin/bash"]):
            self.assertEqual(client.detect(), "generic")


class AgreesWithTheRuntimeGates(unittest.TestCase):
    """The doctrine says client.py is the one table every detector delegates to."""

    def test_the_js_gates_resolve_grok_before_claudecode_too(self):
        # Scoped to the function BODY: the file's header comment names CLAUDECODE first,
        # and asserting a raw file offset would have read that comment as the order.
        repo = Path(__file__).resolve().parent.parent
        src = (repo / "runtime" / "inline-gate.mjs").read_text()
        start = src.index("export function inlineGateActive()")
        body = src[start:src.index("\n}", start)]
        self.assertLess(body.index("GROK_AGENT"), body.index("CLAUDECODE"),
                        "inline-gate resolves CLAUDECODE before GROK_*; client.py must match it")

    def test_client_py_names_grok_at_all(self):
        # It named it zero times before 2026-11-14, which is how the two detectors diverged.
        src = (Path(__file__).resolve().parent.parent / "engine" / "client.py").read_text()
        self.assertIn("GROK_AGENT", src)
        self.assertIn("GROK_SESSION_ID", src)


if __name__ == "__main__":
    unittest.main()
