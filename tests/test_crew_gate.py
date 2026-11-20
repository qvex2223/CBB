"""crew-gate: during an armed hunt the orchestrator does not fire requests.

Operator, 2026-10-21: "мне нужно что бы постоянно мульти агентность работала".
On 2026-10-20 four armed hunts ran with zero workers because the orchestration rule
lived only in prose. These tests pin the decision table so it cannot drift back.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))
GATE = REPO / "scripts" / "crew-gate.py"

spec = importlib.util.spec_from_file_location("crew_gate", GATE)
cg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cg)


def _engagement():
    """A throwaway Targets/<name>/ so find_project_dir() resolves without a live one."""
    root = Path(tempfile.mkdtemp())
    eng = root / "Targets" / "lab" / "demo"
    eng.mkdir(parents=True)
    (eng / "scope.md").write_text("# scope\n- `*.example.test`\n", encoding="utf-8")
    (eng / "profile.json").write_text("{}", encoding="utf-8")
    return root, eng


def _run(ev, cwd, **env):
    e = dict(os.environ)
    e.update({"CBH_MEMORY_DIR": tempfile.mkdtemp(), "CBH_CAIDO_AUTOSTART": "off",
              "CBH_TARGETS_ROOT": str(Path(cwd).parents[1])})
    e.pop("CBH_AGENT_ROLE", None)
    e.pop("CBH_CREW_GATE", None)
    # Claude path is the default under test. A bare shell carries no client flag at
    # all, which client() reads as `generic` — a client the gate leaves alone — so pin
    # Claude here instead of inheriting whatever launched the suite.
    e.pop("CBH_AGENT", None)
    # `_from_env()` in engine/client.py checks GROK_AGENT / GROK_SESSION_ID BEFORE
    # CLAUDECODE, by design: Grok Build's compat layer leaks CLAUDECODE=1, so the Grok
    # markers have to win there. The consequence here is that popping CBH_AGENT and
    # setting CLAUDECODE=1 does NOT pin Claude while the suite is launched from a Grok
    # process — the inherited marker still decides, the gate correctly leaves that client
    # alone, and the assertion below fails for an environmental reason. Measured
    # 2026-11-17 from inside Grok Build: 13 failures and 3 errors across test_crew,
    # test_crew_gate, test_control_guard and test_mcp_gate, with the same tree green under
    # Claude Code. A test must pin the row it asserts.
    e.pop("GROK_AGENT", None)
    e.pop("GROK_SESSION_ID", None)
    e["CLAUDECODE"] = "1"
    e.update(env)
    p = subprocess.run([sys.executable, str(GATE)], input=json.dumps(ev), text=True,
                       capture_output=True, cwd=cwd, env=e)
    if not p.stdout.strip():
        return "allow"
    return json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"]


BB = {"tool_name": "Bash", "tool_input": {"command": "bbcurl https://app.example.test/x"}}


class Decisions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root, cls.eng = _engagement()

    def test_orchestrator_request_is_denied_while_armed(self):
        self.assertEqual("deny", _run(BB, self.eng, CBH_HUNT_MODE="on"))

    def test_subagent_request_passes(self):
        self.assertEqual("allow", _run(dict(BB, agent_id="a-1"), self.eng, CBH_HUNT_MODE="on"))

    def test_cli_worker_request_passes(self):
        self.assertEqual("allow", _run(BB, self.eng, CBH_HUNT_MODE="on", CBH_AGENT_ROLE="worker"))

    def test_another_client_is_not_the_claude_orchestrator_deny(self):
        """A client whose subagents are its own processes carries no agent_id here. The
        Claude deny would block every sender it has (engine/client.py holds the row)."""
        self.assertEqual("allow", _run(BB, self.eng, CBH_HUNT_MODE="on", CBH_AGENT="generic"))

    def test_unarmed_session_is_never_gated(self):
        self.assertEqual("allow", _run(BB, self.eng, CBH_HUNT_MODE="off"))

    def test_outside_an_engagement_is_never_gated(self):
        self.assertEqual("allow", _run(BB, tempfile.mkdtemp(), CBH_HUNT_MODE="on"))

    def test_override_passes_and_is_audited(self):
        mem = tempfile.mkdtemp()
        ev = {"tool_name": "Bash", "tool_input": {
            "command": "bbcurl https://app.example.test/x # crew-gate: override operator asked"}}
        self.assertEqual("allow", _run(ev, self.eng, CBH_HUNT_MODE="on", CBH_MEMORY_DIR=mem))
        rows = [json.loads(l) for l in (Path(mem) / "audit.jsonl").read_text().splitlines()]
        self.assertTrue(any(r.get("source") == "crew-gate" and r.get("event") == "override"
                            for r in rows))

    def test_env_switch_disables(self):
        self.assertEqual("allow", _run(BB, self.eng, CBH_HUNT_MODE="on", CBH_CREW_GATE="off"))

    def _deny_reason(self, settings_env):
        """Run the gate with HOME pointed at a fixture, so the recipe it prints depends
        on that fixture's wiring and not on the machine running the tests."""
        home = tempfile.mkdtemp()
        (Path(home) / ".claude").mkdir()
        (Path(home) / ".claude" / "settings.json").write_text(
            json.dumps({"env": settings_env}), encoding="utf-8")
        e = dict(os.environ, CBH_MEMORY_DIR=tempfile.mkdtemp(), CBH_HUNT_MODE="on",
                 CBH_CAIDO_AUTOSTART="off", CBH_TARGETS_ROOT=str(self.root / "Targets"),
                 HOME=home)
        e.pop("CBH_AGENT_ROLE", None)
        e.pop("CBH_AGENT", None)
        # Same pin as `_run` above, and for the same reason: GROK_AGENT / GROK_SESSION_ID
        # outrank CLAUDECODE in engine/client.py's `_from_env()`, so without this the gate
        # leaves a Grok-launched suite alone, prints nothing, and `json.loads("")` raises.
        e.pop("GROK_AGENT", None)
        e.pop("GROK_SESSION_ID", None)
        e["CLAUDECODE"] = "1"
        out = subprocess.run([sys.executable, str(GATE)], input=json.dumps(BB), text=True,
                             capture_output=True, cwd=self.eng, env=e).stdout
        return json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]

    def test_the_deny_names_the_agent_tool_and_the_crew(self):
        """A deny that only forbids is a dead end: the operator reads the recipe off it.

        Until 2026-11-13 this text had a second branch — a background `claude -p` on a
        second provider, printed when the local router was down. Both are gone, so the
        way through is the `Agent` tool and nothing else.
        """
        reason = self._deny_reason({})
        for must in ("Agent(subagent_type=", "deep-hunter", "Scout", "Hunter", "Freeroam",
                     "bbcurl", "crew-gate: override"):
            self.assertIn(must, reason)

    def test_the_deny_never_names_a_background_process(self):
        """`agent-gate` denies those spellings, so printing one here sends the operator
        into a second deny."""
        reason = self._deny_reason({})
        for must_not in ("claude -p", "cbh worker", "--print"):
            self.assertNotIn(must_not, reason)


class WhatCountsAsFiring(unittest.TestCase):
    def test_network_senders(self):
        for ev in (BB,
                   {"tool_name": "Bash", "tool_input": {"command": "nomore403 -u https://a.example.test/admin"}},
                   {"tool_name": "mcp__caido__caido_send_request", "tool_input": {}},
                   {"tool_name": "mcp__caido__caido_batch_send", "tool_input": {}},
                   {"tool_name": "mcp__playwright__browser_navigate", "tool_input": {}},
                   {"tool_name": "mcp__playwright__browser_click", "tool_input": {}}):
            self.assertTrue(cg.fires_request(ev), ev)

    def test_merge_and_offline_work_stays_with_the_orchestrator(self):
        for ev in ({"tool_name": "Bash", "tool_input": {"command": "bbcurl --bb-dry-run https://a.example.test/"}},
                   {"tool_name": "Bash", "tool_input": {"command": "jsluice urls /tmp/a.js"}},
                   {"tool_name": "Bash", "tool_input": {"command": "curl http://127.0.0.1:8080/"}},
                   {"tool_name": "Bash", "tool_input": {"command": "cbh vectors next app.example.test"}},
                   {"tool_name": "mcp__caido__caido_list_requests", "tool_input": {}},
                   {"tool_name": "mcp__caido__caido_get_request", "tool_input": {}},
                   {"tool_name": "mcp__playwright__browser_snapshot", "tool_input": {}},
                   {"tool_name": "Read", "tool_input": {}}):
            self.assertFalse(cg.fires_request(ev), ev)


class WorkerModel(unittest.TestCase):
    def test_one_default_no_stale_literals(self):
        import agent
        self.assertEqual("claude-sonnet-5-5", agent.DEFAULT_WORKER_MODEL)
        for f in ("engine/agent.py", "engine/freeroam.py", "engine/engine.py"):
            src = (REPO / f).read_text(encoding="utf-8")
            code = "\n".join(l for l in src.splitlines() if not l.strip().startswith(("#", "It used")))
            self.assertNotIn('"claude-sonnet-4-6"', code, f)

    def test_precedence(self):
        import agent
        self.assertEqual("x", agent.worker_model(explicit="x"))
        old = os.environ.get("CBH_WORKER_MODEL")
        os.environ["CBH_WORKER_MODEL"] = "env-model"
        try:
            self.assertEqual("env-model", agent.worker_model())
        finally:
            if old is None:
                os.environ.pop("CBH_WORKER_MODEL")
            else:
                os.environ["CBH_WORKER_MODEL"] = old


if __name__ == "__main__":
    unittest.main()
