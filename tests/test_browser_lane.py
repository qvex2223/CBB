#!/usr/bin/env python3
"""The browser lane must say what to do, not only what failed.

Measured 2026-11-11: four navigations to the same host each
failed in under a second with `net::ERR_TOO_MANY_RETRIES`, the agent re-fired the same
call every time, paused Caido's intercept queue while looking for the request (which
holds every proxied request and guarantees the next failure), and its one recovery move
— `browser_navigate about:blank` — was refused by our own gate as an unscoped target.

So: the remedy travels with the error (engine/browser_hints.py, delivered by
scripts/mcp-hint.py under Claude Code and by `runtime/inline-gate.mjs` for a client that
gates inline), and the local state is readable in one call (engine/browser_doctor.py).

A third measure went out with the second client (2026-11-13): that client's per-tool
timeout defaulted to 6000 s, so one wedged navigation parked a lane for 100 minutes, and
its config pinned every server to numbers this workspace can actually reach. Nothing
here depends on it any more; `.mcp.json` carries the Claude Code side.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
sys.path.insert(0, str(ROOT / "engine"))

import browser_hints  # noqa: E402
import browser_state  # noqa: E402

NAV_FAIL = ("### Error\nError: browserBackend.callTool: net::ERR_TOO_MANY_RETRIES at "
            "https://account.mail.ru/login\nCall log:\n  - navigating to "
            "\"https://account.mail.ru/login\", waiting until \"domcontentloaded\"\n")


class Hints(unittest.TestCase):
    def test_the_measured_failure_gets_the_measured_remedy(self):
        hint = browser_hints.hint_for("playwright__browser_navigate", NAV_FAIL)
        self.assertIn("caido_intercept_status", hint)
        self.assertIn("playwright-direct", hint)
        self.assertIn("bbcurl", hint)
        self.assertIn("do NOT re-fire", hint)

    def test_every_rule_fires_on_its_own_error_text(self):
        cases = {
            "net::ERR_PROXY_CONNECTION_FAILED": "caido-up.sh",
            "net::ERR_NAME_NOT_RESOLVED": "scope.py --resolve",
            "net::ERR_CONNECTION_TIMED_OUT": "cbh identity new",
            "net::ERR_CERT_AUTHORITY_INVALID": "doctor",
            "net::ERR_BLOCKED_BY_CLIENT": "browser_console_messages",
            "Error: Timeout 30000ms exceeded": "browser_network_requests",
            "profile /x/browser-profile is held by pid 1": "stalled",
        }
        for error, expected in cases.items():
            with self.subTest(error=error):
                hint = browser_hints.hint_for("playwright__browser_navigate", error)
                self.assertTrue(hint, f"no hint for {error}")
                self.assertIn(expected, hint)

    def test_a_gate_refusal_is_answered_as_final_never_as_a_retry(self):
        hint = browser_hints.hint_for("playwright__browser_navigate",
                                      "MCP GATE: OUT-OF-SCOPE host")
        self.assertIn("final", hint)
        self.assertNotIn("re-fire the same navigation", hint)

    def test_a_paused_intercept_queue_is_explained_where_it_is_read(self):
        hint = browser_hints.hint_for("caido__caido_intercept_status",
                                      '{"status":"PAUSED"}')
        self.assertIn("resume", hint)

    def test_unrelated_tools_and_clean_results_get_nothing(self):
        self.assertEqual(browser_hints.hint_for("burpmcp__http1-send", NAV_FAIL), "")
        self.assertEqual(browser_hints.hint_for("playwright__browser_navigate",
                                                "### Ran Playwright code\nawait page.goto()"), "")
        self.assertEqual(browser_hints.hint_for("playwright__browser_navigate", ""), "")

    def test_the_hook_feeds_the_hint_back_and_stays_advisory(self):
        """exit 2 + stderr is how a PostToolUse hook speaks; anything else must exit 0."""
        hook = ROOT / "scripts" / "mcp-hint.py"
        ev = {"tool_name": "mcp__playwright__browser_navigate",
              "tool_response": {"content": [{"type": "text", "text": NAV_FAIL}],
                                "isError": True}}
        r = subprocess.run([sys.executable, "-B", str(hook)], input=json.dumps(ev),
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)
        self.assertIn("caido_intercept_status", r.stderr)
        clean = {"tool_name": "mcp__playwright__browser_navigate",
                 "tool_response": {"content": [{"type": "text", "text": "### Page state"}]}}
        r = subprocess.run([sys.executable, "-B", str(hook)], input=json.dumps(clean),
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stderr.strip(), "")
        r = subprocess.run([sys.executable, "-B", str(hook)], input="not json at all",
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, "a broken hook must never wedge the session")

    def test_the_hook_is_wired_for_both_mcp_servers_and_for_failures(self):
        cfg = json.loads((ROOT / "docs" / "setup" / "hooks.json").read_text())
        hooks = cfg.get("hooks", cfg)
        wired = {m["matcher"] for phase in ("PostToolUse", "PostToolUseFailure")
                 for m in hooks.get(phase, [])
                 for h in m["hooks"] if h["command"].endswith("mcp-hint.py")}
        self.assertIn("mcp__playwright__.*", wired)
        self.assertIn("mcp__caido__.*", wired)
        self.assertIn(".*", wired, "a failed call may never reach PostToolUse")

    def test_the_inline_gate_delivers_the_same_table(self):
        src = (ROOT / "runtime" / "inline-gate.mjs").read_text()
        self.assertIn("browser_hints.py", src)
        self.assertIn("pending.set(msg.id, name)", src)


class InlineGateDelivery(unittest.TestCase):
    """End-to-end: a failing MCP result comes back carrying the remedy, in order.

    The inline gate is the only place a non-Claude client's tool result can be answered,
    and it must not reorder the stream while doing it.
    """

    def fake_server(self) -> Path:
        """One error result for https://fail/, one clean result for anything else."""
        server = Path(self.tmp.name) / "fake-server.mjs"
        server.write_text(
            "import readline from 'node:readline';\n"
            "readline.createInterface({ input: process.stdin }).on('line', line => {\n"
            "  const m = JSON.parse(line);\n"
            "  const text = m.params.arguments.url === 'https://fail/'\n"
            "    ? 'Error: browserBackend.callTool: net::ERR_NAME_NOT_RESOLVED at https://fail/'\n"
            "    : '### Page state';\n"
            "  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id,\n"
            "    result: { content: [{ type: 'text', text }], isError: text.startsWith('Error') } }) + '\\n');\n"
            "});\n", encoding="utf-8")
        driver = Path(self.tmp.name) / "driver.mjs"
        driver.write_text(
            f"import {{ spawnGated }} from {json.dumps((ROOT / 'runtime' / 'inline-gate.mjs').as_uri())};\n"
            f"spawnGated('playwright', process.execPath, [{json.dumps(str(server))}], "
            "{ env: process.env });\n", encoding="utf-8")
        return driver

    def drive(self, urls, env=None):
        calls = "\n".join(json.dumps(
            {"jsonrpc": "2.0", "id": i, "method": "tools/call",
             "params": {"name": "browser_navigate", "arguments": {"url": url}}})
            for i, url in enumerate(urls, start=1))
        e = dict(os.environ, CBH_AGENT="generic",
                 CBH_MEMORY_DIR=str(Path(self.tmp.name) / "mem"))
        e.update(env or {})
        r = subprocess.run([NODE, str(self.fake_server())], input=calls + "\n",
                           capture_output=True, text=True, timeout=120, cwd=str(ROOT), env=e)
        return [json.loads(x) for x in r.stdout.splitlines() if x.startswith("{")], r

    @unittest.skipUnless(NODE, "node is not installed")
    def test_a_failing_result_comes_back_with_the_hint_appended(self):
        lines, r = self.drive(["https://fail/", "about:blank"],
                              env={"CBH_MCP_GATE": "off"})
        self.assertEqual([m["id"] for m in lines], [1, 2], f"order changed: {r.stdout}")
        texts = [c["text"] for c in lines[0]["result"]["content"]]
        self.assertIn("ERR_NAME_NOT_RESOLVED", texts[0])
        self.assertIn(browser_hints.HEADER, texts[1])
        self.assertEqual(len(lines[1]["result"]["content"]), 1,
                         "a clean result must come back untouched")

    @unittest.skipUnless(NODE, "node is not installed")
    def test_a_gate_refusal_also_carries_its_answer(self):
        """Launched at the repo root, a remote navigation is refused — and the refusal
        says the refusal is final, which is the part that was re-fired four times."""
        lines, r = self.drive(["https://fail/"])
        texts = [c["text"] for c in lines[0]["result"]["content"]]
        self.assertIn("MCP GATE", texts[0])
        self.assertIn("final", texts[1])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)


class LaneState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.project = self.root / "Targets" / "standoff365" / "acme"
        self.profile = self.project / "browser-profile"
        self.profile.mkdir(parents=True)
        self.addCleanup(self.tmp.cleanup)

    def lock(self, pid):
        (self.profile / browser_state.LOCK_NAME).write_text(json.dumps(
            {"pid": pid, "label": "xss lane", "started_at": "2026-11-11T07:00:00.000Z"}))

    def test_a_live_lock_is_a_lane_and_carries_its_route(self):
        self.lock(os.getpid())
        lanes = browser_state.live_lanes(self.root)
        self.assertEqual(len(lanes), 1)
        self.assertEqual(lanes[0]["engagement"], "acme")
        self.assertTrue(lanes[0]["via_caido"])
        (self.project / "playwright-direct").write_text("")
        self.assertFalse(browser_state.live_lanes(self.root)[0]["via_caido"])
        self.assertEqual(browser_state.caido_proxied_lanes(self.root), [])

    def test_a_dead_pid_is_not_a_lane(self):
        self.lock(2 ** 22 - 1)       # above the default pid_max: nothing holds it
        self.assertEqual(browser_state.live_lanes(self.root), [])

    def test_an_unreadable_lock_is_ignored_not_raised(self):
        (self.profile / browser_state.LOCK_NAME).write_text("half-written{")
        self.assertEqual(browser_state.live_lanes(self.root), [])

    def test_the_lock_name_matches_the_server_that_writes_it(self):
        src = (ROOT / "runtime" / "browser-lock.mjs").read_text()
        self.assertIn(f"'{browser_state.LOCK_NAME}'", src)


class Doctor(unittest.TestCase):
    def test_it_reads_the_state_and_sends_nothing(self):
        import browser_doctor
        state = browser_doctor.collect()
        for key in ("engagement", "caido", "chrome", "lanes", "headless"):
            self.assertIn(key, state)
        self.assertEqual(sorted(state["caido"]),
                         ["browser_uses_it", "endpoint", "intercept_status", "listening"])
        text = "\n".join(browser_doctor.render(state))
        self.assertIn("browser doctor", text)

    def test_cbh_exposes_it(self):
        sys.path.insert(0, str(ROOT))
        from cbh.cli import ENGINE_MODULES
        self.assertEqual(ENGINE_MODULES["browser"], "browser_doctor")

    def test_it_reads_the_live_server_flags_not_only_the_marker(self):
        """2026-11-12: doctor said "direct marker present — browser goes direct" while the
        RUNNING server carried --proxy-server and --isolated, so a whole browser lane died
        on net::ERR_TOO_MANY_RETRIES with the diagnosis one `ps` away. The flags the live
        process was started with are part of the state this command reports."""
        import browser_doctor  # type: ignore
        state = browser_doctor.collect()
        self.assertIn("running_servers", state)
        for s in state["running_servers"]:
            self.assertEqual(sorted(s), ["headless", "isolated", "output_dir", "pid",
                                         "proxy", "started_at"])

    def test_a_proxied_server_on_a_direct_engagement_is_called_a_mismatch(self):
        import browser_doctor  # type: ignore
        state = browser_doctor.collect()
        state["direct_marker"] = True
        state["running_servers"] = [{"pid": 4242, "proxy": "http://127.0.0.1:8080",
                                     "isolated": True, "headless": True,
                                     "output_dir": "", "started_at": ""}]
        text = "\n".join(browser_doctor.render(state))
        self.assertIn("MISMATCH", text)
        self.assertIn("--proxy-server", text)
        self.assertIn("ERR_TOO_MANY_RETRIES", text)

    def test_no_server_running_says_a_killed_one_does_not_respawn(self):
        import browser_doctor  # type: ignore
        state = browser_doctor.collect()
        state["running_servers"] = []
        text = "\n".join(browser_doctor.render(state))
        self.assertIn("does NOT respawn", text)
        self.assertIn("/mcp", text)


class OperatorLogin(unittest.TestCase):
    """`cbh browser login` is the only lane the operator types a password into.

    It drives the browser over CDP, which means scripts/mcp-gate.py never sees the
    navigation: no scope check, no pacing, no audit row. So the scope check has to
    happen in the command itself, and it has to be default-deny — on 2026-11-12 the
    first version of this subcommand would have opened any URL it was handed.
    """

    def _run(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "engine" / "browser_doctor.py"),
                               "login", *args],
                              capture_output=True, text=True, cwd=str(ROOT),
                              env=dict(os.environ, CBH_PROJECT=""))

    def test_an_out_of_scope_url_opens_no_window(self):
        r = self._run("standoff365/konsol", "--url", "https://evil.example/login")
        self.assertEqual(r.returncode, 1)
        self.assertIn("REFUSED", r.stderr)
        self.assertIn("default deny", r.stderr)

    def test_an_unknown_engagement_opens_no_window(self):
        r = self._run("no-such-platform/no-such-program", "--url", "https://konsol.pro/login")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("WINDOW OPEN", r.stdout)

    def test_url_is_required(self):
        r = self._run("standoff365/konsol")
        self.assertEqual(r.returncode, 2)

    def test_in_scope_url_passes_the_same_check(self):
        """The positive control: a refusal that refuses everything proves nothing."""
        sys.path.insert(0, str(ROOT / "engine"))
        from scope import _scope_from_md  # type: ignore
        scope = _scope_from_md(str(ROOT / "Targets" / "standoff365" / "konsol" / "scope.md"))
        self.assertIsNone(scope.reject_reason("https://konsol.pro/login"))
        self.assertIsNotNone(scope.reject_reason("https://evil.example/login"))


class HeadlessIsReadFromTheServerEnv(unittest.TestCase):
    """The browser runs in the MCP server, which takes its env from .mcp.json.

    `cbh browser doctor` used to answer "headless or headed" from the shell it was run
    in, which is not the process that owns the browser: it reported headless while the
    configured server was headed.
    """

    def test_mcp_json_env_is_the_authority(self):
        import browser_doctor  # type: ignore
        env = browser_doctor.mcp_server_env("playwright")
        self.assertEqual(env.get("CBH_PLAYWRIGHT_HEADED"), "1",
                         ".mcp.json should keep the playwright server headed for the operator")

    def test_a_missing_server_name_is_empty_not_an_error(self):
        import browser_doctor  # type: ignore
        self.assertEqual(browser_doctor.mcp_server_env("no-such-server"), {})

    def test_doctor_reports_headed_when_mcp_json_says_so(self):
        import browser_doctor  # type: ignore
        d = browser_doctor.collect()
        if not d["display"]:
            self.skipTest("no display on this box")
        self.assertFalse(d["headless"])
        self.assertTrue(d["headed_configured_in_mcp_json"])
