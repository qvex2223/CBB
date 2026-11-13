#!/usr/bin/env python3
"""The MCP transport must obey the same request policy as bbcurl and poc_runtime.

Burp, Caido and Playwright talk to the network themselves. Before scripts/mcp-gate.py
the fastest route to an unscoped, unpaced, unaudited request against a live program was
the tool this workspace tells you to use for the last mile.

The Caido cases below exist because that server is richer than Burp's: one call can
carry fifty requests, one tool fires them through raw sockets that never reach Caido's
own history, and three tools name a target this hook cannot see at all.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "mcp-gate.py"


class McpGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.memdir = self.root / "hunt-memory"
        self.memdir.mkdir()
        self.project = self.root / "Targets" / "acme"
        self.project.mkdir(parents=True)
        (self.project / "scope.md").write_text("# Scope\n\n## In scope\n- `*.acme.com`\n")
        (self.project / "profile.json").write_text(json.dumps(
            {"min_interval_seconds": 0, "required_headers": {"X-Bug-Bounty": "qvex"}}))
        self.addCleanup(self.tmp.cleanup)

    def run_gate(self, tool, tool_input, cwd=None, env=None):
        payload = json.dumps({"tool_name": tool, "tool_input": tool_input,
                              "session_id": "t", "transcript_path": ""})
        e = dict(os.environ, CBH_MEMORY_DIR=str(self.memdir))
        e["PYTHONPATH"] = str(ROOT / "engine")
        e.update(env or {})
        r = subprocess.run([sys.executable, "-B", str(GATE)], input=payload,
                           capture_output=True, text=True, timeout=60,
                           cwd=str(cwd or self.project), env=e)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = (r.stdout or "").strip()
        return json.loads(out)["hookSpecificOutput"] if out else None

    def audit_rows(self):
        p = self.memdir / "audit.jsonl"
        return [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []

    # ---------------------------------------------------------------- burp
    def test_burp_send_to_an_out_of_scope_host_is_denied(self):
        d = self.run_gate("mcp__burpmcp__http1-send",
                          {"host": "evil.example.com", "port": 443, "secure": True,
                           "data": "GET /x HTTP/1.1\r\nHost: evil.example.com\r\n\r\n"})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("OUT-OF-SCOPE", d["permissionDecisionReason"])
        self.assertEqual(self.audit_rows(), [])

    def test_burp_send_in_scope_is_allowed_and_audited(self):
        d = self.run_gate("mcp__burpmcp__http1-send",
                          {"host": "api.acme.com", "port": 443, "secure": True,
                           "data": "POST /v1/orders HTTP/1.1\r\nHost: api.acme.com\r\n"
                                   "X-Bug-Bounty: qvex\r\n\r\n"})
        self.assertIsNone(d, "in-scope request was blocked")
        row = self.audit_rows()[-1]
        self.assertEqual(row["method"], "POST")
        self.assertEqual(row["urls"], ["https://api.acme.com/v1/orders"])
        self.assertEqual(row["transport"], "mcp")
        self.assertEqual(row["engagement"], "acme")

    def test_burp_send_without_the_mandatory_header_is_denied(self):
        d = self.run_gate("mcp__burpmcp__http1-send",
                          {"host": "api.acme.com", "port": 443, "secure": True,
                           "data": "GET /x HTTP/1.1\r\nHost: api.acme.com\r\n\r\n"})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("X-Bug-Bounty: qvex", d["permissionDecisionReason"])

    def test_resend_without_a_host_is_refused_as_unverified(self):
        d = self.run_gate("mcp__burpmcp__http1-resend", {"id": 7})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("UNVERIFIED", d["permissionDecisionReason"])

    def test_resend_with_an_explicit_in_scope_host_passes(self):
        self.assertIsNone(self.run_gate("mcp__burpmcp__http1-resend",
                                        {"id": 7, "host": "api.acme.com", "port": 443,
                                         "secure": True}))

    def test_saving_a_request_is_not_a_send(self):
        self.assertIsNone(self.run_gate("mcp__burpmcp__save-http1-request",
                                        {"host": "evil.example.com", "port": 443,
                                         "secure": True, "data": "GET / HTTP/1.1\r\n\r\n"}))
        self.assertEqual(self.audit_rows(), [], "a local save must not be audited as sent")

    def test_collaborator_is_denied_unless_the_program_allows_oob(self):
        d = self.run_gate("mcp__burpmcp__generate-collaborator-payload", {})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("out-of-band", d["permissionDecisionReason"].lower())

    def test_collaborator_is_allowed_when_the_profile_says_so(self):
        (self.project / "profile.json").write_text(json.dumps(
            {"min_interval_seconds": 0, "allow_oob": True}))
        self.assertIsNone(self.run_gate("mcp__burpmcp__generate-collaborator-payload", {}))

    # ---------------------------------------------------------- playwright
    def test_navigate_off_scope_is_denied(self):
        d = self.run_gate("mcp__playwright__browser_navigate",
                          {"url": "https://evil.example.com/"})
        self.assertEqual(d["permissionDecision"], "deny")

    def test_navigate_in_scope_is_audited(self):
        self.assertIsNone(self.run_gate("mcp__playwright__browser_navigate",
                                        {"url": "https://www.acme.com/login"}))
        self.assertEqual(self.audit_rows()[-1]["tool"], "mcp__playwright__browser_navigate")

    def test_in_page_actions_pass_through(self):
        """They name no host; the origin was gated at navigate. Documented, not hidden."""
        self.assertIsNone(self.run_gate("mcp__playwright__browser_click",
                                        {"element": "button", "ref": "e1"}))

    # A navigation does not have to arrive as browser_navigate: browser_run_code_unsafe
    # and browser_evaluate hand the server arbitrary code, and a page.goto() inside it
    # was ungated, unpaced and unaudited until 2026-11-12 (zero `run_code` rows in the
    # audit for a whole engagement). A brief on standoff365/mail_vk told a worker to pin
    # its page that way, which made the brief itself the bypass.
    def test_run_code_unsafe_navigating_off_scope_is_denied(self):
        d = self.run_gate("mcp__playwright__browser_run_code_unsafe",
                          {"code": "async (page) => { await page.goto('https://evil.example.com/x'); }"})
        self.assertEqual(d["permissionDecision"], "deny")

    def test_run_code_unsafe_in_scope_is_audited(self):
        self.assertIsNone(self.run_gate(
            "mcp__playwright__browser_run_code_unsafe",
            {"code": "async (page) => { await page.goto(\"https://www.acme.com/a\"); }"}))
        self.assertEqual(self.audit_rows()[-1]["tool"],
                         "mcp__playwright__browser_run_code_unsafe")

    def test_evaluate_fetching_off_scope_is_denied(self):
        d = self.run_gate("mcp__playwright__browser_evaluate",
                          {"function": "() => fetch('https://evil.example.com/steal')"})
        self.assertEqual(d["permissionDecision"], "deny")

    def test_in_page_read_with_no_absolute_url_passes(self):
        """A relative fetch or a runtime-built URL is invisible here, like a click that
        fires an XHR. That is why navigation belongs in browser_navigate."""
        self.assertIsNone(self.run_gate(
            "mcp__playwright__browser_run_code_unsafe",
            {"code": "async (page) => page.evaluate(() => document.title)"}))

    def test_run_code_control_urls_pass(self):
        self.assertIsNone(self.run_gate(
            "mcp__playwright__browser_run_code_unsafe",
            {"code": "async (page) => { await page.goto('about:blank'); }"}))

    def test_localhost_is_never_gated(self):
        self.assertIsNone(self.run_gate("mcp__playwright__browser_navigate",
                                        {"url": "http://localhost:3000/"}))

    # Browser control URLs: a navigation to one of these sends nothing, so there is no
    # host to scope-check, nothing to pace and nothing to audit. Until 2026-11-11 the
    # gate read them as remote targets: `about:blank` was refused with "no engagement
    # resolved", which is the one recovery move an agent has after a failed navigation
    # (measured 2026-11-11).
    CONTROL_URLS = ("about:blank", "about:newtab", "data:text/html,<p>x", "blob:null/abc",
                    "chrome://version", "devtools://devtools/bundled/x.html",
                    "file:///tmp/report.html", "javascript:void(0)")

    def test_browser_control_urls_pass_inside_an_engagement(self):
        for url in self.CONTROL_URLS:
            with self.subTest(url=url):
                self.assertIsNone(self.run_gate("mcp__playwright__browser_navigate",
                                                {"url": url}))
        self.assertEqual(self.audit_rows(), [], "a control URL sends nothing to audit")

    def test_browser_control_urls_pass_with_no_engagement_at_all(self):
        """The strict-client branch must not refuse a page reset: it reaches no network."""
        for url in self.CONTROL_URLS:
            with self.subTest(url=url):
                self.assertIsNone(self.run_gate("mcp__playwright__browser_navigate",
                                                {"url": url}, cwd=self.root,
                                                env={"CBH_AGENT": "generic"}))

    def test_view_source_is_gated_on_the_url_it_fetches(self):
        """view-source: DOES fetch its inner URL, and urlsplit gives it no hostname."""
        d = self.run_gate("mcp__playwright__browser_navigate",
                          {"url": "view-source:https://evil.example.com/"})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertEqual(self.audit_rows(), [])
        self.assertIsNone(self.run_gate("mcp__playwright__browser_navigate",
                                        {"url": "view-source:https://www.acme.com/app.js"}))
        self.assertEqual(self.audit_rows()[-1]["urls"], ["https://www.acme.com/app.js"])

    def test_a_remote_navigation_with_no_engagement_is_still_refused(self):
        d = self.run_gate("mcp__playwright__browser_navigate",
                          {"url": "https://evil.example.com/"}, cwd=self.root,
                          env={"CBH_AGENT": "generic"})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("no engagement resolved", d["permissionDecisionReason"])

    # -------------------------------------------------------------- scope
    def test_outside_an_engagement_nothing_is_gated(self):
        self.assertIsNone(self.run_gate("mcp__playwright__browser_navigate",
                                        {"url": "https://evil.example.com/"},
                                        cwd=self.root))

    def test_env_escape_hatch(self):
        self.assertIsNone(self.run_gate("mcp__burpmcp__http1-send",
                                        {"host": "evil.example.com", "port": 443,
                                         "secure": True, "data": "GET / HTTP/1.1\r\n\r\n"},
                                        env={"CBH_MCP_GATE": "off"}))

    # ---------------------------------------------------------------- caido

    RAW = "GET /me HTTP/1.1\r\nHost: api.acme.com\r\nX-Bug-Bounty: qvex\r\n\r\n"
    RAW_EVIL = "GET /me HTTP/1.1\r\nHost: api.evil.example.com\r\nX-Bug-Bounty: qvex\r\n\r\n"

    def bulk_ok(self):
        (self.project / "profile.json").write_text(json.dumps(
            {"min_interval_seconds": 0, "required_headers": {"X-Bug-Bounty": "qvex"},
             "allow_bulk_tools": True}))

    def test_caido_send_takes_the_host_from_the_raw_request(self):
        """No host argument: the Host header is what Caido routes on, so gate on that."""
        self.assertIsNone(self.run_gate("mcp__caido__caido_send_request", {"raw": self.RAW}))
        self.assertEqual(self.audit_rows()[-1]["urls"], ["https://api.acme.com/me"])

    def test_caido_send_to_an_out_of_scope_host_header_is_denied(self):
        d = self.run_gate("mcp__caido__caido_send_request", {"raw": self.RAW_EVIL})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("api.evil.example.com", d["permissionDecisionReason"])

    def test_caido_host_argument_overrides_an_in_scope_host_header(self):
        """The argument wins on the wire, so it has to win in the gate too."""
        d = self.run_gate("mcp__caido__caido_send_request",
                          {"raw": self.RAW, "host": "api.evil.example.com"})
        self.assertEqual(d["permissionDecision"], "deny")

    def test_caido_send_without_the_mandatory_header_is_denied(self):
        d = self.run_gate("mcp__caido__caido_send_request",
                          {"raw": "GET /me HTTP/1.1\r\nHost: api.acme.com\r\n\r\n"})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("X-Bug-Bounty: qvex", d["permissionDecisionReason"])

    def test_caido_plaintext_port_and_tls_false_are_honoured(self):
        self.assertIsNone(self.run_gate("mcp__caido__caido_send_request",
                                        {"raw": self.RAW, "host": "api.acme.com",
                                         "port": 8080, "tls": False}))
        self.assertEqual(self.audit_rows()[-1]["urls"], ["http://api.acme.com:8080/me"])

    def test_caido_batch_needs_the_bulk_opt_in(self):
        d = self.run_gate("mcp__caido__caido_batch_send",
                          {"requests": [{"label": "a", "raw": self.RAW}]})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("allow_bulk_tools", d["permissionDecisionReason"])

    def test_caido_batch_checks_every_request_not_just_the_first(self):
        self.bulk_ok()
        d = self.run_gate("mcp__caido__caido_batch_send",
                          {"requests": [{"label": "ok", "raw": self.RAW},
                                        {"label": "oops", "raw": self.RAW_EVIL}]})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("api.evil.example.com", d["permissionDecisionReason"])

    def test_caido_batch_pays_the_budget_for_every_request(self):
        self.bulk_ok()
        self.assertIsNone(self.run_gate(
            "mcp__caido__caido_batch_send",
            {"requests": [{"label": "a", "raw": self.RAW}, {"label": "b", "raw": self.RAW}]}))
        row = self.audit_rows()[-1]
        self.assertEqual(row["requests"], 2)
        self.assertEqual(len(row["urls"]), 2)

    def test_caido_batch_over_the_pacing_cap_is_refused_not_slept_through(self):
        (self.project / "profile.json").write_text(json.dumps(
            {"min_interval_seconds": 10, "allow_bulk_tools": True}))
        d = self.run_gate("mcp__caido__caido_batch_send",
                          {"requests": [{"label": str(i), "raw": self.RAW} for i in range(50)]})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("Send at most 12 per call", d["permissionDecisionReason"])

    def test_caido_race_burst_is_scope_checked_and_marked_proxy_bypassing(self):
        self.bulk_ok()
        self.assertIsNone(self.run_gate(
            "mcp__caido__caido_race_window_send",
            {"host": "api.acme.com", "requests": [{"raw": self.RAW}, {"raw": self.RAW}]}))
        self.assertIn("bypasses Caido proxy history", self.audit_rows()[-1]["note"])

    def test_caido_race_burst_inherits_the_calls_host_for_every_item(self):
        self.bulk_ok()
        d = self.run_gate("mcp__caido__caido_race_window_send",
                          {"host": "api.evil.example.com", "requests": [{"raw": self.RAW}]})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("api.evil.example.com", d["permissionDecisionReason"])

    def test_caido_edit_request_without_a_host_is_unverified(self):
        d = self.run_gate("mcp__caido__caido_edit_request", {"requestId": "7", "path": "/admin"})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("UNVERIFIED", d["permissionDecisionReason"])

    def test_caido_edit_request_with_an_explicit_in_scope_host_passes(self):
        self.assertIsNone(self.run_gate("mcp__caido__caido_edit_request",
                                        {"requestId": "7", "host": "api.acme.com",
                                         "method": "DELETE"}))
        self.assertEqual(self.audit_rows()[-1]["method"], "DELETE")

    def test_caido_edit_request_may_not_remove_the_mandatory_header(self):
        d = self.run_gate("mcp__caido__caido_edit_request",
                          {"requestId": "7", "host": "api.acme.com",
                           "removeHeaders": ["X-Bug-Bounty"]})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("X-Bug-Bounty: qvex", d["permissionDecisionReason"])

    def test_caido_forward_intercept_is_refused_as_unverified(self):
        d = self.run_gate("mcp__caido__caido_forward_intercept", {"id": "3"})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("caido_list_intercept_entries", d["permissionDecisionReason"])

    def test_caido_active_workflow_is_refused_convert_passes(self):
        d = self.run_gate("mcp__caido__caido_run_workflow", {"id": "w", "type": "active",
                                                            "request_id": "3"})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIsNone(self.run_gate("mcp__caido__caido_run_workflow",
                                        {"id": "w", "type": "convert", "input": "x"}))

    def test_caido_automate_start_is_refused_without_the_bulk_opt_in(self):
        d = self.run_gate("mcp__caido__caido_automate_task_control",
                          {"action": "start", "session_id": "s"})
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("fuzzing engine", d["permissionDecisionReason"])

    def test_caido_automate_cancel_always_passes(self):
        """Stopping traffic is never gated — that would be the wrong way round."""
        self.assertIsNone(self.run_gate("mcp__caido__caido_automate_task_control",
                                        {"action": "cancel", "task_id": "t"}))

    # Caido's intercept queue PAUSED means "hold every proxied request", so pausing it
    # while a browser is behind Caido stops that browser loading anything and Chromium
    # calls it net::ERR_TOO_MANY_RETRIES. An agent did exactly this on 2026-11-11 while
    # chasing a navigation failure, and every navigation after it failed the same way.
    def live_browser_lane(self, direct=False):
        profile = self.project / "browser-profile"
        profile.mkdir(parents=True, exist_ok=True)
        (profile / ".cbh-browser.lock").write_text(json.dumps(
            {"pid": os.getpid(), "label": "xss lane",
             "started_at": "2026-11-11T07:00:00.000Z", "profile": str(profile)}))
        if direct:
            (self.project / "playwright-direct").write_text("")
        return {"CBH_TARGETS_ROOT": str(self.root / "Targets")}

    def test_pausing_intercept_under_a_live_proxied_browser_is_refused(self):
        env = self.live_browser_lane()
        d = self.run_gate("mcp__caido__caido_intercept_control", {"action": "pause"}, env=env)
        self.assertEqual(d["permissionDecision"], "deny")
        reason = d["permissionDecisionReason"]
        self.assertIn("ERR_TOO_MANY_RETRIES", reason)
        self.assertIn("xss lane", reason, "the refusal must name the lane it protects")

    def test_resuming_intercept_is_never_refused(self):
        env = self.live_browser_lane()
        self.assertIsNone(self.run_gate("mcp__caido__caido_intercept_control",
                                        {"action": "resume"}, env=env))

    def test_pausing_intercept_passes_when_the_browser_goes_direct(self):
        """With a playwright-direct marker the browser never touches Caido."""
        env = self.live_browser_lane(direct=True)
        self.assertIsNone(self.run_gate("mcp__caido__caido_intercept_control",
                                        {"action": "pause"}, env=env))

    def test_pausing_intercept_passes_with_no_browser_running(self):
        self.assertIsNone(self.run_gate("mcp__caido__caido_intercept_control",
                                        {"action": "pause"},
                                        env={"CBH_TARGETS_ROOT": str(self.root / "Targets")}))

    def test_caido_read_only_tools_pass_through(self):
        for tool, ti in (("caido_list_requests", {"limit": 10}),
                         ("caido_get_request", {"id": "3"}),
                         ("caido_export_curl", {"requestId": "3"}),
                         ("caido_create_finding", {"title": "x", "requestId": "3"}),
                         ("caido_create_replay_session", {"name": "acme"}),
                         ("caido_get_sitemap", {})):
            self.assertIsNone(self.run_gate(f"mcp__caido__{tool}", ti), tool)

    def test_caido_localhost_is_never_gated(self):
        self.assertIsNone(self.run_gate(
            "mcp__caido__caido_send_request",
            {"raw": "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"}))

    def test_non_mcp_tools_are_ignored(self):
        self.assertIsNone(self.run_gate("Bash", {"command": "curl https://evil.example.com"}))

    def test_a_malformed_event_never_wedges_the_session(self):
        e = dict(os.environ, CBH_MEMORY_DIR=str(self.memdir))
        r = subprocess.run([sys.executable, "-B", str(GATE)], input="not json",
                           capture_output=True, text=True, timeout=60, cwd=str(self.project), env=e)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
