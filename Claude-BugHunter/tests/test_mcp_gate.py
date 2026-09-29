#!/usr/bin/env python3
"""The MCP transport must obey the same request policy as bbcurl and poc_runtime.

Burp and Playwright talk to the network themselves. Before scripts/mcp-gate.py the
fastest route to an unscoped, unpaced, unaudited request against a live program was
the tool this workspace tells you to use for the last mile.
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

    def test_localhost_is_never_gated(self):
        self.assertIsNone(self.run_gate("mcp__playwright__browser_navigate",
                                        {"url": "http://localhost:3000/"}))

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

    def test_non_mcp_tools_are_ignored(self):
        self.assertIsNone(self.run_gate("Bash", {"command": "curl https://evil.example.com"}))

    def test_a_malformed_event_never_wedges_the_session(self):
        e = dict(os.environ, CBH_MEMORY_DIR=str(self.memdir))
        r = subprocess.run([sys.executable, "-B", str(GATE)], input="not json",
                           capture_output=True, text=True, timeout=60, cwd=str(self.project), env=e)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
