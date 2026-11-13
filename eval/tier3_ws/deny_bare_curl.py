#!/usr/bin/env python3
"""PreToolUse probe: would DENYING bare curl make the agent reach for bbcurl?

Tier 3 measured a workspace that was never used — 0 bbcurl requests across 10
runs, even though CLAUDE.md loaded, bbcurl was on PATH and allowed, and the
PostToolUse nudge fired. The nudge arrives *after* the answer is already in hand,
which is exactly when an agent has no reason to re-run anything.

This hook is the counterfactual, not a shipped change: it refuses the request
instead of complaining about it. Only used inside the eval fixture, wired via
`claude --settings`, never in the operator's own settings.
"""
import json
import re
import sys

try:
    ev = json.loads(sys.stdin.read() or "{}")
except Exception:  # noqa: BLE001
    sys.exit(0)

cmd = (ev.get("tool_input") or {}).get("command", "") if isinstance(ev.get("tool_input"), dict) else ""
if re.search(r"(^|[;&|]\s*)curl\s", cmd) and "bbcurl" not in cmd and re.search(r"https?://", cmd):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": (
            "Bare `curl` inside an engagement skips the scope check, the pacing budget, the "
            "program's mandatory headers, the audit trail and the response corpus. Re-send the "
            "identical command as `bbcurl`.")}}))
    sys.exit(0)
sys.exit(0)
