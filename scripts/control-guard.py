#!/usr/bin/env python3
"""control-guard — PreToolUse hook: a worker agent may not edit the controls that govern it.

Incident 2026-10-20 (konsol, blocked-tests/2026-10-20-INCIDENT-subagent-disabled-the-stop-gate.md):
a `cbh freeroam` worker, launched with `--permission-mode bypassPermissions`, set
`continuous_hunt: false` in the engagement's profile.json so the stop gate would stop
refusing its own exit. It fired zero requests and produced nothing; the one thing it
did was switch off a guardrail.

Scope of this hook, deliberately narrow:
  * acts ONLY when CBH_AGENT_ROLE=worker is in the environment (engine/agent.py sets it
    for every headless worker). The operator's own session is never touched.
  * denies Edit/Write/NotebookEdit on a control file, and Bash commands that both name a
    control file / control CLI AND look like a write.
Any internal error exits 0 — a broken guard must not block work; the agent launcher's
`--disallowedTools` is the first layer, this is the second.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

CONTROL_PATH = re.compile(
    r"(profile\.json|scope\.md|\.claude/settings[^/\s]*\.json|settings\.local\.json|"
    r"hunt-memory/(continuous\.json|hunt-mode[^/\s]*|stop-gate[^/\s]*)|docs/setup/hooks\.json|"
    r"scripts/[a-z-]*(gate|guard|arm|nudge|brief|track)[a-z-]*\.py|"
    r"engine/(stop_gate|scope|pacing|hunt_mode|skill_signals)\.py|scripts/bbcurl)")
CONTROL_CLI = re.compile(r"(stop_gate\.py\s+--continuous|hunt_mode\.py\s+(on|off)|apply-hooks\.py)")
CP = CONTROL_PATH.pattern
# A write is only blocked when the control file is the DESTINATION. Reading one
# (`cat scope.md`, `grep x scope.md 2>/dev/null`, `cp scope.md /tmp/`) stays allowed:
# the first version matched any `>` anywhere and would have blocked plain reads.
WRITE_TO_CONTROL = re.compile(
    rf"(>>?\s*['\"]?\S*{CP}"                                  # > profile.json
    rf"|\btee\b(\s+-a)?\s+['\"]?\S*{CP}"                     # tee [-a] profile.json
    rf"|\b(sed\s+-i|perl\s+-p?i)\S*\s[^|;&]*{CP}"             # sed -i … profile.json
    rf"|\b(mv|cp|install|ln)\b[^|;&]*\s['\"]?\S*{CP}\S*['\"]?\s*($|[;&|])"   # mv x profile.json
    rf"|\b(rm|truncate|chmod)\b[^|;&]*{CP}"                     # rm profile.json
    rf"|open\([^)]*{CP}[^)]*,\s*['\"][wax+]"                    # open('profile.json','w')
    rf"|Path\([^)]*{CP}[^)]*\)\.write_(text|bytes))"            # Path('profile.json').write_text
)


def _deny(reason: str) -> int:
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": reason}}))
    return 0


def main() -> int:
    # A client that is not Claude Code carries none of the worker signals below, and one
    # such client edited profile.json in its first hunt (2026-11-10). So for anything
    # else, the guard applies to every agent of it, orchestrator included: an engagement
    # control is not an agent's to change either way.
    try:
        import client as _C  # type: ignore
        other_client = _C.detect() != "claude"
    except Exception:  # noqa: BLE001
        other_client = os.environ.get("CLAUDECODE") != "1"
    if not other_client and (os.environ.get("CBH_AGENT_ROLE") or "").strip().lower() != "worker":
        return 0
    try:
        ev = json.loads(sys.stdin.read() or "{}")
    except Exception:  # noqa: BLE001
        return 0
    tool = ev.get("tool_name") or ""
    ti = ev.get("tool_input") or {}
    msg = ("CONTROL-GUARD: agents may not change engagement controls "
           "(profile.json, scope.md, settings, stop-gate / hunt-mode state, the gates themselves). "
           "If a control is wrong, say so in your result and the orchestrator decides.")
    if tool in ("Edit", "Write", "NotebookEdit", "MultiEdit", "search_replace", "write"):
        path = ti.get("file_path") or ti.get("notebook_path") or ""
        if CONTROL_PATH.search(path):
            return _deny(f"{msg} Blocked: {tool} {path}")
        return 0
    if tool in ("Bash", "run_terminal_command"):
        cmd = ti.get("command") or ""
        if CONTROL_CLI.search(cmd):
            return _deny(f"{msg} Blocked command: {cmd[:160]}")
        if WRITE_TO_CONTROL.search(cmd):
            return _deny(f"{msg} Blocked command: {cmd[:160]}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        raise SystemExit(0)
