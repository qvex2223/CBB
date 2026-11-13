#!/usr/bin/env python3
"""
crew-gate — PreToolUse hook: during an armed hunt the orchestrator does not fire.

Operator directive 2026-10-16 made `/parallel` the shape of every hunt: one agent
orchestrates (plan, merge, notes.md, vector ledger, /remember) and the workers fire
the requests. It lived only in prose — CLAUDE.md plus the text hunt-arm injects —
and on 2026-10-20 four armed hunts (04:20, 05:12, 09:14, 10:35 rowi) ran with zero
workers while the main session fired every request itself. Every other rule here
was moved into code because prose loses to momentum; this one had not been, and
Claude Code's own default guidance ("when in doubt, don't spawn") pulls the other
way. Operator, 2026-10-21: "мне нужно что бы постоянно мульти агентность работала".

How main thread vs worker is told apart, without guessing:
  * Claude Code puts `agent_id` in the hook input **only** when the hook fires from
    inside a subagent (Agent tool). Absent => main thread.
  * CLI workers started by engine/agent.py run with CBH_AGENT_ROLE=worker.
Either one => allow. Neither => this is the orchestrator.

Denies, on the orchestrator only:
  * Bash commands that fire a request (engine/skill_signals.py::SENDER_RE)
  * MCP calls that put traffic on the wire (Caido send/batch/race/replay, Playwright
    navigate/click/type/fill/submit-shaped calls)
Only while the hunt is armed and only inside an engagement — a question the
operator asks between hunts is answered directly, never gated.

Never gated: `--bb-dry-run`, local URLs, offline tools (jsluice, wakaru, gf, ...).

Escape hatches, both audited to hunt-memory/audit.jsonl:
  * `# crew-gate: override <reason>` appended to the Bash command
  * CBH_CREW_GATE=off in the environment (whole shell)
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

OVERRIDE_RE = re.compile(r"#\s*crew-gate:\s*override\s*(.*)", re.I)

# MCP tools that put a request on the wire. Read-only tools (list/get/sitemap,
# snapshot, screenshot, console) stay with the orchestrator: reading what a
# worker captured is merge work, not hunting.
MCP_SENDERS = re.compile(
    r"^mcp__(caido__caido_(send_request|batch_send|race_window_send|edit_request"
    r"|forward_intercept|run_workflow|automate_task_control)"
    r"|playwright__browser_(navigate|navigate_back|click|type|fill_form|press_key"
    r"|select_option|file_upload|drag|drop|run_code_unsafe|evaluate))$")


def _event() -> dict:
    try:
        return json.loads(sys.stdin.read() or "{}")
    except Exception:  # noqa: BLE001
        return {}


def _allow() -> int:
    return 0


def _deny(reason: str) -> int:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    return 0


def is_worker(ev: dict, env=None) -> bool:
    env = os.environ if env is None else env
    if ev.get("agent_id"):
        return True
    return (env.get("CBH_AGENT_ROLE") or "").strip().lower() == "worker"


def _own_subagents() -> bool:
    """True for a client whose workers carry none of Claude Code's worker signals.

    The orchestrator/worker split below reads `agent_id` and `CBH_AGENT_ROLE=worker`,
    which are Claude Code signals. Applying it to a client that has neither denies every
    sender, including the subagents that are supposed to fire, so such a client is not
    gated here — `engine/client.py` holds that row and the safety floor in AGENTS.md
    still binds it.
    """
    try:
        import client as _C  # type: ignore
        return _C.detect() != "claude"
    except Exception:  # noqa: BLE001
        return os.environ.get("CLAUDECODE") != "1"


def fires_request(ev: dict) -> bool:
    name = ev.get("tool_name") or ""
    ti = ev.get("tool_input") or {}
    if name == "Bash":
        cmd = ti.get("command", "") if isinstance(ti, dict) else ""
        if not cmd or "--bb-dry-run" in cmd:
            return False
        try:
            from skill_signals import sends_request, strip_heredocs  # type: ignore
        except Exception:  # noqa: BLE001
            return False
        if not sends_request(cmd):
            return False
        body = strip_heredocs(cmd)
        urls = re.findall(r"https?://([^/\s'\"]+)", body)
        if urls and all(re.match(r"(localhost|127\.0\.0\.1|0\.0\.0\.0)(:|$)", u) for u in urls):
            return False
        return True
    return bool(MCP_SENDERS.match(name))


def _in_engagement() -> bool:
    try:
        from pacing import find_project_dir  # type: ignore
        return find_project_dir() is not None
    except Exception:  # noqa: BLE001
        return False


def _armed(ev: dict) -> bool:
    try:
        from hunt_mode import armed  # type: ignore
        return bool(armed(ev.get("session_id", ""), ev.get("transcript_path", "")))
    except Exception:  # noqa: BLE001
        return False


def _audit(event: str, reason: str, ev: dict) -> None:
    try:
        from memory import Memory  # type: ignore
        ti = ev.get("tool_input") or {}
        Memory().audit({
            "source": "crew-gate",
            "event": event,
            "reason": (reason or "").strip() or "(none given)",
            "tool": ev.get("tool_name", ""),
            "command": (ti.get("command", "") if isinstance(ti, dict) else "")[:400],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except Exception:  # noqa: BLE001
        pass


def _spawn_recipe() -> str:
    """How this session hands work to a worker: the `Agent` tool, always.

    It is the shape the operator knows and can open in the UI, and `agent-gate` denies
    the background-process path for exactly that reason (directive 2026-10-30).
    """
    return ("Hand it to a worker — you plan and merge, it sends:\n"
            "    Agent(subagent_type=\"deep-hunter|scout|refuter\", description=\"<role>: <vector>\",\n"
            "          prompt=\"Engagement <name>. Load Skill(\\\"<hunt-skill>\\\"). Fire via "
            "`CBH_PROJECT=<name> bbcurl`. Task: <exactly this request and what it decides>. "
            "Log to hosts/<host>.md, write leads/primitives/findings, report back.\")\n")


def deny_text() -> str:
    return (
        "CREW GATE: you are the orchestrator of an armed hunt, and the orchestrator does "
        "not fire requests — workers do (operator directive; CLAUDE.md, /parallel).\n"
        + _spawn_recipe() +
        "Default crew, up to 3 at once: Scout (surface) · Hunter (top vector + its hunt-* "
        "skill) · Freeroam (`cbh freeroam run`, no methodology). Paste the engagement's "
        "forbidden-action list into every worker prompt.\n"
        "Your job meanwhile: plan, merge results, notes.md, vectors ledger, /remember.\n"
        "Override for a genuine one-off (audited): append `# crew-gate: override <reason>`."
    )


def main() -> int:
    ev = _event()
    if os.environ.get("CBH_CREW_GATE", "").lower() in ("off", "0", "false"):
        return _allow()
    if _own_subagents():
        return _allow()
    if is_worker(ev):
        return _allow()
    if not fires_request(ev):
        return _allow()
    if not _in_engagement():
        return _allow()
    if not _armed(ev):
        return _allow()

    ti = ev.get("tool_input") or {}
    cmd = ti.get("command", "") if isinstance(ti, dict) else ""
    m = OVERRIDE_RE.search(cmd)
    if m:
        _audit("override", m.group(1), ev)
        return _allow()

    _audit("deny", "", ev)
    return _deny(deny_text())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001 - a broken gate must never block real work
        raise SystemExit(0)
