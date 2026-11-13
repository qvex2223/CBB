#!/usr/bin/env python3
"""
agent-gate — PreToolUse hook: a worker is an `Agent` subagent, not a background shell.

Operator directive 2026-10-30 ("сделай что бы всегда через Agent запускались"): a worker
spawned as its own process is a separate session, so the operator cannot open its chat —
only `claude --resume <id>` reaches it, and on 2026-10-30 three such background shells
ran in one hunt beside the in-process subagents. An `Agent` subagent is visible and
openable in the UI, and `scripts/crew-gate.py` already denies the orchestrator's own
requests, so the worker path has to be the one the operator can watch.

So this hook runs on `Bash` and denies the worker-spawn commands, printing the
`Agent(...)` call to use instead. `--status`/`--health`/`--show-log` are reads, not
spawns, and stay allowed.

The gate used to do the opposite as well: until 2026-11-13 every worker had to run on a
second provider, which an in-process subagent cannot do, so the `Agent`
tool itself was denied on the main thread. That provider is gone — the crew runs on this
plan — and with it that half of the gate: `Agent` and `Task` now pass untouched.

Not gated:
  * a worker spawning something (hook input carries `agent_id`, or CBH_AGENT_ROLE=worker)
  * a client whose subagents are its own, not in-process (engine/client.py row)
Escape hatch, audited: CBH_AGENT_GATE=off, or `# agent-gate: override <reason>`
appended to the Bash command.
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

DEFAULT_ALLOW = {"statusline-setup"}

ROLE_BY_TYPE = {
    # The crew roles, generated into .claude/agents/ by agents/gen_role_agents.py. A role
    # spawn carries the forbidden-action list and the named-victim rule in its definition
    # instead of in whatever the brief remembered.
    "deep-hunter": "hunter",
    "scout": "scout",
    "refuter": "review",   # the role key for "try to disprove it"
    "Explore": "scout",
    "general-purpose": "general",
    "claude": "general",
    "Plan": "general",
    "caveman:cavecrew-investigator": "scout",
    "caveman:cavecrew-reviewer": "review",
}


def _event() -> dict:
    try:
        return json.loads(sys.stdin.read() or "{}")
    except Exception:  # noqa: BLE001
        return {}


def _deny(reason: str) -> int:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    return 0


def _audit(kind: str, ev: dict) -> None:
    try:
        from memory import Memory  # type: ignore
        ti = ev.get("tool_input") or {}
        Memory().audit({
            "source": "agent-gate",
            "event": kind,
            "tool": ev.get("tool_name", ""),
            "subagent_type": ti.get("subagent_type", "") if isinstance(ti, dict) else "",
            "description": (ti.get("description", "") if isinstance(ti, dict) else "")[:200],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except Exception:  # noqa: BLE001
        pass


# A Bash command that SPAWNS a worker as its own process. `--status`/`--health`/
# `--show-log` read the provider or a past run and are not spawns.
#
# The token has to sit at a COMMAND position, not anywhere in the line: the first
# version matched the string itself, so `grep -n "cbh worker" CLAUDE.md` was denied
# as a spawn (seen immediately, 2026-10-30). So each `;`/`&&`/`|`/newline segment is
# read separately and only a segment whose executable is a spawner counts.
WORKER_SPAWN_RE = re.compile(r"(?:\bcbh\s+worker\b|\bclaude\s+(?:-p|--print)\b)")
WORKER_READ_RE = re.compile(r"--(?:status|health|show-log|help)\b")
OVERRIDE_RE = re.compile(r"#\s*agent-gate:\s*override\s+(\S.*)$", re.M)
SEGMENT_RE = re.compile(r"(?:&&|\|\||[;|&\n()])")
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Wrappers that take the real command as their tail. `timeout` also takes a duration,
# which `_executable` drops with the generic "skip a non-command token" rule.
WRAPPERS = {"timeout", "nohup", "setsid", "env", "stdbuf", "nice", "command", "exec",
            "sudo", "time", "xargs"}
SPAWNERS = {"cbh", "python", "python3", "bash", "sh", "zsh", "claude"}


def _executable(segment: str) -> str:
    """The segment's executable, past env assignments and wrapper words."""
    for tok in segment.split():
        if ASSIGN_RE.match(tok) or tok.startswith("-") or tok.replace(".", "").isdigit():
            continue
        base = tok.rsplit("/", 1)[-1]
        if base in WRAPPERS:
            continue
        return base
    return ""


def spawns_worker(cmd: str) -> bool:
    for seg in SEGMENT_RE.split(cmd or ""):
        if not WORKER_SPAWN_RE.search(seg) or WORKER_READ_RE.search(seg):
            continue
        if _executable(seg) in SPAWNERS:
            return True
    return False


def bash_deny_text() -> str:
    return (
        "AGENT GATE: a worker is spawned with the ordinary `Agent` tool, not as its own "
        "process. An `Agent` subagent is visible and openable in the UI, while a "
        "background `claude -p` (or `cbh worker`) is a separate session the operator can "
        "only reach with `claude --resume <id>` (operator directive 2026-10-30).\n"
        "    Agent(subagent_type=\"deep-hunter|scout|refuter\", description=\"<short label>\",\n"
        "          prompt=\"<the full brief - goal, what is already ruled out, which "
        "files to read, exact scope, what to report back>\")\n"
        "Send every lane in ONE message so they run concurrently; crew size from "
        "`cbh crew` (3 by default).\n"
        "Reads are not spawns: `--status` / `--health` / `--show-log` pass.\n"
        "Override (audited): `# agent-gate: override <reason>` on the command, or "
        "CBH_AGENT_GATE=off."
    )


def _strip_heredocs(cmd: str) -> str:
    """A brief that merely MENTIONS `cbh worker` inside a heredoc is not a spawn."""
    try:
        from skill_signals import strip_heredocs  # type: ignore
        return strip_heredocs(cmd)
    except Exception:  # noqa: BLE001
        return cmd


def gate_bash(ev: dict) -> int:
    cmd = (ev.get("tool_input") or {}).get("command") or ""
    if not isinstance(cmd, str) or not WORKER_SPAWN_RE.search(cmd):
        return 0
    cmd = _strip_heredocs(cmd)
    if not spawns_worker(cmd):
        return 0
    if OVERRIDE_RE.search(cmd):
        _audit("override-bash", ev)
        return 0
    _audit("deny-bash", ev)
    return _deny(bash_deny_text())


def _own_subagents() -> bool:
    """True for a client whose workers are its own processes, not in-process `Agent`s.

    This gate's recipe is the `Agent` tool, so it has nothing to offer such a client and
    must not deny its only spawn path. `engine/client.py` holds that row.
    """
    try:
        import client as _C  # type: ignore
        return _C.detect() != "claude"
    except Exception:  # noqa: BLE001
        return os.environ.get("CLAUDECODE") != "1"


def main() -> int:
    ev = _event()
    tool = ev.get("tool_name") or ""
    if tool != "Bash":
        return 0                     # `Agent`/`Task` are the path now, not the problem
    if os.environ.get("CBH_AGENT_GATE", "").lower() in ("off", "0", "false"):
        _audit("override", ev)
        return 0
    if _own_subagents():
        return 0
    if ev.get("agent_id") or (os.environ.get("CBH_AGENT_ROLE", "").lower() == "worker"):
        return 0
    return gate_bash(ev)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        raise SystemExit(0)
