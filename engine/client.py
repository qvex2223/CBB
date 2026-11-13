#!/usr/bin/env python3
"""client.py — ONE source of truth for "which agent CLI is driving this session,
and what changes because of it".

Why this exists: the workspace doctrine used to be forked per client, and the same
lesson had to be written once per fork and went stale in all but one. The doctrine is
now one file (root `AGENTS.md`); the little that genuinely depends on the driving CLI
lives here, in code, as one row. A session asks `cbh client` and gets its row.

The toolkit targets Claude Code (operator directive 2026-11-13). The `generic` row
remains for any other CLI that picks the repo up: it promises nothing, assumes no
hooks are enforced, and tells that session to send through `bbcurl` only.

Detection order (first hit wins):
  1. `CBH_AGENT=<name>` — explicit override, always respected.
  2. `CLAUDECODE=1` → claude.
  3. Process ancestry (`/proc/<pid>/cmdline` up the ppid chain) — so a client that
     exports nothing is still recognised without the operator setting anything.
  4. `generic` — the safe row: assume no hooks, assume you may send, crew 6.

Capability fields are what the doctrine keys on, so AGENTS.md can say "your row" once
instead of repeating itself per client:
  crew                   how many concurrent workers to launch by default
  orchestrator_may_send  may the main thread fire requests, or workers only
  gates_enforced         are the PreToolUse hooks (crew/skill/agent-gate) live
  skills / commands      how this client loads `skills/` and `commands/`
  subagents              how to spawn a role worker
  browser                how browser work is driven
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# A client name is only ever one of these keys; `generic` is the fallback row.
PROFILES: dict[str, dict] = {
    "claude": {
        "client": "claude",
        "label": "Claude Code",
        "crew": 3,
        "orchestrator_may_send": False,
        "gates_enforced": True,
        "skills": "Skill(\"<name>\") tool; copies in ~/.claude/skills (scripts/sync_clients.py)",
        "commands": "/<name> slash commands; copies in ~/.claude/commands",
        "subagents": "Agent tool, subagent_type from .claude/agents/ (deep-hunter|scout|refuter)",
        "browser": "Playwright MCP through scripts/mcp-gate.py; one lane per engagement",
        "notes": [
            "crew-gate denies requests from the orchestrator: you plan and merge, workers fire",
            "skill-gate denies a surface whose hunt-* skill is not loaded",
            "hooks must be installed in ~/.claude/settings.json (docs/setup/apply-hooks.py --apply)",
        ],
    },
    "generic": {
        "client": "generic",
        "label": "unrecognised agent CLI",
        # 6, not 3: a client with no crew-gate can run its own workers, and
        # engine/crew.py still warns when the pacing budget cannot feed them.
        "crew": 6,
        "orchestrator_may_send": True,
        "gates_enforced": False,
        "skills": "read skills/<name>/SKILL.md as a file",
        "commands": "read commands/<name>.md and follow it",
        "subagents": "whatever parallel mechanism this client has; else work serially",
        "browser": "Playwright MCP, gated by whatever wrapper this client has; `bbcurl` otherwise",
        "notes": [
            "unrecognised client: assume nothing is enforced for you and send through bbcurl only",
            "set CBH_AGENT=claude if you are in fact driving Claude Code",
        ],
    },
}

ALIASES = {
    "claude-code": "claude", "claudecode": "claude", "opus": "claude", "sonnet": "claude",
}

_PROC_MARKERS = (
    ("claude", "claude"),
)


def _norm(name: str) -> str:
    n = (name or "").strip().lower()
    n = ALIASES.get(n, n)
    return n if n in PROFILES else ""


def _from_env() -> str:
    if os.environ.get("CLAUDECODE") == "1":
        return "claude"
    return ""


def _ancestry() -> list[str]:
    """Command lines of this process and its ancestors, lowercased. Empty off Linux."""
    out: list[str] = []
    try:
        pid = os.getpid()
        for _ in range(12):  # a client is never twelve forks above a tool call
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
            out.append(cmd.decode("utf-8", "replace").lower())
            stat = Path(f"/proc/{pid}/stat").read_text()
            ppid = int(stat.rsplit(")", 1)[1].split()[1])
            if ppid <= 1 or ppid == pid:
                break
            pid = ppid
    except Exception:  # noqa: BLE001 - detection must never raise into a hunt
        pass
    return out


def _from_proc() -> str:
    lines = _ancestry()
    for marker, name in _PROC_MARKERS:
        if any(marker in line for line in lines):
            return name
    return ""


def detect() -> str:
    """The client driving this session. Never raises; worst case returns `generic`."""
    explicit = _norm(os.environ.get("CBH_AGENT", ""))
    if explicit:
        return explicit
    return _from_env() or _from_proc() or "generic"


def profile(name: str = "") -> dict:
    """The capability row for `name` (default: the detected client), plus `detected_by`."""
    want = _norm(name) or detect()
    row = dict(PROFILES[want])
    if name:
        row["detected_by"] = "argument"
    elif _norm(os.environ.get("CBH_AGENT", "")):
        row["detected_by"] = "CBH_AGENT"
    elif _from_env():
        row["detected_by"] = "client env var"
    elif _from_proc():
        row["detected_by"] = "process ancestry"
    else:
        row["detected_by"] = "fallback (nothing identified this client)"
    return row


def crew(name: str = "") -> int:
    return int(profile(name)["crew"])


def may_send(name: str = "") -> bool:
    return bool(profile(name)["orchestrator_may_send"])


def gates_enforced(name: str = "") -> bool:
    return bool(profile(name)["gates_enforced"])


def brief(name: str = "") -> str:
    """The client's own row, for a session brief or a worker launch text."""
    p = profile(name)
    send = ("you MAY fire requests yourself, and so may your workers"
            if p["orchestrator_may_send"] else
            "you do NOT fire requests: you plan and merge, workers send (crew-gate enforces it)")
    gates = ("PreToolUse hooks are live: crew-gate, skill-gate, agent-gate can deny you"
             if p["gates_enforced"] else
             "no PreToolUse hooks for you: scope and pacing bind via bbcurl and the MCP inline gate")
    lines = [
        f"CLIENT: {p['label']} ({p['client']}) — detected by {p['detected_by']}",
        f"  crew          {p['crew']} concurrent workers by default "
        f"(\"hunt_agents\" in profile.json overrides it)",
        f"  sending       {send}",
        f"  gates         {gates}",
        f"  skills        {p['skills']}",
        f"  commands      {p['commands']}",
        f"  subagents     {p['subagents']}",
        f"  browser       {p['browser']}",
    ]
    lines += [f"  · {n}" for n in p["notes"]]
    lines.append("Everything else is in root AGENTS.md: it is the doctrine, and the safety "
                 "floor there binds you.")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="cbh client",
        description="which agent CLI is driving this session, and what changes because of it")
    ap.add_argument("name", nargs="?", default="",
                    help="print another client's row instead of the detected one")
    ap.add_argument("--json", action="store_true", help="machine-readable row")
    ap.add_argument("--list", action="store_true", help="list every known client row")
    ap.add_argument("--field", default="", help="print one field only (crew, "
                                                "orchestrator_may_send, gates_enforced, …)")
    a = ap.parse_args(argv)

    if a.list:
        for key in PROFILES:
            sys.stdout.write(brief(key) + "\n")
        return 0
    p = profile(a.name)
    if a.field:
        if a.field not in p:
            sys.stderr.write(f"no such field: {a.field}\nfields: {', '.join(p)}\n")
            return 2
        val = p[a.field]
        sys.stdout.write((json.dumps(val) if isinstance(val, (list, dict)) else str(val)) + "\n")
        return 0
    sys.stdout.write(json.dumps(p, indent=2) + "\n" if a.json else brief(a.name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
