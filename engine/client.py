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
  2. A non-Claude client's own env (`GROK_AGENT`/`GROK_SESSION_ID`) → generic. Before
     `CLAUDECODE`, because Grok Build's compat layer leaks `CLAUDECODE=1`; the two runtime
     gates (`runtime/inline-gate.mjs`, `runtime/playwright-mcp.mjs`) already resolve in
     this order and this module has to agree with them, not contradict them.
  3. `CLAUDECODE=1` → claude.
  4. Process ancestry (`/proc/<pid>/cmdline` up the ppid chain, nearest ancestor first) —
     so a client that exports nothing is still recognised without the operator setting
     anything. Matched on exact argv tokens, never substrings: see `_PROC_MARKERS`.
  5. `generic` — the safe row: assume no hooks, assume you may send, crew 6.

Capability fields are what the doctrine keys on, so AGENTS.md can say "your row" once
instead of repeating itself per client:
  crew                   how many concurrent workers to launch by default
  orchestrator_may_send  may the main thread fire requests, or workers only
  gates_enforced         are the PreToolUse hooks (crew/skill/agent-gate) live
  stop_hook              does a Stop hook keep this client hunting after a finding
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
        "stop_hook": True,
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
        # Separate from gates_enforced on purpose: that field is about being DENIED, this one
        # about being KEPT GOING. engine/stop_gate.py is a Claude Code `Stop` hook, so for
        # every other client the continuous-mode verdict is advisory and continuing after a
        # finding is the client's OWN obligation. Measured 2026-11-14: 0 of the 59 sessions in
        # hunt-memory/pacing/stop_gate.json came from a non-Claude client, i.e. the gate has
        # never once run for one.
        "stop_hook": False,
        "skills": "read skills/<name>/SKILL.md as a file",
        "commands": "read commands/<name>.md and follow it",
        # Names the FILE, because `scripts/sync_clients.py` deploys roles only into
        # `.claude/agents` — this client gets no role registry, so without this line the
        # doctrine, the forbidden-action list and the handback-citation rule reach none of
        # its lanes once they stopped being pasted into every brief.
        "subagents": ("whatever parallel mechanism this client has; else work serially — "
                      "read `agents/roles/<role>.md` as a file first, it carries the "
                      "role's obligations and the crit/high doctrine"),
        "browser": "Playwright MCP, gated by whatever wrapper this client has; `bbcurl` otherwise",
        "notes": [
            "unrecognised client: assume nothing is enforced for you and send through bbcurl only",
            "set CBH_AGENT=claude if you are in fact driving Claude Code",
        ],
    },
}

ALIASES = {
    "claude-code": "claude", "claudecode": "claude", "opus": "claude", "sonnet": "claude",
    # By NAME, not only by process. `_PROC_MARKERS` below recognises a live `grok` process,
    # but an explicit argument took a different path: `_norm("grok")` returned "" and
    # `profile("grok")` fell through to `detect()`, so asking about Grok's row FROM a Claude
    # session printed CLAUDE's row — crew 3 and "you do not fire requests", neither of which
    # is Grok's. That is the 01a1d946 incident surviving in the by-name path, and it also made
    # `scripts/decision_replay.py --client grok` replay as claude and return a clean parity
    # diff for the wrong reason. Measured 2026-11-17.
    "grok": "generic", "grok-build": "generic", "grokbuild": "generic", "xai": "generic",
}

# Matched as an exact argv TOKEN — a token's basename, or one whole path component of it —
# never as a bare substring of the command line.
#
# The bare substring `claude` was a false-positive machine, because this workspace is full of
# the word: the repo answers to `/home/qvex/security-research/Claude-BugHunter` (a symlink kept
# for the old name), every Claude scratchpad lives under `/tmp/claude-1000/...`, and shared
# config sits in `~/.claude/`. `_ancestry()` reads twelve ancestor command lines, so ONE of
# them carrying any of those strings flipped the row. Measured 2026-11-14 on Grok session
# 01a1d946: `cbh client` answered "Claude Code (claude) — detected by process ancestry" to a
# Grok Build session, which then ran a 3-worker crew instead of 6 and was told "you do NOT
# fire requests" — neither of which is Grok's row. Same bug class as the grep-token traps:
# a short token matching inside a longer word.
#
# Exact-component matching keeps every near-miss out: component `.claude` != `claude`,
# `claude-1000` != `claude`, `Claude-BugHunter` != `claude`, basename `cli.py` != `claude`.
_PROC_MARKERS = (
    ("claude", "claude"),
    ("claude-code", "claude"),
    # Grok Build's process is literally named `grok`. It takes the `generic` row: crew 6,
    # may send, no hooks promised. Recognising it here is what keeps the ancestry backstop
    # from guessing `claude` for it.
    ("grok", "generic"),
)

# Clients that announce themselves in the environment but are NOT Claude Code. Checked
# BEFORE `CLAUDECODE`, for the reason `runtime/playwright-mcp.mjs` already documents:
# "Grok Build's compat layer leaks CLAUDECODE=1 into MCP, so GROK_AGENT / GROK_SESSION_ID
# still win." `runtime/inline-gate.mjs` resolves in that same order. This table is what
# makes `cbh client` agree with them instead of contradicting them.
_ENV_MARKERS = (
    (("GROK_AGENT", "GROK_SESSION_ID"), "generic"),
)


def _norm(name: str) -> str:
    n = (name or "").strip().lower()
    n = ALIASES.get(n, n)
    return n if n in PROFILES else ""


def _from_env() -> str:
    for names, client in _ENV_MARKERS:
        if any(os.environ.get(n) for n in names):
            return client
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


def _tokens(line: str) -> set[str]:
    """Every argv token's basename plus each of its path components, for one command line.

    `/usr/bin/claude --flag` -> {"/usr/bin/claude", "usr", "bin", "claude", "--flag"}
    `/tmp/claude-1000/x/p.py` -> {..., "tmp", "claude-1000", "x", "p.py"}  (no bare "claude")
    """
    out: set[str] = set()
    for tok in line.split():
        out.add(tok)
        out.add(tok.rsplit("/", 1)[-1])
        out.update(part for part in tok.split("/") if part)
    return out


def _from_proc() -> str:
    # Nearest ancestor first: `_ancestry()` walks this process up the ppid chain, so the
    # client's own process line is found before anything that merely launched it. Matching
    # marker-first across all twelve lines let a far ancestor outvote the real client.
    for line in _ancestry():
        toks = _tokens(line)
        for marker, name in _PROC_MARKERS:
            if marker in toks:
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


def stop_hook(name: str = "") -> bool:
    """Does a Stop hook keep this client hunting, or must the client keep itself hunting?"""
    return bool(profile(name).get("stop_hook"))


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
    keep_going = ("the Stop hook keeps you hunting: a banked Medium+ does not end the "
                  "session, engine/stop_gate.py decides"
                  if p.get("stop_hook") else
                  "NO Stop hook for you, so NOTHING keeps the hunt alive but you: after every "
                  "wave re-run `cbh autohunt` and obey its `Stop gate:` line, and never end the "
                  "session on a finding — bank it, confirm it, take the next vector. Only the "
                  "operator ends a hunt")
    lines = [
        f"CLIENT: {p['label']} ({p['client']}) — detected by {p['detected_by']}",
        f"  crew          {p['crew']} concurrent workers by default "
        f"(\"hunt_agents\" in profile.json overrides it)",
        f"  sending       {send}",
        f"  gates         {gates}",
        f"  continuing    {keep_going}",
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
