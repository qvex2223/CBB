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

Since 2026-11-13 it also sizes the crew, because the brief does not. In the Activ hunt
the engagement's `profile.json` said `"hunt_agents": 3` and the session ran **7**
concurrent lanes: lanes were spawned one per message, so nothing ever compared the
number of live workers against the cap. Extra workers do not add requests — pacing is
one `flock`'d budget per engagement, so they queue on it (one worker logged exactly
that) and they do spend context, which is what truncates a hand-back. So an `Agent`
spawn is denied while the crew is full, and a single message carrying more lanes than
the cap is denied as a batch.

And it reads the brief for the funnel files it names: briefing a lane that is already
closed costs a whole lane. One such brief went out in the same hunt — the orchestrator
picked the file off `ls leads/` instead of `cbh leads`, and the lead had been closed
REFUTED hours earlier. A `stalled` closure is exempt: that one is OUR tooling failing,
it stays in the queue, and re-running it is the point.

Not gated:
  * a worker spawning something (hook input carries `agent_id`, or CBH_AGENT_ROLE=worker)
  * a client whose subagents are its own, not in-process (engine/client.py row)
  * anything outside an armed hunt — crew size is a hunt rule, and `Explore`/`Plan`
    agents during ordinary work are not a crew
Escape hatch, audited: CBH_AGENT_GATE=off, or `# agent-gate: override <reason>`
appended to the Bash command. For an `Agent` spawn the equivalent is an explicit
`agent-gate: override <reason>` line inside the prompt.
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


AGENT_OVERRIDE_RE = re.compile(r"agent-gate:\s*override\s+(\S.*)", re.I)
FUNNEL_PATH_RE = re.compile(r"(?:^|[\s(`'\"])((?:leads|primitives|findings)/[^\s)`'\"]+\.md)")
# A worker whose transcript has not moved in this long is not a live lane whatever its
# meta file says: a killed agent's meta keeps neither `finished` nor `stoppedByUser`
# (measured 2026-11-13 — two lanes killed at the session's end look exactly like this).
STALE_WORKER_MINUTES = 20


def _crew_limit(cwd: str) -> tuple[int, str, str]:
    """(cap, where it comes from, engagement name) — `engine/crew.py` decides, not this."""
    try:
        import crew  # type: ignore
        plan = crew.plan(start=cwd or "")
    except Exception:  # noqa: BLE001
        return (0, "", "")
    eng = plan.get("engagement") or ""
    if not eng:
        return (0, "", "")
    try:
        cap = int(plan.get("agents") or 0)
    except (TypeError, ValueError):
        cap = 0
    return (cap, str(plan.get("source") or ""), str(eng))


def _live_workers(ev: dict) -> list[str]:
    """The descriptions of this session's workers that are still running.

    Read from the per-agent `*.meta.json` the client writes beside the transcript, which
    is the only record that says whether a worker ENDED: `finished` after a hand-back,
    `stoppedByUser` after a kill. A transcript that has not been appended to for
    STALE_WORKER_MINUTES is treated as ended whatever its meta says, so one crashed lane
    cannot wedge the crew for the rest of the session.
    """
    tp = ev.get("transcript_path") or ""
    sid = ev.get("session_id") or ""
    if not tp or not sid:
        return []
    subagents = Path(tp).parent / sid / "subagents"
    if not subagents.is_dir():
        return []
    import time
    now = time.time()
    live: list[str] = []
    for meta_path in sorted(subagents.glob("*.meta.json")):
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:  # noqa: BLE001
            continue
        if meta.get("finished") or meta.get("stoppedByUser"):
            continue
        jsonl = meta_path.with_name(meta_path.name.replace(".meta.json", ".jsonl"))
        try:
            if (now - jsonl.stat().st_mtime) > STALE_WORKER_MINUTES * 60:
                continue
        except OSError:
            continue
        live.append(str(meta.get("description") or meta_path.stem)[:60])
    return live


def _batch_size(ev: dict) -> int:
    """How many `Agent` calls the assistant's current message carries, this one included.

    The transcript already holds the message whose tool calls are being approved, so the
    whole batch is visible here while the siblings' own hooks have not run yet. Without
    this, a crew of six sent in ONE message passes six times over: every sibling is
    pending, none is running, and the cap is compared against zero.
    """
    tp = ev.get("transcript_path") or ""
    if not tp:
        return 1
    try:
        lines = Path(tp).read_text(errors="replace").splitlines()
    except OSError:
        return 1
    for line in reversed(lines):
        try:
            row = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        if row.get("type") != "assistant":
            continue
        content = (row.get("message") or {}).get("content") or []
        n = sum(1 for b in content if isinstance(b, dict)
                and b.get("type") == "tool_use" and b.get("name") in ("Agent", "Task"))
        return max(1, n)
    return 1


def _closed_leads(prompt: str, eng_dir: Path) -> list[tuple[str, str]]:
    """[(path, verdict)] for every funnel file the brief names that is already closed.

    `stalled` is not closed for this purpose — `engine/lead_queue.py` keeps it in the
    queue on purpose, because our own tooling is what did not finish.
    """
    out: list[tuple[str, str]] = []
    try:
        import lead_queue as LQ  # type: ignore
    except Exception:  # noqa: BLE001
        return out
    seen: set[str] = set()
    for rel in FUNNEL_PATH_RE.findall(prompt or ""):
        if rel in seen:
            continue
        seen.add(rel)
        path = eng_dir / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if not LQ._is_closed(text) or LQ._is_stalled(text):
            continue
        # `_banners` yields the verdict payload itself (one string), already lower-cased
        # and stripped of emphasis — the first one that starts with a closure word is the
        # verdict `cbh leads close` wrote, since close() inserts at the FIRST status line.
        verdict = ""
        for banner in LQ._banners(text):
            if banner.startswith(LQ.CLOSURE_WORDS):
                verdict = banner[:60]
                break
        out.append((rel, verdict or "closed"))
    return out


def gate_agent(ev: dict) -> int:
    ti = ev.get("tool_input") or {}
    if not isinstance(ti, dict):
        return 0
    prompt = str(ti.get("prompt") or "")
    if AGENT_OVERRIDE_RE.search(prompt):
        _audit("override-agent", ev)
        return 0
    cwd = str(ev.get("cwd") or "")
    try:
        from hunt_mode import armed  # type: ignore
        if not armed(ev.get("session_id", ""), ev.get("transcript_path", "")):
            return 0
    except Exception:  # noqa: BLE001
        return 0

    cap, source, eng_name = _crew_limit(cwd)
    eng_dir = None
    try:
        import lead_queue as LQ  # type: ignore
        eng_dir = LQ.resolve_engagement(eng_name) if eng_name else None
    except Exception:  # noqa: BLE001
        eng_dir = None

    if eng_dir is not None and prompt:
        closed = _closed_leads(prompt, eng_dir)
        if closed and len(closed) == len(set(FUNNEL_PATH_RE.findall(prompt))):
            rows = "\n".join(f"    {rel}  —  closed {verdict}" for rel, verdict in closed)
            _audit("deny-agent-closed-lead", ev)
            return _deny(
                "AGENT GATE: every funnel file this brief names is already closed, so the "
                "lane would re-fire settled work:\n" + rows + "\n"
                "Lanes come from `cbh leads` (ranked, with the holds subtracted), not from "
                "`ls leads/`: the queue prints the closure, the file's own banner does not "
                "reach a brief. If the closure is wrong, reopen it on the record first —\n"
                "    cbh leads reopen <file> --note \"why it is not settled\"\n"
                "A `stalled` closure is exempt and never reaches this message; `blocked` is "
                "held back for the operator on purpose.\n"
                "Override (audited): put `agent-gate: override <reason>` in the prompt."
            )

    if cap > 0:
        live = _live_workers(ev)
        batch = _batch_size(ev)
        if batch > cap:
            _audit("deny-agent-batch", ev)
            return _deny(
                f"AGENT GATE: this message carries {batch} lanes and the crew cap is {cap} "
                f"({source or 'engine/crew.py'}) on `{eng_name}`. Send {cap}, keep the rest in "
                "the queue and refill a slot as each lane hands back.\n"
                "More workers do not mean more requests: pacing is ONE flock'd budget per "
                "engagement, so the extra lanes queue on it while still spending the context "
                "that truncates a hand-back. Raise the cap in `profile.json` "
                "(\"hunt_agents\") if the operator wants it raised — never in a brief.\n"
                "Override (audited): put `agent-gate: override <reason>` in the prompt."
            )
        if len(live) >= cap:
            rows = "\n".join(f"    {d}" for d in live[:8])
            _audit("deny-agent-cap", ev)
            return _deny(
                f"AGENT GATE: {len(live)} workers are still running and the crew cap is {cap} "
                f"({source or 'engine/crew.py'}) on `{eng_name}`:\n" + rows + "\n"
                "Wait for one to hand back, then fill that slot from `cbh leads` / "
                "`cbh autohunt`. A lane that has fired nothing for ~5 minutes is dead: kill it "
                "once (TaskStop), give the slot a different lane, and note it — check "
                "`hunt-memory/audit.jsonl` before believing it died at the target.\n"
                "Override (audited): put `agent-gate: override <reason>` in the prompt."
            )
    return 0


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
    if tool not in ("Bash", "Agent", "Task"):
        return 0
    if os.environ.get("CBH_AGENT_GATE", "").lower() in ("off", "0", "false"):
        _audit("override", ev)
        return 0
    if _own_subagents():
        return 0
    if ev.get("agent_id") or (os.environ.get("CBH_AGENT_ROLE", "").lower() == "worker"):
        return 0                     # a worker's own helper is not the orchestrator's crew
    if tool in ("Agent", "Task"):
        return gate_agent(ev)
    return gate_bash(ev)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        raise SystemExit(0)
