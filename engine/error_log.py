#!/usr/bin/env python3
"""
error_log — one durable file for every tool error this workspace hits.

Operator instruction 2026-10-29: errors have been ephemeral. A tool failure, a
permission denial, a `command not found`, a gate refusal — the agent reads it,
routes around it, and the next session never learns it happened. Worse, a worker's
failure only ever existed in that worker's own transcript, so the orchestrator's
merge read a short answer and could not tell "nothing there" from "the tool broke".

Every error now lands in `hunt-memory/errors.jsonl`, append-only, one JSON row per
error, written by `scripts/error-log.py` (PostToolUseFailure on every tool, plus
PostToolUse on Bash for a command that returned non-zero). Main thread and subagents
go to the same file; `agent_id` and `role` say which.

Read it back with `cbh errors`:

    cbh errors                      # grouped digest, most frequent first
    cbh errors --since 24h          # only the last day
    cbh errors --kind gate_refusal  # one class
    cbh errors --tool Bash --raw    # the rows themselves, newest last
    cbh errors --brief              # one line, for the session brief

The hook never blocks and never fails a tool: it swallows its own errors and always
exits 0. A logger that can break a hunt is worse than no logger.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

LOG_NAME = "errors.jsonl"
MAX_BYTES = 8 * 1024 * 1024
KEEP_ROTATIONS = 3
MSG_CHARS = 2000

# Ordered: the first pattern that matches names the kind, so the specific
# classes sit above the generic ones.
KINDS = [
    ("command_not_found", re.compile(r"command not found|not recognized as"
                                     r"|No such file or directory: '?[\w./-]+'?$", re.I | re.M)),
    ("missing_path", re.compile(r"File does not exist|does not exist"
                                r"|No such file or directory|not found:", re.I)),
    ("permission_denied", re.compile(r"\[Self-Modification\]|\[Third-Party Attack\]"
                                     r"|\[DNS / Domain / Cert Changes\]|\[Credential Exploration\]"
                                     r"|\[Security Weaken\]|requested permissions"
                                     r"|permission denied|user doesn't want to proceed"
                                     r"|operation not permitted", re.I)),
    ("gate_refusal", re.compile(r"REFUSING|BLOCKED|OUT-OF-SCOPE|UNVERIFIED"
                                r"|skill-gate|crew-gate|agent-gate|control-guard|mcp-gate"
                                r"|bbscan:|bbcurl:|MissingRequiredHeader", re.I)),
    ("timeout", re.compile(r"timed out|timeout|ETIMEDOUT|Terminated", re.I)),
    ("network", re.compile(r"ECONNREFUSED|Connection refused|NXDOMAIN|Could not resolve"
                           r"|SSL|certificate|curl: \(\d+\)", re.I)),
    ("traceback", re.compile(r"Traceback \(most recent call last\)|\w+Error:|\w+Exception:")),
]


def log_path(memdir: Path | None = None) -> Path:
    if memdir is None:
        try:
            from paths import memory_dir  # type: ignore
            memdir = Path(memory_dir())
        except Exception:  # noqa: BLE001
            memdir = Path(os.environ.get("CBH_MEMORY_DIR", ".")) / ""
    return Path(memdir) / LOG_NAME


def classify(message: str, exit_code=None) -> str:
    text = message or ""
    for kind, pat in KINDS:
        if pat.search(text):
            return kind
    if isinstance(exit_code, int) and exit_code != 0:
        return "nonzero_exit"
    return "tool_failure"


def _scrub(text: str) -> str:
    if not text:
        return ""
    try:
        from responses import scrub_text  # type: ignore
        text = scrub_text(text)
    except Exception:  # noqa: BLE001
        pass
    return text[:MSG_CHARS]


def _redact_cmd(cmd: str) -> str:
    if not cmd:
        return ""
    try:
        from responses import redact  # type: ignore
        out = redact([cmd])
        return (out[0] if isinstance(out, list) and out else str(out))[:MSG_CHARS]
    except Exception:  # noqa: BLE001
        return _scrub(cmd)


def _message_of(ev: dict) -> tuple[str, object]:
    """-> (message, exit_code). Reads the shapes a hook payload actually carries."""
    parts: list[str] = []
    exit_code = None
    for key in ("error", "message", "stopReason", "reason"):
        v = ev.get(key)
        if isinstance(v, str) and v.strip():
            parts.append(v)
    tr = ev.get("tool_response")
    if isinstance(tr, dict):
        for key in ("error", "stderr", "message", "output", "stdout", "content"):
            v = tr.get(key)
            if isinstance(v, str) and v.strip():
                parts.append(v)
        for key in ("exit_code", "exitCode", "returncode", "code"):
            if isinstance(tr.get(key), int):
                exit_code = tr[key]
                break
        if tr.get("is_error") or tr.get("isError"):
            parts.append("tool reported is_error")
    elif isinstance(tr, str) and tr.strip():
        parts.append(tr)
    text = "\n".join(dict.fromkeys(parts))
    if exit_code is None:
        # The harness reports a failed Bash call as the text "Exit code N" with no
        # structured field, so without this the row carried exit_code=None and the
        # kind fell through to the generic bucket.
        m = re.search(r"\bexit(?:ed with)?[ _]?code[: ]+(\d{1,3})\b", text, re.I)
        if m:
            exit_code = int(m.group(1))
    return text, exit_code


def _signature(message: str) -> str:
    """A stable key for grouping: digits, hex ids, paths and quotes normalised out."""
    s = (message or "").strip().splitlines()
    s = s[0] if s else ""
    s = re.sub(r"0x[0-9a-f]+|[0-9a-f]{8,}", "<hex>", s, flags=re.I)
    s = re.sub(r"\d+", "<n>", s)
    s = re.sub(r"(/[\w.\-]+){2,}", "<path>", s)
    s = re.sub(r"['\"][^'\"]{0,80}['\"]", "<str>", s)
    return re.sub(r"\s+", " ", s)[:160]


# Which client a row came from. Several agent CLIs share this file, and the session
# brief is read by one of them: measured 2026-11-20, 250 of 314 rows over 72 h were
# `run_terminal_command` from another client, so the one-line brief a Claude session
# opened with was three quarters someone else's errors. New rows carry `client`;
# legacy rows are inferred from the tool name (Claude Code's own tools and its
# `mcp__`-prefixed MCP tools vs anything else).
_CLAUDE_TOOLS = frozenset({
    "Bash", "Read", "Edit", "Write", "Glob", "Grep", "Agent", "Task", "WebFetch",
    "WebSearch", "NotebookEdit", "Skill", "ToolSearch", "Monitor", "TaskStop",
    "SendMessage", "AskUserQuestion", "Artifact", "ListAgents",
})


def _current_client() -> str:
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import client as _C  # type: ignore
        return _C.detect()
    except Exception:  # noqa: BLE001 - a logger must never break the caller
        return ""


def row_client(row: dict) -> str:
    """The client that wrote `row`: its own field, else inferred from the tool name."""
    if row.get("client"):
        return row["client"]
    tool = row.get("tool") or ""
    return "claude" if (tool in _CLAUDE_TOOLS or tool.startswith("mcp__")) else "other"


def row_for(ev: dict, now: str | None = None) -> dict | None:
    """Build the row for a hook payload, or None when this is not an error."""
    event = ev.get("hook_event_name") or ev.get("hookEventName") or ""
    message, exit_code = _message_of(ev)
    failed = (event == "PostToolUseFailure"
              or (isinstance(exit_code, int) and exit_code != 0)
              or bool(ev.get("error")))
    if not failed:
        return None
    if not message and not isinstance(exit_code, int):
        return None
    ti = ev.get("tool_input") if isinstance(ev.get("tool_input"), dict) else {}
    cmd = ti.get("command") or ti.get("file_path") or ti.get("url") or ""
    agent_id = ev.get("agent_id") or ""
    return {
        "ts": now or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event or "unknown",
        "kind": classify(message, exit_code),
        "tool": ev.get("tool_name") or "",
        "exit_code": exit_code,
        "session_id": ev.get("session_id") or "",
        "agent_id": agent_id,
        "actor": "subagent" if agent_id else (os.environ.get("CBH_AGENT_ROLE") or "main"),
        "engagement": os.environ.get("CBH_PROJECT") or "",
        "client": _current_client(),
        "cwd": ev.get("cwd") or os.getcwd(),
        "cmd": _redact_cmd(str(cmd)),
        "message": _scrub(message),
        "sig": _signature(message),
    }


def _rotate(path: Path) -> None:
    try:
        if not path.is_file() or path.stat().st_size < MAX_BYTES:
            return
        for i in range(KEEP_ROTATIONS, 0, -1):
            src = path.with_suffix(path.suffix + f".{i}")
            if i == KEEP_ROTATIONS and src.exists():
                src.unlink()
                continue
            if src.exists():
                src.rename(path.with_suffix(path.suffix + f".{i + 1}"))
        path.rename(path.with_suffix(path.suffix + ".1"))
    except OSError:
        pass


def append(row: dict, memdir: Path | None = None) -> Path | None:
    """Append one row. Concurrent sessions share this file, so the write is locked."""
    path = log_path(memdir)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _rotate(path)
        with path.open("a", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return path
    except Exception:  # noqa: BLE001 - a logger must never break the caller
        return None


def record(ev: dict, memdir: Path | None = None) -> dict | None:
    row = row_for(ev)
    if row is None:
        return None
    append(row, memdir)
    return row


# ---------------------------------------------------------------------------
# reader
# ---------------------------------------------------------------------------
def _parse_since(text: str) -> datetime | None:
    if not text:
        return None
    m = re.fullmatch(r"(\d+)\s*([smhd])", text.strip(), re.I)
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2).lower()
    delta = {"s": timedelta(seconds=n), "m": timedelta(minutes=n),
             "h": timedelta(hours=n), "d": timedelta(days=n)}[unit]
    return datetime.now(timezone.utc) - delta


def load(memdir: Path | None = None, since: datetime | None = None,
         kind: str = "", tool: str = "", engagement: str = "",
         actor: str = "") -> list[dict]:
    path = log_path(memdir)
    rows: list[dict] = []
    files = [path.with_suffix(path.suffix + f".{i}")
             for i in range(KEEP_ROTATIONS, 0, -1)] + [path]
    for f in files:
        if not f.is_file():
            continue
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since:
                try:
                    if datetime.fromisoformat(r.get("ts", "")) < since:
                        continue
                except ValueError:
                    pass
            if kind and r.get("kind") != kind:
                continue
            if tool and (r.get("tool") or "").lower() != tool.lower():
                continue
            if engagement and engagement not in (r.get("engagement") or ""):
                continue
            if actor and (r.get("actor") or "") != actor:
                continue
            rows.append(r)
    return rows


def digest(rows: list[dict]) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for r in rows:
        key = (r.get("kind"), r.get("tool"), r.get("sig"))
        g = groups.setdefault(key, {"kind": key[0], "tool": key[1], "sig": key[2],
                                    "count": 0, "first": r.get("ts"), "last": r.get("ts"),
                                    "actors": set(), "engagements": set(),
                                    "sample": r.get("message", "")})
        g["count"] += 1
        g["last"] = r.get("ts")
        if r.get("actor"):
            g["actors"].add(r["actor"])
        if r.get("engagement"):
            g["engagements"].add(r["engagement"])
    out = sorted(groups.values(), key=lambda g: -g["count"])
    for g in out:
        g["actors"] = sorted(g["actors"])
        g["engagements"] = sorted(g["engagements"])
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="cbh errors",
        description="every tool error this workspace recorded (hunt-memory/errors.jsonl)")
    ap.add_argument("--since", default="", metavar="30m|24h|7d")
    ap.add_argument("--kind", default="", help="command_not_found|permission_denied|"
                                              "gate_refusal|timeout|network|traceback|"
                                              "nonzero_exit|tool_failure")
    ap.add_argument("--tool", default="", help="Bash, Read, Edit, mcp__caido__…")
    ap.add_argument("--engagement", default="")
    ap.add_argument("--actor", default="", help="main|subagent|worker")
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--raw", action="store_true", help="the rows themselves, newest last")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--brief", action="store_true", help="one line for the session brief")
    a = ap.parse_args(argv)

    rows = load(since=_parse_since(a.since), kind=a.kind, tool=a.tool,
                engagement=a.engagement, actor=a.actor)

    if a.brief:
        day = load(since=_parse_since("24h"))
        if not day:
            return 0
        me = _current_client() or "generic"
        mine = [r for r in day if row_client(r) == me
                or (me != "claude" and row_client(r) == "other")]
        others = len(day) - len(mine)
        if not mine:
            return 0
        by = {}
        for r in mine:
            by[r.get("kind", "?")] = by.get(r.get("kind", "?"), 0) + 1
        top = ", ".join(f"{k} {v}" for k, v in sorted(by.items(), key=lambda x: -x[1])[:3])
        tail = f" · other clients {others}" if others else ""
        print(f"ERRORS (24h, {me}): {len(mine)} — {top}{tail} · detail `cbh errors --since 24h`")
        return 0

    if a.json:
        print(json.dumps(rows if a.raw else digest(rows), ensure_ascii=False, indent=1))
        return 0

    if not rows:
        where = log_path()
        print(f"no errors recorded{' for that filter' if (a.kind or a.tool or a.since) else ''} "
              f"({where})")
        return 0

    if a.raw:
        for r in rows[-a.limit:]:
            head = (f"{r.get('ts','')}  {r.get('kind',''):<18} {r.get('tool',''):<10} "
                    f"{r.get('actor','')}"
                    + (f" exit={r['exit_code']}" if isinstance(r.get("exit_code"), int) else ""))
            print(head)
            if r.get("cmd"):
                print(f"    cmd: {r['cmd'][:160]}")
            first = (r.get("message") or "").strip().splitlines()
            if first:
                print(f"    {first[0][:200]}")
        print(f"\n{len(rows)} row(s) matched; showing the last {min(a.limit, len(rows))}.")
        return 0

    groups = digest(rows)
    print(f"{len(rows)} error(s) in {len(groups)} distinct signature(s)"
          + (f" since {a.since}" if a.since else "") + f"  ·  {log_path()}")
    print()
    for g in groups[:a.limit]:
        actors = ",".join(g["actors"]) or "?"
        eng = ",".join(g["engagements"])
        print(f"  {g['count']:>4}x  {g['kind']:<18} {g['tool']:<10} {actors}"
              + (f"  [{eng}]" if eng else ""))
        print(f"        {g['sig']}")
        print(f"        first {g['first']}  last {g['last']}")
    if len(groups) > a.limit:
        print(f"\n… {len(groups) - a.limit} more signature(s); raise --limit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
