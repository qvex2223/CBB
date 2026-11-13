#!/usr/bin/env python3
"""
limits.py — the usage ledger for this plan: what the harness says is left, and what the
local transcripts say was spent.

What is actually knowable, measured 2026-10-28:

* **Claude's plan counter exists, but only the harness has it.** Claude Code passes
  `.rate_limits.{five_hour,seven_day}` to the statusline on stdin at every render; it is
  in no local file (`~/.claude.json` lacks it, `stats-cache.json` is token totals and was
  16 days stale). `~/.claude/hooks/statusline.sh` therefore caches it to
  `~/.claude/cbh-claude-ratelimits.json`, which `claude_plan_limits()` reads. That counter
  is the authoritative one and is always labelled as the harness's own.
* **Consumption is knowable exactly.** Claude Code writes one transcript per session
  under `~/.claude/projects/<slug>/*.jsonl`, and every `assistant` row carries
  `message.usage` plus `message.model`, so the spend is measured, never estimated.

Declared plan caps (if filled in, `~/.claude/cbh-limits.json`) turn counts into
percentages; they are labelled `declared`, never `measured`.

Dedup matters: one API request is written as several `assistant` rows (one per
`apiBlockIndex`) with the *same* `message.usage`, so counting rows double-counts
tokens. Rows are keyed by `message.id`, falling back to `requestRef`.

The second ledger this module used to carry — a second provider's credits, its quota
endpoint, the console paste and the credit estimator — went out with that provider on
2026-11-13 (operator directive: this toolkit drives Claude Code and nothing else).
Transcript rows whose model is not a Claude model are now simply not counted.

    cbh limits [--days N] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECTS = Path(os.environ.get("CBH_CLAUDE_PROJECTS",
                               str(Path.home() / ".claude" / "projects")))
LIMITS_CONFIG = Path(os.environ.get("CBH_LIMITS_CONFIG",
                                    str(Path.home() / ".claude" / "cbh-limits.json")))

WINDOWS = (("5h", timedelta(hours=5)), ("today", None),
           ("7d", timedelta(days=7)), ("30d", timedelta(days=30)))

def _memdir() -> Path:
    try:
        from paths import memory_dir  # type: ignore
        return Path(memory_dir())
    except Exception:  # noqa: BLE001
        return Path(os.path.expanduser("~/.claude"))


CLAUDE_RL_CACHE = Path(os.environ.get(
    "CBH_CLAUDE_RL_CACHE",
    str(Path.home() / ".claude" / "cbh-claude-ratelimits.json")))


def claude_plan_limits() -> dict:
    """The REAL Claude plan counters, as Claude Code hands them to the statusline.

    `~/.claude/hooks/statusline.sh` receives `.rate_limits.{five_hour,seven_day}` on
    stdin on every render and caches them here. Nothing else on this box has them:
    they are not in `~/.claude.json`, and `stats-cache.json` is Claude-only token
    totals that went 16 days stale.
    """
    try:
        d = json.loads(CLAUDE_RL_CACHE.read_text(encoding="utf-8"))
        if isinstance(d, dict) and d.get("rate_limits"):
            return d
    except Exception:  # noqa: BLE001
        pass
    return {}


def _load_caps() -> dict:
    """Declared plan caps, operator-maintained. Absent = counts without percentages."""
    out = {"claude": {}}
    try:
        d = json.loads(LIMITS_CONFIG.read_text(encoding="utf-8"))
        if isinstance(d.get("claude"), dict):
            out["claude"] = d["claude"]
    except Exception:  # noqa: BLE001
        pass
    return out


def _side(model: str) -> str:
    """`claude` for a Claude model, "" for anything else.

    Returning "" rather than a second side is what keeps an old transcript row from a
    retired provider out of the count instead of silently inflating it.
    """
    m = (model or "").lower()
    if not m or m.startswith("<"):
        return ""
    return "claude" if m.startswith("claude") else ""


def _blank() -> dict:
    return {"requests": 0, "sessions": set(), "input": 0, "output": 0,
            "cache_read": 0, "cache_write": 0, "models": {},
            "first": None, "last": None}


def collect(days: int = 30, projects: Path | None = None, now=None) -> dict:
    """One pass over the transcripts; returns {side: {window: totals}}."""
    root = projects or PROJECTS
    now = now or datetime.now(timezone.utc)
    horizon = now - timedelta(days=max(days, 1))
    midnight_local = datetime.now().astimezone().replace(
        hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc)

    acc = {s: {w: _blank() for w, _ in WINDOWS} for s in ("claude",)}
    seen: set[str] = set()
    files = 0
    if not root.is_dir():
        return {"sides": acc, "files": 0, "now": now, "root": str(root),
                "error": f"no transcript directory at {root}"}

    for f in root.rglob("*.jsonl"):
        try:
            if datetime.fromtimestamp(f.stat().st_mtime, timezone.utc) < horizon:
                continue
        except OSError:
            continue
        files += 1
        try:
            fh = f.open(encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                if '"assistant"' not in line or '"usage"' not in line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                if d.get("type") != "assistant":
                    continue
                msg = d.get("message") or {}
                usage = msg.get("usage") if isinstance(msg, dict) else None
                if not isinstance(usage, dict):
                    continue
                side = _side(msg.get("model") or d.get("requestedModel") or "")
                if not side:
                    continue
                key = msg.get("id") or d.get("requestRef") or d.get("uuid")
                if not key or key in seen:
                    continue
                seen.add(key)
                try:
                    ts = datetime.fromisoformat(
                        (d.get("timestamp") or "").replace("Z", "+00:00"))
                except Exception:  # noqa: BLE001
                    continue
                if ts < horizon:
                    continue
                for name, span in WINDOWS:
                    start = midnight_local if span is None else now - span
                    if ts < start:
                        continue
                    a = acc[side][name]
                    a["requests"] += 1
                    a["sessions"].add(d.get("sessionId") or f.name)
                    a["input"] += int(usage.get("input_tokens") or 0)
                    a["output"] += int(usage.get("output_tokens") or 0)
                    a["cache_read"] += int(usage.get("cache_read_input_tokens") or 0)
                    a["cache_write"] += int(usage.get("cache_creation_input_tokens") or 0)
                    mdl = msg.get("model") or "?"
                    a["models"][mdl] = a["models"].get(mdl, 0) + 1
                    a["first"] = min(a["first"] or ts, ts)
                    a["last"] = max(a["last"] or ts, ts)
    return {"sides": acc, "files": files, "now": now, "root": str(root)}


def _fmt_reset(v) -> str:
    """`resets_at` arrives as epoch seconds or an ISO string; print local time."""
    if v in (None, "", "null"):
        return ""
    try:
        ts = (datetime.fromtimestamp(float(v), timezone.utc) if str(v).isdigit()
              else datetime.fromisoformat(str(v).replace("Z", "+00:00")))
    except Exception:  # noqa: BLE001
        return str(v)
    return ts.astimezone().strftime("%d.%m %H:%M")


def _fmt_tok(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1e6:.1f}M"
    if n >= 1_000:
        return f"{n / 1e3:.0f}k"
    return str(n)


def render(data: dict, caps: dict | None = None) -> list[str]:
    caps = caps if caps is not None else _load_caps()
    out = []
    if data.get("error"):
        return [f"limits: {data['error']}"]

    side = "claude"
    plan = (caps.get(side) or {}).get("plan")
    out.append("")
    out.append("=== CLAUDE — this session, its in-process agents and its workers")
    if plan:
        out.append(f"    plan (declared): {plan}")
    out.append("    the plan counter below comes from the harness itself (same source as "
               "the statusline and `/usage`); the per-window rows under it are measured "
               "consumption from local transcripts.")
    rl = claude_plan_limits()
    if rl.get("rate_limits"):
        age = ""
        try:
            seen = datetime.fromisoformat(rl["cached_at"])
            mins = int((datetime.now(timezone.utc) - seen).total_seconds() // 60)
            age = f" (cached {mins} min ago by the statusline)"
        except Exception:  # noqa: BLE001
            pass
        out.append(f"    PLAN COUNTER{age} — this is the authoritative one:")
        for k, label in (("five_hour", "5h window"), ("seven_day", "7d window")):
            v = (rl["rate_limits"] or {}).get(k) or {}
            used = v.get("used_percentage")
            if used is None:
                continue
            r = _fmt_reset(v.get("resets_at"))
            out.append(f"      {label:<10} {float(used):.0f}% used, "
                       f"{100 - float(used):.0f}% left"
                       + (f"  ·  resets {r}" if r else ""))
    else:
        out.append("    PLAN COUNTER: not cached yet — it arrives with the next "
                   "statusline render (~/.claude/hooks/statusline.sh)")
    rows = data["sides"][side]
    if not rows["30d"]["requests"]:
        out.append("    no requests in the scanned window")
    else:
        for name, _ in WINDOWS:
            a = rows[name]
            # No percentage here on purpose: the percentage is the harness's own counter
            # above, and a request count is not a budget.
            out.append(f"    {name:<6} {a['requests']:>5} requests"
                       f"  ·  {len(a['sessions']):>3} sessions"
                       f"  ·  in {_fmt_tok(a['input'])} / out {_fmt_tok(a['output'])}"
                       f"  ·  cache r {_fmt_tok(a['cache_read'])} "
                       f"w {_fmt_tok(a['cache_write'])}")
        mdl = ", ".join(f"{k} ×{v}" for k, v in
                        sorted(rows["30d"]["models"].items(), key=lambda x: -x[1]))
        out.append(f"    models (30d): {mdl}")
        last = rows["30d"]["last"]
        if last:
            out.append(f"    last request: {last.astimezone().strftime('%Y-%m-%d %H:%M %Z')}")
    out.append("")
    out.append(f"    source: {data['root']} ({data['files']} transcript files scanned); "
               "one API request counted once (deduped by message id).")
    if not LIMITS_CONFIG.is_file():
        out.append(f"    declared caps: none set. Write {LIMITS_CONFIG} as "
                   '{"claude": {"plan": "...", "prompts_per_5h": N}} to get percentages.')
    return out


def brief_line(days: int = 1) -> str:
    """One compact line for session-brief: the plan counter, or a measured fallback.

    The plan counter is authoritative but reaches us only through the statusline cache,
    so when it is not cached yet the line says so instead of printing a measured count
    that would read as a quota.
    """
    rl = (claude_plan_limits().get("rate_limits") or {})
    fh = rl.get("five_hour") or {}
    sd = rl.get("seven_day") or {}
    if fh.get("used_percentage") is not None:
        seg = f"claude plan 5h {100 - float(fh['used_percentage']):.0f}% left"
        r = _fmt_reset(fh.get("resets_at"))
        if r:
            seg += f" ↻{r}"
        if sd.get("used_percentage") is not None:
            seg += f", 7d {100 - float(sd['used_percentage']):.0f}% left"
    else:
        d = collect(days=days)
        c = d["sides"]["claude"]["5h"] if not d.get("error") else {"requests": 0}
        seg = f"claude measured 5h {c['requests']} req (plan counter not cached yet)"
    return f"LIMITS:  {seg}  ·  detail `cbh limits`"


def statusline_segment(now=None) -> str:
    """Empty: there is no second ledger to draw any more.

    This segment existed to show the worker provider's own credit window beside the
    Claude percentages, because nothing else on the box could see it. The workers run on
    this plan now, and `~/.claude/hooks/statusline.sh` already draws that counter from
    the harness's own `rate_limits`. A measured request count beside it would read as a
    second budget, so the segment prints nothing — and the flag stays, so an installed
    statusline hook keeps working unchanged.
    """
    return ""


def roles(minutes: int = 30, now=None) -> dict:
    """Which model each ROLE actually ran on, from the transcripts.

    This is the check for "did my workers actually run, and on which model?". Claude
    Code marks an in-process subagent's rows `isSidechain: true`, so they can be told
    apart from the orchestrator's own turns without trusting any configuration. Rows
    from a separate worker process (`cbh worker`) or a background agent are their own
    session, so they land under `worker/background` — not sidechains, but not the
    orchestrator either.
    """
    now = now or datetime.now(timezone.utc)
    cut = now - timedelta(minutes=minutes)
    out = {"orchestrator": {}, "subagents": {}, "worker_or_background": {}}
    root = PROJECTS
    if not root.is_dir():
        return out
    seen = set()
    for f in root.rglob("*.jsonl"):
        try:
            if datetime.fromtimestamp(f.stat().st_mtime, timezone.utc) < cut:
                continue
        except OSError:
            continue
        try:
            fh = f.open(encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                if '"assistant"' not in line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                if d.get("type") != "assistant":
                    continue
                msg = d.get("message") or {}
                model = msg.get("model")
                if not model:
                    continue
                key = msg.get("id") or d.get("uuid")
                if key in seen:
                    continue
                seen.add(key)
                try:
                    ts = datetime.fromisoformat((d.get("timestamp") or "").replace("Z", "+00:00"))
                except Exception:  # noqa: BLE001
                    continue
                if ts < cut:
                    continue
                if d.get("isSidechain"):
                    bucket = "subagents"
                elif (d.get("entrypoint") or "") == "sdk-cli":
                    bucket = "worker_or_background"
                else:
                    bucket = "orchestrator"
                out[bucket][model] = out[bucket].get(model, 0) + 1
    return out


def render_roles(minutes: int = 30) -> list:
    r = roles(minutes)
    out = [f"WHO RAN ON WHAT — last {minutes} min, from the transcripts "
           "(isSidechain marks an in-process subagent):"]
    for label, key in (("orchestrator (this session)", "orchestrator"),
                       ("subagents (in-process)", "subagents"),
                       ("workers / background sessions", "worker_or_background")):
        d = r[key]
        body = ", ".join(f"{m} ×{n}" for m, n in sorted(d.items(), key=lambda x: -x[1])) or "-"
        out.append(f"  {label:<30} {body}")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cbh limits", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=30, help="how far back to scan (default 30)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--brief", action="store_true", help="the one-line session-brief form")
    ap.add_argument("--roles", nargs="?", type=int, const=30, default=None,
                    metavar="MINUTES",
                    help="which model each role actually ran on")
    ap.add_argument("--statusline", action="store_true",
                    help="the extra statusline segment (empty: the harness draws the "
                         "plan counter itself)")
    a = ap.parse_args(argv)
    if a.roles is not None:
        for line in render_roles(a.roles):
            print(line)
        return 0
    if a.statusline:
        print(statusline_segment())
        return 0
    if a.brief:
        line = brief_line()
        if line:
            print(line)
        return 0
    data = collect(days=a.days)
    if a.json:
        out = {"root": data.get("root"), "files": data.get("files"),
               "now": data["now"].isoformat() if data.get("now") else None,
               "caps_declared": _load_caps(), "sides": {}}
        for side, rows in data.get("sides", {}).items():
            out["sides"][side] = {
                w: {**{k: v for k, v in a2.items() if k not in ("sessions", "first", "last")},
                    "sessions": len(a2["sessions"]),
                    "first": a2["first"].isoformat() if a2["first"] else None,
                    "last": a2["last"].isoformat() if a2["last"] else None}
                for w, a2 in rows.items()}
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    for line in render(data):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
