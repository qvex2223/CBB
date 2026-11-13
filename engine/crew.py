#!/usr/bin/env python3
"""
crew — how many workers this engagement's own budget can actually feed.

Operator instruction 2026-10-29: "при ханте одной программы запускалось макс
количество агентов, но в разумном количестве". Until now the number was a constant
in prose — "Cap is 3 concurrent workers" in scripts/hunt-arm.py — the same 3 for a
programme that publishes 30 rps and for one still on the 10-second default. One of
those two numbers was always wrong.

The arithmetic, all of it measured in this workspace:

  * `engine/pacing.py::wait_turn` holds its flock ACROSS the sleep, and
    `max_concurrency` is not read in that path at all. So the whole engagement —
    every worker, every concurrent session — shares one serialised budget:

        ceiling_rps = 1 / min_interval_seconds

  * a worker turns over at p50 24 s (measured 2026-10-29 over n=6242 worker turns) and
    fires roughly 1-3 requests per turn, so one worker sustains about
    WORKER_RPS = 0.08 req/s.

  * therefore `ceiling_rps / WORKER_RPS` workers saturate the budget. Past that a
    worker adds no requests at all: it only queues on the flock and spends credits.

Two ceilings then clamp that, and both are measured rather than chosen:

  * MAX_WORKERS = 6 — the ceiling when workers are separate `claude -p` processes
    (`cbh worker`), where the compaction limit below does not apply; each one still
    spends the plan and the orchestrator still merges every result by hand. Where
    workers are in-process `Agent` subagents nothing reaches it: IN_PROCESS_CAP is the
    crew cap and `scripts/agent-gate.py` denies the overflow path.
  * IN_PROCESS_CAP = 3 — in-process `Agent` subagents share THIS session's context
    window, and past three, compaction truncates a worker mid-run while the merge
    silently reads half an answer. That is the konsol-era measurement and it stands.

Finally the quota: the crew spends the same 5-hour plan window the orchestrator needs,
so when that window runs low the crew shrinks instead of draining it and stalling
ordinary work too.

    cbh crew                 # the number for the engagement resolved from cwd/$CBH_PROJECT
    cbh crew --project standoff365/yukki
    cbh crew --json
"""
from __future__ import annotations

import argparse
import json
import os
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

WORKER_RPS = 0.08          # one worker's sustained request rate (p50 24s/turn)
MAX_WORKERS = 6            # separate `cbh worker` processes
IN_PROCESS_CAP = 3         # in-process `Agent` subagents: context compaction
HARD_MAX = 12              # an explicit operator override is still bounded
# Operator directive 2026-11-10 (final): every engagement runs 3 workers unless its
# profile.json sets "hunt_agents". None = derive from the pacing budget.
DEFAULT_HUNT_AGENTS: int | None = 3
# Operator directive 2026-11-10: a client with no crew-gate runs 6 of its own subagents,
# regardless of profile.json and of this plan's quota.
NON_CLAUDE_AGENTS = 6
LOW_QUOTA_PCT = 25         # below this the crew halves
CRITICAL_QUOTA_PCT = 10    # below this the crew is one


def _engagement(project: str = "", start: str = ""):
    """`start` is the directory to resolve from — a hook knows the session's cwd,
    which is not the hook process's own cwd."""
    from pacing import Engagement, find_project_dir  # type: ignore
    if project:
        from paths import targets_root  # type: ignore
        p = Path(targets_root()) / project
        if not p.is_dir():
            raise SystemExit(f"cbh crew: no engagement at {p}")
        return Engagement(p)
    return Engagement(find_project_dir(Path(start) if start else None))


def _quota_pct() -> float | None:
    """Percent of this plan's 5-hour window still left, or None when unknown.

    It is the same window the orchestrator needs, so a low reading shrinks the crew:
    the workers and this session draw on one counter.
    """
    try:
        import limits  # type: ignore
        fh = ((limits.claude_plan_limits().get("rate_limits") or {})
              .get("five_hour") or {})
        used = fh.get("used_percentage")
        return None if used is None else max(0.0, 100.0 - float(used))
    except Exception:  # noqa: BLE001 - an unreadable quota must not block a hunt
        return None


def _client() -> str:
    """Which agent CLI drives this session — ONE implementation, engine/client.py."""
    try:
        import client as _C  # type: ignore
        return _C.detect()
    except Exception:  # noqa: BLE001 - detection must never block a hunt
        explicit = (os.environ.get("CBH_AGENT") or "").strip().lower()
        if explicit:
            return explicit
        return "claude" if os.environ.get("CLAUDECODE") == "1" else "generic"


def _in_process_workers() -> bool:
    """True when a worker is an in-process `Agent` subagent sharing this context.

    That is what makes IN_PROCESS_CAP binding: three is where compaction starts
    truncating a worker mid-run. A client that spawns its own separate subagents is not
    bound by it, and `engine/client.py` holds that row.
    """
    try:
        import client as _C  # type: ignore
        return _C.detect() == "claude"
    except Exception:  # noqa: BLE001
        return os.environ.get("CLAUDECODE") == "1"


def plan(project: str = "", credits_pct: float | None = -1.0,
         start: str = "") -> dict:
    eng = _engagement(project, start)
    if eng.project_dir is None:
        return {"engagement": None, "agents": 1, "in_process_cap": 1,
                "reason": "no engagement resolved — nothing to size a crew against"}

    interval = eng.min_interval
    ceiling_rps = (1.0 / interval) if interval > 0 else float("inf")
    budget_useful = (MAX_WORKERS if ceiling_rps == float("inf")
                     else max(1, int(ceiling_rps / WORKER_RPS)))

    override = eng.profile.get("hunt_agents")
    try:
        override = int(override) if override is not None else None
    except (TypeError, ValueError):
        override = None

    notes: list[str] = []
    default_used = False
    if _client() != "claude":
        agents = NON_CLAUDE_AGENTS
        routed = _in_process_workers()
        notes.append(f"client {_client()}: always {NON_CLAUDE_AGENTS} subagents, "
                     "no quota-based cut")
        if agents > budget_useful:
            notes.append(f"the budget only feeds {budget_useful}: the extra "
                         f"{agents - budget_useful} will queue on the flock without "
                         "adding a single request")
        return {"engagement": eng.name, "agents": agents, "in_process_cap": agents,
                "min_interval_seconds": interval, "ceiling_rps": ceiling_rps,
                "budget_useful": budget_useful, "credits_left_pct": None,
                "source": f"{_client()}: always {NON_CLAUDE_AGENTS} (operator directive 2026-11-10)",
                "notes": notes, "in_process": routed, "client": _client()}
    if override is None and DEFAULT_HUNT_AGENTS:
        override, default_used = DEFAULT_HUNT_AGENTS, True
    if override is not None:
        agents = max(1, min(HARD_MAX, override))
        source = (f"default {override} (operator directive 2026-11-10; set \"hunt_agents\" "
                  "in profile.json to change)" if default_used
                  else f'"hunt_agents": {override} in profile.json (operator override)')
        if agents > budget_useful:
            notes.append(f"the budget only feeds {budget_useful}: the extra "
                         f"{agents - budget_useful} will queue on the flock without "
                         "adding a single request")
    else:
        agents = min(budget_useful, MAX_WORKERS)
        source = (f"derived: ceiling {ceiling_rps:.2f} req/s "
                  f"(1/{interval}s) / {WORKER_RPS} req/s per worker = {budget_useful}, "
                  f"capped at {MAX_WORKERS}")

    # Operator directive 2026-10-30: every worker is spawned with the `Agent` tool, so
    # the in-process cap IS the crew cap — the old "run the rest as `cbh worker`" overflow
    # went out with the second provider (2026-11-13) and is denied by
    # scripts/agent-gate.py. Past the cap, rotate roles through the queue.
    # An explicit "hunt_agents" is the operator accepting the compaction risk
    # (operator instruction 2026-11-10: speed over the in-process cap).
    routed = _in_process_workers()
    if routed and agents > IN_PROCESS_CAP and isinstance(override, int) and override > 0:
        notes.append(f"operator override above the in-process cap of {IN_PROCESS_CAP}: "
                     "keep each worker's hand-back short (counts + verdict + file paths) "
                     "so compaction cannot truncate the merge")
    elif routed and agents > IN_PROCESS_CAP:
        notes.append(f"subagents run in-process in this session, so the crew is capped at "
                     f"{IN_PROCESS_CAP} (the budget would feed {agents}); cover the rest by "
                     "rotating roles through the queue")
        agents = IN_PROCESS_CAP

    label = "Claude plan"
    pct = _quota_pct() if credits_pct == -1.0 else credits_pct
    # A client with its own subagents was already returned above, unthrottled: the
    # operator wants no quota-based cut there (2026-11-10).
    if pct is not None:
        if pct < CRITICAL_QUOTA_PCT:
            agents = 1
            notes.append(f"{label} 5h window at {pct:.0f}% left "
                         f"(<{CRITICAL_QUOTA_PCT}%): crew cut to 1 so a hunt does not "
                         "drain the quota")
        elif pct < LOW_QUOTA_PCT:
            agents = max(1, agents // 2)
            notes.append(f"{label} 5h window at {pct:.0f}% left (<{LOW_QUOTA_PCT}%): "
                         "crew halved")

    return {"engagement": eng.name, "agents": agents,
            "in_process_cap": (agents if routed and override and agents > IN_PROCESS_CAP
                               else min(agents, IN_PROCESS_CAP)),
            "min_interval_seconds": interval, "ceiling_rps": ceiling_rps,
            "budget_useful": budget_useful, "credits_left_pct": pct,
            "source": source, "notes": notes, "in_process": routed}


def orders_line(project: str = "", start: str = "") -> str:
    """The sentence scripts/hunt-arm.py injects into an armed hunt."""
    try:
        p = plan(project, start=start)
    except Exception:  # noqa: BLE001
        return ("Crew size: 3 concurrent workers (crew sizing unavailable, falling back "
                "to the measured in-process cap).")
    if p.get("engagement") is None:
        n = (NON_CLAUDE_AGENTS if _client() != "claude"
             else DEFAULT_HUNT_AGENTS or IN_PROCESS_CAP)
        return (f"Crew size: {n} concurrent workers by default (operator directive "
                "2026-11-10) — after `/pickup <target>`, run `cbh crew` for that engagement's "
                f"number and launch all of them in ONE message; refill each slot as it frees.")
    out = [f"Crew size for {p['engagement']}: {p['agents']} concurrent worker(s) — "
           f"{p['source']}."]
    if p.get("client", "claude") != "claude":
        out.append(f"Spawn all {p['agents']} as your own parallel subagents, in one message, "
                   "and refill each slot from the queue the moment it hands back.")
    elif p.get("in_process") and p["agents"] > IN_PROCESS_CAP:
        out.append(f"Spawn all {p['agents']} with the `Agent` tool, in one message, and keep "
                   "every slot filled from the queue (operator override above the "
                   f"in-process cap of {IN_PROCESS_CAP}).")
    else:
        out.append(f"Spawn every one with the `Agent` tool (cap {IN_PROCESS_CAP}: past that, "
                   "compaction truncates one mid-run and the merge reads half an answer).")
    for n in p["notes"]:
        out.append(n[0].upper() + n[1:] + ".")
    out.append("More coverage beyond this number = rotate roles through the queue, not "
               "more agents.")
    return " ".join(out)


def brief_line(project: str = "", start: str = "") -> str:
    try:
        p = plan(project, start=start)
    except Exception:  # noqa: BLE001
        return ""
    if p.get("engagement") is None:
        return ""
    extra = " (all via the `Agent` tool)" if p.get("in_process") else ""
    return (f"CREW SIZE: {p['agents']} worker(s) for {p['engagement']}{extra}  ·  "
            f"budget {p['ceiling_rps']:.1f} req/s  ·  detail `cbh crew`")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="cbh crew",
        description="how many workers this engagement's pacing budget can actually feed")
    ap.add_argument("--project", default="", help="engagement name, may be nested")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    p = plan(a.project)
    if a.json:
        print(json.dumps(p, ensure_ascii=False, indent=1, default=str))
        return 0
    if p.get("engagement") is None:
        print(p["reason"])
        return 1
    print(f"engagement        {p['engagement']}")
    print(f"min_interval      {p['min_interval_seconds']}s  ->  ceiling "
          f"{p['ceiling_rps']:.2f} req/s for the WHOLE engagement")
    print(f"worker rate       {WORKER_RPS} req/s each (p50 24s/turn, 1-3 requests)")
    print(f"budget feeds      {p['budget_useful']} worker(s)")
    if p["credits_left_pct"] is not None:
        print(f"Claude plan 5h left  {p['credits_left_pct']:.0f}%")
    tail = ("all as the client's own subagents" if p.get("client", "claude") != "claude"
            else "all via the `Agent` tool")
    print(f"=> crew           {p['agents']}  ({tail})")
    print(f"   {p['source']}")
    for n in p["notes"]:
        print(f"   note: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
