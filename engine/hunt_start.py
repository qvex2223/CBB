#!/usr/bin/env python3
"""hunt_start.py — start a hunt from any agent CLI: `cbh hunt-start <program>`.

Under Claude Code a plain "начни хантить X" arms the hunt through the
UserPromptSubmit hook (scripts/hunt-arm.py). A client without that hook has no way to
arm a hunt implicitly, so this command does the same job explicitly:

  1. resolves the program name to its engagement folder under Targets/;
  2. arms hunt mode for the session (engine/hunt_mode.py);
  3. prints the folder, the env to export, the standing orders and the crew size —
     the same text hunt-arm injects, plus the client mapping for non-Claude agents.

Usage:
    cbh hunt-start ozon
    cbh hunt-start standoff365/wildberries --session <id>
    cbh hunt-start --list
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

CLIENT_MAP = """\
CLIENT MAPPING ({client}) — the orders below are written in Claude Code terms:
- `/pickup`, `/remember`, `/chain`, `/validate`, `/poc-run`, `/refute`, … = slash commands:
  read `commands/<name>.md` and do what it says (most have a `cbh <name>` twin).
- `Skill("hunt-xss")` = read `skills/hunt-xss/SKILL.md` before testing that class.
  There is no Skill tool here, and skill-gate does not deny this client.
- "`Agent` tool" = your own parallel subagents. Spawn all crew slots at once and give
  each the full brief: engagement, program, scope summary, forbidden actions,
  `CBH_PROJECT=<engagement>` for every bbcurl call.
- You plan and merge, and you may send the request yourself. Subagents may send too.
  Do not wait on a worker when one request decides the lead. The Claude line
  "the orchestrator does not fire" does not apply. crew-gate, skill-gate and
  agent-gate do not deny this client.
- "cap 3" and the in-process cap: Claude Code plumbing, because its subagents share one
  context window. Your own subagents do not, so `cbh crew` gives you 6.
- Follow "How a client without the hooks hunts here" in the root AGENTS.md: lanes are
  leads taken to proof, code
  sinks get a Playwright check, authenticated work goes through the browser profile, each
  subagent writes its own record and hands back <=10 lines. Crew by role (subagent_type):
  4 deep-hunter + 1 scout + 1 refuter; queue: primitives -> leads -> vectors -> new surface.
- ONE browser lane at a time for the whole engagement: Chromium allows one browser per
  profile, so a second Playwright lane stalls for the length of the first (19 of 38
  subagents killed that way on 2026-11-11). Give the browser to the lane that needs a
  rendered DOM or a login; the others fire bbcurl. An unauthenticated render may run
  concurrently with CBH_PLAYWRIGHT_ISOLATED=1.
- A lane our own tooling could not finish closes `--as stalled` (stays in the queue,
  flagged RETRY), never `--as blocked` (that is for the target or the programme blocking
  it, and it takes the lead out of the queue). `cbh leads reopen <file> --note "why"`
  undoes a mis-marked block.
- Stop the hunt only when the operator says so; then run `cbh hunt-stop`."""


def client() -> str:
    """Which agent CLI drives this session — ONE implementation, engine/client.py."""
    try:
        import client as _C  # type: ignore
        return _C.detect()
    except Exception:  # noqa: BLE001 - detection must never block a hunt
        explicit = (os.environ.get("CBH_AGENT") or "").strip().lower()
        if explicit:
            return explicit
        return "claude" if os.environ.get("CLAUDECODE") == "1" else "generic"


def _targets_root() -> Path:
    try:
        from paths import targets_root  # type: ignore
        return Path(targets_root())
    except Exception:  # noqa: BLE001
        return REPO / "Targets"


def engagements() -> list[Path]:
    root = _targets_root()
    return sorted(p.parent for p in root.glob("**/scope.md")
                  if "_TEMPLATE" not in p.parts and ".trash" not in p.parts)


def resolve(name: str) -> tuple[Path | None, list[Path]]:
    root = _targets_root()
    want = name.strip().strip("/").lower()
    all_ = engagements()
    rel = {p: str(p.relative_to(root)).lower() for p in all_}
    exact = [p for p in all_ if rel[p] == want or p.name.lower() == want]
    if len(exact) == 1:
        return exact[0], []
    fuzzy = [p for p in all_ if want and want in rel[p]]
    if len(fuzzy) == 1:
        return fuzzy[0], []
    return None, (exact or fuzzy)


def _hunt_arm():
    spec = importlib.util.spec_from_file_location("hunt_arm", str(REPO / "scripts" / "hunt-arm.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cbh hunt-start")
    ap.add_argument("program", nargs="?", help="program name, e.g. ozon or standoff365/ozon")
    ap.add_argument("--session", default="", help="session id (default: $CBH_SESSION_ID)")
    ap.add_argument("--list", action="store_true", help="list engagements")
    a = ap.parse_args(argv)

    root = _targets_root()
    if a.list or not a.program:
        for p in engagements():
            print(p.relative_to(root))
        return 0 if a.list else 2

    eng, cands = resolve(a.program)
    if eng is None:
        if cands:
            print(f"Ambiguous program '{a.program}': " + ", ".join(str(c.relative_to(root)) for c in cands))
            print("Ask the operator which one.")
        else:
            print(f"No engagement matches '{a.program}'. `cbh hunt-start --list` shows them.")
        return 2

    project = str(eng.relative_to(root))
    who = client()
    session = a.session or os.environ.get("CBH_SESSION_ID") or f"{who}-{os.getppid()}"

    from hunt_mode import arm  # type: ignore
    arm(session, f"cbh hunt-start {project}")

    ha = _hunt_arm()
    ev = {"cwd": str(eng), "session_id": session}
    spawn = (ha._spawn_line() if who == "claude" else
             "Spawn them as your own parallel subagents, all in ONE message, each with "
             "the full brief.")
    orders = ha.ORDERS.replace("{SPAWN}", spawn).replace("{CREW}", ha._crew_line(ev))

    print(f"ENGAGEMENT: {project}")
    print(f"FOLDER:     {eng}")
    print(f"EXPORT:     export CBH_PROJECT={project} CBH_AGENT={who} CBH_SESSION_ID={session}")
    print(f"READ FIRST: {eng / 'AGENTS.md' if (eng / 'AGENTS.md').exists() else eng / 'CLAUDE.md'}, "
          f"{eng / 'scope.md'}, {eng / 'notes.md'}")
    print(f"HUNT MODE:  armed for session {session}")
    print()
    if who != "claude":
        print(CLIENT_MAP.format(client=who))
        print()
    print(orders)
    try:
        from lead_queue import scan, render  # type: ignore
        q = scan(eng)
        print()
        print("\n".join(render(q, 6).splitlines()[:12]))
    except Exception:  # noqa: BLE001
        pass
    try:
        line = ha.caido_line()
        if line:
            print()
            print(line)
    except Exception:  # noqa: BLE001
        pass
    return 0


def stop_main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cbh hunt-stop")
    ap.add_argument("--session", default="")
    a = ap.parse_args(argv)
    who = client()
    session = a.session or os.environ.get("CBH_SESSION_ID") or f"{who}-{os.getppid()}"
    from hunt_mode import disarm  # type: ignore
    disarm(session)
    print(f"HUNT MODE DISARMED for session {session}. Bank what is proven, then report.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--stop":
        raise SystemExit(stop_main(sys.argv[2:]))
    raise SystemExit(main())
