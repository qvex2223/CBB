#!/usr/bin/env python3
"""
hunt_mode.py — is this session actually hunting, or just talking?

The skill gate was unconditional, and that was wrong. Forcing `hunt-business-logic`
before a one-off `bbcurl` fired to answer "wait, does that endpoint still 401?" buys
nothing: the operator asked a question, not for a hunt. The gate belongs on *analysis*
— the part where hand-rolling curl instead of loading the skill actually costs bugs.

So the gate is armed, not always-on:

  armed   — a hunt entry point ran this session (`/hunt`, `/autopilot`, `/recon`,
            `/chain`, `/pickup`, `hunt-dispatch`, `bb-methodology`, or any `hunt-*`
            skill). Blocking is live: probing a payment flow loads the payment skill.
  idle    — default. Questions, follow-ups, reading a finding, one-off checks. The
            gate allows everything; nudges stay quiet.

Arming is per session and sticky until the session ends or someone disarms it, so a
question asked in the middle of a hunt does not silently unarm the gate.

CLI:
    python3 engine/hunt_mode.py status [--session <id>]
    python3 engine/hunt_mode.py on     [--session <id>] [--reason ...]
    python3 engine/hunt_mode.py off    [--session <id>]
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Skills whose presence means "a hunt started". Anything named hunt-* counts too
# (see `is_entry_point`) — loading hunt-idor by hand is starting a hunt.
ENTRY_SKILLS = {
    "hunt", "autopilot", "recon", "chain", "pickup", "surface",
    "hunt-dispatch", "bb-methodology", "bug-bounty", "web2-recon",
}

# Skills that are analysis-of-a-finding, not hunting. Loading /validate to answer
# "is this reportable?" must not arm the gate.
NEUTRAL_SKILLS = {
    "validate", "triage", "report", "remember", "view", "scope", "intel",
    "triage-validation", "report-writing", "bugcrowd-reporting",
    "evidence-hygiene", "memory-gc",
}


def _base() -> Path:
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from memory import resolve_dir  # type: ignore
        return resolve_dir()
    except Exception:  # noqa: BLE001
        return Path(__file__).resolve().parent.parent.parent / "hunt-memory"


def _path(session_id: str) -> Optional[Path]:
    if not session_id:
        return None
    d = _base() / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", session_id)[:80]
    return d / f"mode-{safe}.json"


def is_entry_point(skill: str) -> bool:
    name = (skill or "").split(":")[-1].strip()
    if name in NEUTRAL_SKILLS:
        return False
    return name in ENTRY_SKILLS or name.startswith("hunt-")


def arm(session_id: str, reason: str = "") -> None:
    p = _path(session_id)
    if not p:
        return
    if p.exists():
        try:
            if json.loads(p.read_text()).get("armed"):
                return  # already armed; keep the original reason/timestamp
        except Exception:  # noqa: BLE001
            pass
    p.write_text(json.dumps({
        "armed": True,
        "reason": reason or "hunt entry point",
        "since": datetime.now(timezone.utc).isoformat(),
    }))


def disarm(session_id: str) -> None:
    p = _path(session_id)
    if not p:
        return
    p.write_text(json.dumps({
        "armed": False,
        "since": datetime.now(timezone.utc).isoformat(),
    }))


def armed_since(session_id: str = "") -> Optional[float]:
    """Unix time this session entered analysis mode, if the mode file says so.

    The stop gate needs it to ask "did THIS hunt produce anything", rather than
    accepting a finding from three weeks ago as proof that today went well.
    """
    p = _path(session_id)
    if not p or not p.exists():
        return None
    try:
        doc = json.loads(p.read_text())
        if not doc.get("armed"):
            return None
        stamp = doc.get("since")
        if stamp:
            return datetime.fromisoformat(stamp).timestamp()
        return p.stat().st_mtime
    except Exception:  # noqa: BLE001
        return None


def armed(session_id: str = "", transcript_path: str = "") -> bool:
    """True when this session is in analysis mode.

    Env override `CBH_HUNT_MODE=on|off` wins, for a shell that has no session id.
    """
    env = os.environ.get("CBH_HUNT_MODE", "").strip().lower()
    if env in ("on", "1", "true"):
        return True
    if env in ("off", "0", "false"):
        return False

    p = _path(session_id)
    if p and p.exists():
        try:
            state = json.loads(p.read_text())
            if state.get("armed"):
                return True
            if state.get("armed") is False:
                return False  # explicit disarm beats the transcript
        except Exception:  # noqa: BLE001
            pass

    # Second witness: the state file is missing after a resume, but the transcript
    # still shows the hunt that started. Same tail trick as skill_signals.
    if _armed_from_transcript(transcript_path):
        return True

    # Third witness, for sessions that predate this file: skills-<sid>.json was
    # already being written before hunt mode existed, and a session with hunt-idor
    # in it was hunting. Without this, an in-flight hunt started before the change
    # — or any session whose transcript the hook did not pass — silently loses the
    # gate, which is the one failure mode worth spending a file read on.
    try:
        from skill_signals import skills_loaded  # type: ignore
        return any(is_entry_point(s) for s in skills_loaded(session_id, ""))
    except Exception:  # noqa: BLE001
        return False


def _armed_from_transcript(transcript_path: str, tail_bytes: int = 10_000_000) -> bool:
    if not transcript_path:
        return False
    p = Path(transcript_path)
    if not p.exists():
        return False
    try:
        size = p.stat().st_size
        with p.open("rb") as fh:
            if size > tail_bytes:
                fh.seek(size - tail_bytes)
            blob = fh.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return False
    for m in re.finditer(r'"skill"\s*:\s*"([^"]+)"', blob):
        if is_entry_point(m.group(1)):
            return True
    return False


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="hunt_mode")
    ap.add_argument("action", choices=["status", "on", "off"])
    ap.add_argument("--session", default=os.environ.get("CLAUDE_SESSION_ID", ""))
    ap.add_argument("--reason", default="")
    a = ap.parse_args(argv)

    if a.action == "on":
        arm(a.session, a.reason or "manual")
    elif a.action == "off":
        disarm(a.session)

    state = "ARMED (analysis mode — skill gate enforces)" if armed(a.session) \
        else "idle (questions/ad-hoc — skill gate allows)"
    print(f"hunt mode: {state}")
    if not a.session:
        print("  no session id: pass --session or set CBH_HUNT_MODE=on|off")
    return 0


if __name__ == "__main__":
    sys.exit(main())
