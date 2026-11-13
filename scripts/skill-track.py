#!/usr/bin/env python3
"""
skill-track — PostToolUse hook on Skill. Records which skills this session loaded.

The gate (`skill-gate.py`) also reads the transcript, but the transcript is tailed
and a long session can push an early Skill call out of the window. This file is the
cheap, exact witness.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))


def main() -> int:
    try:
        ev = json.loads(sys.stdin.read() or "{}")
    except Exception:  # noqa: BLE001
        return 0
    if (ev.get("tool_name") or "") != "Skill":
        return 0
    ti = ev.get("tool_input") or {}
    skill = ti.get("skill", "") if isinstance(ti, dict) else ""
    if not skill:
        return 0
    try:
        from skill_signals import record_skill  # type: ignore
        record_skill(ev.get("session_id", ""), skill)
    except Exception:  # noqa: BLE001
        pass

    # A hunt entry point (/hunt, /recon, /autopilot, any hunt-*) arms the skill
    # gate for the rest of the session. Nothing else does — loading /validate to
    # answer a question about a finding leaves the gate asleep.
    try:
        from hunt_mode import arm, is_entry_point  # type: ignore
        if is_entry_point(skill):
            arm(ev.get("session_id", ""), f"skill: {skill}")
    except Exception:  # noqa: BLE001
        pass
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001
        sys.exit(0)
