#!/usr/bin/env python3
"""
hunt-stop-gate — Stop hook. Refuses to let a hunt end with nothing to report.

The operator's complaint, verbatim: the tool stops. Not when the target is
covered — when momentum runs out. Everything else in this workspace gates the
*start* of an action (scope, pacing, skills); nothing gated the end, which is
exactly where the giving-up happens.

Fires only in analysis mode (`engine/hunt_mode.py`), so answering a question or
writing a report is never blocked. Inside a hunt, stopping is allowed when the
engagement has a finding of severity >= medium with a PASSing PoC behind it, or
when the session has been pushed to the engagement's ceiling and the gate stands
down rather than becoming a loop.

In **continuous mode** (`stop_gate.continuous_config`) the finding door is closed
on purpose: a proven Medium+ is banked in `findings/` and the sweep rolls on to the
next vector, the next host, the next recon pass, until the operator stops it.

Wire as a Stop hook. Any internal error exits 0: a broken gate must never trap a
session that wants to end.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))


def _allow() -> int:
    return 0


def main() -> int:
    try:
        ev = json.loads(sys.stdin.read() or "{}")
    except Exception:  # noqa: BLE001
        return _allow()

    session_id = ev.get("session_id", "") or ""

    try:
        from hunt_mode import armed, armed_since  # type: ignore
        if not armed(session_id, ev.get("transcript_path", "")):
            return _allow()          # not hunting: ending is none of this hook's business
        since = armed_since(session_id)
    except Exception:  # noqa: BLE001
        return _allow()

    try:
        from pacing import find_project_dir  # type: ignore
        import stop_gate as sg  # type: ignore
    except Exception:  # noqa: BLE001
        return _allow()

    project = find_project_dir()
    verdict = sg.assess(project, since)
    if verdict["allow"]:
        return _allow()

    # The ceiling is per engagement: continuous mode raises it far out of the way,
    # but never removes it — an operator who walked away must not come back to a
    # session that spent the night arguing with itself.
    ceiling = sg.max_blocks(project)
    continuous = bool((verdict.get("continuous") or {}).get("on"))
    already = sg.blocks_so_far(session_id)
    if already >= ceiling:
        # Pushed enough. Past this point the gate is noise, and a gate that cannot
        # be escaped stops being a check and starts being a bill.
        tail = ("continuous mode is still on — re-arm with /hunt to carry on."
                if continuous else
                "If the target really is exhausted, say so with the ledger to back it.")
        print(json.dumps({"systemMessage":
                          f"stop-gate: pushed {already}x on {verdict['engagement']} "
                          f"(ceiling {ceiling}) — standing down. " + tail}))
        return _allow()

    sg.record_block(session_id)
    print(json.dumps({
        "decision": "block",
        "reason": sg.block_message(verdict) +
                  f"\n\n(stop-gate {already + 1}/{ceiling} — after that it stands down. "
                  f"The operator can end the session at any time; this only refuses the "
                  f"agent's own decision to stop.)",
    }))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001
        sys.exit(0)
