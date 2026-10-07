#!/usr/bin/env python3
"""
hunt-recall — PreToolUse hook: put the endpoint's own history in front of the next request.

The response corpus is written on every bbcurl call and, measured over 30 tier-3 runs,
read zero times. A rule telling the agent to run `cbh diff` loses to momentum; this
runs it for the agent. Before a request-firing Bash command reaches a route that already
has traffic, the summary (methods burned, statuses, distinct bodies, never-moving decision
fields, untried shapes) is injected as additional context. Never blocks, never denies.

Scoped like skill-gate: engagement folder, real senders, non-local URLs. Silent on new
ground. Shown once per route until at least RESHOW_AFTER new requests land on it.
Off: CBH_RECALL=off.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

RESHOW_AFTER = 5
LOCAL_RE = re.compile(r"^https?://(localhost|127\.|0\.0\.0\.0|\[::1\])")


def _state_path() -> Path:
    import responses  # type: ignore
    return responses._memdir() / "recall-state.json"


def _load() -> dict:
    try:
        return json.loads(_state_path().read_text())
    except Exception:  # noqa: BLE001
        return {}


def main() -> int:
    if os.environ.get("CBH_RECALL", "").lower() == "off":
        return 0
    try:
        ev = json.loads(sys.stdin.read() or "{}")
    except Exception:  # noqa: BLE001
        return 0
    if (ev.get("tool_name") or "") != "Bash":
        return 0
    ti = ev.get("tool_input") or {}
    cmd = ti.get("command", "") if isinstance(ti, dict) else ""
    from skill_signals import sends_request, urls_in  # type: ignore
    if not cmd or not sends_request(cmd):
        return 0
    from pacing import find_project_dir  # type: ignore
    proj = find_project_dir()
    if proj is None:
        return 0
    import recall  # type: ignore
    state = _load()
    blocks, changed = [], False
    for url in [u for u in urls_in(cmd) if not LOCAL_RE.match(u)][:3]:
        s = recall.recall(url, engagement=Path(proj).name)
        if not s:
            continue
        key = s["route"]
        if s["requests"] - state.get(key, -RESHOW_AFTER) < RESHOW_AFTER:
            continue
        state[key] = s["requests"]
        changed = True
        blocks.append(recall.render(s))
    if changed:
        try:
            _state_path().write_text(json.dumps(state))
        except Exception:  # noqa: BLE001
            pass
    if blocks:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": "\n\n".join(blocks)}}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001 - a broken hook must never block the session
        sys.exit(0)
