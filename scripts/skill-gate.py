#!/usr/bin/env python3
"""
skill-gate — PreToolUse hook that makes the hunt-* skills mandatory, not advisory.

62 skills installed, and hunts that consisted of hand-rolled curl. Naming the right
skill after the fact (hunt-nudge) turned out to be a suggestion, and suggestions
lose to momentum. This one denies the Bash call outright: if the URL says you are
probing a payment flow and `hunt-business-logic` was never loaded this session, the
request does not go out until it is.

The point is not ceremony. Each skill carries the bypass table and chain templates
for its class — loading it once per session is the difference between trying four
mutations and trying twenty.

Deny is scoped tight, because a gate that fires on unrelated commands gets disabled:
  * only while the session is in **analysis mode** (`engine/hunt_mode.py`): a hunt
    entry point ran — `/hunt`, `/autopilot`, `/recon`, `/pickup`, `/chain`, or a
    `hunt-*` skill. Answering a question about a finding, or firing one ad-hoc
    request to check something the operator asked about, is not a hunt and is
    never gated.
  * only inside a `Targets/<name>/` engagement
  * only for commands that carry an http(s) URL at a non-local host
  * only for surfaces where hand-rolling is the actual failure mode (recon-ish
    URLs — JS bundles, sourcemaps, robots.txt — are never blocked)
  * `--bb-dry-run` always passes

Escape hatches, both audited:
  * `CBH_SKILL_GATE=off` in the environment
  * `# skill-gate: override <reason>` appended to the command — recorded to
    hunt-memory/audit.jsonl so "I bypassed the gate 40 times" is visible later.
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

OVERRIDE_RE = re.compile(r"#\s*skill-gate:\s*override\s*(.*)", re.I)


def _event() -> dict:
    try:
        return json.loads(sys.stdin.read() or "{}")
    except Exception:  # noqa: BLE001
        return {}


def _allow() -> int:
    return 0


def _deny(reason: str) -> int:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    return 0


def _in_engagement() -> bool:
    try:
        from pacing import find_project_dir  # type: ignore
        return find_project_dir() is not None
    except Exception:  # noqa: BLE001
        return False


def _log_override(cmd: str, reason: str, skills) -> None:
    try:
        from memory import Memory  # type: ignore
        Memory().audit({
            "source": "skill-gate",
            "event": "override",
            "reason": reason.strip() or "(none given)",
            "skills_skipped": [s for _, s in skills],
            "command": cmd[:400],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except Exception:  # noqa: BLE001
        pass


def main() -> int:
    ev = _event()
    if (ev.get("tool_name") or "") != "Bash":
        return _allow()

    ti = ev.get("tool_input") or {}
    cmd = ti.get("command", "") if isinstance(ti, dict) else ""
    if not cmd or "--bb-dry-run" in cmd:
        return _allow()
    if os.environ.get("CBH_SKILL_GATE", "").lower() in ("off", "0", "false"):
        return _allow()
    if not re.search(r"https?://(?!(localhost|127\.0\.0\.1|0\.0\.0\.0))", cmd):
        return _allow()
    if not _in_engagement():
        return _allow()

    try:
        from hunt_mode import armed  # type: ignore
        from skill_signals import satisfied, sends_request, skills_loaded  # type: ignore
    except Exception:  # noqa: BLE001 - never block on a broken gate
        return _allow()

    # Analysis mode only. Outside a hunt the operator is asking questions, and a
    # gate that answers a question with "load a skill first" is noise.
    if not armed(ev.get("session_id", ""), ev.get("transcript_path", "")):
        return _allow()

    if not sends_request(cmd):
        return _allow()

    loaded = skills_loaded(ev.get("session_id", ""), ev.get("transcript_path", ""))
    ok, missing = satisfied(cmd, loaded)
    if ok:
        return _allow()

    m = OVERRIDE_RE.search(cmd)
    if m:
        _log_override(cmd, m.group(1), missing)
        return _allow()

    pairs = ", ".join(f"{c} -> {s}" for c, s in missing)
    first = missing[0][1]
    return _deny(
        f"SKILL GATE: this URL is {pairs}, and that skill is not loaded in this session.\n"
        f"Load it first, then re-send this exact command:\n"
        f"    Skill(skill=\"claude-bughunter:{first}\")\n"
        f"The skill carries the bypass table and chain templates for this class — hand-rolling "
        f"the request without it is how a vector gets abandoned after four attempts instead of "
        f"twenty.\n"
        f"Already loaded this session: {', '.join(sorted(loaded)) or 'none'}.\n"
        f"If the skill genuinely does not apply, append `# skill-gate: override <reason>` to the "
        f"command — the override is logged to audit.jsonl."
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001
        sys.exit(0)
