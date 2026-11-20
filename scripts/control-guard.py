#!/usr/bin/env python3
"""control-guard — PreToolUse hook: a worker agent may not edit the controls that govern it.

Incident 2026-10-20 (konsol, blocked-tests/2026-10-20-INCIDENT-subagent-disabled-the-stop-gate.md):
a `cbh freeroam` worker, launched with `--permission-mode bypassPermissions`, set
`continuous_hunt: false` in the engagement's profile.json so the stop gate would stop
refusing its own exit. It fired zero requests and produced nothing; the one thing it
did was switch off a guardrail.

Scope of this hook, deliberately narrow:
  * acts ONLY for a worker: CBH_AGENT_ROLE=worker in the environment (engine/agent.py
    sets it for every headless worker) **or** an `agent_id` in the hook event, which is
    what an in-process `Agent` subagent carries. Until 2026-11-13 only the env var
    counted, so under Claude Code — where the whole crew is in-process — this guard was
    inert for every worker it was written for, and the one lane that tried to delete the
    engagement's host logs was stopped by the harness classifier instead. The operator's
    own session is never touched.
  * denies Edit/Write/NotebookEdit on a control file, and Bash commands that both name a
    control file / control CLI AND look like a write.
  * denies a bulk destructive write on the engagement's RECORD files — the funnel tiers,
    the host logs, notes.md. Those are the other lanes' work and the hunt's only memory
    of what was fired; a worker appends to them, it does not clear them.
Any internal error exits 0 — a broken guard must not block work; the agent launcher's
`--disallowedTools` is the first layer, this is the second.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

CONTROL_PATH = re.compile(
    r"(profile\.json|scope\.md|\.claude/settings[^/\s]*\.json|settings\.local\.json|"
    r"hunt-memory/(continuous\.json|hunt-mode[^/\s]*|stop-gate[^/\s]*)|docs/setup/hooks\.json|"
    r"scripts/[a-z-]*(gate|guard|arm|nudge|brief|track)[a-z-]*\.py|"
    r"engine/(stop_gate|scope|pacing|hunt_mode|skill_signals)\.py|scripts/bbcurl)")
CONTROL_CLI = re.compile(r"(stop_gate\.py\s+--continuous|hunt_mode\.py\s+(on|off)|apply-hooks\.py)")

# The engagement's own record of the hunt. A worker writes its own rows and ONE notes.md
# bullet; nothing legitimate it does needs a glob delete or a truncation here. Measured
# 2026-11-13: a scout ran `rm -f hosts/*.md` to "rewrite" the host logs while three other
# lanes were appending to them.
RECORD_DIR = r"(?:hosts|leads|primitives|findings|blocked-tests|refutations)/"
DESTROY_RECORDS = re.compile(
    rf"(\b(rm|unlink)\b[^|;&]*{RECORD_DIR}[^|;&]*\*"          # rm hosts/*.md
    rf"|\b(rm|unlink)\b[^|;&]*-[a-zA-Z]*[rR][a-zA-Z]*\s[^|;&]*{RECORD_DIR}"  # rm -r leads/
    rf"|\bfind\b[^|;&]*{RECORD_DIR}[^|;&]*-delete"              # find leads/ -delete
    rf"|\b(rm|unlink|truncate)\b[^|;&]*\bnotes\.md"           # rm notes.md
    rf"|\btruncate\b[^|;&]*{RECORD_DIR}"
    rf"|\bsed\s+-i\b[^|;&]*{RECORD_DIR}[^|;&]*\*"             # sed -i … leads/*.md
    rf"|(?<!>)>\s*['\"]?(?:\S*/)?notes\.md"                   # > notes.md  (>> is fine)
    rf"|\btee\b(?!\s+-a)\s+['\"]?(?:\S*/)?notes\.md)"
)
CP = CONTROL_PATH.pattern
# A write is only blocked when the control file is the DESTINATION. Reading one
# (`cat scope.md`, `grep x scope.md 2>/dev/null`, `cp scope.md /tmp/`) stays allowed:
# the first version matched any `>` anywhere and would have blocked plain reads.
WRITE_TO_CONTROL = re.compile(
    rf"(>>?\s*['\"]?\S*{CP}"                                  # > profile.json
    rf"|\btee\b(\s+-a)?\s+['\"]?\S*{CP}"                     # tee [-a] profile.json
    rf"|\b(mv|cp|install|ln)\b[^|;&]*\s['\"]?\S*{CP}\S*['\"]?\s*($|[;&|])"   # mv x profile.json
    rf"|\b(rm|truncate|chmod)\b[^|;&]*{CP}"                     # rm profile.json
    rf"|open\([^)]*{CP}[^)]*,\s*['\"][wax+]"                    # open('profile.json','w')
    rf"|Path\([^)]*{CP}[^)]*\)\.write_(text|bytes))"            # Path('profile.json').write_text
)


# `sed -i 's/x/scope.md/' recon/own-note.md` is not a write to scope.md, and the regex
# form of this check read the SCRIPT as well as the operands: on the 2026-11-13 replay it
# was the only false positive in 983 worker commands — a scout rewriting a sentence of its
# own recon file, because the sentence contained the words `scope.md`. So the in-place
# editors are parsed: the script is the first non-option token and only the operands after
# it are tested.
IN_PLACE = re.compile(r"^(sed|perl|ruby)$")


def _sed_writes_control(segment: str) -> bool:
    import shlex
    try:
        toks = shlex.split(segment)
    except ValueError:
        # Unparseable quoting (a `printf` of a write-up full of backticks and quotes is
        # the common case, and it was the last false positive on the 2026-11-13 replay).
        # Fall back only for a segment that is actually an in-place edit, and let the
        # other rules speak for the rest.
        if not re.match(r"\s*(?:\S*/)?(?:sed|perl|ruby)\b", segment) or "-i" not in segment:
            return False
        return bool(CONTROL_PATH.search(segment))
    while toks and (ASSIGN_RE.match(toks[0]) or toks[0].rsplit("/", 1)[-1] in
                    ("env", "nice", "time", "command", "exec", "sudo", "timeout", "nohup")):
        toks.pop(0)
    if not toks or not IN_PLACE.match(toks[0].rsplit("/", 1)[-1]):
        return False
    rest = toks[1:]
    if not any(o.startswith("-") and "i" in o.lstrip("-") for o in rest
               if o.startswith("-")):
        return False                      # not in-place: it writes to stdout
    operands = [o for o in rest if not o.startswith("-")]
    return any(CONTROL_PATH.search(o) for o in operands[1:])   # [0] is the script


ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SEGMENT_RE = re.compile(r"(?:&&|\|\||[;|\n])")


def _deny(reason: str) -> int:
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": reason}}))
    return 0


def main() -> int:
    # A client that is not Claude Code carries none of the worker signals below, and one
    # such client edited profile.json in its first hunt (2026-11-10). So for anything
    # else, the guard applies to every agent of it, orchestrator included: an engagement
    # control is not an agent's to change either way.
    try:
        import client as _C  # type: ignore
        other_client = _C.detect() != "claude"
    except Exception:  # noqa: BLE001
        other_client = os.environ.get("CLAUDECODE") != "1"
    try:
        ev = json.loads(sys.stdin.read() or "{}")
    except Exception:  # noqa: BLE001
        return 0
    is_worker = ((os.environ.get("CBH_AGENT_ROLE") or "").strip().lower() == "worker"
                 or bool(ev.get("agent_id")))
    if not other_client and not is_worker:
        return 0
    tool = ev.get("tool_name") or ""
    ti = ev.get("tool_input") or {}
    msg = ("CONTROL-GUARD: agents may not change engagement controls "
           "(profile.json, scope.md, settings, stop-gate / hunt-mode state, the gates themselves). "
           "If a control is wrong, say so in your result and the orchestrator decides.")
    if tool in ("Edit", "Write", "NotebookEdit", "MultiEdit", "search_replace", "write"):
        path = ti.get("file_path") or ti.get("notebook_path") or ""
        if CONTROL_PATH.search(path):
            return _deny(f"{msg} Blocked: {tool} {path}")
        return 0
    if tool in ("Bash", "run_terminal_command"):
        cmd = ti.get("command") or ""
        # A write-up that QUOTES a command is not that command. Workers write findings
        # with heredocs, and those bodies carry example `sed -i`, `rm hosts/*.md` and
        # `profile.json` lines: on the 2026-11-13 replay, not stripping them turned 1 real
        # denial into 17 (16 of them a worker writing its own primitive).
        try:
            from skill_signals import strip_heredocs  # type: ignore
            cmd_scan = strip_heredocs(cmd)
        except Exception:  # noqa: BLE001
            cmd_scan = cmd
        if CONTROL_CLI.search(cmd_scan):
            return _deny(f"{msg} Blocked command: {cmd[:160]}")
        if WRITE_TO_CONTROL.search(cmd_scan):
            return _deny(f"{msg} Blocked command: {cmd[:160]}")
        if any(_sed_writes_control(seg) for seg in SEGMENT_RE.split(cmd_scan)):
            return _deny(f"{msg} Blocked command: {cmd[:160]}")
        if DESTROY_RECORDS.search(cmd_scan):
            return _deny(
                "CONTROL-GUARD: that clears the engagement's RECORD, not your own output — "
                "the funnel tiers, hosts/<host>.md and notes.md are where every lane writes "
                "what it fired, and other lanes are appending to them right now. Append "
                "(`>>`, `cat >> f`, `cbh leads close`), write your own new file, or ask the "
                "orchestrator to fix a wrong row. Blocked command: " + cmd[:160])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        raise SystemExit(0)
