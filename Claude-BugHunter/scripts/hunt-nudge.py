#!/usr/bin/env python3
"""
hunt-nudge — PostToolUse hook that refuses to let a hunt dead-end silently.

Two failure modes this workspace keeps reproducing, both invisible from inside the
session because they feel like work:

  1. **curl-only tunnel vision.** 62 skills installed, and a hunt that consists of
     hand-rolled requests. Nothing ever told the agent, at the moment it mattered,
     which skill covers what it is currently poking.
  2. **grinding.** Dozens of requests at one host, zero hunt-memory writes, same
     vector, no rotation — then the host gets closed as "hardened".

A hook fires deterministically, unlike a rule in a prompt that competes with ten
other rules. Exit code 2 sends the message straight back into the model's context,
so the nudge arrives attached to the request that triggered it.

Wire as PostToolUse on Bash. Never blocks real work: any internal error exits 0.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

NUDGE_EVERY = 12          # requests-since-last-finding between two nudges
STUCK_THRESHOLD = 12      # when grinding starts counting as stuck

# The URL->skill table lives in engine/skill_signals.py — shared with skill-gate.py
# (PreToolUse), which blocks on it. One table, two enforcement points.


def _read_event() -> dict:
    try:
        return json.loads(sys.stdin.read() or "{}")
    except Exception:  # noqa: BLE001
        return {}


def _command(ev: dict) -> str:
    ti = ev.get("tool_input") or {}
    return ti.get("command", "") if isinstance(ti, dict) else ""


def _in_engagement() -> bool:
    try:
        from pacing import find_project_dir  # type: ignore
        return find_project_dir() is not None
    except Exception:  # noqa: BLE001
        return False


def _target_name() -> str:
    try:
        from pacing import find_project_dir  # type: ignore
        p = find_project_dir()
        return p.name if p else ""
    except Exception:  # noqa: BLE001
        return ""


def _ledger_key(host: str) -> str:
    """Return `host` if a vector ledger exists for it, else ''."""
    if not host:
        return ""
    try:
        from vectors import _path  # type: ignore
        return host if _path(host).exists() else ""
    except Exception:  # noqa: BLE001
        return ""


def _armed(ev: dict) -> bool:
    """Analysis mode? Skill routing is only useful mid-hunt."""
    try:
        from hunt_mode import armed  # type: ignore
        return armed(ev.get("session_id", ""), ev.get("transcript_path", ""))
    except Exception:  # noqa: BLE001
        return False


def _classify(cmd: str, ev: dict):
    """Signals worth naming — minus the skills this session already loaded.

    Naming a skill that is open in the session is not a nudge, it is noise, and
    noise is what gets a hook switched off.
    """
    try:
        from skill_signals import sends_request, signals_for, skills_loaded  # type: ignore
        if not sends_request(cmd):
            return []
        loaded = skills_loaded(ev.get("session_id", ""), ev.get("transcript_path", ""))
        return [(c, s) for c, s, _block in signals_for(cmd) if s not in loaded]
    except Exception:  # noqa: BLE001
        return []


def _nudge_state_path() -> Path:
    try:
        from memory import resolve_dir  # type: ignore
        base = resolve_dir()
    except Exception:  # noqa: BLE001
        base = REPO.parent / "hunt-memory"
    d = base / "pacing"
    d.mkdir(parents=True, exist_ok=True)
    return d / "nudge_state.json"


def _state() -> dict:
    try:
        return json.loads(_nudge_state_path().read_text())
    except Exception:  # noqa: BLE001
        return {}


def _save_state(**kw) -> None:
    st = _state()
    st.update(kw)
    try:
        _nudge_state_path().write_text(json.dumps(st))
    except Exception:  # noqa: BLE001
        pass


def _should_nudge(count: int) -> bool:
    last = _state().get("last_count", 0)
    if count - last < NUDGE_EVERY:
        return False
    _save_state(last_count=count)
    return True


def _should_alert_repeat(alert: dict) -> bool:
    """Say it once per stretch of sameness, not once per request."""
    prev = _state().get("repeat") or {}
    if prev.get("hash") == alert["hash"] and alert["repeats"] < prev.get("repeats", 0) + 5:
        return False
    _save_state(repeat={"hash": alert["hash"], "repeats": alert["repeats"]})
    return True


def _should_alert_constant(alert: dict) -> bool:
    """Once per path+field set, not once per request."""
    prev = _state().get("constant") or {}
    key = alert["path"] + "|" + ",".join(alert["decisive_fields"])
    if prev.get("key") == key and alert["responses"] < prev.get("responses", 0) + 6:
        return False
    _save_state(constant={"key": key, "responses": alert["responses"]})
    return True


def main() -> int:
    ev = _read_event()
    if (ev.get("tool_name") or "") != "Bash":
        return 0
    cmd = _command(ev)
    if not cmd:
        return 0

    msgs = []

    # --- bare curl at a live target bypasses scope + pacing + audit ------------
    if re.search(r"(^|[;&|]\s*)curl\s", cmd) and "bbcurl" not in cmd:
        if re.search(r"https?://(?!(localhost|127\.0\.0\.1))", cmd) and _in_engagement():
            msgs.append(
                "GATE BYPASSED: bare `curl` inside an engagement. That request skipped the "
                "scope check, the pacing budget, the program's mandatory headers, and "
                "audit.jsonl — so it is also invisible to the stuck detector and cannot "
                "back a report. Re-run it as `bbcurl` with the same arguments.")

    # --- the same answer, over and over ---------------------------------------
    # A request count says "you are working". A response hash says whether anything
    # you sent ever reached something that decides the answer.
    try:
        from responses import repeat_alert  # type: ignore
        alert = repeat_alert()
        if alert and _should_alert_repeat(alert):
            where = ", ".join(alert["hosts"]) or alert.get("engagement", "this host")
            msgs.append(
                f"IDENTICAL RESPONSES: {alert['repeats']} of the last {alert['window']} requests "
                f"({where}) returned the *byte-identical* body — status {alert['status']}, "
                f"{alert['bytes']} bytes, sha {alert['hash'][:12]}. Nothing you are sending "
                "reaches anything that decides that answer, so more payloads of the same shape "
                "will not either.\n"
                f"  see it: cbh diff {alert['urls'][-1] if alert['urls'] else '<url>'}\n"
                "  then rotate the SHAPE, not the payload: method swap, content-type swap, "
                "auth strip/downgrade, /v2->/v1, path normalization, X-Original-URL — "
                "`python3 engine/vectors.py rotate <class>`.")
    except Exception:  # noqa: BLE001
        pass

    # --- the answer that never moved ------------------------------------------
    # Distinct from IDENTICAL RESPONSES above: those bodies are byte-identical.
    # Here every body differs — they echo the varying input back — while the field
    # that carries the verdict is the same in every capture. That is the shape that
    # gets a stub reported as an oracle.
    try:
        from responses import _path_of, constant_field_alert  # type: ignore
        from skill_signals import urls_in  # type: ignore
        # Only while the operator is actually on that surface. The corpus keeps this
        # state forever; nagging about last hour's endpoint during unrelated work is
        # how a useful signal gets tuned out.
        here = {_path_of(u) for u in urls_in(cmd)}
        oracle = constant_field_alert() if here else None
        if oracle and oracle["path"] in here and oracle["decisive_fields"] \
                and _should_alert_constant(oracle):
            fields = ", ".join(f"{k}={oracle['constant_fields'][k]}"
                               for k in oracle["decisive_fields"][:3])
            msgs.append(
                f"ANSWER NEVER MOVED: {oracle['path']} has answered "
                f"{oracle['distinct_requests']} different requests across "
                f"{oracle['responses']} captures, and {fields} in every single one. "
                "A field that does not react to input is a stub, not a disclosure — "
                "whatever you are about to conclude from that boolean, the data says it "
                "would say the same thing for any input you send.\n"
                f"  see it: cbh diff {oracle['path']} --fields\n"
                "  before reporting: find one input that changes it. If none exists, the "
                "finding is the absence of a check, not an oracle.")
    except Exception:  # noqa: BLE001
        pass

    # --- skill routing: name the skill that already covers this surface --------
    # Only mid-hunt. A single request fired to answer the operator's question does
    # not need a skill lecture attached to it.
    hits = _classify(cmd, ev) if _armed(ev) else []
    if hits and ("bbcurl" in cmd or "curl" in cmd):
        pairs = ", ".join(f"{c} -> {s}" for c, s in hits[:3])
        msgs.append(
            f"SKILL AVAILABLE for what you are probing: {pairs}. "
            "Load it with the Skill tool before hand-rolling more requests — it carries the "
            "bypass tables and chain templates you are otherwise re-deriving one curl at a time.")

    # --- grinding detector ----------------------------------------------------
    try:
        from vectors import CATALOG, mutations_for, next_vectors, stuck_report  # type: ignore
        rep = stuck_report(STUCK_THRESHOLD)
        if rep and _should_nudge(rep["requests_since_last_finding"]):
            # The ledger is keyed by whatever `seed` was called with — usually the
            # host being hunted, not the engagement folder. Prefer a ledger that
            # actually exists so the command printed here is runnable as printed.
            target = _ledger_key(rep.get("top_host", "")) or _target_name()
            lines = [
                f"STUCK: {rep['requests_since_last_finding']} requests fired since the last "
                f"hunt-memory write (top host: {rep['top_host']}). Grinding one vector is not "
                "persistence — rotating is."
                + (f" Of those, {rep.get('responses_recorded')} responses were recorded and only "
                   f"{rep.get('distinct')} were distinct." if rep.get("distinct") else ""),
                "Do these in order, do not close the host:",
                "  1. `python3 engine/vectors.py rotate <class>` — burn the next untried mutation "
                "(method swap, /v1 downgrade, auth strip, content-type swap, header override).",
                f"  2. `python3 engine/vectors.py next {target or '<target>'}` — the impact-ranked "
                "vector you have not touched yet.",
                f"  3. `python3 engine/vectors.py revisit {target or '<target>'}` — old "
                "non-confirmed findings still have untried methods; a rejected result is one "
                "burned mutation, not a closed door.",
                "  4. Log what was tried with `/remember` (result=rejected is a real result) so "
                "this counter resets and the next session does not repeat it.",
            ]
            nxt = next_vectors(target, 3) if target else []
            if nxt:
                lines.append("Untried right now:")
                for v in nxt:
                    lines.append(f"  - [{v['class']}] {v['endpoint']}  (skill: {v['skill']})")
                    if v.get("next_mutation"):
                        lines.append(f"      next move: {v['next_mutation']}")
            else:
                lines.append(
                    f"No vector ledger for {rep.get('top_host') or 'this host'} yet — build one "
                    f"first: `python3 engine/vectors.py seed {rep.get('top_host') or '<host>'} "
                    "--endpoints '<comma-separated paths you already found>'`. Then `next` always "
                    "has an answer and 'stuck' stops being a state you can be in.")
            msgs.append("\n".join(lines))
    except Exception:  # noqa: BLE001
        pass

    if msgs:
        print("\n\n".join(msgs), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001 - a broken hook must never block the session
        sys.exit(0)
