#!/usr/bin/env python3
"""mcp-signals.py — PostToolUse hook: wire signals for Caido responses.

bbcurl records `signals` on its audit row and hunt-nudge prints them. Requests sent
through Caido never touch bbcurl, so the same three checks (body on a 3xx, data in
a refusal, a secret in a body — engine/responses.py::wire_signals) run here on the
tool's own JSON result. Advisory only: exit 2 with the text on stderr feeds it back
to the model, exit 0 otherwise; any error exits 0. Source of the lessons:
docs/disclosed-reports/HIGH-CRIT-LESSONS-2026-11.md.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))


def _responses(obj, depth=0):
    """Yield (status, body, size) for every HTTP response object in a Caido result."""
    if depth > 6:
        return
    if isinstance(obj, str):
        s = obj.strip()
        if s[:1] in "{[":
            try:
                yield from _responses(json.loads(s), depth + 1)
            except ValueError:
                return
        return
    if isinstance(obj, list):
        for x in obj[:50]:
            yield from _responses(x, depth + 1)
        return
    if not isinstance(obj, dict):
        return
    resp = obj.get("response")
    if isinstance(resp, dict) and ("body" in resp or "bodySize" in resp):
        status = obj.get("statusCode") or (resp.get("fingerprint") or {}).get("statusCode")
        if status is None:
            first = str(resp.get("firstLine") or "").split()
            status = first[1] if len(first) > 1 else 0
        yield status, resp.get("body") or "", resp.get("bodySize")
        return
    for k in ("content", "results", "entries", "text", "output", "responses"):
        if k in obj:
            yield from _responses(obj[k], depth + 1)


def main() -> int:
    ev = json.loads(sys.stdin.read() or "{}")
    if not str(ev.get("tool_name") or "").startswith("mcp__caido__"):
        return 0
    from responses import wire_signals  # type: ignore
    msgs = []
    for status, body, size in _responses(ev.get("tool_response")):
        for s in wire_signals({"http_code": status}, body, size):
            extra = s.get("keys") and f" keys={','.join(s['keys'])}" or \
                (s.get("prefix") and f" prefix={s['prefix']}") or \
                (s.get("bytes") and f" bytes={s['bytes']}") or ""
            msgs.append(f"SIGNAL {s['signal'].upper()} via Caido (status {s.get('status')}{extra}): "
                        f"{s['next']}")
    if msgs:
        print("\n".join(dict.fromkeys(msgs)), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001 - a broken hook must never block the session
        sys.exit(0)
