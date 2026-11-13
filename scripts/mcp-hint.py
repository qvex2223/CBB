#!/usr/bin/env python3
"""mcp-hint.py — PostToolUse hook: attach the remedy to a browser/proxy failure.

A Playwright or Caido failure reaches the model as one line of Chromium network
vocabulary (`net::ERR_TOO_MANY_RETRIES`). Three of its causes live in this workspace —
the Caido proxy in front of the browser, Caido's intercept queue, and whether this
engagement took the direct lane — and none of them is visible in that line. So the
answer travels with the failure: `engine/browser_hints.py` owns the table, this hook
delivers it under Claude Code, and a client running the gate inline delivers the same text for
clients that run the inline gate instead of hooks.

It also answers the second question a PostToolUse hook is the only place to ask: WHERE
DID THE BROWSER ACTUALLY LAND. `scripts/mcp-gate.py` gates the URL passed to
`browser_navigate`, but it is a PreToolUse hook — it cannot see the response, so a 30x
to another host is followed unchecked. That is how a navigation to `https://e.mail.ru/`
carried this workspace's browser to `id.vk.ru`, a host the engagement is not allowed to
fetch. `engine/poc_runtime.py` closed the equivalent hole for specs by checking the
redirect chain; the browser cannot be checked before the fact, so the honest fix is to
check the landing after it and say so loudly. Prevention is not available here — this
hook cannot un-send a request. Detection and a written record are.

Hook-only, for now: a client running the gate inline delivers the failure hints if it
run the inline gate instead of hooks, but it does not see tool results, so the landing
check does not reach them. Under Claude Code it needs the hook wired
(`python3 docs/setup/apply-hooks.py --apply`, then restart) — until then this file runs
only when something calls it by hand.

Advisory only: exit 2 with the text on stderr feeds it back to the model, exit 0
otherwise, and any error exits 0. It decides nothing — a gate refusal stays final.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

MAX_TEXT = 20000


def _text(obj, depth: int = 0) -> str:
    """Every string in a tool result, flattened — the error may sit at any depth."""
    if depth > 6:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, list):
        return "\n".join(_text(x, depth + 1) for x in obj[:50])
    if isinstance(obj, dict):
        return "\n".join(_text(v, depth + 1) for k, v in obj.items()
                         if k in ("content", "text", "error", "message", "result",
                                  "output", "stderr", "isError", "status"))
    return ""


# Playwright MCP reports the page it ended up on in its own result text. Both spellings
# appear depending on the call, and a redirect shows up ONLY here — the navigate argument
# still says the host that was asked for.
LANDING_RE = re.compile(
    r"(?:Page URL|Navigated to|current url)\s*[:=]?\s*(?P<url>[a-zA-Z][a-zA-Z0-9+.\-]*:[^\s\)\]\'\"<>]+)",
    re.I)


def _landings(body: str) -> list:
    """Distinct URLs the result says the browser is on, newest first, order kept."""
    out = []
    for m in LANDING_RE.finditer(body):
        url = m.group("url").rstrip(".,;")
        if url not in out:
            out.append(url)
    return out[:5]


def _in_scope(url: str) -> bool:
    """True when some engagement's scope.md admits this URL (the current one first).

    Fails OPEN on any error: this hook must never invent an out-of-scope claim, and an
    unreadable scope file is a workspace problem, not evidence about the target.
    """
    try:
        from request_broker import is_local_url, is_non_network_url, unwrap_url  # type: ignore
        from scope import _scope_from_md  # type: ignore
        from paths import targets_root  # type: ignore
    except Exception:  # noqa: BLE001
        return True
    try:
        if is_non_network_url(url) or is_local_url(url):
            return True
        target = unwrap_url(url)
        mds = []
        project = (os.environ.get("CBH_PROJECT") or "").strip()
        if project:
            own = Path(targets_root()) / project / "scope.md"
            if own.exists():
                mds.append(own)
        mds += [q for q in Path(targets_root()).glob("**/scope.md")
                if "_TEMPLATE" not in q.parts and ".trash" not in q.parts and q not in mds]
        checked = False
        for md in mds:
            try:
                if _scope_from_md(str(md)).reject_reason(target) is None:
                    return True
                checked = True
            except Exception:  # noqa: BLE001
                continue
        return not checked
    except Exception:  # noqa: BLE001
        return True


def _record(url: str, tool: str) -> None:
    """Browser traffic leaves no audit row, so the landing is written down here."""
    try:
        base = os.environ.get("CBH_MEMORY_DIR") or str(REPO / "hunt-memory")
        path = Path(base) / "browser-landings.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "tool": tool,
               "landed_url": url, "verdict": "OUT-OF-SCOPE",
               "project": os.environ.get("CBH_PROJECT") or ""}
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001
        pass


def _landing_notice(tool: str, body: str) -> str:
    """The warning for a browser that ended up on a host no scope.md admits."""
    if "browser" not in tool:
        return ""
    bad = [u for u in _landings(body) if not _in_scope(u)]
    if not bad:
        return ""
    for url in bad:
        _record(url, tool)
    lines = ["OFF-SCOPE LANDING — the browser is on a host no scope.md admits:"]
    lines += [f"  {u}" for u in bad]
    lines += [
        "scripts/mcp-gate.py checked the URL you passed; this is where a redirect took the",
        "browser, which a PreToolUse hook cannot see. The request has already been sent —",
        "this is a record, not a block.",
        "Do not keep working here: no click, no evaluate, no form fill on this origin.",
        "Navigate back to an in-scope URL, and write the hop into the engagement's",
        "notes.md (or blocked-tests/ if the flow cannot be tested without it).",
        "Logged: hunt-memory/browser-landings.jsonl",
    ]
    return "\n".join(lines)


def main() -> int:
    ev = json.loads(sys.stdin.read() or "{}")
    tool = str(ev.get("tool_name") or "")
    if not tool.startswith("mcp__"):
        return 0
    from browser_hints import hint_for  # type: ignore
    body = _text(ev.get("tool_response"))[:MAX_TEXT]
    if not body:
        body = str(ev.get("tool_error") or "")[:MAX_TEXT]
    hint = hint_for(tool, body)
    # A landing notice is reported even when the call itself succeeded — a followed
    # redirect is not a failure, which is exactly why nothing else catches it.
    notice = _landing_notice(tool, body)
    out = "\n\n".join(x for x in (notice, hint) if x)
    if not out:
        return 0
    print(out, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001 - a broken hook must never block the session
        sys.exit(0)
