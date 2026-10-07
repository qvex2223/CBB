#!/usr/bin/env python3
"""
mcp-gate — PreToolUse hook that puts Burp/Playwright MCP calls under the same
outbound-request policy as every other transport.

`bbcurl`, `poc_runtime` and the recon engine all go through `engine/request_broker`:
scope verified, pacing waited out, mandatory headers injected, request audited. The
MCP servers did not. Burp talks straight to its own HTTP client and Playwright drives
a real browser, so until this hook existed the fastest way to send an unscoped,
unpaced, unaudited request at a live program was to reach for Burp — the tool the
workspace tells you to reach for on the last mile.

What is gated, and what is honestly not:

  * GATED — the calls that choose a target: burpmcp http1/http2 send and resend,
    and playwright browser_navigate. Scope is checked, the engagement's pacing
    budget is waited out, and an audit row is written before the call proceeds.
  * NOT GATED, by design — in-page actions (browser_click, browser_evaluate, form
    fills). They name no host: the origin was chosen at navigate, which is gated,
    and they inherit it. A click that triggers a cross-origin XHR is not visible
    here. Claiming otherwise would be worse than the gap.
  * NOT SENDERS — save-http1-request, get-saved-request, update-note and the
    snapshot/read tools touch local state only and pass through untouched.

A resend with no explicit host cannot be scope-checked: the target lives in Burp's
saved-request store, which this hook cannot read. That is `UNVERIFIED`, and this
workspace's own rule is that UNVERIFIED is not approval to test — so it is refused
with the fix (pass host/port/secure explicitly), not waved through.

Escape hatch, audited: CBH_MCP_GATE=off.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

# tool -> how the target is expressed
BURP_SENDERS = {"http1-send", "http2-send"}
BURP_RESENDERS = {"http1-resend", "http2-resend"}
OOB_TOOLS = {"generate-collaborator-payload", "retrieve-collaborator-interactions"}
PLAYWRIGHT_NAVIGATORS = {"browser_navigate"}

REQUEST_LINE_RE = re.compile(r"^\s*([A-Z]+)\s+(\S+)", re.M)


def _event() -> dict:
    try:
        return json.loads(sys.stdin.read() or "{}")
    except Exception:  # noqa: BLE001
        return {}


def _allow() -> int:
    return 0


def _deny(reason: str) -> int:
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))
    return 0


def _short_name(tool: str) -> tuple[str, str]:
    """mcp__burpmcp__http1-send -> ('burpmcp', 'http1-send')"""
    parts = tool.split("__")
    return (parts[1], parts[2]) if len(parts) >= 3 else ("", tool)


def _burp_url(ti: dict) -> str | None:
    host = ti.get("host")
    if not host:
        return None
    port = ti.get("port") or (443 if ti.get("secure") else 80)
    scheme = "https" if ti.get("secure") else "http"
    path = "/"
    m = REQUEST_LINE_RE.search(str(ti.get("data") or ""))
    if m:
        path = m.group(2)
    if path.startswith("http"):
        return path
    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    netloc = host if default_port else f"{host}:{port}"
    return f"{scheme}://{netloc}{path}"


def _burp_method(ti: dict) -> str:
    m = REQUEST_LINE_RE.search(str(ti.get("data") or ""))
    return m.group(1) if m else "GET"


def main() -> int:
    ev = _event()
    tool = ev.get("tool_name") or ""
    if not tool.startswith("mcp__"):
        return _allow()
    if os.environ.get("CBH_MCP_GATE", "").lower() in ("off", "0", "false"):
        return _allow()

    server, name = _short_name(tool)
    ti = ev.get("tool_input") or {}
    if not isinstance(ti, dict):
        return _allow()

    try:
        from pacing import MissingRequiredHeader  # type: ignore
        from request_broker import RequestBlocked, RequestBroker, is_local_url  # type: ignore
    except Exception:  # noqa: BLE001 - never block on a broken gate
        return _allow()

    try:
        broker = RequestBroker.detect(source=f"mcp:{server}/{name}")
    except Exception:  # noqa: BLE001
        return _allow()

    # Outside an engagement there is no program on the other end: lab work stays free.
    if broker.engagement.project_dir is None:
        return _allow()

    if server == "burpmcp" and name in OOB_TOOLS:
        if not broker.engagement.allow_oob:
            return _deny(
                f"MCP GATE: {broker.engagement.name} does not permit out-of-band "
                f"(Collaborator/DNS) testing.\n"
                "The callback resolves through a third-party server, so the interaction data "
                "leaves this machine and lands on infrastructure the program never authorized.\n"
                "If this program does allow OOB, set \"allow_oob\": true in "
                f"Targets/{broker.engagement.name}/profile.json — the number belongs in the "
                "profile, not in a prose exception.")
        return _allow()

    url = method = None
    if server == "burpmcp" and name in BURP_SENDERS | BURP_RESENDERS:
        url, method = _burp_url(ti), _burp_method(ti)
        if url is None:
            if name in BURP_RESENDERS:
                return _deny(
                    "MCP GATE: this resend names no host, so its target lives only in Burp's "
                    "saved-request store and cannot be scope-checked from here.\n"
                    "UNVERIFIED is not approval to test. Re-send with host/port/secure set "
                    "explicitly (the resend tool accepts all three as overrides) so the scope "
                    "gate can see the target, or re-fire it as a poc_runtime spec.")
            return _allow()
    elif server == "playwright" and name in PLAYWRIGHT_NAVIGATORS:
        url, method = ti.get("url"), "GET"
        if not url:
            return _allow()
    else:
        return _allow()          # not a sender

    if is_local_url(url):
        return _allow()

    try:
        broker.validate([url])
    except RequestBlocked as e:
        return _deny(
            f"MCP GATE: {e}\n"
            f"Engagement: {broker.engagement.name}. Burp and Playwright bypass bbcurl, so this "
            "is the only place the scope gate can see this request.\n"
            "Check the target with `python3 engine/scope.py --resolve <host>` before retrying.")

    # Mandatory headers: a raw Burp request is a string this hook cannot rewrite, so
    # the honest move is to refuse and name the exact line to add.
    try:
        required = broker.prepare_headers({})
    except MissingRequiredHeader as e:
        return _deny(f"MCP GATE: {e}")
    if server == "burpmcp" and name in BURP_SENDERS:
        raw = str(ti.get("data") or "").lower()
        missing = [f"{k}: {v}" for k, v in required.items() if f"{k.lower()}:" not in raw]
        if missing:
            return _deny(
                f"MCP GATE: {broker.engagement.name} requires header(s) this raw request does "
                f"not carry. Add to the request block, then re-send:\n    "
                + "\n    ".join(missing))

    # Pacing: the hook blocking IS the throttle — same global budget, same lock file.
    waited = 0.0
    try:
        waited = broker.wait_turn()
    except Exception:  # noqa: BLE001
        pass

    try:
        broker.audit({"urls": [url], "method": method, "tool": tool,
                      "waited_seconds": round(waited, 2), "transport": "mcp"})
    except Exception:  # noqa: BLE001
        pass
    return _allow()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001 - a broken gate must never wedge the session
        sys.exit(0)
