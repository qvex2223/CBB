#!/usr/bin/env python3
"""What to do about a browser/proxy MCP failure, attached to the failure itself.

A Playwright MCP error arrives as one line of Chromium network vocabulary:

    Error: browserBackend.callTool: net::ERR_TOO_MANY_RETRIES at https://account.mail.ru/login

Nothing in that names the cause, and three of the causes live in THIS workspace: the
browser is proxied through Caido by default, Caido's intercept queue may be holding the
request, and one engagement may have taken the direct lane while another has not. On
In a 2026-11-11 session the same navigation was re-fired four times — each
failing in under half a second, so the retries could never have helped — and the
recovery move after them was a page reset the gate then refused.

So the remedy travels with the error. A client that gates inline appends it to the tool
result for clients that run the inline gate, and `scripts/mcp-hint.py` does the same as
a PostToolUse hook under Claude Code. One table, two transports; the wording is the
same for both, because the fix is the same.

Nothing here sends anything, and nothing here decides policy — a gate refusal is final
and its own text says so; this only answers "what next".
"""
from __future__ import annotations

import re
import sys

HEADER = "NEXT MOVE (cbh browser hint, not from the server):"

# (regex over the error text, lines of remedy). First match wins, so the specific
# patterns come before the general ones.
RULES: list[tuple[str, list[str]]] = [
    (r"MCP GATE:", [
        "This is the workspace's own gate, not the target. It is final: never re-fire the",
        "same call, and never route around it with another tool, agent or bare curl.",
        "Its text names the one legal next step — take that one.",
    ]),
    (r"net::ERR_TOO_MANY_RETRIES", [
        "Chromium gave up before the target answered. Through this workspace that has three",
        "causes, in the order worth checking — do NOT re-fire the same navigation, it failed",
        "in well under a second, which is a refusal, not a slow host:",
        "  1. Caido's intercept queue is PAUSED, so every proxied request is being held:",
        "     caido_intercept_status -> if PAUSED, caido_intercept_control {\"action\":\"resume\"}.",
        "  2. The target RSTs a MITM'd HTTP/2 connection (mail.ru does). This engagement needs",
        "     the direct lane: a `playwright-direct` marker next to browser-state.json, then a",
        "     restarted Playwright MCP server. Operator-side; ask, do not create controls.",
        "  3. Caido itself is wedged: scripts/caido-up.sh, or CBH_PLAYWRIGHT_CAIDO=off at the",
        "     server (again operator-side).",
        "Meanwhile `CBH_PROJECT=<program> bbcurl` reaches the same host over HTTP/1.1 and is",
        "the honest way to keep the lane moving. Run `cbh browser doctor` for the live state.",
    ]),
    (r"net::ERR_(PROXY_CONNECTION_FAILED|TUNNEL_CONNECTION_FAILED)", [
        "The browser could not reach its proxy — Caido is down or on another port.",
        "`cbh browser doctor`, then scripts/caido-up.sh. The target was never contacted.",
    ]),
    (r"net::ERR_CERT_", [
        "Certificate rejected. Through Caido this is the MITM CA; the wrapper already passes",
        "--ignore-https-errors, so a cert error here usually means a second proxy in the",
        "chain. `cbh browser doctor`. Pinned-host questions belong to bbcurl, not the browser.",
    ]),
    (r"net::ERR_NAME_NOT_RESOLVED", [
        "DNS has no answer for that host — it is not reachable, not blocked.",
        "`python3 engine/scope.py --resolve <host>` before spending another request on it.",
        "A saved passive name list rots: re-resolve locally before believing it.",
    ]),
    (r"net::ERR_(CONNECTION_TIMED_OUT|CONNECTION_RESET|CONNECTION_CLOSED|EMPTY_RESPONSE|SOCKET_NOT_CONNECTED)", [
        "The connection died mid-flight. Check whether it is us before it is them: a",
        "previously fast host that now times out is often a throttle on this identity.",
        "Check one other in-scope host once; if that is fine, the profile carries a block —",
        "`cbh identity new <url>` BEFORE re-probing, and log it in hosts/<host>.md.",
        "Never retry-loop a timing-out host.",
    ]),
    (r"net::ERR_(BLOCKED_BY_CLIENT|BLOCKED_BY_RESPONSE|ABORTED)", [
        "The request was aborted locally, not by the target. A route predicate or an abort",
        "filter in the automation is the usual cause; an allowlist starves a challenge",
        "solver. Read the console (browser_console_messages) before concluding anything",
        "about the target.",
    ]),
    # runtime/browser-lock.mjs::busyMessage — "the browser profile <dir> is held by pid N"
    (r"(SingletonLock|profile .{0,200}?is held by|is already in use)", [
        "One browser per --user-data-dir: another lane holds this engagement's profile.",
        "Do not wait it out silently. Either fire this lane's requests with bbcurl, or",
        "restart with CBH_PLAYWRIGHT_ISOLATED=1 for an unauthenticated render. If the lead",
        "cannot proceed: `cbh leads close <file> --as stalled`, never `--as blocked` —",
        "nothing about the target blocked it.",
    ]),
    (r"(input schema was not in your prompt|Invalid arguments for tool|Invalid input: expected)", [
        "This is an argument error, not the target: the tool's schema was deferred, so the",
        "call was written from memory. Load the schemas first, in ONE call, and re-read the",
        "parameter names from it:",
        "  ToolSearch(\"select:mcp__playwright__browser_navigate,mcp__playwright__browser_click,",
        "             mcp__playwright__browser_snapshot,mcp__playwright__browser_evaluate\")",
        "Playwright's click takes `element` (the human-readable description) plus `target`",
        "(the snapshot ref) — `ref` is the field name in the SNAPSHOT, not in the call. One",
        "guessed field cost a click on a live login page on 2026-11-13.",
    ]),
    (r"(waiting for element to be (visible|enabled|stable)|attempting click action|locator resolved to)", [
        "The element EXISTS and is not actionable — that 5000 ms is the per-call default, so",
        "waiting longer is not the fix and re-firing the same ref is not either (a re-render",
        "invalidates every aria-ref). In this order:",
        "  1. browser_snapshot again and use the NEW ref — stale refs are the usual cause.",
        "  2. Look for what covers it: a cookie wall, a city/region confirm dialog, a modal",
        "     overlay. Dismiss that first; it is also worth a line in hosts/<host>.md.",
        "  3. Still stuck: drive it in page context — browser_evaluate with",
        "     `() => document.querySelector(<selector>).click()` — and say in the write-up",
        "     that the click was scripted, not a real user gesture.",
        "An element that never becomes stable is often an animation or a challenge frame,",
        "which is a fact about the surface, not a tool failure.",
    ]),
    (r"(Timeout .* exceeded|timed out after)", [
        "The call hit its own timeout. Ask what actually arrived before re-navigating:",
        "browser_network_requests for the request list, browser_console_messages for the",
        "page's own errors. A page that never fires domcontentloaded is often a challenge",
        "page, which is a finding about the surface, not a tool failure.",
    ]),
    (r"PAUSED", [
        "Caido's intercept queue is PAUSED: it HOLDS every request it proxies instead of",
        "forwarding it, so a browser behind Caido loads nothing and reports",
        "net::ERR_TOO_MANY_RETRIES. caido_intercept_control {\"action\":\"resume\"} before",
        "navigating, or read traffic after the fact with caido_list_requests.",
    ]),
]

# Only these tools get hints: a hint on an unrelated server's error would be noise.
TOOLS = re.compile(r"^(browser_|caido_)")


def hint_for(tool: str, text: str) -> str:
    """The remedy block for this failure, or "" when there is nothing useful to say."""
    name = (tool or "").split("__")[-1]
    if not TOOLS.search(name):
        return ""
    body = text or ""
    for pattern, lines in RULES:
        if re.search(pattern, body, re.I):
            return "\n".join([HEADER, *lines])
    return ""


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    tool = ""
    if "--tool" in argv:
        i = argv.index("--tool")
        tool = argv[i + 1] if i + 1 < len(argv) else ""
    if "--rules" in argv:
        for pattern, _ in RULES:
            print(pattern)
        return 0
    hint = hint_for(tool, sys.stdin.read())
    if hint:
        print(hint)
    return 0


if __name__ == "__main__":
    sys.exit(main())
