#!/usr/bin/env python3
"""
mcp-gate — PreToolUse hook that puts Burp/Caido/Playwright MCP calls under the
same outbound-request policy as every other transport.

`bbcurl`, `poc_runtime` and the recon engine all go through `engine/request_broker`:
scope verified, pacing waited out, mandatory headers injected, request audited. The
MCP servers did not. Burp talks straight to its own HTTP client, Caido sends through
its own Replay engine (and, for race bursts, through raw sockets that never reach
Caido's own history), and Playwright drives a real browser — so until this hook existed
the fastest way to send an unscoped, unpaced, unaudited request at a live program was to
reach for the proxy, the tool the workspace tells you to reach for on the last mile.

What is gated, and what is honestly not:

  * GATED — the calls that choose a target: burpmcp http1/http2 send and resend,
    and playwright browser_navigate. Scope is checked, the engagement's pacing
    budget is waited out, and an audit row is written before the call proceeds.
  * NOT GATED, by design — in-page actions (browser_click, browser_evaluate, form
    fills). They name no host: the origin was chosen at navigate, which is gated,
    and they inherit it. A click that triggers a cross-origin XHR is not visible
    here. Claiming otherwise would be worse than the gap.
  * GATED — the Caido tools that choose a target: caido_send_request,
    caido_batch_send, caido_race_window_send and caido_edit_request. The target is
    read from the explicit host/port/tls arguments, or failing that from the raw
    request's own Host header, and every request in a batch is checked, not just
    the first.
  * NOT SENDERS — save-http1-request, get-saved-request, update-note, and Caido's
    list_*/get_*/export/convert/findings/scope/project/session tools touch local
    state only and pass through untouched.

Three Caido tools are refused rather than gated, because what they would fire is not
visible in their arguments:

  * caido_forward_intercept names only an entry id; the target lives in Caido's
    intercept queue.
  * caido_run_workflow with type=active runs somebody else's workflow against a
    stored request — arbitrary requests, no host in the call.
  * caido_automate_task_control with action=start/resume runs Caido's fuzzing engine,
    which is exactly the broad automated scanning every project file here forbids.

Bulk senders (caido_batch_send, caido_race_window_send, and Automate) additionally
require "allow_bulk_tools": true in the engagement profile, and the whole batch is
paid for out of the engagement's pacing budget before the first byte leaves.

A resend with no explicit host cannot be scope-checked: the target lives in Burp's
saved-request store, which this hook cannot read. That is `UNVERIFIED`, and this
workspace's own rule is that UNVERIFIED is not approval to test — so it is refused
with the fix (pass host/port/secure explicitly), not waved through.

Escape hatch, audited: CBH_MCP_GATE=off.
"""
from __future__ import annotations

import json
import os
import time
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
# A navigation does not have to arrive as browser_navigate. These tools hand the MCP
# server arbitrary JS/Playwright code, and `page.goto(...)` inside that code reached the
# network completely ungated until 2026-11-12: unscoped, unpaced and with no audit row
# (`grep -c run_code hunt-memory/audit.jsonl` -> 0 for the whole engagement). A brief
# that says "pin the page with browser_run_code_unsafe" is therefore a gate bypass, and
# one was written on this engagement before the gap was found. What this branch can see
# is the absolute http(s) URL literals in the snippet, so those get the full scope,
# pacing and audit treatment. What it cannot see is a relative fetch or a URL built at
# runtime from variables; those stay invisible exactly like a click that fires an XHR,
# which is why navigation belongs in browser_navigate and these tools belong to in-page
# READS.
PLAYWRIGHT_SCRIPTERS = {"browser_run_code_unsafe", "browser_evaluate"}
# Absolute targets only. A bare path cannot be resolved without knowing the page's
# current origin, which this hook does not have, and guessing an origin would either
# invent an out-of-scope claim or wave a real one through.
SCRIPT_URL_RE = re.compile(r"""https?://[^\s'"`)\\<>]+""")
# A snippet that SENDS. Measured on Grok session 01a1ea8b (intigriti/1password, 2026-11-18):
# workers fired the target's API from inside the page and the extension service worker with
# `fetch('/api/v3/auth/start')` and a client method `CTX.session.request({path: ...})` —
# relative paths, so the URL branch above saw nothing and passed them. Two lanes reported
# ~110 target requests between them; the audit holds 14 browser rows for the whole
# engagement. A sender with no absolute URL literal is refused now, with the remedy: name
# every target as an absolute URL (a comment is enough when the client takes a bare path),
# and the gate scopes, paces and audits each one. Wrapping `fetch` to observe it does not
# match (`self.fetch = …`, `origFetch(…)`), because observing is not sending.
SCRIPT_SEND_RE = re.compile(
    r"\bfetch\s*\(|\bXMLHttpRequest\b|\bsendBeacon\s*\(|\bnew\s+WebSocket\s*\(|"
    r"\bnew\s+EventSource\s*\(|\.request\s*\(|\.request\.(?:get|post|put|patch|delete|"
    r"head|fetch)\s*\(")
# `browser_run_code_unsafe {"filename": ...}` carries a PATH, not code. On the same session
# 11 calls went that way (`sw-invite-fire.js`, `sw-keysets.js`, ...) and the gate read only
# the path string. The file is read and gated as if its text were inline.
SCRIPT_FILE_MAX_BYTES = 1_000_000

# Caido: tool -> how the target is expressed. Names carry their own prefix, so the
# server-qualified call is mcp__caido__caido_send_request.
CAIDO_RAW_SENDERS = {"caido_send_request"}       # raw + optional host/port/tls
CAIDO_BATCH_SENDERS = {"caido_batch_send"}       # requests[] of the same shape
CAIDO_RACE_SENDERS = {"caido_race_window_send"}  # host required, requests[] raw
CAIDO_RESENDERS = {"caido_edit_request"}         # stored requestId + overrides
CAIDO_BLIND_SENDERS = {"caido_forward_intercept"}
CAIDO_INTERCEPT = {"caido_intercept_control"}  # pause/resume the intercept QUEUE
CAIDO_AUTOMATE = {"caido_automate_task_control"}
CAIDO_WORKFLOW = {"caido_run_workflow"}

REQUEST_LINE_RE = re.compile(r"^\s*([A-Z]+)\s+(\S+)", re.M)
HOST_HEADER_RE = re.compile(r"^host:[ \t]*([^\r\n]+)", re.I | re.M)

# A bulk call pays the engagement's pacing budget for every request it carries, and
# this hook is what blocks while that is waited out. Past this much waiting the honest
# answer is "send a smaller batch", not a hook that looks wedged.
BULK_WAIT_CAP_SECONDS = 120.0


# A client may run this file twice for one MCP call: as a Claude-compatible PreToolUse
# hook, and again inline from its own wrapper (CBH_MCP_INLINE=1). The hook leaves a
# marker for each sender it allowed; the inline run consumes it instead of pacing and
# auditing the same call a second time. No marker (hook off, args reshaped) = the
# inline run gates in full, which is the safe direction.
PASSED_TTL_SECONDS = 120


_NO_ENGAGEMENT_MSG = (
    "MCP GATE: no engagement resolved — neither from the launch folder nor from the URL "
    "(no program's scope.md admits it, or more than one does), so there is no scope to "
    "check this request against.\n"
    "Restart the agent inside Targets/<platform>/<program>/ (the MCP servers take their "
    "folder from the launch directory), or use local URLs only. Nothing was sent.\n"
    "This refusal is about THIS url, not about the browser: about:blank, data:, blob:, "
    "chrome:// and file:// need no engagement at all, so a page reset still works here.")


def _first_url(server: str, name: str, ti: dict) -> str:
    url = ti.get("url") if isinstance(ti, dict) else None
    if url:
        # A navigation can be wrapped (view-source:https://target/ still fetches the
        # target) or fetch nothing at all (about:blank). Resolve the engagement from
        # what actually leaves the browser.
        try:
            from request_broker import is_non_network_url, unwrap_url  # type: ignore
            return "" if is_non_network_url(url) else unwrap_url(url)
        except Exception:  # noqa: BLE001
            return str(url)
    if not isinstance(ti, dict):
        return ""
    host = ti.get("host")
    raws = [ti.get("raw")] + [i.get("raw") for i in (ti.get("requests") or []) if isinstance(i, dict)]
    if not host:
        for raw in raws:
            m = HOST_HEADER_RE.search(_raw_text(raw))
            if m:
                host = m.group(1).strip()
                break
    if host:
        secure = ti.get("secure", ti.get("tls", True))
        return f"{'https' if secure else 'http'}://{host}/"
    return ""


def _engagement_for(url: str):
    """The one engagement whose scope.md admits this URL, else None."""
    if not url:
        return None
    try:
        from request_broker import is_local_url  # type: ignore
        from scope import _scope_from_md  # type: ignore
        from paths import targets_root  # type: ignore
        if is_local_url(url):
            return None
        hits = []
        for md in Path(targets_root()).glob("**/scope.md"):
            if "_TEMPLATE" in md.parts or ".trash" in md.parts:
                continue
            try:
                if _scope_from_md(str(md)).reject_reason(url) is None:
                    hits.append(md.parent)
            except Exception:  # noqa: BLE001
                continue
        return hits[0] if len(hits) == 1 else None
    except Exception:  # noqa: BLE001
        return None


def _strict_client() -> bool:
    """Any client that is not Claude Code: fail closed outside an engagement.

    Claude Code's hooks carry the session's cwd, so an engagement is normally resolved
    before this gate runs. A client without them was launched from the repo root and its
    browser opened an arbitrary site through the free-lab branch (2026-11-10), so for
    anything else "no engagement" means local URLs only.
    """
    if os.environ.get("CBH_MCP_INLINE") == "1":
        return True
    agent = (os.environ.get("CBH_AGENT") or "").strip().lower()
    if agent:
        return agent != "claude"
    try:
        import client as _C  # type: ignore
        return _C.detect() != "claude"
    except Exception:  # noqa: BLE001
        return os.environ.get("CLAUDECODE") != "1"


def _passed_dir() -> Path:
    base = os.environ.get("CBH_MEMORY_DIR") or str(Path(__file__).resolve().parent.parent / "hunt-memory")
    return Path(base) / ".mcp-gate-passed"


def _call_key(tool: str, ti: dict) -> str:
    import hashlib
    blob = json.dumps([tool, ti], sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _mark_passed(tool: str, ti: dict) -> None:
    if os.environ.get("CBH_MCP_INLINE") == "1":
        return
    try:
        d = _passed_dir()
        d.mkdir(parents=True, exist_ok=True)
        (d / _call_key(tool, ti)).write_text(str(time.time()), encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass


def _consume_passed(tool: str, ti: dict) -> bool:
    if os.environ.get("CBH_MCP_INLINE") != "1":
        return False
    f = _passed_dir() / _call_key(tool, ti)
    try:
        fresh = time.time() - float(f.read_text(encoding="utf-8")) < PASSED_TTL_SECONDS
        f.unlink()
        return fresh
    except Exception:  # noqa: BLE001
        return False


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


def _raw_text(value) -> str:
    """Caido senders take a plain raw request; forward_intercept takes base64."""
    raw = str(value or "")
    if not raw or REQUEST_LINE_RE.search(raw):
        return raw
    try:
        import base64
        decoded = base64.b64decode(raw, validate=True).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - not base64, hand back what we were given
        return raw
    return decoded if REQUEST_LINE_RE.search(decoded) else raw


def _caido_target(item: dict) -> tuple[str | None, str]:
    """(url, method) for one Caido request item, or (None, method) if no host.

    The host is whatever the call says explicitly; failing that, the raw request's
    own Host header, which is what Caido itself would route on. `tls` defaults to
    true in the tool schema, so this defaults the same way — guessing http here
    would scope-check a different URL than the one that gets sent.
    """
    raw = _raw_text(item.get("raw"))
    host = str(item.get("host") or "").strip()
    if not host:
        m = HOST_HEADER_RE.search(raw)
        host = m.group(1).strip() if m else ""
    if not host:
        return None, "GET"
    secure = True if item.get("tls") is None else bool(item.get("tls"))
    if "://" in host:                       # a host field that is really a URL
        host = host.split("://", 1)[1]
    if host.startswith("["):                # IPv6 literal, port may follow
        host_only, _, tail = host.partition("]")
        host_only += "]"
        inline_port = tail[1:] if tail.startswith(":") else ""
    else:
        host_only, _, inline_port = host.partition(":")
    port = item.get("port") or (int(inline_port) if inline_port.isdigit() else None) \
        or (443 if secure else 80)
    scheme = "https" if secure else "http"
    m = REQUEST_LINE_RE.search(raw)
    method, path = (m.group(1), m.group(2)) if m else ("GET", "/")
    if path.startswith("http"):
        return path, method
    default_port = (scheme == "https" and int(port) == 443) or \
                   (scheme == "http" and int(port) == 80)
    netloc = host_only if default_port else f"{host_only}:{port}"
    return f"{scheme}://{netloc}{path}", method


def _header_gap(required: dict, raw: str) -> list[str]:
    low = raw.lower()
    return [f"{k}: {v}" for k, v in required.items() if f"{k.lower()}:" not in low]


def _caido_targets(name: str, ti: dict, broker) -> list[tuple[str, str]] | str:
    """Targets for a Caido call, or a deny reason as a string."""
    engagement = broker.engagement

    if name in CAIDO_BLIND_SENDERS:
        return (
            "MCP GATE: caido_forward_intercept names only an intercept entry id, so its "
            "target lives in Caido's intercept queue and cannot be scope-checked from "
            "here.\nUNVERIFIED is not approval to test. Read the entry with "
            "caido_list_intercept_entries, then either caido_drop_intercept it, or fire "
            "it deliberately with caido_send_request and an explicit host so the scope "
            "gate can see the target.")

    if name in CAIDO_INTERCEPT:
        # Caido's intercept queue PAUSED means "hold every request until someone
        # forwards it", not "stop intercepting". A browser proxied through Caido
        # therefore stops loading anything the moment this is paused, and Chromium
        # reports it as net::ERR_TOO_MANY_RETRIES — a failure that looks exactly like
        # the target refusing the connection. That is what happened on 2026-11-11: the
        # queue was paused while hunting a navigation failure, and every navigation
        # afterwards failed in under half a second.
        if str(ti.get("action") or "").lower() != "pause":
            return []                       # resume/other: never creates the trap
        try:
            sys.path.insert(0, str(REPO / "engine"))
            from browser_state import caido_proxied_lanes  # type: ignore
            lanes = caido_proxied_lanes()
        except Exception:  # noqa: BLE001
            lanes = []
        if not lanes:
            return []
        who = ", ".join(f"{l['engagement']} (pid {l['pid']}, {l['label']})" for l in lanes)
        return (
            "MCP GATE: pausing Caido's intercept queue holds every request it proxies, and "
            f"a live browser is going through Caido right now — {who}.\n"
            "Paused, that browser loads nothing and Chromium reports it as "
            "net::ERR_TOO_MANY_RETRIES, which reads like the target refusing the "
            "connection. Nothing was paused.\n"
            "To inspect traffic without stalling the browser: caido_list_requests / "
            "caido_get_request after the fact, or a tamper rule. To intercept "
            "deliberately: close the browser first (browser_close), pause, then resume "
            "with action=resume before navigating again.")

    if name in CAIDO_WORKFLOW:
        if str(ti.get("type") or "").lower() == "active":
            return (
                "MCP GATE: an active Caido workflow sends requests of its own choosing "
                "against a stored request, and this call names no host — nothing here can "
                "be scope-checked.\nRun the workflow's requests through caido_send_request "
                "with an explicit host, or re-fire them as a poc_runtime spec. Convert "
                "workflows (type=convert) transform data locally and are not gated.")
        return []

    if name in CAIDO_AUTOMATE:
        action = str(ti.get("action") or "").lower()
        if action not in ("start", "resume"):
            return []                       # pause/cancel stop traffic, never start it
        if not engagement.allow_bulk_tools:
            return (
                f"MCP GATE: caido_automate_task_control action={action} starts Caido's "
                f"fuzzing engine, which fires an unbounded number of requests this hook "
                f"cannot see or pace one by one — the broad automated scanning "
                f"{engagement.name} forbids.\nIf this program really does permit it, set "
                f"\"allow_bulk_tools\": true in Targets/{engagement.name}/profile.json and "
                f"set the session's own rate limit inside Caido. Otherwise drive the same "
                f"payload list through caido_batch_send, which is gated per request.")
        return []                           # permitted: Caido owns its own pacing here

    if name in CAIDO_RESENDERS:
        url, method = _caido_target(ti)
        if url is None:
            return (
                "MCP GATE: caido_edit_request resends a request stored in Caido, and this "
                "call overrides no host, so the target cannot be scope-checked from "
                "here.\nUNVERIFIED is not approval to test. Pass host (and port/tls when "
                "they are not 443/https) explicitly — the tool accepts all three as "
                "overrides.")
        return [(url, str(ti.get("method") or method))]

    if name in CAIDO_RAW_SENDERS:
        url, method = _caido_target(ti)
        return [] if url is None else [(url, method)]

    if name in CAIDO_BATCH_SENDERS | CAIDO_RACE_SENDERS:
        items = ti.get("requests")
        if not isinstance(items, list) or not items:
            return []
        if not engagement.allow_bulk_tools:
            return (
                f"MCP GATE: {name} fires {len(items)} requests in one call "
                f"({'in parallel' if name in CAIDO_BATCH_SENDERS else 'simultaneously, by design'}), "
                f"and {engagement.name} has not opted in to bulk tools.\nSet "
                f"\"allow_bulk_tools\": true in Targets/{engagement.name}/profile.json if the "
                f"program permits it — the number belongs in the profile, not in a prose "
                f"exception. Until then send them one at a time with caido_send_request.")
        shared = {k: ti.get(k) for k in ("host", "port", "tls") if ti.get(k) is not None}
        targets: list[tuple[str, str]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            url, method = _caido_target({**shared, **item})
            if url is None:
                return (
                    f"MCP GATE: one request in this {name} call names no host and carries no "
                    f"Host header, so it cannot be scope-checked.\nUNVERIFIED is not approval "
                    f"to test — give every item a host, or send them individually.")
            targets.append((url, method))
        return targets

    return []


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
        from request_broker import (RequestBlocked, RequestBroker,  # type: ignore
                                    is_local_url, is_non_network_url, unwrap_url)
    except Exception:  # noqa: BLE001 - never block on a broken gate
        return _allow()

    try:
        broker = RequestBroker.detect(source=f"mcp:{server}/{name}")
    except Exception:  # noqa: BLE001
        return _allow()
    # A client launched outside Targets/<program>/: find the engagement by the request's own
    # URL, so the browser keeps working from the repo root while every gate still applies
    # (scope, pacing, mandatory headers, audit). Ambiguous or unmatched = stays blocked.
    if broker.engagement.project_dir is None and _strict_client():
        eng_dir = _engagement_for(_first_url(server, name, ti))
        if eng_dir is not None:
            try:
                broker = RequestBroker.detect(start=eng_dir, source=f"mcp:{server}/{name}")
            except Exception:  # noqa: BLE001
                pass

    # Outside an engagement there is no program on the other end: lab work stays free.
    # Except for a client with no cwd-carrying hooks (2026-11-10): launched from the repo
    # root, its browser opened an arbitrary site through this branch. There, no engagement means
    # local URLs only — the senders below are resolved and refused if they leave the box.
    no_engagement = broker.engagement.project_dir is None
    if no_engagement and not _strict_client():
        return _allow()
    if no_engagement and server == "burpmcp" and name in OOB_TOOLS:
        return _deny(_NO_ENGAGEMENT_MSG)

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

    targets: list[tuple[str, str]] = []
    if server == "caido":
        decided = _caido_targets(name, ti, broker)
        if isinstance(decided, str):
            return _deny(decided)
        targets = decided
    elif server == "burpmcp" and name in BURP_SENDERS | BURP_RESENDERS:
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
        targets = [(url, method)]
    elif server == "playwright" and name in PLAYWRIGHT_NAVIGATORS:
        url = ti.get("url")
        if not url:
            return _allow()
        # Browser control URLs (about:blank, data:, blob:, chrome://, file://) send
        # nothing: no host to scope-check, no request to pace, nothing to audit. They
        # used to be read as remote targets and refused with "no engagement resolved",
        # which took away the one recovery move an agent has after a failed navigation
        # (measured 2026-11-11). view-source: is unwrapped instead of
        # waved through, because it does fetch its inner URL.
        if is_non_network_url(url):
            return _allow()
        targets = [(unwrap_url(url), "GET")]
    elif server == "playwright" and name in PLAYWRIGHT_SCRIPTERS:
        # Every string the call carries, because the snippet arrives under different key
        # names per tool (`code`, `function`, ...) and a new one must not silently
        # reopen the hole.
        blob = " ".join(v for v in ti.values() if isinstance(v, str))
        fname = ti.get("filename") if isinstance(ti, dict) else None
        if isinstance(fname, str) and fname.strip():
            try:
                fp = Path(fname).expanduser()
                if fp.stat().st_size > SCRIPT_FILE_MAX_BYTES:
                    raise OSError("larger than the gate reads")
                blob += " " + fp.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                return _deny(
                    f"MCP GATE: could not read the script file `{fname}` ({e}), so nothing "
                    "in it can be scope-checked, paced or audited. Pass the code inline as "
                    "`code`, or a readable file under 1 MB. Nothing was sent.")
        urls = []
        for u in SCRIPT_URL_RE.findall(blob):
            u = u.rstrip(".,;")
            if is_non_network_url(u) or u in urls:
                continue
            urls.append(u)
        if not [u for u in urls if not is_local_url(unwrap_url(u))] and SCRIPT_SEND_RE.search(blob):
            return _deny(
                "MCP GATE: this snippet sends a request (fetch / XMLHttpRequest / "
                "`.request(` / WebSocket) but names no absolute URL, so the target cannot be "
                "scope-checked, paced or audited — which makes it a bbcurl bypass.\n"
                "Do one of these instead:\n"
                "  * the browser goes through Caido: drive the flow in the page, then read the "
                "real request with `caido_list_requests` (HTTPQL `req.host.eq:\"<host>\"`) "
                "and mutate it with `caido_edit_request` — gated, and the Caido entry is your "
                "wire evidence;\n"
                "  * the request must come from inside the client (a per-request signature or "
                "MAC that a replay cannot carry): name EVERY target as an absolute URL literal "
                "in the snippet — a comment such as `// https://host/api/v2/x` is enough when "
                "the client takes a bare path — and the gate scopes, paces and audits each.\n"
                "Nothing was sent.")
        if not urls:
            return _allow()      # in-page read, or a target this hook cannot see
        targets = [(unwrap_url(u), "GET") for u in urls]
    else:
        return _allow()          # not a sender

    targets = [(u, m) for u, m in targets if not is_local_url(u)]
    if not targets:
        return _allow()
    if no_engagement:
        return _deny(_NO_ENGAGEMENT_MSG)
    if _consume_passed(tool, ti):
        return _allow()          # the PreToolUse hook already gated, paced and audited it

    try:
        broker.validate([u for u, _ in targets])
    except RequestBlocked as e:
        return _deny(
            f"MCP GATE: {e}\n"
            f"Engagement: {broker.engagement.name}. The proxy MCP servers and Playwright "
            "bypass bbcurl, so this is the only place the scope gate can see this request.\n"
            "Check the target with `python3 engine/scope.py --resolve <host>` before retrying.")

    # Mandatory headers: a raw request is a string this hook cannot rewrite, so the
    # honest move is to refuse and name the exact line to add.
    try:
        required = broker.prepare_headers({})
    except MissingRequiredHeader as e:
        return _deny(f"MCP GATE: {e}")
    if required:
        missing: list[str] = []
        if server == "burpmcp" and name in BURP_SENDERS:
            missing = _header_gap(required, str(ti.get("data") or ""))
        elif server == "caido" and name in CAIDO_RAW_SENDERS:
            missing = _header_gap(required, _raw_text(ti.get("raw")))
        elif server == "caido" and name in CAIDO_BATCH_SENDERS | CAIDO_RACE_SENDERS:
            for item in (ti.get("requests") or []):
                if isinstance(item, dict):
                    for line in _header_gap(required, _raw_text(item.get("raw"))):
                        if line not in missing:
                            missing.append(line)
        # caido_edit_request is deliberately not header-checked: it preserves the
        # stored request's own headers, which this hook cannot read, so a "missing"
        # header here would be a guess. The removeHeaders case is the one real risk.
        elif server == "caido" and name in CAIDO_RESENDERS:
            dropped = {str(h).lower() for h in (ti.get("removeHeaders") or [])}
            missing = [f"{k}: {v}" for k, v in required.items() if k.lower() in dropped]
        if missing:
            return _deny(
                f"MCP GATE: {broker.engagement.name} requires header(s) this raw request does "
                f"not carry. Add to the request block, then re-send:\n    "
                + "\n    ".join(missing))

    # Pacing: the hook blocking IS the throttle — same global budget, same lock file.
    # A bulk call pays for every request it carries, up front.
    interval = broker.engagement.min_interval
    if len(targets) > 1 and interval > 0 and len(targets) * interval > BULK_WAIT_CAP_SECONDS:
        fits = max(1, int(BULK_WAIT_CAP_SECONDS // interval))
        return _deny(
            f"MCP GATE: {len(targets)} requests against a {interval:g}s pacing budget is "
            f"{len(targets) * interval:g}s of waiting, which this hook will not sit through.\n"
            f"Send at most {fits} per call, or raise min_interval_seconds in "
            f"Targets/{broker.engagement.name}/profile.json only if the program's own rate "
            f"limit actually allows it. Pacing is not relaxed to make a batch faster.")
    waited = 0.0
    for _ in targets:
        try:
            waited += broker.wait_turn()
        except Exception:  # noqa: BLE001
            break

    row = {"urls": [u for u, _ in targets], "method": targets[0][1], "tool": tool,
           "waited_seconds": round(waited, 2), "transport": "mcp",
           "requests": len(targets)}
    if server == "caido" and name in CAIDO_RACE_SENDERS:
        # Race bursts leave through raw sockets inside the MCP server, so Caido's own
        # history never sees them. This audit row is the only record they happened.
        row["note"] = "caido race burst: bypasses Caido proxy history"
    try:
        broker.audit(row)
    except Exception:  # noqa: BLE001
        pass
    _mark_passed(tool, ti)
    return _allow()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001 - a broken gate must never wedge the session
        sys.exit(0)
