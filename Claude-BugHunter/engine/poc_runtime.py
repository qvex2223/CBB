#!/usr/bin/env python3
"""
poc_runtime.py — deterministic single-shot PoC execution + validation.

Strix-style idea (execute the exploit, don't just claim it), kept inside this
repo's constraints: curl-first, scope-gated, no autonomous retries/hammering.
The human still picks the request — this just fires it once, captures the
real bytes, and judges the result in code instead of from memory.

A PoC spec is a small JSON file describing ONE HTTP request and what a
successful trigger looks like:

{
  "note":    "IDOR check — victim id 124 while authenticated as 123",
  "method":  "GET",
  "url":     "https://api.example.com/v1/users/124",
  "headers": {"Cookie": "session=..."},
  "body":    null,
  "follow_redirects": true,
  "expect": {
    "status": 200,
    "body_contains": ["\"id\":124"],
    "body_not_contains": ["\"id\":123"],
    "header_contains": {"content-type": "application/json"},
    "final_url_contains": "/v1/users/124",
    "set_cookie_contains": "session=",
    "no_redirect": false
  },
  "repeat": 1
}

The redirect keys are not decoration. urllib follows 302s silently, so an
exploit that actually bounced to /login reports the login page's 200 and the
spec's `expect: {status: 200}` passes. Every hop is captured, and a PASS on a
redirected response is downgraded to INCONCLUSIVE unless the spec says what the
final URL should be (`final_url_contains`) or forbids redirects (`no_redirect`,
or `"follow_redirects": false` to capture the raw 3xx instead).

A multi-step PoC (login -> act -> verify) uses `steps` instead of a single
request. One cookie jar rides through the whole chain, `capture` lifts values
out of a response into {{placeholders}} for later steps, each step is judged
against its own `expect`, and the chain stops at the first step that fails:

{
  "note": "ATO — reset another user's password and log in as them",
  "steps": [
    {"name": "login", "method": "POST", "url": "https://app.example.com/login",
     "body": "user=own&pass=own",
     "expect": {"status": 200, "set_cookie_contains": "session="},
     "capture": {"csrf": {"from": "body", "regex": "\"csrf\":\"([^\"]+)\""}}},
    {"name": "exploit", "method": "POST", "url": "https://app.example.com/reset",
     "body": "victim=124&csrf={{csrf}}",
     "expect": {"status": 200}},
    {"name": "verify", "method": "GET", "url": "https://app.example.com/api/me",
     "expect": {"status": 200, "body_contains": ["\"id\":124"]}}
  ]
}

The `verify` step is the point. "The POST returned 200" is the claim that gets
reports closed as N/A; the state change read back afterwards is the one that
does not.

Scope is enforced the same way engine/scope.py enforces it for the rest of
the engine: deny wins, default deny, checked BEFORE any request goes out.
No scope source given -> refuses to fire unless --no-scope-check is passed
explicitly (for localhost/lab targets).

Usage:
    python3 engine/poc_runtime.py spec.json --md ~/Targets/acme/scope.md
    python3 engine/poc_runtime.py spec.json --in-scope acme.com
    python3 engine/poc_runtime.py spec.json --no-scope-check   # localhost/lab only

Writes <spec-stem>.result.json next to the spec with the captured evidence
and a PASS / FAIL / ERROR / INCONCLUSIVE verdict, plus a one-line hint
mapping the result to the triage-validation 7-Question Gate's Q1/Q6.
"""
from __future__ import annotations

import argparse
import datetime
import http.cookiejar
import json
import os
import re
import ssl
import sys
import time
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pacing import Engagement, MissingRequiredHeader  # noqa: E402
from request_broker import RequestBroker, RequestBlocked  # noqa: E402
from scope import Scope, _scope_from_md  # noqa: E402

MAX_REPEAT = 5              # hard cap — this is a validator, not a brute-forcer
MAX_BODY_CAPTURE = 250000   # bytes of response body kept in the result file
                            # 20000 was too small for server-rendered pages: the
                            # disclosed field routinely sits past byte 60k, so an
                            # `expect` on it failed even though the bug was real.


def _load_scope(args: argparse.Namespace) -> Scope | None:
    if args.md:
        return _scope_from_md(args.md)
    if args.scope_file:
        return Scope.load(args.scope_file)
    if args.in_scope or args.out_of_scope:
        return Scope(in_scope=args.in_scope, out_of_scope=args.out_of_scope)
    return None


def _scrub(text: str) -> str:
    """Mask identity fields (iin/msisdn/phone/passport/...) before anything is written.

    Delegates to responses.scrub_text so bbcurl and poc_runtime cannot drift apart on
    what counts as PII. Best-effort: a missing sibling module must not fail a run.
    """
    try:
        from responses import scrub_text  # noqa: PLC0415 - optional sibling module
        return scrub_text(text)
    except Exception:  # noqa: BLE001
        return text


def _scrub_doc(obj):
    """Scrub every string in the artifact tree, not just the serialised blob.

    `_scrub` on the finished `json.dumps` output misses identities that live inside a
    captured body, because there they are quoted as \"msisdn\":\"7…\" — escaped quotes
    the key/value regex never matches. Found live on 2026-09-14: a PASS artifact for
    /api/v1/optionals/public/fraud-numbers kept 60k real subscriber numbers on disk.
    Scrubbing each string before serialisation sees the body as raw text and masks it.
    """
    if isinstance(obj, str):
        return _scrub(obj)
    if isinstance(obj, list):
        return [_scrub_doc(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _scrub_doc(v) for k, v in obj.items()}
    return obj

def _audit(spec: dict, url: str, runs: list, verdict: str, evidence_path: str) -> None:
    """Append this fire to hunt-memory/audit.jsonl. Best-effort — never fails the run.

    /autopilot documents "every request is logged to hunt-memory/audit.jsonl"; this is
    what makes that true. Headers are dropped here rather than redacted downstream —
    a PoC spec's headers are exactly where the session cookie lives.
    """
    try:
        from memory import Memory  # noqa: PLC0415 - optional sibling module
        Memory().audit({
            "source": "poc_runtime",
            "method": spec.get("method", "GET").upper(),
            "url": _scrub(url),
            "note": spec.get("note"),
            "runs": len(runs),
            "statuses": [r["result"].get("status") for r in runs],
            "verdict": verdict,
            "evidence": evidence_path,
        })
    except Exception:  # noqa: BLE001 - audit logging must never break a PoC run
        pass


# A fired PoC is the only thing that turns a hypothesis into a result, so the
# verdict maps straight onto hunt memory's vocabulary. ERROR is deliberately absent:
# a request that never completed says nothing about the bug and must not be logged
# as though it did.
_VERDICT_TO_RESULT = {"PASS": "confirmed", "FAIL": "rejected", "INCONCLUSIVE": "partial"}


def _journal(spec: dict, url: str, verdict: str, evidence_path: str) -> None:
    """Record the run in hunt memory automatically. Best-effort — never fails the run.

    `/remember` was documented as the way findings reach the corpus, and in practice
    it was almost never called by hand: the journal held 35 entries and patterns.jsonl
    did not exist at all. Anything backed by a real request now lands there without
    anyone remembering to ask, which is the only way cross-target learning accumulates.
    """
    result = _VERDICT_TO_RESULT.get(verdict)
    if result is None:
        return
    try:
        from memory import Memory  # noqa: PLC0415 - optional sibling module
        parsed = urllib.parse.urlsplit(url)
        Memory().remember({
            "target": parsed.hostname or url,
            "vuln_class": spec.get("vuln_class") or "unspecified",
            "endpoint": parsed.path or "/",
            "result": result,
            "severity": spec.get("severity"),
            "technique": spec.get("technique"),
            "tech_stack": spec.get("tech_stack") or [],
            "tags": (spec.get("tags") or []) + ["poc-verified"],
            "notes": spec.get("note"),
            "evidence": evidence_path,
            "verified_by_request": True,
        })
    except Exception:  # noqa: BLE001 - memory logging must never break a PoC run
        pass


class _RecordingRedirect(urllib.request.HTTPRedirectHandler):
    """Follows redirects like the default handler, but writes down every hop.

    The default handler swallows the chain: a PoC that 302s to /login comes back
    as the login page's 200 with no trace of the bounce. "The exploit returned
    200" is then a lie the evidence file cannot contradict.
    """

    def __init__(self, follow: bool = True) -> None:
        self.hops: list[dict] = []
        self.follow = follow

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.hops.append({
            "status": code,
            "from": req.full_url,
            "to": newurl,
            "set_cookie": headers.get_all("Set-Cookie") or [],
        })
        if not self.follow:
            return None  # urllib then surfaces the raw 3xx as an HTTPError
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _capture(resp_headers) -> tuple[dict, list, list]:
    """(dict view, every header pair, Set-Cookie values).

    `dict(headers.items())` keeps only the last value of a repeated header, which
    silently drops all but one Set-Cookie — exactly the session/state evidence a
    PoC is supposed to show.
    """
    pairs = list(resp_headers.items()) if resp_headers else []
    cookies = (resp_headers.get_all("Set-Cookie") or []) if resp_headers else []
    return dict(pairs), [list(kv) for kv in pairs], list(cookies)


_PINNED: dict[str, str] = {}
_REAL_GETADDRINFO = socket.getaddrinfo


def _pin_host(url: str, ip: str) -> None:
    """Send the request to the exact address the scope gate just verified.

    Two reasons, both real. It closes a DNS-rebinding window — without it the
    name is resolved twice, once for the gate and once for the request, and the
    second answer is the one that actually gets contacted. And it survives a
    flaky resolver: on this box the WSL forwarder fails roughly three requests
    in four, which turned every fired PoC into `Temporary failure in name
    resolution` even though the gate had just resolved the same host fine.

    Only ever pins an address the gate itself resolved and approved — never an
    operator-supplied one — so this cannot be used to point a request somewhere
    the scope check did not look.
    """
    host = urllib.parse.urlsplit(url).hostname
    if not host or host in _PINNED:
        return
    _PINNED[host] = ip

    def _patched(host_arg, port, *a, **kw):
        pinned = _PINNED.get(host_arg)
        if pinned:
            return _REAL_GETADDRINFO(pinned, port, *a, **kw)
        return _REAL_GETADDRINFO(host_arg, port, *a, **kw)

    socket.getaddrinfo = _patched


def _warm_dns(url: str, attempts: int = 4, backoff: float = 0.4) -> None:
    """Resolve the URL's host, retrying a flaky resolver. Sends nothing anywhere."""
    try:
        host = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return
    if not host:
        return
    for i in range(attempts):
        try:
            socket.getaddrinfo(host, None)
            return
        except (socket.gaierror, OSError):
            if i < attempts - 1:
                time.sleep(backoff)


def fire_once(spec: dict, timeout: int = 15, headers: dict | None = None,
              jar: "http.cookiejar.CookieJar | None" = None) -> dict:
    """Send exactly one HTTP request and capture the real response. No retries here.

    `jar` is how a multi-step PoC keeps the session the login step established:
    the same cookie jar rides through every step, so step 3 is authenticated by
    step 1 instead of by a cookie someone pasted into the spec by hand.
    """
    # Pre-flight DNS only. A flaky forwarder (WSL's 10.255.255.254) fails
    # intermittently, and that failure happens BEFORE anything leaves the
    # machine — so warming the name here costs nothing and cannot double-fire a
    # request. The request itself is still sent exactly once, no retries.
    _warm_dns(spec.get("url", ""))
    body = spec.get("body")
    req = urllib.request.Request(
        spec["url"],
        method=spec.get("method", "GET").upper(),
        headers=(spec.get("headers") or {}) if headers is None else headers,
        data=body.encode("utf-8") if isinstance(body, str) else None,
    )
    redir = _RecordingRedirect(follow=spec.get("follow_redirects", True))
    handlers = [redir]
    if spec.get("insecure_tls"):
        # Internal hosts routinely serve a self-signed cert, or one issued for a
        # name that does not resolve publicly — so the target is reached by IP +
        # Host header and the cert never matches. Refusing those makes the whole
        # class untestable. Opt-in per step, never the default: the scope gate
        # still decides what may be contacted at all.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    if jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    opener = urllib.request.build_opener(*handlers)
    started = time.time()
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_BODY_CAPTURE + 1)
            hdrs, pairs, cookies = _capture(resp.headers)
            return {
                "ok": True,
                "status": resp.status,
                "headers": hdrs,
                "headers_all": pairs,
                "set_cookie": cookies,
                "redirects": redir.hops,
                "redirects_followed": redir.follow,
                "final_url": resp.geturl(),
                "body": raw[:MAX_BODY_CAPTURE].decode("utf-8", "replace"),
                "body_truncated": len(raw) > MAX_BODY_CAPTURE,
                "elapsed_ms": round((time.time() - started) * 1000, 1),
            }
    except urllib.error.HTTPError as e:
        raw = e.read(MAX_BODY_CAPTURE + 1)
        hdrs, pairs, cookies = _capture(e.headers)
        return {
            "ok": True,
            "status": e.code,
            "headers": hdrs,
            "headers_all": pairs,
            "set_cookie": cookies,
            "redirects": redir.hops,
            "redirects_followed": redir.follow,
            "final_url": getattr(e, "url", spec["url"]),
            "body": raw[:MAX_BODY_CAPTURE].decode("utf-8", "replace"),
            "body_truncated": len(raw) > MAX_BODY_CAPTURE,
            "elapsed_ms": round((time.time() - started) * 1000, 1),
        }
    except Exception as e:  # noqa: BLE001 — network layer, want the message, not a crash
        return {"ok": False, "error": str(e), "elapsed_ms": round((time.time() - started) * 1000, 1)}


def evaluate(result: dict, expect: dict) -> tuple[str, list[str]]:
    """Deterministic pass/fail — no LLM judgment on whether the bytes matched."""
    if not result.get("ok"):
        return "ERROR", [f"request failed: {result.get('error')}"]
    if not expect:
        return "INCONCLUSIVE", ["no `expect` block in spec — evidence captured, no automatic verdict"]

    reasons: list[str] = []
    ok = True
    if "status" in expect and result["status"] != expect["status"]:
        ok = False
        reasons.append(f"status {result['status']} != expected {expect['status']}")
    body = result.get("body", "")
    for needle in expect.get("body_contains", []):
        if needle not in body:
            ok = False
            reasons.append(f"body missing expected string: {needle!r}")
    for needle in expect.get("body_not_contains", []):
        if needle in body:
            ok = False
            reasons.append(f"body contains string that should be absent: {needle!r}")
    # Repeated headers matter (Set-Cookie above all), so match across every value,
    # not just the last one dict() would have kept.
    pairs = result.get("headers_all") or [list(kv) for kv in result.get("headers", {}).items()]
    for hk, hv in expect.get("header_contains", {}).items():
        values = [v for k, v in pairs if k.lower() == hk.lower()]
        if not any(hv in v for v in values):
            ok = False
            reasons.append(f"header {hk!r} = {values or 'absent'} does not contain {hv!r}")

    cookies = result.get("set_cookie") or []
    want_cookie = expect.get("set_cookie_contains")
    if want_cookie and not any(want_cookie in c for c in cookies):
        ok = False
        reasons.append(f"no Set-Cookie contains {want_cookie!r} (got {cookies or 'none'})")

    hops = result.get("redirects") or []
    final_url = result.get("final_url", "")
    want_final = expect.get("final_url_contains")
    if want_final and want_final not in final_url:
        ok = False
        reasons.append(f"final URL {final_url!r} does not contain {want_final!r}")
    if expect.get("no_redirect") and hops:
        ok = False
        reasons.append(f"response redirected {len(hops)}x, ending at {final_url!r}")

    if not ok:
        return "FAIL", reasons

    # The article-documented failure: an exploit that 302s to /login reports the
    # login page's 200 and passes. A pass on a redirected response is only a pass
    # if the spec said where it should land.
    if hops and result.get("redirects_followed", True) and not (want_final or expect.get("no_redirect")):
        chain = " -> ".join(f"{h['status']} {h['to']}" for h in hops)
        return "INCONCLUSIVE", [
            f"response was redirected {len(hops)}x ({chain}) and the spec never said where it "
            f"should land, so this 'pass' describes {final_url!r}, not the endpoint you attacked. "
            "Add `final_url_contains`, or set `no_redirect: true` / `\"follow_redirects\": false` "
            "to assert on the raw 3xx.",
        ]
    return "PASS", reasons


# ---------------------------------------------------------------------------
# multi-step chains
#
# One request is not a proof of impact for most real bugs: the account takeover
# is login -> reset -> login-as-victim, the IDOR is authenticate -> read someone
# else's object, the race is prepare -> fire twice. Written as three separate
# single-shot specs, the "did step 2 actually work?" judgment lands back on the
# operator's memory — which is the exact failure this file exists to remove.
#
# So a spec may carry `steps`, each with its own `expect`. Every step is judged
# in code, the chain stops at the first step that fails, and the chain's verdict
# is the failing step's. Session state carries in a shared cookie jar; anything
# else (CSRF token, reset link, object id) is pulled out with `capture` and
# substituted into later steps as {{name}}.
# ---------------------------------------------------------------------------
VAR_RE = re.compile(r"\{\{([A-Za-z0-9_.-]+)\}\}")
# Specs that carry credentials reference them by variable NAME, never by value:
# `{{env:ACTOR_TOKEN}}` is read from the environment at fire time, so the spec
# file stays versionable without holding a secret.
ENV_RE = re.compile(r"\{\{env:([A-Za-z_][A-Za-z0-9_]*)\}\}")


def substitute(value, variables: dict):
    """Replace {{name}} (from `variables`) and {{env:NAME}} (from the process
    environment) in strings, recursively through dicts/lists. Unknown {{name}}
    and unset {{env:NAME}} are left verbatim so preflight can report them —
    substituting "" would send `Authorization: Bearer ` and call it a test."""
    if isinstance(value, str):
        value = ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(0)), value)
        return VAR_RE.sub(lambda m: str(variables.get(m.group(1), m.group(0))), value)
    if isinstance(value, dict):
        return {k: substitute(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, variables) for v in value]
    return value


def _placeholders(node, found=None):
    found = [] if found is None else found
    if isinstance(node, str):
        for m in ENV_RE.finditer(node):
            found.append(("env", m.group(1)))
        for m in VAR_RE.finditer(ENV_RE.sub("", node)):
            found.append(("var", m.group(1)))
    elif isinstance(node, dict):
        for v in node.values():
            _placeholders(v, found)
    elif isinstance(node, list):
        for v in node:
            _placeholders(v, found)
    return found


def preflight(spec: dict) -> list[str]:
    """Blocking readiness checks, run before the first request leaves.

    A spec that still carries placeholders has NOT been prepared by the
    operator ({{OBJECT_ID}}) or cannot authenticate ({{env:TOKEN}} unset).
    Firing it anyway would burn scope, pacing and — worst — authenticate a
    request as somebody unintended. Returns a list of reasons; empty = ready.
    """
    errors: list[str] = []
    seen_env_fail: set = set()

    def check_placeholders(node, available, where):
        for kind, name in _placeholders(node):
            if kind == "env":
                if name not in os.environ and name not in seen_env_fail:
                    seen_env_fail.add(name)
                    errors.append(f"{where}: {{{{env:{name}}}}} references an unset "
                                  f"environment variable — export it (never inline the token)")
            elif name not in available:
                errors.append(f"{where}: unresolved {{{{{name}}}}} — fill it in, or provide a "
                              f"`vars` entry / an earlier `capture` step that produces it")

    FIRE_KEYS = ("url", "headers", "body", "expect")
    if spec.get("steps"):
        available = set((spec.get("vars") or {}).keys())
        for i, step in enumerate(spec["steps"], 1):
            check_placeholders({k: step.get(k) for k in FIRE_KEYS if k in step},
                               available, step.get("name") or f"step {i}")
            available |= set((step.get("capture") or {}).keys())
    else:
        check_placeholders({k: spec.get(k) for k in FIRE_KEYS if k in spec},
                           set((spec.get("vars") or {}).keys()), "spec")
    return errors


def capture_vars(result: dict, capture: dict) -> tuple[dict, list[str]]:
    """Pull values out of a response for later steps.

    Each entry is {"from": "body"|"header"|"set_cookie"|"final_url", "regex": "(...)"}
    with optional "header" for from=header. Group 1 is the value. A capture that
    finds nothing is an error, not an empty string — a chain silently continuing
    with an empty CSRF token is how a "PoC" ends up proving nothing.
    """
    out, errors = {}, []
    for name, rule in (capture or {}).items():
        src = rule.get("from", "body")
        if src == "body":
            hay = result.get("body", "")
        elif src == "final_url":
            hay = result.get("final_url", "")
        elif src == "set_cookie":
            hay = "\n".join(result.get("set_cookie") or [])
        elif src == "header":
            want = (rule.get("header") or "").lower()
            hay = "\n".join(v for k, v in (result.get("headers_all") or []) if k.lower() == want)
        else:
            errors.append(f"capture {name!r}: unknown source {src!r}")
            continue
        pattern = rule.get("regex")
        if not pattern:
            errors.append(f"capture {name!r}: no 'regex' given")
            continue
        m = re.search(pattern, hay)
        if not m:
            errors.append(f"capture {name!r}: {pattern!r} did not match the {src}")
            continue
        out[name] = m.group(1) if m.groups() else m.group(0)
    return out, errors


def fire_sequence(spec: dict, header_fn=None, pace_fn=None, timeout: int = 15) -> tuple[list, str]:
    """Run `spec['steps']` in order against one session. Returns (step records, verdict).

    Stops at the first failing step: continuing past a failed login only produces
    evidence of being logged out.
    """
    jar = http.cookiejar.CookieJar()
    variables: dict = dict(spec.get("vars") or {})
    records: list = []
    verdict = "PASS"

    for i, raw in enumerate(spec["steps"], 1):
        step = substitute(raw, variables)
        name = step.get("name") or f"step {i}"
        step.setdefault("follow_redirects", spec.get("follow_redirects", True))
        headers = header_fn(step.get("headers")) if header_fn else step.get("headers")
        if pace_fn:
            pace_fn()
        result = fire_once(step, timeout=timeout, headers=headers, jar=jar)
        v, reasons = evaluate(result, step.get("expect") or {})

        captured, cap_errors = capture_vars(result, step.get("capture") or {})
        variables.update(captured)
        if cap_errors and v == "PASS":
            v, reasons = "FAIL", cap_errors
        elif cap_errors:
            reasons = reasons + cap_errors

        records.append({
            "step": i, "name": name, "url": step.get("url"),
            "method": step.get("method", "GET").upper(),
            "result": result, "verdict": v, "reasons": reasons,
            "captured": sorted(captured),
        })
        if v != "PASS":
            verdict = v
            break
    return records, verdict


def gate_hint(verdict: str) -> str:
    return {
        "ERROR": "Q1: cannot answer yet — request did not complete. Fix the spec/connectivity, "
                 "don't paste a remembered result.",
        "PASS": "Q1/Q6: real request + response captured and matched `expect`. Use this as the "
                "report's Step 2/Result — not a remembered curl output.",
        "FAIL": "Q1/Q6: request completed but did not match `expect`. Do not report this as "
                "confirmed — either the bug isn't there or the spec needs adjustment.",
        "INCONCLUSIVE": "Not proof for Q6 yet — either the spec has no `expect` block, or the "
                        "response moved (redirect chain) and the spec never asserted where it "
                        "landed. Captured evidence, no verdict.",
    }[verdict]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="poc_runtime.py",
        description="Fire a PoC spec once (or up to --repeat, capped), scope-gated, "
                    "and evaluate it deterministically against an `expect` block.")
    ap.add_argument("spec", help="path to the PoC spec JSON file")
    ap.add_argument("--md", help="path to a scaffolded scope.md (preferred)")
    ap.add_argument("--scope-file", help="path to an engagement scope.json")
    ap.add_argument("--in-scope", action="append", default=[], metavar="PATTERN")
    ap.add_argument("--out-of-scope", action="append", default=[], metavar="PATTERN")
    ap.add_argument("--no-scope-check", action="store_true",
                    help="DANGEROUS: skip the scope gate. Only for localhost/lab targets.")
    ap.add_argument("--repeat", type=int, default=None,
                    help=f"repeat the request N times (default: spec's own 'repeat' or 1; "
                         f"hard cap {MAX_REPEAT})")
    ap.add_argument("--out", help="where to write the result JSON (default: <spec-stem>.result.json)")
    ap.add_argument("--no-pacing", action="store_true",
                    help="DANGEROUS: skip the engagement's rate gate. Only for localhost/lab targets.")
    args = ap.parse_args(argv)

    spec_path = Path(args.spec)
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    # No placeholder survives this gate: an unresolved {{OBJECT_ID}} means the
    # operator never prepared the test; an unset {{env:TOKEN}} means it cannot
    # authenticate as intended. Both refuse BEFORE scope checks and pacing, so
    # a half-prepared skeleton cannot spend either.
    unready = preflight(spec)
    if unready:
        print(f"BLOCKED  {spec_path.name} is not ready to fire:")
        for err in unready:
            print(f"  - {err}")
        print("Nothing was sent. Fill in the values / export the env vars, then fire again.")
        return 2
    # Resolve {{env:...}} and `vars` once here, so the scope gate below sees the
    # REAL urls (placeholders never leave this process; env values never land on disk).
    spec = substitute(spec, dict(spec.get("vars") or {}))
    steps = spec.get("steps") or []
    if steps and "url" not in spec:
        spec["url"] = steps[0].get("url", "")
    url = spec["url"]
    # A chain is only as scoped as its worst step, so every URL is checked before
    # the first one fires — not lazily, step by step, halfway through a session.
    urls = [st.get("url", "") for st in steps] or [url]

    scope = _load_scope(args)

    repeat = args.repeat or spec.get("repeat") or 1
    if repeat > MAX_REPEAT:
        print(f"--repeat {repeat} exceeds hard cap of {MAX_REPEAT} (this validates, it doesn't load-test). Capping.")
        repeat = MAX_REPEAT

    # Engagement policy — pacing and mandatory headers, both enforced here rather
    # than trusted to whoever wrote the spec. Header failures are fatal before the
    # first request, not discovered halfway through a repeat run.
    # Detect from where the spec lives first, not the cwd: specs are written into
    # the engagement folder, and a spec passed by absolute path from elsewhere used
    # to silently resolve to "no engagement" — i.e. no pacing and no mandatory
    # headers, with nothing on screen saying so.
    engagement = Engagement.detect(spec_path.resolve().parent)
    if engagement.name is None:
        engagement = Engagement.detect()
    broker = RequestBroker(engagement=engagement, scope=scope, source="poc_runtime",
                           allow_ungated=args.no_scope_check)
    try:
        checks = broker.validate(urls)
        headers = broker.prepare_headers(spec.get("headers"))
    except (MissingRequiredHeader, RequestBlocked) as e:
        print(f"BLOCKED  {e}")
        print("Refusing to fire — request policy was not satisfied.")
        return 2
    for check in checks:
        print(f"scope: {check['url']} resolves to {', '.join(check['in_range_ips'])} (in-scope netblock)")
        _pin_host(check["url"], check["in_range_ips"][0])
    if engagement.name:
        injected = sorted(set(headers) - set(spec.get("headers") or {}))
        print(f"engagement: {engagement.name}  (pacing {engagement.min_interval}s"
              f"{', injected ' + ', '.join(injected) if injected else ''})")
    elif not args.no_scope_check:
        # Scope-gated means a live program is on the other end, so an undetected
        # engagement is a misconfiguration, not a lab run. Say so loudly.
        print("WARNING: no engagement detected for this spec — pacing and mandatory "
              "headers are OFF. Put the spec inside Targets/<name>/ or set $CBH_PROJECT.")

    def _pace():
        if args.no_pacing:
            return
        waited = broker.wait_turn()
        if waited:
            print(f"paced: waited {waited:.1f}s for {engagement.name}'s budget")

    def _headers_for(step_headers):
        try:
            return broker.prepare_headers(step_headers)
        except MissingRequiredHeader as e:
            print(f"BLOCKED  {e}")
            raise SystemExit(2)

    runs = []
    for i in range(repeat):
        if steps:
            records, verdict = fire_sequence(spec, header_fn=_headers_for, pace_fn=_pace)
            for r in records:
                note = f"  ({r['reasons'][0]})" if r["reasons"] else ""
                got = f"status={r['result'].get('status')}"
                cap = f"  captured: {', '.join(r['captured'])}" if r["captured"] else ""
                print(f"  step {r['step']}/{len(spec['steps'])} {r['verdict']:<12} "
                      f"{r['method']} {r['url']}  {got}{cap}{note}")
            if verdict != "PASS":
                stopped = records[-1]
                print(f"  chain stopped at step {stopped['step']} ({stopped['name']}) — "
                      "later steps were not fired, so they prove nothing either way.")
            reasons = records[-1]["reasons"] if records else ["no steps ran"]
            runs.append({"steps": records, "result": records[-1]["result"] if records else {},
                         "verdict": verdict, "reasons": reasons})
            print(f"[{i + 1}/{repeat}] {verdict}  chain of {len(spec['steps'])} steps")
        else:
            _pace()
            result = fire_once(spec, headers=headers)
            verdict, reasons = evaluate(result, spec.get("expect") or {})
            runs.append({"result": result, "verdict": verdict, "reasons": reasons})
            reason_note = f"  ({reasons[0]})" if reasons else ""
            print(f"[{i + 1}/{repeat}] {verdict}  {spec.get('method', 'GET')} {url}  "
                  f"status={result.get('status')}{reason_note}")

    final = runs[-1]
    final_verdict = final["verdict"]
    out_path = Path(args.out) if args.out else spec_path.with_name(spec_path.stem + ".result.json")
    # The artifact holds full requests AND responses, so it is the densest PII surface
    # this tool writes. Scrub identity fields on the way out: the evidence a report needs
    # is the status, the differential and the shape of the answer, never the subscriber.
    out_path.write_text(_scrub(json.dumps(_scrub_doc({
        "spec_file": str(spec_path),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "runs": runs,
        "final_verdict": final_verdict,
        "gate_hint": gate_hint(final_verdict),
    }), indent=2)), encoding="utf-8")

    _audit(spec, url, runs, final_verdict, str(out_path))
    _journal(spec, url, final_verdict, str(out_path))

    print()
    print(f"VERDICT: {final_verdict}")
    print(gate_hint(final_verdict))
    print(f"Evidence written: {out_path}")
    return {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 1, "ERROR": 2}[final_verdict]


if __name__ == "__main__":
    sys.exit(main())
