#!/usr/bin/env python3
"""
diff_matrix.py — the differential oracle plan: compare, don't guess a payload.

The hunt-* taxonomy is a map of *known* classes, and hunting only through it is
survivorship bias: the bugs that stop paying are exactly the ones that no longer
fit a class name. What still pays is not a cleverer payload — it is a
**disagreement between two states of the same call**. Role A vs role B, with
auth vs without, v2 vs v1, declared vs observed. A differential is falsifiable
by construction: both sides are the same request, so any difference is the
finding, and no difference is a real negative.

This module builds that comparison plan **offline** from an API manifest
(`api_manifest.py`, schema 2.0). It fires nothing. A plan row is a hypothesis,
and per this workspace's standing rule an unfired request is not a result — so
every row carries `not_a_finding_until` and is meant to be executed through
`poc_runtime` / `bbcurl`, never counted as coverage by mere existence.

The axes are deliberately *class-agnostic*. They are not "check IDOR" or "check
mass assignment"; they are the dimensions along which an application's belief
about a request can change. Turning a divergence into a vulnerability class is
the hunter's job afterwards.

Two outputs matter:
  * `comparisons` — baseline vs probe pairs, with the reason the axis was chosen
    for *this* operation (so the plan is auditable, not a checkbox sweep).
  * `negative_space` — for each operation, the axes that were never worth
    generating *and* the axes that `coverage.py` reports as never actually
    varied. "We did not test that" is the honest map; "we found nothing" is not.

CLI:
    python3 engine/diff_matrix.py manifest.json --out plan.json
    python3 engine/diff_matrix.py manifest.json --out plan.json --audit ../../hunt-memory/audit.jsonl
    python3 engine/diff_matrix.py manifest.json --format md
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

SCHEMA_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Axes. Each is a belief the server may be holding about a request.
# `applies` decides whether an operation is a candidate; `build` makes the probe.
# ---------------------------------------------------------------------------

IDENTITY_HEADER_CANDIDATES = [
    "X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-For",
    "X-Original-URL", "X-Rewrite-URL", "X-Real-IP",
    "X-MSISDN", "X-Subscriber-Id", "X-User-Id", "X-User-Role",
    "X-Auth-Request-User", "X-Remote-User", "X-Original-Host",
]

GARBAGE_VALUES = ["", "0", "-1", "999999999", "null", "undefined", "true",
                  "<script>", "{{7*7}}", "..%2f..%2f", "' OR 1=1--",
                  "00000000-0000-0000-0000-000000000000"]

BOUNDARY_VALUES = ["0", "-1", "0.01", "999999999999", "1e18"]

# A field name that, if the server trusts it from the client, is the bug class
# "the application believes what it was told". Deliberately broader than a
# vuln class: these are *beliefs*, and the probe is only a comparison.
CLIENT_BELIEF_FIELDS = re.compile(
    r"(?i)(msisdn|imei|imsi|icc|user_?id|client_?id|account|owner|tenant|"
    r"org(_?id)?|role|is_?admin|is_?staff|permission|scope|privilege|"
    r"iin|ssn|passport|email|phone|login|username|"
    r"price|amount|sum|total|discount|fee|balance|currency|rate|"
    r"status|state|step|stage|approved|verified|paid|refunded|cancelled|"
    r"quota|limit|balance|points|bonus|credit)")

STATE_WORDS = re.compile(
    r"(?i)(status|state|step|stage|phase|approved|verified|paid|refund|"
    r"cancel|void|revoke|disable|enable|activate|suspend|close|complete|"
    r"confirm|reject|delete|remove|reset)")

MONEY_WORDS = re.compile(
    r"(?i)(price|amount|sum|total|discount|fee|balance|currency|rate|"
    r"payment|pay|refund|transfer|topup|top-?up|bonus|credit|points|quota)")

ACTION_WORDS = re.compile(
    r"(?i)(delete|remove|revoke|reset|disable|destroy|purge|cancel|unsub)")

VERSION_SEG = re.compile(r"/v(\d+)(/|$)")


def _fields_of(op: dict) -> List[str]:
    out = list(op.get("fields") or [])
    out += list(op.get("parameters") or [])
    return sorted(set(f for f in out if f))


# Object-id placeholder; an observed id from the response corpus can replace it.
TEMPLATE_ID = "{{OBJECT_ID}}"


def _base_url(op: dict) -> str:
    return op.get("url") or f"https://{op.get('host', '')}{op.get('path', '')}"


def _replace_path_id(path: str) -> str:
    """Turn /users/123 or /users/{id} into a stable placeholder path."""
    p = re.sub(r"\{[^}]+\}", TEMPLATE_ID, path)
    p = re.sub(r"/\d+", "/" + TEMPLATE_ID, p)
    return p


def _origin(op: dict) -> str:
    u = _base_url(op)
    parts = urllib.parse.urlsplit(u)
    return f"{parts.scheme}://{parts.netloc}" if parts.netloc else f"https://{op.get('host','')}"


def _with_url(op: dict, path: str = "", query: Optional[Dict[str, str]] = None,
              headers: Optional[Dict[str, str]] = None, method: Optional[str] = None,
              body: Optional[str] = None) -> dict:
    base = urllib.parse.urlsplit(_base_url(op))
    new_path = path or _replace_path_id(base.path)
    q = dict(urllib.parse.parse_qsl(base.query, keep_blank_values=True))
    if query:
        q.update(query)
    url = urllib.parse.urlunsplit(
        (base.scheme or "https", base.netloc or op.get("host", ""), new_path,
         urllib.parse.urlencode(q), base.fragment))
    probe = {"method": (method or op.get("method", "GET")).upper(),
             "url": url, "headers": headers or {}, "body": body}
    return probe


# --- axis implementations -------------------------------------------------

def _axis_auth_strip(op: dict) -> Optional[dict]:
    if op.get("secured") is False:
        return None  # already declared public; stripping nothing is not a delta
    baseline = _with_url(op, headers={"Authorization": "Bearer {{TOKEN}}",
                                     "Cookie": "{{SESSION}}"})
    probe = _with_url(op, headers={})
    return {
        "axis": "auth-strip",
        "why": ("declared or assumed authenticated, never compared against the "
                "same call with credentials removed"),
        "baseline": baseline, "probe": probe,
        "verdict_hint": ("status or body MUST differ; an identical answer means the "
                         "check is a stub, and the finding is the absence of a check"),
    }


def _axis_principal_swap(op: dict, observed: Optional[dict] = None) -> Optional[dict]:
    if op.get("secured") is False:
        return None
    baseline = _with_url(op, headers={"Authorization": "Bearer {{TOKEN_A}}",
                                     "Cookie": "{{SESSION_A}}"})
    probe = _with_url(op, headers={"Authorization": "Bearer {{TOKEN_B}}",
                                  "Cookie": "{{SESSION_B}}"})
    return {
        "axis": "principal-swap",
        "why": ("two principals, same object; ownership is the belief under test"),
        "baseline": baseline, "probe": probe,
        "verdict_hint": ("B must NOT see or mutate A's object; a shared answer is the bug"),
    }


def _axis_identity_headers(op: dict) -> Optional[dict]:
    if not re.search(r"(?i)(user|account|member|subscriber|profile|order|invoice|"
                     r"payment|admin|tenant|org|msisdn|phone|email)", op.get("path", "")):
        return None
    baseline = _with_url(op, headers={"Authorization": "Bearer {{TOKEN}}"})
    probe = _with_url(op, headers={"Authorization": "Bearer {{TOKEN}}",
                                  **{h: "{{ATTACKER_VALUE}}" for h in IDENTITY_HEADER_CANDIDATES[:6]}})
    return {
        "axis": "identity-headers",
        "why": ("path names a principal-owned object; a proxy-injected identity "
                "header is the classic way the app stops asking who you are"),
        "baseline": baseline, "probe": probe,
        "verdict_hint": ("identity-bearing headers must not change whose data comes back"),
    }


def _axis_method_swap(op: dict) -> Optional[dict]:
    others = [m for m in ("GET", "POST", "PUT", "PATCH", "DELETE") if m != op["method"]]
    alt = "GET" if op["method"] != "GET" else "POST"
    baseline = _with_url(op)
    probe = _with_url(op, method=alt, body="{}" if alt != "GET" else None)
    return {
        "axis": "method-swap",
        "why": (f"declared {op['method']} only; routers that dispatch on path "
                f"instead of method answer {alt} on the same route"),
        "baseline": baseline, "probe": probe,
        "verdict_hint": ("an unexpected method must not perform the action, nor "
                         "leak the object; 405/404 is the healthy answer"),
        "siblings": others,
    }


def _axis_garbage_input(op: dict) -> Optional[dict]:
    fields = _fields_of(op)
    if not fields:
        return None
    victim = fields[0]
    baseline = _with_url(op, query={victim: "{{VALID_VALUE}}"} if op["method"] == "GET" else None,
                         body=None if op["method"] == "GET" else json.dumps({victim: "{{VALID_VALUE}}"}))
    probes = []
    for val in GARBAGE_VALUES[:5]:
        probes.append(_with_url(op, query={victim: val} if op["method"] == "GET" else None,
                                body=None if op["method"] == "GET" else json.dumps({victim: val})))
    return {
        "axis": "garbage-input",
        "why": (f"field `{victim}` is taken from the client; garbage is how a stub "
                "is told apart from a check"),
        "baseline": baseline, "probe": probes[0], "probes": probes,
        "verdict_hint": ("a check rejects garbage; a stub answers the same as valid "
                         "input — that sameness IS the observation"),
    }


def _axis_value_boundary(op: dict) -> Optional[dict]:
    fields = [f for f in _fields_of(op) if MONEY_WORDS.search(f) or CLIENT_BELIEF_FIELDS.search(f)]
    if not fields:
        return None
    victim = fields[0]
    probes = []
    for val in BOUNDARY_VALUES:
        probes.append(_with_url(op, query={victim: val} if op["method"] == "GET" else None,
                                body=None if op["method"] == "GET" else json.dumps({victim: val})))
    baseline = _with_url(op, query={victim: "{{VALID_VALUE}}"} if op["method"] == "GET" else None,
                         body=None if op["method"] == "GET" else json.dumps({victim: "{{VALID_VALUE}}"}))
    return {
        "axis": "value-boundary",
        "why": (f"field `{victim}` looks like a number the app may trust; boundary "
                "values are how money and quotas break without any payload"),
        "baseline": baseline, "probe": probes[0], "probes": probes,
        "verdict_hint": ("server must clamp or reject; a negative total or a free "
                         "object is a finding, and needs the state read back to prove it"),
    }


def _axis_hidden_field(op: dict) -> Optional[dict]:
    if op["method"] not in ("POST", "PUT", "PATCH"):
        return None
    fields = _fields_of(op)
    suspects = [f for f in fields if CLIENT_BELIEF_FIELDS.search(f)]
    extra = [f for f in ("role", "is_admin", "verified", "balance", "status", "owner_id",
                         "tenant_id", "user_id", "price", "discount") if f not in fields]
    if not suspects and not extra:
        return None
    inject = extra[:4] or suspects[:2]
    body = {**{f: "{{VALID_VALUE}}" for f in fields[:4]}, **{k: "{{ATTACKER_VALUE}}" for k in inject}}
    return {
        "axis": "hidden-field",
        "why": (f"state-changing call; extra fields {inject} may be accepted because "
                "the handler binds the whole object"),
        "baseline": _with_url(op, body=json.dumps({f: "{{VALID_VALUE}}" for f in fields[:4] or ["x"]})),
        "probe": _with_url(op, body=json.dumps(body)),
        "verdict_hint": ("read the object back; if an injected field persisted, the "
                         "finding is the write, not the 200"),
    }


def _axis_path_version(op: dict) -> Optional[dict]:
    path = op.get("path", "")
    m = VERSION_SEG.search(path)
    if not m:
        return None
    ver = int(m.group(1))
    if ver <= 1:
        return None
    older = VERSION_SEG.sub(lambda mm: f"/v{ver - 1}{mm.group(2)}", path, count=1)
    return {
        "axis": "path-version",
        "why": (f"declared on /v{ver}; an older /v{ver - 1} may still route and may "
                "not carry the newer checks"),
        "baseline": _with_url(op),
        "probe": _with_url(op, path=older),
        "verdict_hint": ("the older surface must not expose what the newer one "
                         "withdrew; if it answers, diff the two bodies field by field"),
    }


def _axis_content_type(op: dict) -> Optional[dict]:
    if op["method"] in ("GET", "DELETE") and not _fields_of(op):
        return None
    fields = _fields_of(op) or ["x"]
    payload = {f: "{{VALID_VALUE}}" for f in fields[:4]}
    body_json = json.dumps(payload)
    body_form = urllib.parse.urlencode(payload)
    return {
        "axis": "content-type",
        "why": ("same action, different body parser; parsers disagreeing is how "
                "a filter written for one format is bypassed through another"),
        "baseline": _with_url(op, headers={"Content-Type": "application/json"}, body=body_json),
        "probe": _with_url(op, headers={"Content-Type": "application/x-www-form-urlencoded"},
                           body=body_form),
        "verdict_hint": ("both must be validated the same way; a 200 only through "
                         "the second format is a filter gap"),
    }


def _axis_param_pollution(op: dict) -> Optional[dict]:
    fields = _fields_of(op)
    if not fields:
        return None
    victim = fields[0]
    q = {victim: ["{{VALID_VALUE}}", "{{ATTACKER_VALUE}}"]}
    # urlencode with doseq to express the duplicate
    base = urllib.parse.urlsplit(_base_url(op))
    new_path = _replace_path_id(base.path)
    query = urllib.parse.urlencode(q, doseq=True)
    url = urllib.parse.urlunsplit((base.scheme or "https", base.netloc or op.get("host", ""),
                                   new_path, query, base.fragment))
    return {
        "axis": "param-pollution",
        "why": (f"field `{victim}` is taken more than once if the parser keeps the "
                "first or the last — and the two disagree"),
        "baseline": _with_url(op, query={victim: "{{VALID_VALUE}}"}),
        "probe": {"method": op["method"], "url": url, "headers": {}, "body": None},
        "verdict_hint": ("the server must pick one deterministically and say which; "
                         "whichever value it used is the one to attack with"),
    }


AXES = [
    ("auth-strip", _axis_auth_strip, 95),
    ("principal-swap", lambda op: _axis_principal_swap(op), 94),
    ("identity-headers", _axis_identity_headers, 93),
    ("hidden-field", _axis_hidden_field, 90),
    ("path-version", _axis_path_version, 88),
    ("value-boundary", _axis_value_boundary, 86),
    ("garbage-input", _axis_garbage_input, 84),
    ("method-swap", _axis_method_swap, 80),
    ("content-type", _axis_content_type, 75),
    ("param-pollution", _axis_param_pollution, 72),
]

ALL_AXES = [a[0] for a in AXES]


# ---------------------------------------------------------------------------
# Plan assembly
# ---------------------------------------------------------------------------

def plan(manifest: dict, *, limit: int = 0, axes: Optional[Sequence[str]] = None,
         only_hosts: Optional[Sequence[str]] = None,
         audit_urls: Optional[Iterable[str]] = None) -> dict:
    """Build the comparison plan. Pure — no I/O, no requests."""
    wanted = set(axes) if axes else set(ALL_AXES)
    hosts = set(only_hosts) if only_hosts else None
    fired = set()
    if audit_urls:
        for u in audit_urls:
            parts = urllib.parse.urlsplit(u)
            # Same normalisation as op_path below: /users/124 and /users/{id}
            # must land on the same placeholder or "already fired" never matches.
            fired.add(_replace_path_id((parts.path or "/").rstrip("/") or "/"))

    comparisons: List[dict] = []
    negative_space: List[dict] = []
    ops_seen = 0
    for op in manifest.get("operations") or []:
        if hosts and op.get("host") not in hosts:
            continue
        ops_seen += 1
        op_path = _replace_path_id(op.get("path", ""))
        never: List[str] = []
        made: List[str] = []
        for name, fn, rank in AXES:
            if name not in wanted:
                continue
            try:
                row = fn(op)
            except Exception:  # a bad operation must not kill the plan
                row = None
            if row is None:
                never.append(name)
                continue
            row["operation_id"] = op.get("id") or f"{op.get('method')} {op.get('host')}{op.get('path')}"
            row["priority"] = rank
            row["host"] = op.get("host", "")
            row["path"] = op.get("path", "")
            row["risk_hints"] = list(op.get("risk_hints") or [])
            row["not_a_finding_until"] = (
                "a fired request through poc_runtime/bbcurl that shows the two "
                "sides disagree; a plan row alone is an open thread, never a result")
            if audit_urls is not None:
                row["already_fired"] = op_path in fired
            comparisons.append(row)
            made.append(name)
        negative_space.append({
            "operation_id": op.get("id") or f"{op.get('method')} {op.get('host')}{op.get('path')}",
            "host": op.get("host", ""),
            "path": op.get("path", ""),
            "method": op.get("method", ""),
            "axes_not_applicable": never,
            "axes_planned": made,
            "never_varied": never if audit_urls is None else
                            [a for a in made] if audit_urls is not None and op_path not in fired
                            else never,
        })

    # Impact first: axes that test a belief outrank format quirks, and an
    # operation whose risk hints already name authz goes above a static asset.
    def _score(row: dict) -> tuple:
        hints = set(row.get("risk_hints") or [])
        boost = 0
        for h in hints:
            if "authorization" in h or "business-flow" in h or "state-change" in h:
                boost += 10
        return (-(row["priority"] + boost), row["host"], row["path"], row["axis"])

    comparisons.sort(key=_score)
    if limit and limit > 0:
        comparisons = comparisons[:limit]

    return {
        "schema_version": SCHEMA_VERSION,
        "axes": ALL_AXES,
        "counts": {
            "operations_considered": ops_seen,
            "comparisons": len(comparisons),
            "negative_space_rows": len(negative_space),
            "by_axis": {a: sum(1 for c in comparisons if c["axis"] == a) for a in wanted},
        },
        "comparisons": comparisons,
        "negative_space": negative_space,
    }


def _audit_paths(audit_file: Path) -> List[str]:
    urls: List[str] = []
    if not audit_file or not audit_file.exists():
        return urls
    for line in audit_file.read_text(encoding="utf-8", errors="replace").splitlines()[-20000:]:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        u = row.get("url") or row.get("command", "")
        if isinstance(u, str) and u.startswith("http"):
            urls.append(u)
    return urls


def to_markdown(result: dict) -> str:
    out = ["# Differential oracle plan", "",
           f"Comparisons: **{result['counts']['comparisons']}** across "
           f"**{result['counts']['operations_considered']}** operations. "
           "Every row is a hypothesis — it is not a finding until the two sides "
           "were actually fired and disagreed.", ""]
    by_host: Dict[str, List[dict]] = {}
    for c in result["comparisons"]:
        by_host.setdefault(c.get("host") or "?", []).append(c)
    for host in sorted(by_host):
        out.append(f"## {host}")
        out.append("")
        out.append("| pri | axis | path | why |")
        out.append("|---|---|---|---|")
        for c in by_host[host]:
            fired = " ✓" if c.get("already_fired") else ""
            out.append(f"| {c['priority']}{fired} | `{c['axis']}` | `{c['path']}` | {c['why']} |")
        out.append("")
    ns = result.get("negative_space") or []
    thin = [n for n in ns if len(n.get("axes_planned") or []) <= 1]
    if thin:
        out.append("## Negative space — operations with almost nothing to compare")
        out.append("")
        out.append("These were never given a second dimension. That is a coverage gap, "
                   "not a clean bill of health.")
        out.append("")
        for n in thin[:40]:
            out.append(f"- `{n['method']} {n['host']}{n['path']}` — planned: "
                       f"{', '.join(n['axes_planned']) or 'nothing'}")
    return "\n".join(out) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("manifest", type=Path, help="api_manifest JSON (schema 2.0)")
    ap.add_argument("--out", type=Path, default=None, help="write the plan here")
    ap.add_argument("--format", choices=("json", "md"), default="json")
    ap.add_argument("--axes", default="", help="comma-separated axis names to include")
    ap.add_argument("--hosts", default="", help="comma-separated hosts to limit to")
    ap.add_argument("--limit", type=int, default=0, help="cap the comparison list")
    ap.add_argument("--audit", type=Path, default=None,
                    help="hunt-memory/audit.jsonl — mark rows already fired")
    args = ap.parse_args(argv)

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    axes = [a.strip() for a in args.axes.split(",") if a.strip()] or None
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()] or None
    audit_urls = _audit_paths(args.audit) if args.audit else None

    result = plan(manifest, limit=args.limit, axes=axes, only_hosts=hosts,
                  audit_urls=audit_urls)

    text = to_markdown(result) if args.format == "md" else \
        json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"{args.out}: {result['counts']['comparisons']} comparisons "
              f"on {result['counts']['operations_considered']} operations")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
