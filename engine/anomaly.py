#!/usr/bin/env python3
"""
anomaly.py — the second track: look for what does not add up, not for a class.

The `hunt-*` taxonomy is a map of what already paid. Working only through it is
survivorship bias — by the time a bug has a class name, the program has a
known-issues entry for it. The findings that still pay rarely announce
themselves as "IDOR" or "mass assignment"; they show up first as an
**incoherence**: the application believes a header, the older API still answers,
a status is client-writable, a delete path answers on GET.

So this module refuses the taxonomy on purpose. It takes an API manifest (and
optionally the response corpus) and emits three *class-agnostic* artefacts:

  * `anomalies`   — places where the surface contradicts itself
  * `assumptions` — beliefs the server is probably holding, each with the probe
                    that inverts it ("the id belongs to the session" → use
                    someone else's)
  * `invariants`  — things that must never be true of a correct application
                    (balance < 0, refund > payment, access after revoke),
                    which is where business-logic money bugs actually live

Nothing here is a finding. Every row says `not_a_finding_until` — a fired
request that shows the contradiction is real. That is this workspace's standing
rule, and it is written into the artefact so a plan cannot be laundered into a
report.

House-style note on the 404 differential: a random-UUID probe proves nothing
when the backend looks up before it authorizes. Probes here carry
`needs_real_id: true` where that applies.

CLI:
    python3 engine/anomaly.py manifest.json --out anomalies.json
    python3 engine/anomaly.py manifest.json --format md --engagement kcell
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Sequence

SCHEMA_VERSION = "1.0"

# A field that, when writable by the client, is the application trusting input
# it should be deriving. Kept wide on purpose: the probe is a comparison, the
# class name comes after.
BELIEF_FIELDS = re.compile(
    r"(?i)(^|_)(msisdn|imei|imsi|icc_?id|iin|ssn|passport|user_?id|client_?id|"
    r"account(_?id)?|owner(_?id)?|tenant(_?id)?|org(_?id)?|role|is_?admin|"
    r"is_?staff|permission|privilege|scope|verified|approved|"
    r"price|amount|sum|total|discount|fee|balance|currency|rate|points|bonus|"
    r"status|state|step|stage|phase|paid|refunded|cancelled|quota|limit)($|_)")

STATE_FIELD = re.compile(
    r"(?i)(status|state|step|stage|phase|approved|verified|paid|refund|"
    r"cancel|void|revoke|disable|activate|suspend|complete|confirm|reject)")

MONEY_FIELD = re.compile(
    r"(?i)(price|amount|sum|total|discount|fee|balance|currency|rate|"
    r"payment|refund|transfer|top.?up|bonus|credit|points|quota)")

ACTION_PATH = re.compile(
    r"(?i)(delete|remove|revoke|reset|disable|destroy|purge|cancel|unsub|"
    r"deactivate|terminate|kill)")

READ_PATH = re.compile(r"(?i)(get|list|read|fetch|show|view|search|find|query|export|download)")

INTERNAL_PATH = re.compile(
    r"(?i)(/admin|/internal|/worker|/backoffice|/manage|/debug|/actuator|"
    r"/metrics|/env|/console|/phpinfo|/server-status|/hidden|/staging|/test)")

VERSION_SEG = re.compile(r"/v(\d+)(/|$)")

IDENTITY_HEADER_PATH = re.compile(
    r"(?i)(user|account|member|subscriber|profile|customer|patient|order|"
    r"invoice|payment|billing|admin|tenant|org|msisdn|phone|email|card|wallet)")

URL_OVERRIDE_HEADERS = ["X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Uri",
                        "X-Forwarded-Path", "X-Original-Host"]

# Assumptions: a belief, and the request that inverts it. Generic on purpose —
# these are the beliefs every application holds until proven otherwise.
# `tags` is what the matcher looks for in the derived surface tags; `signal` is
# the human-readable reason for a reader of the report.
ASSUMPTIONS = [
    {"id": "id-belongs-to-session",
     "belief": "an object id in the path/query is always the caller's own",
     "invert": "substitute an id observed for another principal and read the object back",
     "needs_real_id": True,
     "tags": ["object-id", "identity"],
     "signal": "any path or parameter carrying a user-owned identifier"},
    {"id": "authz-before-lookup",
     "belief": "authorization is checked before the object is fetched",
     "invert": ("compare a real foreign id against a random UUID: 404 for both proves "
                "nothing; 200/403-vs-404 disagreement on a REAL id is the oracle"),
     "needs_real_id": True,
     "tags": ["object-id", "secured"],
     "signal": "403/404 differential on object endpoints"},
    {"id": "status-moves-forward",
     "belief": "workflow state only advances along the intended order",
     "invert": "replay the terminal transition, or skip to it directly; read state back",
     "needs_real_id": True,
     "tags": ["state", "writable"],
     "signal": "state-changing verbs plus status/state/step fields"},
    {"id": "amount-is-server-side",
     "belief": "money and quota values are computed, not accepted",
     "invert": "send 0, negative, fractional and boundary values; verify the ledger",
     "needs_real_id": True,
     "tags": ["money", "writable"],
     "signal": "price/amount/discount/balance fields on writable calls"},
    {"id": "this-host-is-internal",
     "belief": "admin/worker/internal paths are unreachable or authenticated",
     "invert": "reach them unauthenticated and through Host/X-Original-URL override",
     "needs_real_id": False,
     "tags": ["internal"],
     "signal": "internal-looking path segments"},
    {"id": "only-the-declared-method-routes",
     "belief": "the router dispatches on method, not on path",
     "invert": "send GET where POST is declared and the reverse; watch for the action firing",
     "needs_real_id": False,
     "tags": ["writable", "action"],
     "signal": "state-changing routes"},
    {"id": "identity-is-not-in-headers",
     "belief": "the caller's identity comes from the session, not from a header",
     "invert": "add X-MSISDN / X-Forwarded-User / X-Original-URL style headers and see whose data returns",
     "needs_real_id": False,
     "tags": ["identity", "object-id"],
     "signal": "paths naming a principal-owned object"},
    {"id": "the-old-version-is-gone",
     "belief": "withdrawing a field on /v2 also withdrew it on /v1",
     "invert": "call the same operation on the older version and diff the bodies field by field",
     "needs_real_id": False,
     "tags": ["versioned"],
     "signal": "versioned paths"},
    {"id": "one-parser-one-validation",
     "belief": "every body format goes through the same validation",
     "invert": "resend the same action as form-encoded and as XML; compare acceptance",
     "needs_real_id": False,
     "tags": ["writable"],
     "signal": "POST/PUT/PATCH with a body"},
    {"id": "delete-is-idempotent-and-final",
     "belief": "a deleted object is gone and stays gone",
     "invert": "read it back, then retry the create with the same key; watch for resurrection",
     "needs_real_id": True,
     "tags": ["delete", "action"],
     "signal": "DELETE routes and /delete|/remove/ paths"},
]

# Invariants: properties a correct application never violates. The probe is
# always "make this false, then read the state back".
INVARIANTS = [
    {"id": "balance-never-negative",
     "statement": "an account balance is never driven below zero",
     "probe": "concurrent or boundary-value debit; read balance afterwards"},
    {"id": "no-double-spend",
     "statement": "one-time value (voucher, bonus, top-up, refund) is applied exactly once",
     "probe": "replay the apply with the same idempotency key; verify ledger state"},
    {"id": "refund-le-payment",
     "statement": "total refunded never exceeds total paid",
     "probe": "partial then full refund, or two partials past the total; verify"},
    {"id": "no-access-after-revoke",
     "statement": "revoking a session, role or share takes effect on the next request",
     "probe": "reuse the old token/scope after revoke; the read must fail"},
    {"id": "total-equals-lines",
     "statement": "an order total equals the sum of its line items",
     "probe": "mutate a line price or quantity after the total is set; re-read the total"},
    {"id": "discount-le-subtotal",
     "statement": "a discount never exceeds the amount it discounts",
     "probe": "stack, negative or oversized discount values; verify the charged amount"},
    {"id": "terminal-state-is-terminal",
     "statement": "cancelled/refunded/settled objects do not transition again",
     "probe": "repeat the transition on a terminal object; read state back"},
    {"id": "ownership-survives-mutation",
     "statement": "changing an object's owner/tenant is never a client-side write",
     "probe": "write owner_id/tenant_id on an update; read the object back as the old owner"},
]


def _fields(op: dict) -> List[str]:
    return sorted(set(list(op.get("fields") or []) + list(op.get("parameters") or [])))


def _path(op: dict) -> str:
    return op.get("path") or ""


def _method(op: dict) -> str:
    return (op.get("method") or "GET").upper()


def _opid(op: dict) -> str:
    return op.get("id") or f"{_method(op)} {op.get('host','')}{_path(op)}"


def _object_id_path(path: str) -> bool:
    """A trailing id segment or an {id} template — the shape an object call has."""
    return bool(re.search(r"/\{[^}/]+\}$|/\d+$", path.rstrip("/") or "/"))


def _surface_tags(ops: Sequence[dict]) -> set:
    """What this surface actually is, as words an assumption can match on.

    Path text is a bad signal: `/v2/users/124` never contains the words
    "object endpoint", yet that is exactly what it is. So the shape is derived
    once and matched as tags.
    """
    tags: set = set()
    for o in ops:
        p = _path(o)
        fields = _fields(o)
        joined = " ".join([p] + fields).lower()
        method = _method(o)
        if _object_id_path(p) or any(f.lower().endswith("id") and f.lower() not in ("valid", "paid")
                                     for f in fields):
            tags.add("object-id")
        if VERSION_SEG.search(p):
            tags.add("versioned")
        if INTERNAL_PATH.search(p):
            tags.add("internal")
        if ACTION_PATH.search(p) or method == "DELETE":
            tags.add("action")
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            tags.add("writable")
        if method == "GET":
            tags.add("read")
        if o.get("secured"):
            tags.add("secured")
        if IDENTITY_HEADER_PATH.search(p):
            tags.add("identity")
        if MONEY_FIELD.search(joined):
            tags.add("money")
        if STATE_FIELD.search(joined):
            tags.add("state")
        for h in (o.get("risk_hints") or []):
            tags.add(str(h).lower().replace(" ", "-"))
    return tags


def _probe(op: dict, note: str, *, headers: Optional[dict] = None,
           query: Optional[dict] = None, body: Optional[str] = None,
           method: Optional[str] = None) -> dict:
    parts = urllib.parse.urlsplit(op.get("url") or f"https://{op.get('host','')}{_path(op)}")
    q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    if query:
        q.update(query)
    url = urllib.parse.urlunsplit((parts.scheme or "https", parts.netloc or op.get("host", ""),
                                   parts.path, urllib.parse.urlencode(q), parts.fragment))
    return {"method": (method or _method(op)).upper(), "url": url,
            "headers": headers or {}, "body": body, "note": note}


# --- anomaly detectors ----------------------------------------------------

def _anom_identity_fields(op: dict) -> List[dict]:
    if _method(op) not in ("POST", "PUT", "PATCH"):
        return []
    hits = [f for f in _fields(op) if BELIEF_FIELDS.search(f)]
    if not hits:
        return []
    return [{
        "kind": "client-supplied-identity",
        "operation_id": _opid(op), "host": op.get("host", ""), "path": _path(op),
        "fields": hits[:8],
        "signal": (f"state-changing call accepts {hits[:4]} — values the server should "
                   "derive from the session, not from the body"),
        "probe": _probe(op, f"write {hits[0]} as another principal's value; read the object back",
                        body=json.dumps({hits[0]: "{{OTHER_PRINCIPAL_VALUE}}"})),
        "needs_real_id": True,
    }]


def _anom_state_writable(op: dict) -> List[dict]:
    if _method(op) not in ("POST", "PUT", "PATCH"):
        return []
    hits = [f for f in _fields(op) if STATE_FIELD.search(f)]
    if not hits:
        return []
    return [{
        "kind": "client-driven-state-machine",
        "operation_id": _opid(op), "host": op.get("host", ""), "path": _path(op),
        "fields": hits[:8],
        "signal": (f"workflow fields {hits[:4]} are writable by the client — the state "
                   "machine may be driven from outside"),
        "probe": _probe(op, "write the terminal state directly and read state back",
                        body=json.dumps({hits[0]: "{{TERMINAL_STATE}}"})),
        "needs_real_id": True,
    }]


def _anom_money_writable(op: dict) -> List[dict]:
    if _method(op) not in ("POST", "PUT", "PATCH"):
        return []
    hits = [f for f in _fields(op) if MONEY_FIELD.search(f)]
    if not hits:
        return []
    return [{
        "kind": "client-supplied-value",
        "operation_id": _opid(op), "host": op.get("host", ""), "path": _path(op),
        "fields": hits[:8],
        "signal": (f"money/quota fields {hits[:4]} are accepted from the client"),
        "probe": _probe(op, "send 0 / -1 / boundary values; verify the ledger afterwards",
                        body=json.dumps({hits[0]: "0"})),
        "needs_real_id": True,
    }]


def _anom_method_path_mismatch(op: dict) -> List[dict]:
    path, method = _path(op), _method(op)
    out = []
    if method == "GET" and ACTION_PATH.search(path):
        out.append({
            "kind": "safe-method-on-action-path",
            "operation_id": _opid(op), "host": op.get("host", ""), "path": path,
            "fields": [],
            "signal": f"{method} on a path that names an action ({path}) — CSRF-shaped, or the action really fires",
            "probe": _probe(op, "issue it with no session and with a cross-site shape; read state back"),
            "needs_real_id": True,
        })
    if method in ("POST", "PUT", "DELETE") and READ_PATH.search(path) and not ACTION_PATH.search(path):
        out.append({
            "kind": "write-on-read-path",
            "operation_id": _opid(op), "host": op.get("host", ""), "path": path,
            "fields": [],
            "signal": f"{method} on a path that names a read ({path}) — the router may not be checking method at all",
            "probe": _probe(op, "send the write; read the object back to see whether anything moved"),
            "needs_real_id": True,
        })
    return out


def _anom_internal_surface(op: dict) -> List[dict]:
    path = _path(op)
    if not INTERNAL_PATH.search(path):
        return []
    return [{
        "kind": "internal-looking-surface",
        "operation_id": _opid(op), "host": op.get("host", ""), "path": path,
        "fields": [],
        "signal": f"internal/admin-shaped path published on the same origin: {path}",
        "probe": _probe(op, "reach it unauthenticated; then again with X-Original-URL / Host override",
                        headers={h: "{{OVERRIDE}}" for h in URL_OVERRIDE_HEADERS}),
        "needs_real_id": False,
    }]


def _norm_version_path(path: str) -> str:
    """Collapse `/v2/users/124` and `/v1/users/456` onto one shape."""
    p = VERSION_SEG.sub("/v{V}", path, count=1)
    p = re.sub(r"/\d+", "/{id}", p)
    p = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
               "{id}", p, flags=re.I)
    return p


def _anom_version_skew(ops: List[dict]) -> List[dict]:
    """Same path shape on two versions, with different field sets."""
    out = []
    by_key: Dict[str, List[tuple]] = {}
    for op in ops:
        p = _path(op)
        m = VERSION_SEG.search(p)
        if not m:
            continue
        ver = int(m.group(1))
        by_key.setdefault(_norm_version_path(p), []).append((ver, op))
    for norm, items in by_key.items():
        versions = sorted({v for v, _ in items})
        if len(versions) < 2:
            continue
        older = min(versions)
        newer = max(versions)
        old_ops = [op for v, op in items if v == older]
        new_ops = [op for v, op in items if v == newer]
        old_fields = set(_fields(old_ops[0]))
        new_fields = set(_fields(new_ops[0]))
        only_new = sorted(new_fields - old_fields)
        only_old = sorted(old_fields - new_fields)
        if not (only_new or only_old):
            continue
        out.append({
            "kind": "version-skew",
            "operation_id": _opid(old_ops[0]),
            "host": old_ops[0].get("host", ""),
            "path": _path(old_ops[0]),
            "fields": sorted(only_new or only_old),
            "signal": (f"/v{older} and /v{newer} of the same operation disagree: "
                       f"only on newer {only_new[:6] or '-'}; only on older {only_old[:6] or '-'}"),
            "probe": _probe(old_ops[0],
                            f"call /v{older} with the fields that exist only on /v{newer}; diff the bodies",
                            body=json.dumps({f: "{{VALUE}}" for f in (only_new or only_old)[:4]})),
            "needs_real_id": False,
        })
    return out


def _anom_identity_headers(op: dict) -> List[dict]:
    if not IDENTITY_HEADER_PATH.search(_path(op)):
        return []
    return [{
        "kind": "identity-header-oracle",
        "operation_id": _opid(op), "host": op.get("host", ""), "path": _path(op),
        "fields": [],
        "signal": ("path names a principal-owned object; a proxy-injected identity "
                   "header is the usual way the app stops asking who you are"),
        "probe": _probe(op, "same call, with X-MSISDN / X-Forwarded-User / X-Original-URL set",
                        headers={h: "{{ATTACKER_VALUE}}" for h in
                                 ("X-MSISDN", "X-Forwarded-User", "X-Original-URL",
                                  "X-Subscriber-Id", "X-User-Id")}),
        "needs_real_id": True,
    }]


def _anom_const_fields(op: dict, observed: dict) -> List[dict]:
    """Response corpus said the answer never moved — a stub, not a check."""
    key = _opid(op)
    const = observed.get("constant_fields") or {}
    fields = const.get(key) or const.get(_path(op)) or []
    if not fields:
        return []
    return [{
        "kind": "answer-never-moved",
        "operation_id": key, "host": op.get("host", ""), "path": _path(op),
        "fields": list(fields)[:8],
        "signal": (f"fields {fields[:4]} were constant across many different requests — "
                   "that is a stub; the finding is the absence of a check"),
        "probe": _probe(op, "give it a second, different input and read the same fields"),
        "needs_real_id": False,
    }]


DETECTORS = [
    _anom_identity_fields,
    _anom_state_writable,
    _anom_money_writable,
    _anom_method_path_mismatch,
    _anom_internal_surface,
    _anom_identity_headers,
]


def analyze(manifest: dict, observed: Optional[dict] = None,
            only_hosts: Optional[Sequence[str]] = None) -> dict:
    """Pure analysis over a manifest. No I/O, no requests."""
    ops = [o for o in (manifest.get("operations") or [])
           if not only_hosts or o.get("host") in set(only_hosts)]
    observed = observed or {}

    anomalies: List[dict] = []
    for op in ops:
        for det in DETECTORS:
            try:
                anomalies.extend(det(op))
            except Exception:
                continue
        if observed:
            try:
                anomalies.extend(_anom_const_fields(op, observed))
            except Exception:
                continue
    try:
        anomalies.extend(_anom_version_skew(ops))
    except Exception:
        pass

    for a in anomalies:
        a["not_a_finding_until"] = (
            "a fired request through poc_runtime/bbcurl that shows the contradiction "
            "is real on the wire; an anomaly row is an open thread, never a result")

    # Assumptions: attach only those whose trigger this surface actually shows.
    # Matching on tags, not on path prose — `/v2/users/124` is an object endpoint
    # whether or not the word "object" appears anywhere in it.
    signals = " ".join(
        (_path(o) + " " + _method(o) + " " + " ".join(_fields(o))) for o in ops).lower()
    tags = _surface_tags(ops)
    assumptions = []
    for a in ASSUMPTIONS:
        wanted = list(a.get("tags") or [])
        if wanted:
            score = sum(1 for t in wanted if t in tags)
            if score == 0:
                continue
        else:
            words = [w for w in re.split(r"[^a-z0-9]+", a["signal"].lower()) if len(w) > 3]
            score = sum(1 for w in words if w in signals)
            if score == 0:
                continue
        row = dict(a)
        row["matched_tags"] = sorted(t for t in wanted if t in tags) if wanted else []
        row["match_score"] = score
        row["not_a_finding_until"] = (
            "the inverted probe was fired and the belief held or broke on the wire")
        assumptions.append(row)
    assumptions.sort(key=lambda r: (-r["match_score"], r["id"]))

    # Invariants: relevant when money/state language is present at all.
    invariants = []
    for inv in INVARIANTS:
        words = [w for w in re.split(r"[^a-z0-9]+", inv["id"] + " " + inv["statement"])
                 if len(w) > 3]
        score = sum(1 for w in words if w.lower() in signals)
        if score == 0 and not MONEY_FIELD.search(signals) and not STATE_FIELD.search(signals):
            continue
        row = dict(inv)
        row["match_score"] = max(score, 1)
        row["not_a_finding_until"] = (
            "the state was read back after the probe and the invariant was actually violated")
        invariants.append(row)
    invariants.sort(key=lambda r: -r["match_score"])

    anomalies.sort(key=lambda a: (a.get("host", ""), a.get("path", ""), a["kind"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "counts": {
            "operations": len(ops),
            "anomalies": len(anomalies),
            "assumptions": len(assumptions),
            "invariants": len(invariants),
            "by_kind": {k: sum(1 for a in anomalies if a["kind"] == k)
                        for k in sorted({a["kind"] for a in anomalies})},
        },
        "anomalies": anomalies,
        "assumptions": assumptions,
        "invariants": invariants,
        "reminder": (
            "this is the class-agnostic track: do not name a vulnerability class "
            "until after the probe has fired. Convert a divergence into a class "
            "with the matching hunt-* skill, then /remember it — and if it still "
            "fits no class, that is a signal the taxonomy is stale, so log it as "
            "technique `unclassified` and let the learn loop grow the map."),
    }


def _observed_from_corpus(engagement: str) -> dict:
    """Pull constant-field alerts out of the stored response corpus, if any."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import responses as R  # type: ignore
    except Exception:
        return {}
    try:
        alert = R.constant_field_alert(engagement=engagement) or {}
    except Exception:
        return {}
    const: Dict[str, List[str]] = {}
    for row in (alert.get("fields") or alert.get("alerts") or []):
        if not isinstance(row, dict):
            continue
        key = row.get("path") or row.get("url") or row.get("key") or ""
        fields = row.get("fields") or row.get("field") or []
        if isinstance(fields, str):
            fields = [fields]
        if key:
            const.setdefault(str(key), [])
            for f in fields:
                if f not in const[str(key)]:
                    const[str(key)].append(f)
    return {"constant_fields": const}


def to_markdown(result: dict) -> str:
    out = ["# Anomaly track — what does not add up", "",
           result["reminder"], "",
           f"Operations scanned: **{result['counts']['operations']}** · "
           f"anomalies **{result['counts']['anomalies']}** · "
           f"assumptions **{result['counts']['assumptions']}** · "
           f"invariants **{result['counts']['invariants']}**", ""]
    if result["anomalies"]:
        out.append("## Anomalies")
        out.append("")
        for a in result["anomalies"]:
            out.append(f"### `{a['kind']}` — {a['operation_id']}")
            out.append("")
            out.append(f"- **signal:** {a['signal']}")
            if a.get("fields"):
                out.append(f"- **fields:** {', '.join(f'`{f}`' for f in a['fields'])}")
            p = a.get("probe") or {}
            out.append(f"- **probe:** `{p.get('method','')} {p.get('url','')}` — {p.get('note','')}")
            if a.get("needs_real_id"):
                out.append("- **needs a real id** — a random UUID proves nothing here")
            out.append(f"- **not a finding until:** {a['not_a_finding_until']}")
            out.append("")
    if result["assumptions"]:
        out.append("## Assumptions to invert")
        out.append("")
        out.append("| belief | invert it by | seen on this surface |")
        out.append("|---|---|---|")
        for a in result["assumptions"]:
            out.append(f"| {a['belief']} | {a['invert']} | {a['match_score']} |")
        out.append("")
    if result["invariants"]:
        out.append("## Invariants that must never break")
        out.append("")
        for inv in result["invariants"]:
            out.append(f"- **{inv['statement']}** — {inv['probe']}")
        out.append("")
    return "\n".join(out) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("manifest", type=Path)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--format", choices=("json", "md"), default="json")
    ap.add_argument("--hosts", default="", help="comma-separated hosts to limit to")
    ap.add_argument("--engagement", default="",
                    help="also read this engagement's response corpus for constant fields")
    args = ap.parse_args(argv)

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()] or None
    observed = _observed_from_corpus(args.engagement) if args.engagement else {}
    result = analyze(manifest, observed=observed, only_hosts=hosts)

    text = to_markdown(result) if args.format == "md" else \
        json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"{args.out}: {result['counts']['anomalies']} anomalies, "
              f"{result['counts']['assumptions']} assumptions, "
              f"{result['counts']['invariants']} invariants")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
