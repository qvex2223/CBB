#!/usr/bin/env python3
"""
vectors.py — the anti-dead-end engine.

The workspace already enforces its brakes in code (scope.py, pacing.py) while the
"keep going, rotate the vector, do not close a host on a hunch" half lives only as
prose in CLAUDE.md. Prose loses to prose: an agent that is told ten times to be
careful and once to be aggressive resolves every ambiguous moment into "analyze
more". So the push half gets code too.

Three things live here:

  * a per-target **vector ledger** — every attack vector on a target with a status,
    the number of requests actually fired at it, and the mutations already burned.
    `next` always has an answer, so "I am stuck" stops being a terminal state.
  * a **mutation matrix** — given a vector class and what was already tried, the
    next concrete thing to send. This is what "смени вектор" means operationally.
  * a **stuck detector** — reads hunt-memory/audit.jsonl and notices when many
    requests went out with nothing logged, i.e. grinding instead of rotating.

A vector cannot be marked `dead` without fired requests backing it (audit.jsonl is
the witness). That is the rule the workspace's own data says was never followed:
threads closed as "good hygiene" with zero requests behind them.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from memory import resolve_dir  # type: ignore
except Exception:  # noqa: BLE001 - keep usable standalone
    def resolve_dir(explicit=None) -> Path:  # type: ignore
        env = os.environ.get("CBH_MEMORY_DIR")
        if env:
            return Path(env)
        return Path(__file__).resolve().parent.parent.parent / "hunt-memory"


STATUSES = ("untried", "active", "dead", "confirmed", "blocked")

# ---------------------------------------------------------------------------
# vector catalog — what is always worth trying, ranked by what it pays if true.
# impact is the ranking key for `next`; it is deliberately impact-first, not
# ease-first (the same rule CLAUDE.md states in prose).
# ---------------------------------------------------------------------------
CATALOG: Dict[str, Dict] = {
    "missing_authorization": {"impact": 95, "skill": "hunt-auth-bypass",
                              "hint": "strip Authorization/Cookie entirely on every state-changing route"},
    "idor":                  {"impact": 90, "skill": "hunt-idor",
                              "hint": "swap the object id across two identities, then repeat on PUT/DELETE"},
    "business-logic":        {"impact": 88, "skill": "hunt-business-logic",
                              "hint": "negative/zero/overflow amounts, replay, step-skip, state-machine reorder"},
    "rce":                   {"impact": 98, "skill": "hunt-rce", "hint": "benign markers only (id, sleep)"},
    "ssrf":                  {"impact": 85, "skill": "hunt-ssrf",
                              "hint": "internal ranges, redirect-follow, DNS-only variant before giving up"},
    "sqli":                  {"impact": 85, "skill": "hunt-sqli", "hint": "boolean diff first, then timing"},
    "auth-bypass":           {"impact": 84, "skill": "hunt-auth-bypass",
                              "hint": "forced browse, role swap, expired/none-alg token, sibling controller"},
    "race-condition":        {"impact": 78, "skill": "hunt-race-condition",
                              "hint": "single-packet attack on coupon/credit/limit endpoints"},
    "graphql":               {"impact": 75, "skill": "hunt-graphql",
                              "hint": "introspection, then node(id) IDOR, then unauth mutations"},
    "file-upload":           {"impact": 74, "skill": "hunt-file-upload", "hint": "svg, html, double extension"},
    "deserialization":       {"impact": 74, "skill": "hunt-deserialization", "hint": "magic bytes in any b64 blob"},
    "ssti":                  {"impact": 72, "skill": "hunt-ssti", "hint": "{{7*7}} / ${7*7} in every reflected field"},
    "xxe":                   {"impact": 70, "skill": "hunt-xxe", "hint": "any endpoint that accepts XML or SVG/DOCX"},
    "api-misconfig":         {"impact": 68, "skill": "hunt-api-misconfig",
                              "hint": "old API versions, debug routes, swagger/openapi, actuator"},
    "xss":                   {"impact": 60, "skill": "hunt-xss", "hint": "marker first, payload second"},
    "cors":                  {"impact": 55, "skill": "hunt-cors", "hint": "null origin + credentials"},
    "host-header":           {"impact": 55, "skill": "hunt-host-header", "hint": "password-reset poisoning"},
    "csrf":                  {"impact": 50, "skill": "hunt-csrf", "hint": "state-changing POST without token/SameSite"},
    "open-redirect":         {"impact": 40, "skill": "hunt-open-redirect", "hint": "only matters chained into OAuth"},
    "info-leak":             {"impact": 40, "skill": "hunt-source-leak", "hint": "sourcemaps, .git, backups, env"},
}

# ---------------------------------------------------------------------------
# mutation matrix — ordered. index N is "what to try after N-1 failed".
# generic moves apply to every class and run out last.
# ---------------------------------------------------------------------------
GENERIC_MUTATIONS: List[str] = [
    "method swap: GET->POST->PUT->PATCH->DELETE on the same path (frameworks often authz only one verb)",
    "API version swap: /v2/ -> /v1/ -> /v3/ -> /internal/ -> /beta/ (the fix rarely lands on the old route)",
    "auth removal: send with no Cookie, no Authorization, no CSRF token — separately, not all at once",
    "auth downgrade: expired token, other-account token, empty token, alg=none, token from a sibling tenant",
    "content-type swap: application/json -> x-www-form-urlencoded -> multipart -> text/plain (parser differs)",
    "parameter pollution: repeat the param, array form param[]=, JSON body vs query vs header placement",
    "path normalization: //path, /./path, /path/, %2e%2e%2f, ;/ , unicode dot, trailing %00",
    "header override: X-Original-URL, X-Rewrite-URL, X-Forwarded-For, X-Forwarded-Host, X-Real-IP",
    "case + encoding: uppercase path segment, double-URL-encode the payload, unicode homoglyph",
    "sibling enumeration: every other route in the same controller/prefix, not just this one",
    "mobile / partner surface: same API under /mobile, /app, /partner, different Host or User-Agent",
    "response-shape probing: identical request, wrong id type (string vs int vs uuid) — error text leaks logic",
]

CLASS_MUTATIONS: Dict[str, List[str]] = {
    "idor": [
        "increment/decrement the id; then a UUID from another object you legitimately own",
        "same id on PUT/DELETE after GET was refused",
        "id moved from path to body to query to header (X-User-Id)",
        "batch/bulk endpoint that takes an id array — authz is often per-request, not per-item",
        "GraphQL node(id:) / REST expand=, include=, fields= parameters reaching the same object",
    ],
    "missing_authorization": [
        "drop every credential header on the state-changing route itself",
        "call the internal/worker/external API prefix directly (…/external/, …/internal/, …/worker/)",
        "OPTIONS then the real verb — CORS preflight sometimes reveals allowed unauth verbs",
        "sibling methods of the same worker/controller — guess by naming convention, then confirm by 404-vs-405",
    ],
    "business-logic": [
        "negative, zero, and fractional amounts",
        "replay the same signed request twice (idempotency key reuse)",
        "skip a step: call step 3 with only step 1 completed",
        "swap the currency/plan/tariff id for a cheaper one mid-flow",
        "race the state transition (two requests, one packet)",
    ],
    "ssrf": [
        "127.0.0.1 / localhost / 0.0.0.0 / [::1] / 169.254.169.254",
        "decimal, octal, and hex IP encodings of the same host",
        "attacker host that 302-redirects to the internal target",
        "DNS-only callback to prove blind SSRF before hunting a reachable service",
        "protocol swap: file://, gopher://, dict://, http over a non-80 port",
    ],
    "sqli": [
        "boolean pair: ' AND '1'='1  vs  ' AND '1'='2 — diff the bodies, not the status",
        "the same payload in ORDER BY / LIMIT / column-name position (not just WHERE)",
        "JSON body field instead of query param",
        "second-order: inject on write, observe on the read endpoint",
    ],
    "auth-bypass": [
        "forced browse to the post-auth route directly",
        "role field in JWT/body/header flipped to admin",
        "the sibling endpoints in the same controller — the fix is usually per-route",
        "old API version of the same route",
    ],
    "graphql": [
        "introspection; if disabled, field suggestion via typo'd field names",
        "aliases to bypass per-field rate limits",
        "mutations without auth",
        "node(id:) / relay global ids as an IDOR primitive",
    ],
    "xss": [
        "unencoded marker check first (z1z<svg) before any payload",
        "attribute context, JS-string context, and href/src context separately",
        "the value on the *response* of a different endpoint that renders the same field",
    ],
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _vec_dir(memdir: Optional[Path] = None) -> Path:
    d = (memdir or resolve_dir()) / "vectors"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path(target: str, memdir: Optional[Path] = None) -> Path:
    safe = target.replace("/", "_").replace(":", "_")
    return _vec_dir(memdir) / f"{safe}.json"


def load(target: str, memdir: Optional[Path] = None) -> Dict:
    p = _path(target, memdir)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except json.JSONDecodeError:
            pass
    return {"target": target, "created": _now(), "vectors": []}


def save(ledger: Dict, memdir: Optional[Path] = None) -> Path:
    p = _path(ledger["target"], memdir)
    ledger["updated"] = _now()
    p.write_text(json.dumps(ledger, indent=2, ensure_ascii=False))
    return p


def vector_id(vclass: str, endpoint: str) -> str:
    return f"{vclass}:{endpoint}"


def _new_vector(vclass: str, endpoint: str, *, origin: str, reason: str = "",
                priority: Optional[int] = None, operation_id: str = "") -> Dict:
    return {
        "id": vector_id(vclass, endpoint), "class": vclass, "endpoint": endpoint,
        "status": "untried", "requests_fired": 0, "mutations_tried": [], "notes": "",
        "origin": origin, "reason": reason, "operation_id": operation_id,
        "priority": priority if priority is not None else CATALOG.get(vclass, {}).get("impact", 30),
        "created": _now(), "updated": _now(),
    }


def seed(target: str, endpoints: List[str], classes: Optional[List[str]] = None,
         memdir: Optional[Path] = None) -> Dict:
    """Fill the ledger with every (class, endpoint) pair worth trying.

    This is the blunt Cartesian seeder: it knows nothing about the endpoint, so it
    proposes every class for every path. Rows it creates are tagged
    `origin="cartesian"` so `prune` can drop the untouched ones once a real API
    manifest exists. Prefer `seed_from_manifest()` whenever a manifest is available.
    """
    ledger = load(target, memdir)
    known = {v["id"] for v in ledger["vectors"]}
    classes = classes or list(CATALOG)
    for ep in endpoints:
        for c in classes:
            vid = vector_id(c, ep)
            if vid in known:
                continue
            known.add(vid)
            ledger["vectors"].append(_new_vector(c, ep, origin="cartesian"))
    return ledger


# ---------------------------------------------------------------------------
# manifest-driven seeding — the replacement for the Cartesian product.
#
# `(every endpoint x every class)` produces a ledger nobody can finish and whose
# ranking is pure catalog impact, so `next` recommends RCE on a static asset. The
# normalized API manifest already carries risk hints derived from the operation's
# own shape (path variables, write methods, sensitive schema fields, declared
# security), and the workflow graph already carries ranked business hypotheses.
# Seeding from those yields vectors that have a *reason*, and the reason is what
# `next` should be ranking on.
# ---------------------------------------------------------------------------
HINT_CLASSES: Dict[str, List[str]] = {
    "object-authorization":   ["idor"],
    "function-authorization": ["auth-bypass", "missing_authorization"],
    "property-authorization": ["api-misconfig"],
    "business-flow":          ["business-logic"],
    "state-change":           ["csrf"],
    "declared-public":        ["missing_authorization"],
    "oauth":                  ["auth-bypass", "open-redirect"],
    "graphql":                ["graphql"],
}

# workflow hypothesis kind -> the vector class that owns it
HYPOTHESIS_CLASSES: Dict[str, str] = {
    "replay":          "business-logic",
    "step-skip":       "business-logic",
    "value-boundary":  "business-logic",
    "cross-principal": "idor",
    "hidden-field":    "api-misconfig",
    "race":            "race-condition",
}


def endpoint_of(op: Dict) -> str:
    """Ledger endpoint key for an operation: method + canonical path."""
    return f"{op.get('method', 'GET')} {op.get('path', '/')}".strip()


def classes_for_operation(op: Dict) -> List[Dict]:
    """Which vector classes this one operation actually justifies, and why."""
    hints = list(op.get("risk_hints") or [])
    out: Dict[str, str] = {}
    for hint in hints:
        for vclass in HINT_CLASSES.get(hint, []):
            out.setdefault(vclass, hint)
    # An unauthenticated-looking write is the classic missing-authorization case
    # even when no other hint fired.
    if op.get("method") in ("POST", "PUT", "PATCH", "DELETE") and op.get("secured") is not True:
        out.setdefault("missing_authorization", "unsecured-write")
    # Reflected/echoed input surfaces: any operation that takes parameters can carry
    # an injection, but only those two classes — not the whole catalog.
    if op.get("parameters") or op.get("fields"):
        out.setdefault("sqli", "accepts-input")
        out.setdefault("xss", "accepts-input")
    if not out:
        out["info-leak"] = "no-risk-hint"
    return [{"class": c, "reason": r} for c, r in out.items()]


def seed_from_manifest(target: str, manifest: Dict, workflow: Optional[Dict] = None,
                       memdir: Optional[Path] = None, hosts: Optional[List[str]] = None) -> Dict:
    """Derive vectors from operation risk hints + workflow hypotheses.

    Only relevant classes are created, each carrying the hint that justified it and
    a priority that blends catalog impact with the operation's own risk. Existing
    vectors are never duplicated or downgraded.
    """
    ledger = load(target, memdir)
    by_id = {v["id"]: v for v in ledger["vectors"]}
    hosts = {h.lower() for h in (hosts or [])}
    ops = manifest.get("operations") or []
    added = 0
    for op in ops:
        if hosts and (op.get("host") or "").lower() not in hosts:
            continue
        ep = endpoint_of(op)
        risk_bonus = min(len(op.get("risk_hints") or []) * 3, 12)
        for item in classes_for_operation(op):
            vclass, reason = item["class"], item["reason"]
            vid = vector_id(vclass, ep)
            existing = by_id.get(vid)
            priority = CATALOG.get(vclass, {}).get("impact", 30) + risk_bonus
            if existing:
                # keep whatever progress exists; upgrade provenance and priority only
                existing["origin"] = "manifest"
                existing["reason"] = existing.get("reason") or reason
                existing["operation_id"] = existing.get("operation_id") or op.get("id", "")
                existing["priority"] = max(existing.get("priority") or 0, priority)
                continue
            vec = _new_vector(vclass, ep, origin="manifest", reason=reason,
                              priority=priority, operation_id=op.get("id", ""))
            ledger["vectors"].append(vec)
            by_id[vid] = vec
            added += 1

    op_paths = {op.get("id"): endpoint_of(op) for op in ops}
    for hyp in (workflow or {}).get("hypotheses") or []:
        vclass = HYPOTHESIS_CLASSES.get(hyp.get("kind", ""))
        ep = op_paths.get(hyp.get("operation_id"))
        if not vclass or not ep:
            continue
        vid = vector_id(vclass, ep)
        reason = f"workflow:{hyp['kind']}"
        existing = by_id.get(vid)
        if existing:
            existing["priority"] = max(existing.get("priority") or 0, int(hyp.get("priority", 0)))
            notes = existing.get("notes", "")
            if hyp.get("test") and hyp["test"] not in notes:
                existing["notes"] = (notes + f"\n[{reason}] {hyp['test']}").strip()
            continue
        vec = _new_vector(vclass, ep, origin="manifest", reason=reason,
                          priority=int(hyp.get("priority", 0)),
                          operation_id=hyp.get("operation_id", ""))
        vec["notes"] = f"[{reason}] {hyp.get('test', '')}".strip()
        ledger["vectors"].append(vec)
        by_id[vid] = vec
        added += 1

    ledger["seeded_from_manifest"] = _now()
    ledger["last_seed_added"] = added
    return ledger


def prunable(ledger: Dict) -> List[Dict]:
    """Legacy Cartesian rows that were never touched — safe to drop, and only those.

    A row is prunable only if nothing was ever invested in it: still `untried`, zero
    requests fired, no mutation burned, no note written, and not manifest-derived.
    Everything else is somebody's work and stays.
    """
    return [v for v in ledger.get("vectors", [])
            if v.get("origin", "cartesian") != "manifest"
            and v.get("status") == "untried"
            and not v.get("requests_fired")
            and not v.get("mutations_tried")
            and not (v.get("notes") or "").strip()]


def prune(target: str, apply: bool = False, memdir: Optional[Path] = None) -> Dict:
    """Dry-run by default. Writes a timestamped backup before it removes anything."""
    ledger = load(target, memdir)
    doomed = prunable(ledger)
    report = {"target": target, "total": len(ledger.get("vectors", [])),
              "prunable": len(doomed), "kept": len(ledger.get("vectors", [])) - len(doomed),
              "applied": False, "backup": None,
              "sample": [v["id"] for v in doomed[:10]]}
    if not apply or not doomed:
        return report
    path = _path(target, memdir)
    if path.exists():
        backup = path.with_suffix(f".json.bak-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}")
        backup.write_text(path.read_text())
        report["backup"] = str(backup)
    doomed_ids = {v["id"] for v in doomed}
    ledger["vectors"] = [v for v in ledger["vectors"] if v["id"] not in doomed_ids]
    save(ledger, memdir)
    report["applied"] = True
    return report


def mutations_for(vclass: str) -> List[str]:
    return CLASS_MUTATIONS.get(vclass, []) + GENERIC_MUTATIONS


def next_mutation(vec: Dict) -> Optional[str]:
    tried = set(vec.get("mutations_tried", []))
    for m in mutations_for(vec["class"]):
        if m not in tried:
            return m
    return None


def rank(vectors: List[Dict]) -> List[Dict]:
    def key(v):
        # A manifest-seeded vector carries the priority its own operation earned
        # (risk hints, workflow hypothesis). Fall back to raw catalog impact only
        # for rows nobody derived from evidence.
        impact = v.get("priority") or CATALOG.get(v["class"], {}).get("impact", 30)
        # untried before active; a vector with fired requests behind it ranks below
        # a fresh one of the same impact, so breadth happens before grinding.
        status_bonus = {"untried": 20, "active": 10}.get(v["status"], -100)
        return -(impact + status_bonus - min(v.get("requests_fired", 0), 15))
    return sorted(vectors, key=key)


def next_vectors(target: str, count: int = 5, memdir: Optional[Path] = None) -> List[Dict]:
    ledger = load(target, memdir)
    live = [v for v in ledger["vectors"] if v["status"] in ("untried", "active")]
    out = []
    for v in rank(live)[:count]:
        item = dict(v)
        item["skill"] = CATALOG.get(v["class"], {}).get("skill", "bb-methodology")
        item["hint"] = CATALOG.get(v["class"], {}).get("hint", "")
        item["next_mutation"] = next_mutation(v)
        out.append(item)
    return out


def mark(target: str, vid: str, status: str, mutation: Optional[str] = None,
         note: str = "", requests: int = 0, force: bool = False,
         memdir: Optional[Path] = None) -> Dict:
    """Update a vector. Marking `dead` without fired requests is refused."""
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    ledger = load(target, memdir)
    for v in ledger["vectors"]:
        if v["id"] != vid:
            continue
        v["requests_fired"] = v.get("requests_fired", 0) + max(requests, 0)
        if mutation:
            v.setdefault("mutations_tried", []).append(mutation)
        if status == "dead" and not force:
            fired = v["requests_fired"]
            remaining = next_mutation(v)
            if fired == 0:
                raise SystemExit(
                    f"refusing to kill {vid}: 0 requests fired at it. "
                    "A vector closed on analysis is an open thread, not a dead one. "
                    "Fire something, or use --force with a reason in --note.")
            if remaining:
                raise SystemExit(
                    f"refusing to kill {vid}: {len(mutations_for(v['class'])) - len(v.get('mutations_tried', []))} "
                    f"mutations still untried. Next one: {remaining}\n"
                    "Use --force only if the whole class is structurally impossible here.")
        v["status"] = status
        if note:
            v["notes"] = (v.get("notes", "") + f"\n[{_now()}] {note}").strip()
        v["updated"] = _now()
        save(ledger, memdir)
        return v
    raise SystemExit(f"no such vector: {vid}")


# ---------------------------------------------------------------------------
# stuck detection — grinding one host with nothing logged is the observable
# symptom of "he hits a wall and keeps hitting it".
# ---------------------------------------------------------------------------
def _tail_jsonl(path: Path, limit: int) -> List[Dict]:
    if not path.exists():
        return []
    rows: List[Dict] = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows[-limit:]


def _host_of(url: str) -> str:
    s = url.split("://", 1)[-1]
    return s.split("/", 1)[0]


def stuck_report(threshold: int = 15, memdir: Optional[Path] = None) -> Optional[Dict]:
    """Requests fired since the last hunt-memory write, grouped by host."""
    mem = memdir or resolve_dir()
    audit = _tail_jsonl(mem / "audit.jsonl", 400)
    journal = _tail_jsonl(mem / "journal.jsonl", 50)
    if not audit:
        return None
    last_write = journal[-1].get("timestamp", "") if journal else ""
    since = [r for r in audit if r.get("timestamp", "") > last_write]
    if len(since) < threshold:
        return None
    hosts: Dict[str, int] = {}
    for r in since:
        for u in r.get("urls", []) or []:
            h = _host_of(u)
            hosts[h] = hosts.get(h, 0) + 1
    top = sorted(hosts.items(), key=lambda kv: -kv[1])
    out = {
        "requests_since_last_finding": len(since),
        "engagement": since[-1].get("engagement", ""),
        "hosts": top[:5],
        "top_host": top[0][0] if top else "",
    }
    # How many of those requests actually got a *different* answer? A burst of 30
    # that produced 2 distinct bodies is not 30 probes, and the operator deserves to
    # be told which of the two situations they are in.
    try:
        import responses  # type: ignore
        with_bodies = [r for r in since if r.get("body_sha256")]
        if with_bodies:
            out.update({k: v for k, v in responses.identical_run(with_bodies).items()
                        if k in ("distinct", "identical_ratio")})
            out["responses_recorded"] = len(with_bodies)
    except Exception:  # noqa: BLE001
        pass
    return out


def revisit(target: str, memdir: Optional[Path] = None) -> List[Dict]:
    """Past non-confirmed findings + the mutation that was never tried on them.

    'Пройтись по прошлым находкам другими методами' — a rejected/partial entry is
    a vector with one burned mutation, not a closed door.
    """
    mem = memdir or resolve_dir()
    rows = _tail_jsonl(mem / "journal.jsonl", 500)
    ledger = load(target, memdir)
    by_id = {v["id"]: v for v in ledger["vectors"]}
    out = []
    for r in rows:
        if target and r.get("target") != target:
            continue
        if r.get("result") == "confirmed":
            continue
        vclass = r.get("vuln_class") or "info-leak"
        ep = r.get("endpoint", "")
        vid = vector_id(vclass, ep)
        vec = by_id.get(vid, {"class": vclass, "endpoint": ep, "mutations_tried": []})
        out.append({
            "endpoint": ep,
            "vuln_class": vclass,
            "result": r.get("result"),
            "when": r.get("timestamp", "")[:10],
            "skill": CATALOG.get(vclass, {}).get("skill", "bb-methodology"),
            "untried_mutation": next_mutation(vec),
            "mutations_left": len(mutations_for(vclass)) - len(vec.get("mutations_tried", [])),
        })
    return out


def _print_next(items: List[Dict]) -> None:
    if not items:
        print("ledger empty — seed it:  cbh vectors seed <target> --endpoints a,b,c")
        return
    for i, v in enumerate(items, 1):
        print(f"{i}. [{v['class']}] {v['endpoint']}")
        print(f"   skill: {v['skill']}  ·  status: {v['status']}  ·  fired: {v['requests_fired']}")
        if v.get("hint"):
            print(f"   hint: {v['hint']}")
        if v.get("next_mutation"):
            print(f"   next move: {v['next_mutation']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vectors", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("seed", help="create the vector ledger for a target")
    p.add_argument("target")
    p.add_argument("--endpoints", required=True, help="comma-separated")
    p.add_argument("--classes", help="comma-separated; default = whole catalog")

    p = sub.add_parser("seed-from-manifest",
                       help="derive only relevant vectors from an API manifest (+workflow)")
    p.add_argument("target")
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--workflow", type=Path, help="workflow.json from engine/workflow_graph.py")
    p.add_argument("--hosts", default="", help="comma-separated; limit to these manifest hosts")

    p = sub.add_parser("prune", help="drop untouched legacy Cartesian rows (dry-run by default)")
    p.add_argument("target")
    p.add_argument("--apply", action="store_true", help="actually write (backs up first)")

    p = sub.add_parser("next", help="what to attack next (impact-ranked, never empty)")
    p.add_argument("target")
    p.add_argument("-n", "--count", type=int, default=5)

    p = sub.add_parser("mark", help="update a vector's status")
    p.add_argument("target")
    p.add_argument("id")
    p.add_argument("status", choices=STATUSES)
    p.add_argument("--mutation", help="the mutation just burned")
    p.add_argument("--note", default="")
    p.add_argument("--requests", type=int, default=0)
    p.add_argument("--force", action="store_true")

    p = sub.add_parser("rotate", help="next mutation for a class you are stuck on")
    p.add_argument("vclass")
    p.add_argument("--tried", default="", help="comma-separated indices already burned")

    p = sub.add_parser("revisit", help="old non-confirmed findings + an untried method for each")
    p.add_argument("target")

    p = sub.add_parser("stuck", help="are we grinding? reads audit.jsonl vs journal.jsonl")
    p.add_argument("--threshold", type=int, default=15)

    sub.add_parser("list-classes", help="the catalog with impact ranking")

    args = ap.parse_args(argv)

    if args.cmd == "seed":
        eps = [e.strip() for e in args.endpoints.split(",") if e.strip()]
        cls = [c.strip() for c in args.classes.split(",")] if args.classes else None
        ledger = seed(args.target, eps, cls)
        save(ledger)
        print(f"seeded {len(ledger['vectors'])} vectors for {args.target} -> {_path(args.target)}")
    elif args.cmd == "seed-from-manifest":
        manifest = json.loads(args.manifest.read_text())
        workflow = json.loads(args.workflow.read_text()) if args.workflow else None
        hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
        ledger = seed_from_manifest(args.target, manifest, workflow, hosts=hosts)
        save(ledger)
        print(f"{args.target}: +{ledger['last_seed_added']} vectors from "
              f"{len(manifest.get('operations') or [])} operations "
              f"({len(ledger['vectors'])} total) -> {_path(args.target)}")
    elif args.cmd == "prune":
        rep = prune(args.target, args.apply)
        verb = "pruned" if rep["applied"] else "would prune"
        print(f"{rep['target']}: {verb} {rep['prunable']} of {rep['total']} vectors "
              f"({rep['kept']} kept)")
        for vid in rep["sample"]:
            print(f"  - {vid}")
        if rep["backup"]:
            print(f"backup: {rep['backup']}")
        elif not rep["applied"] and rep["prunable"]:
            print("re-run with --apply to write (a timestamped backup is made first)")
    elif args.cmd == "next":
        _print_next(next_vectors(args.target, args.count))
    elif args.cmd == "mark":
        v = mark(args.target, args.id, args.status, args.mutation, args.note,
                 args.requests, args.force)
        print(f"{v['id']} -> {v['status']} (fired {v['requests_fired']})")
    elif args.cmd == "rotate":
        muts = mutations_for(args.vclass)
        tried = {int(i) for i in args.tried.split(",") if i.strip().isdigit()}
        for i, m in enumerate(muts):
            flag = "x" if i in tried else " "
            print(f"[{flag}] {i}. {m}")
    elif args.cmd == "revisit":
        rows = revisit(args.target)
        if not rows:
            print("nothing to revisit — no non-confirmed entries for this target")
        for r in rows:
            print(f"- {r['when']} [{r['vuln_class']}] {r['endpoint']}  ({r['result']})")
            print(f"    skill: {r['skill']}  ·  {r['mutations_left']} methods untried")
            if r["untried_mutation"]:
                print(f"    try:   {r['untried_mutation']}")
    elif args.cmd == "stuck":
        rep = stuck_report(args.threshold)
        if not rep:
            print("not stuck")
            return 0
        print(f"STUCK: {rep['requests_since_last_finding']} requests since the last hunt-memory write")
        for h, n in rep["hosts"]:
            print(f"  {n:4d}  {h}")
        return 1
    elif args.cmd == "list-classes":
        for c, meta in sorted(CATALOG.items(), key=lambda kv: -kv[1]["impact"]):
            print(f"{meta['impact']:3d}  {c:24s} {meta['skill']:22s} {meta['hint']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
