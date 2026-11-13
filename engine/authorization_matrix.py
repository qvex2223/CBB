#!/usr/bin/env python3
"""Build and evaluate principal/object/action authorization tests offline.

The plan contains identity labels and environment-variable references, never
tokens. Execution remains explicit through bbcurl/poc_runtime or Burp.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List

VOLATILE_KEYS = {"timestamp", "updated_at", "created_at", "request_id", "trace_id",
                 "nonce", "expires", "expires_at", "duration", "elapsed"}
DENIED = {401, 403, 404}
SUCCESS = set(range(200, 300))


def _principal_rows(doc: dict) -> List[dict]:
    rows = doc.get("principals") if isinstance(doc, dict) else doc
    out = []
    for row in rows or []:
        name = row.get("name") or row.get("id")
        if not name:
            raise ValueError("every principal needs name/id")
        if any(k in row for k in ("token", "cookie", "authorization")):
            raise ValueError(f"principal {name}: store only token_env/header_env references, never credentials")
        out.append({"name": name, "role": row.get("role", "user"),
                    "tenant": row.get("tenant"), "token_env": row.get("token_env"),
                    "header_env": row.get("header_env") or {}})
    return out


def plan(manifest: dict, principals_doc: dict) -> dict:
    principals = _principal_rows(principals_doc)
    operations = manifest.get("operations") or []
    tests = []
    for op in operations:
        hints = set(op.get("risk_hints") or [])
        if not hints.intersection({"object-authorization", "function-authorization",
                                   "property-authorization", "state-change",
                                   "resolver-authorization"}):
            continue
        for actor in principals:
            for owner in principals:
                cross = actor["name"] != owner["name"]
                cross_tenant = bool(actor.get("tenant") and owner.get("tenant") and
                                    actor["tenant"] != owner["tenant"])
                if not cross and "function-authorization" not in hints:
                    continue
                basis = f"{op['id']}|{actor['name']}|{owner['name']}"
                tests.append({
                    "id": "authz_" + hashlib.sha256(basis.encode()).hexdigest()[:12],
                    "operation_id": op["id"], "method": op["method"], "url": op["url"],
                    "actor": actor["name"], "actor_role": actor.get("role"),
                    "actor_tenant": actor.get("tenant"), "object_owner": owner["name"],
                    "owner_tenant": owner.get("tenant"), "cross_principal": cross,
                    "cross_tenant": cross_tenant,
                    "expected": "deny" if cross or cross_tenant else "allow",
                    "requires_state_verification": op["method"] in {"POST", "PUT", "PATCH", "DELETE"},
                    "token_env": actor.get("token_env"), "header_env": actor.get("header_env"),
                    # The verification step has to read the state back AS THE OWNER.
                    # Verifying with the attacker's own credentials proves nothing: the
                    # same broken authorization that allowed the write would show it.
                    "owner_token_env": owner.get("token_env"),
                    "owner_header_env": owner.get("header_env"),
                    "risk_hints": sorted(hints),
                })
    return {"schema_version": "1.0", "principals": principals, "tests": tests,
            "counts": {"principals": len(principals), "tests": len(tests)}}


# --------------------------------------------------------------------------- specs
#
# The matrix used to stop at a plan: a JSON list of comparisons somebody still had to
# hand-write into requests. That gap is where access-control testing dies — the plan is
# the easy half, and a hand-rolled curl skips the scope gate, the pacing budget and the
# audit row, so whatever it finds cannot back a report.
#
# So the plan emits poc_runtime specs. Three properties are deliberate:
#   * credentials stay as ENV REFERENCES, never values. The spec file is versioned;
#     `{{env:ACTOR_TOKEN}}` is resolved by poc_runtime at fire time.
#   * a write test always gets a `verify` step that reads the state back. "The POST
#     returned 200" is the claim that gets reports closed as N/A.
#   * object ids are left as `{{OBJECT_ID}}` placeholders the operator fills in. The
#     matrix does not know which order belongs to which account, and inventing one
#     would mean firing at a stranger's data.

OBJECT_ID_PLACEHOLDER = "{{OBJECT_ID}}"
VERIFY_PLACEHOLDER = "{{OWNER_VISIBLE_MARKER}}"


def _auth_headers(test: dict) -> Dict[str, str]:
    """Header block referencing env vars by NAME. No credential value is ever written."""
    headers: Dict[str, str] = {}
    if test.get("token_env"):
        headers["Authorization"] = "Bearer {{env:%s}}" % test["token_env"]
    for header, env_name in (test.get("header_env") or {}).items():
        headers[header] = "{{env:%s}}" % env_name
    return headers


def to_poc_spec(test: dict, *, object_id: str | None = None) -> dict:
    """One authorization test -> a poc_runtime spec skeleton.

    Returns a `steps` spec for state-changing operations (exploit + verify) and a
    single-request spec for reads. Nothing here fires; the spec goes through
    `engine/poc_runtime.py`, which carries the scope gate, pacing and audit.
    """
    url = (test["url"] or "").replace("{id}", object_id or OBJECT_ID_PLACEHOLDER)
    headers = _auth_headers(test)
    denies = test["expected"] == "deny"
    label = ("cross-tenant" if test.get("cross_tenant")
             else "cross-principal" if test.get("cross_principal") else "owner-control")
    # A spec's PASS must mean "the vulnerability is demonstrated" — that is what
    # engine/evidence.py reads and what the stop gate counts. So the exploit step
    # asserts the FINDING condition (the request succeeded when it should have been
    # refused), never the correct behaviour. A spec that PASSes when the server
    # correctly denies would hand every hardened endpoint a green artifact.
    note = (f"{label}: {test['actor']} (role={test.get('actor_role')}) performs "
            f"{test['method']} on an object owned by {test['object_owner']}. "
            + ("This request SHOULD be refused. The spec asserts success on purpose: "
               "PASS here means the authorization check is missing, FAIL means the "
               "endpoint behaved correctly and there is nothing to report."
               if denies else
               "Owner control request — this one SHOULD succeed. It is the baseline that "
               "proves the endpoint works at all, so a deny on the cross-principal test "
               "means authorization and not a broken request. Fire this first."))

    exploit = {
        "name": "exploit", "method": test["method"], "url": url, "headers": headers,
        "expect": {"status": 200},
        "pass_means": ("authorization is missing — this actor reached another "
                       "principal's object" if denies else
                       "the endpoint works for its legitimate owner (baseline only, "
                       "not a finding)"),
    }
    if test["method"] in {"POST", "PUT", "PATCH"}:
        exploit["body"] = "{}"          # operator fills the minimal authorized payload

    spec = {
        "name": test["id"],
        "note": note,
        "authz_test_id": test["id"],
        "operation_id": test["operation_id"],
        "correct_behaviour": test["expected"],
        "is_finding_if_passes": denies,
        "fill_in": [],
    }
    if OBJECT_ID_PLACEHOLDER in url:
        spec["fill_in"].append(
            f"{OBJECT_ID_PLACEHOLDER} — an object id owned by {test['object_owner']}, "
            "from an account you control. Never a stranger's.")
    for header in headers.values():
        spec["fill_in"].append(f"export {header[8:-2]} before firing"
                               if header.startswith("{{env:") else header)

    if not test.get("requires_state_verification"):
        spec.update({k: v for k, v in exploit.items() if k != "name"})
        # A read violation needs the response to actually contain the owner's data;
        # a 200 with an empty list is not a disclosure.
        spec["pass_means"] = exploit["pass_means"]
        if denies:
            spec["verification_required"] = (
                "A 2xx alone is not the finding. The body must contain data belonging to "
                f"{test['object_owner']} — add `body_contains` with a marker you can "
                "attribute to that account before calling this confirmed.")
        return spec

    # The verify step reads the state back as the owner and asserts the change the
    # exploit was supposed to be prevented from making. Same rule as above: it asserts
    # the finding, so the whole chain PASSes only when the write actually landed.
    owner_headers = _auth_headers({"token_env": test.get("owner_token_env"),
                                   "header_env": test.get("owner_header_env")})
    verify = {
        "name": "verify",
        "method": "GET",
        "url": url,
        "headers": owner_headers or headers,
        "pass_means": "the unauthorized write actually changed the owner's state",
    }
    if test["method"] == "DELETE":
        # After a successful unauthorized delete the object is GONE from the owner's
        # own view. Asserting that it is still readable would invert the proof.
        verify["expect"] = {"status": 404}
        verify["pass_means"] = ("the object is gone from the owner's own view — the "
                                "unauthorized delete landed")
        spec["fill_in"].append(
            "verify expects 404. If this API soft-deletes, change it to `status: 200` "
            "with `body_contains: [\"deleted\"]` — the point is the OWNER seeing the "
            "change, not the status number.")
    else:
        verify["expect"] = {"status": 200, "body_contains": [VERIFY_PLACEHOLDER]}
        spec["fill_in"].append(
            f"{VERIFY_PLACEHOLDER} — a string that appears in the owner's view of this "
            "object ONLY IF the write landed. This step is the whole difference between "
            "a finding and 'the request returned 200'.")
    if not owner_headers:
        spec["fill_in"].append(
            f"WARNING: no token_env for {test['object_owner']} — the verify step reuses "
            f"{test['actor']}'s credentials, which cannot prove the owner sees the change. "
            "Add a token_env for every principal.")
    spec["steps"] = [exploit, verify]
    return spec


def emit_specs(plan_doc: dict, out_dir: Path, limit: int | None = None) -> List[Path]:
    """Write one `.poc.json` per authorization test. Nothing is fired."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for test in (plan_doc.get("tests") or [])[:limit]:
        spec = to_poc_spec(test)
        path = out_dir / f"{test['id']}.poc.json"
        path.write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
        written.append(path)
    return written


def _normalize(value):
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in sorted(value.items())
                if k.lower() not in VOLATILE_KEYS}
    if isinstance(value, list):
        return [_normalize(x) for x in value]
    if isinstance(value, str):
        value = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{20,}\b", "<uuid>", value, flags=re.I)
        value = re.sub(r"\b\d{10,}\b", "<number>", value)
    return value


def body_fingerprint(body) -> str:
    if isinstance(body, str):
        try: body = json.loads(body)
        except ValueError: pass
    raw = json.dumps(_normalize(body), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def evaluate(observations: Iterable[dict]) -> dict:
    """Evaluate recorded test results. A write needs a verified state change."""
    results = []
    for obs in observations:
        status = int(obs.get("status") or 0)
        expected = obs.get("expected", "deny")
        method = str(obs.get("method", "GET")).upper()
        state_changed = obs.get("state_changed") is True
        # Ownership is only evidence when BOTH sides carry a real value and they are
        # equal. `None == None` (or "" == "") must never prove a disclosure.
        response_owner = obs.get("response_owner")
        object_owner = obs.get("object_owner")
        exposed_owner = (bool(response_owner) and bool(object_owner)
                         and str(response_owner).strip() == str(object_owner).strip())
        accepted = status in SUCCESS
        if expected == "deny" and accepted:
            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                verdict = "VIOLATION" if state_changed else "INCONCLUSIVE"
                reason = "cross-principal write changed state" if state_changed else "2xx write without state verification"
            else:
                verdict = "VIOLATION" if exposed_owner or obs.get("sensitive_data") is True else "INCONCLUSIVE"
                reason = "cross-principal data returned" if verdict == "VIOLATION" else "2xx read without ownership proof"
        elif expected == "deny" and status in DENIED:
            verdict, reason = "PASS", "request was denied"
        elif expected == "allow" and accepted:
            verdict, reason = "PASS", "owner control request succeeded"
        else:
            verdict, reason = "INCONCLUSIVE", f"status {status} does not prove the expected decision"
        row = dict(obs)
        row.update({"verdict": verdict, "reason": reason,
                    "body_fingerprint": body_fingerprint(obs.get("body", ""))})
        results.append(row)
    counts = {v: sum(r["verdict"] == v for r in results)
              for v in ("VIOLATION", "PASS", "INCONCLUSIVE")}
    return {"schema_version": "1.0", "results": results, "counts": counts}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("plan")
    p.add_argument("manifest", type=Path); p.add_argument("principals", type=Path)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--emit-specs", type=Path, metavar="DIR",
                   help="also write one poc_runtime spec skeleton per test (nothing fires)")
    p.add_argument("--limit", type=int, default=None, help="cap emitted specs")
    p = sub.add_parser("evaluate")
    p.add_argument("observations", type=Path); p.add_argument("--out", type=Path)
    args = ap.parse_args(argv)
    if args.command == "plan":
        result = plan(json.loads(args.manifest.read_text()), json.loads(args.principals.read_text()))
        args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        print(f"{args.out}: {result['counts']['tests']} authorization tests")
        if args.emit_specs:
            paths = emit_specs(result, args.emit_specs, args.limit)
            print(f"{args.emit_specs}: {len(paths)} poc_runtime spec skeleton(s)")
            print("Each carries {{OBJECT_ID}} / {{env:...}} placeholders — fill them in, "
                  "then fire with `python3 engine/poc_runtime.py <spec>`.")
    else:
        doc = json.loads(args.observations.read_text())
        result = evaluate(doc.get("observations", doc) if isinstance(doc, dict) else doc)
        text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if args.out: args.out.write_text(text)
        else: print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
