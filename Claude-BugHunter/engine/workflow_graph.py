#!/usr/bin/env python3
"""Derive business-state transitions and high-value hypotheses from an API manifest.

With `--responses` the graph is also fed the identifiers the target has already handed
back. A create or list call returns ids; those ids are the concrete objects a
cross-principal hypothesis needs, and without them every cross-owner test stays a
`{{OBJECT_ID}}` placeholder the operator has to source by hand. Observed ids are attached
to the entity they belong to, so "perform refund as user B against user A's order"
becomes a test with real material behind it.

Ids are read from the response corpus this workspace already stores — no extra requests.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

VERBS = ("create", "start", "submit", "apply", "approve", "pay", "cancel", "refund",
         "delete", "update", "verify", "complete", "redeem", "transfer", "invite")

# Field names whose values are object references worth reusing as test material.
ID_FIELD_RE = re.compile(r"(?:^|\.)(id|uuid|guid|[a-z_]*_id|[a-z]+Id)$", re.I)
# What an id may look like. Deliberately narrow: free-text values are somebody's data,
# and only opaque references belong in a plan that gets committed.
ID_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
MAX_IDS_PER_ENTITY = 10


def entity_of(op: dict) -> str:
    pieces = [x for x in op.get("path", "").split("/") if x and not x.startswith("{")]
    pieces = [x for x in pieces if not re.fullmatch(r"v\d+|api|rest|internal", x, re.I)]
    return pieces[-2] if len(pieces) > 1 and pieces[-1].lower() in VERBS else (pieces[-1] if pieces else "root")


def action_of(op: dict) -> str:
    name = (op.get("operation_name") or "").lower()
    path = op.get("path", "").lower()
    for verb in VERBS:
        if verb in name or f"/{verb}" in path:
            return verb
    return {"POST": "create", "PUT": "replace", "PATCH": "update",
            "DELETE": "delete", "GET": "read"}.get(op.get("method"), "invoke")


def observed_identifiers(engagement: str = "", memdir: Path | None = None) -> dict:
    """{path -> [id, ...]} lifted from the stored response corpus.

    Only id-shaped keys with id-shaped values are kept. A name, an email or a message
    body is somebody's data and has no business in a workflow artifact — see the
    identity-scrubbing rules the rest of the writers follow.
    """
    try:
        from responses import _flatten, body_of, load, rows  # type: ignore
    except Exception:  # noqa: BLE001
        return {}
    found: dict[str, list[str]] = {}
    for row in rows(engagement=engagement, memdir=memdir):
        digest = row.get("body_sha256")
        url = (row.get("urls") or [""])[0]
        if not digest or not url:
            continue
        try:
            body = body_of(load(row.get("engagement") or engagement, digest, memdir))
            parsed = json.loads(body)
        except Exception:  # noqa: BLE001 - a non-JSON body is simply not a source of ids
            continue
        path = re.sub(r"\?.*$", "", url.split("://", 1)[-1].partition("/")[2])
        bucket = found.setdefault("/" + path, [])
        for key, values in _flatten(parsed).items():
            if not ID_FIELD_RE.search(key.replace("[]", "")):
                continue
            for raw in values:
                try:
                    value = json.loads(raw)
                except (ValueError, TypeError):
                    continue
                value = str(value)
                if ID_VALUE_RE.match(value) and value not in bucket:
                    if len(bucket) < MAX_IDS_PER_ENTITY:
                        bucket.append(value)
    return {k: v for k, v in found.items() if v}


def _ids_for(entity: str, observed: dict) -> list[str]:
    """Ids seen on any path that mentions this entity."""
    out: list[str] = []
    for path, ids in (observed or {}).items():
        if entity and entity.lower() in path.lower():
            for value in ids:
                if value not in out:
                    out.append(value)
    return out[:MAX_IDS_PER_ENTITY]


def build(manifest: dict, observed: dict | None = None) -> dict:
    nodes, edges, hypotheses = {}, [], []
    observed = observed or {}
    for op in manifest.get("operations") or []:
        entity, action = entity_of(op), action_of(op)
        node = nodes.setdefault(entity, {"id": entity, "operations": [],
                                         "observed_ids": _ids_for(entity, observed)})
        node["operations"].append(op["id"])
        edge = {"operation_id": op["id"], "entity": entity, "action": action,
                "method": op["method"], "path": op["path"]}
        edges.append(edge)
        hints = set(op.get("risk_hints") or [])
        if op["method"] in {"POST", "PUT", "PATCH", "DELETE"}:
            hypotheses += [
                {"operation_id": op["id"], "kind": "replay", "priority": 80,
                 "test": f"repeat {action} with the same idempotency key and verify {entity} state"},
                {"operation_id": op["id"], "kind": "step-skip", "priority": 78,
                 "test": f"call {action} before its expected predecessor and verify final state"},
                {"operation_id": op["id"], "kind": "cross-principal", "priority": 92,
                 "test": f"perform {action} as user B against user A's {entity}",
                 "material": _ids_for(entity, observed)},
            ]
        if "business-flow" in hints:
            hypotheses.append({"operation_id": op["id"], "kind": "value-boundary", "priority": 88,
                               "test": "try zero, negative, fractional and boundary values; verify ledger state"})
        if "property-authorization" in hints:
            hypotheses.append({"operation_id": op["id"], "kind": "hidden-field", "priority": 90,
                               "test": "add each sensitive schema field and read the object back"})
    # Explicit race hypotheses only for operations whose names imply one-time value.
    for edge in edges:
        if any(x in (edge["path"] + edge["action"]) for x in ("redeem", "coupon", "pay", "refund", "transfer", "limit")):
            hypotheses.append({"operation_id": edge["operation_id"], "kind": "race", "priority": 86,
                               "test": "send the smallest authorized parallel pair and verify invariant once"})
    # A hypothesis with concrete material behind it outranks the same hypothesis with a
    # placeholder: it is the one that can actually be fired this session.
    for hyp in hypotheses:
        if hyp.get("material"):
            hyp["priority"] += 4
    hypotheses.sort(key=lambda h: (-h["priority"], h["operation_id"], h["kind"]))
    return {"schema_version": "1.1", "nodes": sorted(nodes.values(), key=lambda n: n["id"]),
            "edges": edges, "hypotheses": hypotheses,
            "counts": {"entities": len(nodes), "operations": len(edges),
                       "hypotheses": len(hypotheses),
                       "hypotheses_with_material": sum(1 for h in hypotheses if h.get("material"))}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("manifest", type=Path); ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--responses", metavar="ENGAGEMENT", default=None,
                    help="lift object ids from this engagement's stored response corpus, "
                         "so cross-principal hypotheses carry real material (no new requests)")
    args = ap.parse_args(argv)
    observed = observed_identifiers(args.responses) if args.responses else {}
    result = build(json.loads(args.manifest.read_text()), observed)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(f"{args.out}: {result['counts']['entities']} entities, "
          f"{result['counts']['hypotheses']} hypotheses "
          f"({result['counts']['hypotheses_with_material']} with observed ids)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
