#!/usr/bin/env python3
"""Compare two recon/API manifests and rank newly exposed attack surface."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

RISK = {"function-authorization": 95, "object-authorization": 92,
        "property-authorization": 90, "business-flow": 88, "oauth": 86,
        "resolver-authorization": 85, "state-change": 75, "graphql": 70,
        "declared-public": 55}


def _assets(doc):
    return {a.get("host"): a for a in doc.get("assets") or [] if a.get("host")}


def _operations(doc):
    return {o.get("id") or f"{o.get('method')} {o.get('host')} {o.get('path')}": o
            for o in doc.get("operations") or []}


def compare(old: dict, new: dict) -> dict:
    oa, na, oo, no = _assets(old), _assets(new), _operations(old), _operations(new)
    added_ops, changed_ops = [], []
    for key in no.keys() - oo.keys():
        op = dict(no[key]); op["risk_score"] = max([RISK.get(x, 30) for x in op.get("risk_hints") or []] or [30])
        added_ops.append(op)
    for key in no.keys() & oo.keys():
        fields_added = sorted(set(no[key].get("fields") or []) - set(oo[key].get("fields") or []))
        params_added = sorted(set(no[key].get("parameters") or []) - set(oo[key].get("parameters") or []))
        security_changed = no[key].get("secured") != oo[key].get("secured")
        if fields_added or params_added or security_changed:
            changed_ops.append({"operation": no[key], "fields_added": fields_added,
                                "parameters_added": params_added, "security_changed": security_changed,
                                "risk_score": max([RISK.get(x, 30) for x in no[key].get("risk_hints") or []] or [30])})
    added_ops.sort(key=lambda x: -x["risk_score"])
    changed_ops.sort(key=lambda x: -x["risk_score"])
    return {"schema_version": "1.0",
            "assets_added": [na[k] for k in sorted(na.keys() - oa.keys())],
            "assets_removed": [oa[k] for k in sorted(oa.keys() - na.keys())],
            "operations_added": added_ops,
            "operations_removed": [oo[k] for k in sorted(oo.keys() - no.keys())],
            "operations_changed": changed_ops,
            "counts": {"assets_added": len(na.keys() - oa.keys()),
                       "operations_added": len(added_ops), "operations_changed": len(changed_ops)}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("old", type=Path); ap.add_argument("new", type=Path)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)
    result = compare(json.loads(args.old.read_text()), json.loads(args.new.read_text()))
    text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.out: args.out.write_text(text)
    else: print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
