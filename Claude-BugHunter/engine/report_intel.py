#!/usr/bin/env python3
"""Search a local disclosed-report dataset and return a small relevant context pack.

Bounded retrieval on purpose: loading a whole report corpus into an agent's context costs
more than it returns, and the useful thing is five close matches, not five hundred rows.

**Provenance is not optional.** A disclosed-report dataset is somebody else's work, usually
under a licence, and the reports describe real programs and real researchers. A dataset with
no recorded source is a dataset nobody can check the terms of, so `describe()` reports what
is known and `--strict` refuses to search one that declares nothing. No dataset ships with
this bundle; point it at one you are authorized to hold.

A dataset may declare its provenance in a top-level `meta` object:

    {"meta": {"source": "https://example.org/disclosed-reports",
              "licence": "CC-BY-4.0", "retrieved": "2026-09-01",
              "notes": "public HackerOne disclosures only"},
     "reports": [...]}

or in a sidecar `<dataset>.meta.json` with the same shape, for a dataset file you should
not modify.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

STOP = {"the", "and", "for", "with", "from", "this", "that", "http", "https", "api", "com"}


def tokens(value) -> Counter:
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return Counter(x for x in re.findall(r"[a-z0-9_-]{3,}", text.lower()) if x not in STOP)


META_FIELDS = ("source", "licence", "license", "retrieved", "notes", "count")


def describe(dataset, path: Path | None = None) -> dict:
    """What is known about where this dataset came from. Missing fields stay missing."""
    meta = {}
    if isinstance(dataset, dict) and isinstance(dataset.get("meta"), dict):
        meta.update({k: v for k, v in dataset["meta"].items() if k in META_FIELDS})
    if path:
        sidecar = path.with_name(path.name + ".meta.json")
        if sidecar.is_file():
            try:
                extra = json.loads(sidecar.read_text(encoding="utf-8"))
                meta.update({k: v for k, v in extra.items() if k in META_FIELDS})
            except (OSError, ValueError):
                pass
    meta["rows"] = len(_rows(dataset))
    meta["declared"] = any(meta.get(k) for k in ("source", "licence", "license"))
    return meta


def _rows(doc):
    if isinstance(doc, list): return doc
    for key in ("reports", "data", "items"):
        if isinstance(doc.get(key), list): return doc[key]
    return []


def search(dataset: dict | list, query: str, limit=5, min_severity="") -> list:
    qt = tokens(query)
    out = []
    for row in _rows(dataset):
        severity = str(row.get("severity_rating") or row.get("severity") or "").lower()
        if min_severity and severity and severity not in {min_severity.lower(), "critical"}:
            continue
        rt = tokens({k: row.get(k) for k in ("title", "weakness", "cwe", "vulnerability_information",
                                             "impact", "program", "severity")})
        overlap = sum(min(qt[t], rt[t]) for t in qt)
        if not overlap: continue
        rare_bonus = sum(1 / math.sqrt(1 + rt[t]) for t in qt if rt[t])
        bounty = float(row.get("bounty_awarded") or row.get("bounty") or 0)
        out.append((overlap * 10 + rare_bonus + min(bounty / 5000, 3), {
            "id": row.get("id"), "title": row.get("title"), "program": row.get("program"),
            "severity": severity, "bounty": bounty, "url": row.get("url") or row.get("report_url"),
            "matched_terms": sorted(set(qt) & set(rt)),
        }))
    return [r for _, r in sorted(out, key=lambda x: -x[0])[:max(1, min(limit, 10))]]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dataset", type=Path); ap.add_argument("query")
    ap.add_argument("--limit", type=int, default=5); ap.add_argument("--severity", default="")
    ap.add_argument("--strict", action="store_true",
                    help="refuse a dataset that declares no source/licence")
    ap.add_argument("--describe", action="store_true",
                    help="print the dataset's provenance and exit")
    args = ap.parse_args(argv)
    dataset = json.loads(args.dataset.read_text())
    meta = describe(dataset, args.dataset)
    if args.describe:
        print(json.dumps(meta, indent=2, ensure_ascii=False))
        return 0
    if args.strict and not meta["declared"]:
        print(f"{args.dataset}: no source or licence declared. Add a top-level `meta` "
              f"object, or a sidecar {args.dataset.name}.meta.json, recording where this "
              f"came from and under what terms. Refusing to search it.")
        return 2
    result = search(dataset, args.query, args.limit, args.severity)
    print(json.dumps({"query": args.query, "dataset": meta, "matches": result},
                     indent=2, ensure_ascii=False))
    if not meta["declared"]:
        print("# note: this dataset declares no source/licence — see --describe",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
