#!/usr/bin/env python3
"""
coverage.py — the negative space: what was actually varied, not what was swept.

A path sweep that returned 200 is not coverage (this workspace already learned
that one the hard way — it was an nginx SPA fallback). Coverage is **which
dimension of a request was ever changed while the others were held still**:
a second input value, another method, credentials removed, another principal,
a garbage value. Until one of those moved, an endpoint has been *observed*, not
*tested*.

This module answers that question from artefacts the workspace already keeps —
`hunt-memory/audit.jsonl` (every fired request) and the response corpus — and,
when a manifest is supplied, joins the answer onto it so the gaps land on named
operations instead of on a URL list.

It fires nothing and assumes nothing: an endpoint with one capture is reported
as `1 request, 1 body, 0 dimensions varied`, which is exactly as informative as
it sounds.

CLI:
    python3 engine/coverage.py --engagement kcell
    python3 engine/coverage.py --engagement kcell --manifest manifest.json --format md
    python3 engine/coverage.py --engagement kcell --gap second-input
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

SCHEMA_VERSION = "1.0"

# Dimensions. Each is answered from the audit row alone, which is the point:
# if the request line does not show the variation, it did not happen.
DIMENSIONS = [
    "second-input",       # same path, different query/body value
    "method",             # more than one method on the same path
    "auth-absent",        # a capture with no Authorization and no Cookie
    "auth-present",       # a capture carrying credentials
    "principal-contrast", # both of the above on the same path
    "identity-header",    # an identity-bearing header was sent
    "override-header",    # X-Original-URL / X-Rewrite-URL / X-Forwarded-*
    "content-type",       # more than one Content-Type on the same path
    "garbage-input",      # a value that is not a plausible real id
    "body-present",       # a request with a body
]

IDENTITY_HEADERS = re.compile(
    r"(?i)^(x-msisdn|x-subscriber-id|x-user-id|x-user-role|x-forwarded-user|"
    r"x-forwarded-email|x-auth-request-user|x-remote-user|x-tenant|x-org-id)$")
OVERRIDE_HEADERS = re.compile(
    r"(?i)^(x-original-url|x-rewrite-url|x-forwarded-uri|x-forwarded-path|"
    r"x-original-host|x-forwarded-host)$")
GARBAGE = re.compile(
    r"(?i)^(0|-1|null|undefined|true|false|\{\{.*\}\}|<script>.*|' or 1=1--|"
    r"00000000-0000-0000-0000-000000000000|test|example|foo|bar)$")


def _memdir(explicit: Optional[Path] = None) -> Path:
    if explicit:
        return Path(explicit)
    import os
    env = os.environ.get("CBH_MEMORY_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve().parent.parent
    for cand in (here / "hunt-memory", Path.cwd() / "hunt-memory"):
        if cand.exists():
            return cand
    return Path.home() / ".cbh" / "hunt-memory"


def _audit_rows(engagement: str = "", memdir: Optional[Path] = None,
                limit: int = 20000) -> List[dict]:
    path = _memdir(memdir) / "audit.jsonl"
    if not path.exists():
        return []
    rows: List[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        if engagement and row.get("engagement") not in (None, "", engagement):
            continue
        rows.append(row)
    return rows


def _path_key(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    p = parts.path or "/"
    # collapse obvious ids so /users/1 and /users/2 land on one row
    p = re.sub(r"/\d+", "/{id}", p)
    p = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{id}",
               p, flags=re.I)
    return p.rstrip("/") or "/"


def _headers_of(row: dict) -> Dict[str, str]:
    raw = row.get("headers") or {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    return {}


NO_INPUT = "__no_params__"


def _values_of(row: dict) -> Tuple[str, ...]:
    """The request's input values, for the second-input dimension.

    A request with no parameters still has an input shape — it is the empty one.
    Without a sentinel for that case, "no query" would collapse to zero values
    and a later request with a query would look like the first input rather than
    the second, which is exactly the coverage question being asked.
    """
    url = row.get("url") or row.get("command") or ""
    if not isinstance(url, str):
        return (NO_INPUT,)
    parts = urllib.parse.urlsplit(url)
    q = [f"{k}={v}" for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)]
    body = row.get("body") or row.get("data") or ""
    if isinstance(body, str) and body.strip():
        q.append("body:" + body.strip()[:200])
    return tuple(sorted(q)) if q else (NO_INPUT,)


def summarize(engagement: str = "", memdir: Optional[Path] = None,
              manifest: Optional[dict] = None) -> dict:
    rows = _audit_rows(engagement, memdir)
    per_path: Dict[str, dict] = {}

    for row in rows:
        url = row.get("url") or ""
        if not isinstance(url, str) or not url.startswith("http"):
            continue
        key = _path_key(url)
        rec = per_path.setdefault(key, {
            "path": key,
            "host": urllib.parse.urlsplit(url).hostname or "",
            "requests": 0,
            "methods": set(),
            "values": set(),
            "content_types": set(),
            "headers_seen": set(),
            "has_auth": False,
            "has_no_auth": False,
            "has_identity_header": False,
            "has_override_header": False,
            "has_body": False,
            "status": set(),
            "body_sha256": set(),
        })
        rec["requests"] += 1
        method = (row.get("method") or "").upper()
        if method:
            rec["methods"].add(method)
        vals = _values_of(row)
        rec["values"].update(vals)
        hdrs = _headers_of(row)
        for hk, hv in hdrs.items():
            rec["headers_seen"].add(hk.lower())
            if hk.lower() == "content-type":
                rec["content_types"].add(hv.split(";")[0].strip().lower())
            if IDENTITY_HEADERS.match(hk):
                rec["has_identity_header"] = True
            if OVERRIDE_HEADERS.match(hk):
                rec["has_override_header"] = True
            if hk.lower() in ("authorization", "cookie", "x-api-key", "x-auth-token"):
                rec["has_auth"] = True
        if not any(h.lower() in ("authorization", "cookie", "x-api-key", "x-auth-token")
                   for h in hdrs):
            rec["has_no_auth"] = True
        body = row.get("body") or row.get("data")
        if isinstance(body, str) and body.strip():
            rec["has_body"] = True
        for v in vals:
            for piece in v.split("=", 1):
                if GARBAGE.match(piece.strip().strip('"')):
                    rec["has_garbage"] = True
                    break
        st = row.get("status") or row.get("status_code")
        if st is not None:
            rec["status"].add(st)
        sha = row.get("body_sha256")
        if sha:
            rec["body_sha256"].add(sha)

    # Also count corpus-only distinct bodies when the audit row lacks the hash.
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import responses as R  # type: ignore
        for rec in per_path.values():
            try:
                distinct = R.distinct(R.rows(url_substr=rec["path"], engagement=engagement))
                for d in distinct:
                    if isinstance(d, str) and len(d) == 64:
                        rec["body_sha256"].add(d)
            except Exception:
                pass
    except Exception:
        pass

    out_rows = []
    for rec in per_path.values():
        dims = []
        if len(rec["values"]) >= 2:
            dims.append("second-input")
        if len(rec["methods"]) >= 2:
            dims.append("method")
        if rec["has_auth"]:
            dims.append("auth-present")
        if rec["has_no_auth"]:
            dims.append("auth-absent")
        if rec["has_auth"] and rec["has_no_auth"]:
            dims.append("principal-contrast")
        if rec.get("has_identity_header"):
            dims.append("identity-header")
        if rec.get("has_override_header"):
            dims.append("override-header")
        if len(rec["content_types"]) >= 2:
            dims.append("content-type")
        if rec.get("has_garbage"):
            dims.append("garbage-input")
        if rec["has_body"]:
            dims.append("body-present")
        never = [d for d in DIMENSIONS if d not in dims]
        out_rows.append({
            "path": rec["path"], "host": rec["host"],
            "requests": rec["requests"],
            "methods": sorted(rec["methods"]),
            "distinct_inputs": len(rec["values"]),
            "distinct_bodies": len(rec["body_sha256"]),
            "status": sorted(str(s) for s in rec["status"]),
            "dimensions_varied": dims,
            "dimensions_never_varied": never,
            "verdict": _verdict(rec, dims),
        })

    out_rows.sort(key=lambda r: (-r["requests"], r["path"]))

    # Join onto the manifest when given: name the operations, not just paths.
    if manifest:
        by_path = {_path_key(o.get("path") or ""): o for o in (manifest.get("operations") or [])}
        for r in out_rows:
            op = by_path.get(_path_key(r["path"])) or by_path.get(r["path"])
            if op:
                r["operation_id"] = op.get("id")
                r["risk_hints"] = list(op.get("risk_hints") or [])

    gaps = {
        "never-second-input": [r["path"] for r in out_rows
                               if "second-input" not in r["dimensions_varied"]],
        "never-method-swapped": [r["path"] for r in out_rows
                                 if "method" not in r["dimensions_varied"]],
        "never-auth-contrasted": [r["path"] for r in out_rows
                                  if "principal-contrast" not in r["dimensions_varied"]],
        "never-garbage": [r["path"] for r in out_rows
                          if "garbage-input" not in r["dimensions_varied"]],
        "single-capture": [r["path"] for r in out_rows if r["requests"] <= 1],
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "engagement": engagement or "(all)",
        "counts": {
            "paths": len(out_rows),
            "requests": sum(r["requests"] for r in out_rows),
            "paths_with_second_input": len(out_rows) - len(gaps["never-second-input"]),
            "paths_with_one_body_only": sum(1 for r in out_rows if r["distinct_bodies"] <= 1),
        },
        "dimensions": DIMENSIONS,
        "rows": out_rows,
        "gaps": gaps,
    }


def _verdict(rec: dict, dims: List[str]) -> str:
    if rec["requests"] <= 1:
        return "OBSERVED — one request is not a test"
    if not dims:
        return "UNTESTED — many requests, no dimension ever moved"
    if "second-input" not in dims:
        return "SHALLOW — nothing was ever given a second value"
    if len(rec["body_sha256"]) <= 1 and rec["requests"] >= 6:
        return "STUB-SHAPED — many requests, one distinct body"
    return "VARIED"


def to_markdown(result: dict) -> str:
    out = [f"# Coverage — {result['engagement']}", "",
           f"{result['counts']['paths']} paths, {result['counts']['requests']} requests. "
           f"{result['counts']['paths_with_second_input']} paths ever saw a second input; "
           f"{result['counts']['paths_with_one_body_only']} never changed their answer.", "",
           "A request is not a test. The table is the negative space: what has never "
           "been varied while everything else was held still.", ""]
    out.append("| path | req | bodies | varied | never | verdict |")
    out.append("|---|---|---|---|---|---|")
    for r in result["rows"][:60]:
        varied = ", ".join(r["dimensions_varied"]) or "—"
        never = ", ".join(r["dimensions_never_varied"][:3]) + ("…" if len(r["dimensions_never_varied"]) > 3 else "")
        out.append(f"| `{r['path']}` | {r['requests']} | {r['distinct_bodies']} | {varied} | {never} | {r['verdict']} |")
    out.append("")
    for name, paths in result["gaps"].items():
        if not paths:
            continue
        out.append(f"## Gap: {name} ({len(paths)})")
        out.append("")
        for p in paths[:25]:
            out.append(f"- `{p}`")
        out.append("")
    return "\n".join(out) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engagement", default="", help="limit to one engagement")
    ap.add_argument("--manifest", type=Path, default=None,
                    help="join results onto an api_manifest.json")
    ap.add_argument("--dir", type=Path, default=None, help="hunt-memory directory")
    ap.add_argument("--format", choices=("json", "md"), default="json")
    ap.add_argument("--gap", default="",
                    choices=("", "second-input", "method", "auth-contrast", "garbage", "single-capture"),
                    help="print only this gap list")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    manifest = None
    if args.manifest:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    result = summarize(args.engagement, memdir=args.dir, manifest=manifest)

    if args.gap:
        key = {"second-input": "never-second-input",
               "method": "never-method-swapped",
               "auth-contrast": "never-auth-contrasted",
               "garbage": "never-garbage",
               "single-capture": "single-capture"}[args.gap]
        text = "".join(p + "\n" for p in result["gaps"][key])
    else:
        text = to_markdown(result) if args.format == "md" else \
            json.dumps(result, indent=2, ensure_ascii=False) + "\n"

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"{args.out}: {result['counts']['paths']} paths")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
