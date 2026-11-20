#!/usr/bin/env python3
"""Keep the local Caido instance on the ONE shared project every engagement records into.

Operator directive 2026-11-18: one Caido project for every programme, not one per
engagement — `standoff365-wildberries` and `standoff365-konsol` were deleted and replaced by
`bughunter`. Before this nothing chose the project at all: whatever was current when a hunt
started got the traffic, and on 2026-11-17/18 that was a project named after a programme that
was not being hunted.

Because every programme shares one history, a reader of it MUST filter by host:
`caido_list_requests` with HTTPQL `req.host.cont:"<program domain>"`. An unfiltered listing
is another programme's traffic as often as not.

Usage:
    python3 engine/caido_project.py [--ensure] [--json]

With no `--ensure` it reports. With `--ensure` it selects the shared project, creating it when
absent. It talks only to the local instance (127.0.0.1); it never touches a target. Never
raises into a caller: Caido being down or unauthenticated is a reported state.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

SHARED_PROJECT = os.environ.get("CBH_CAIDO_PROJECT", "bughunter")
TOKEN_PATH = Path(os.environ.get("CBH_CAIDO_TOKEN", str(Path.home() / ".caido-mcp" / "token.json")))
CAIDO_URL = (os.environ.get("CAIDO_URL") or os.environ.get("CBH_CAIDO_URL")
             or "http://127.0.0.1:8080").rstrip("/")
_ERRORS = (OSError, urllib.error.URLError, RuntimeError, ValueError)


def _token() -> str:
    try:
        return json.loads(TOKEN_PATH.read_text(encoding="utf-8")).get("accessToken") or ""
    except (OSError, ValueError):
        return ""


def _gql(query: str, variables: dict | None = None, timeout: float = 8.0) -> dict:
    tok = _token()
    if not tok:
        raise RuntimeError(f"no Caido token at {TOKEN_PATH} (docs/caido.md, 'Finishing the login')")
    req = urllib.request.Request(
        CAIDO_URL + "/graphql",
        data=json.dumps({"query": query, "variables": variables or {}}).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + tok})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # local instance only
        out = json.loads(r.read())
    if out.get("errors"):
        raise RuntimeError("; ".join(e.get("message", "?") for e in out["errors"]))
    return out.get("data") or {}


def state() -> dict:
    d = _gql("query { currentProject { project { id name } } projects { id name status } }")
    cur = ((d.get("currentProject") or {}).get("project") or {})
    return {"current": cur.get("name") or "", "current_id": cur.get("id") or "",
            "projects": d.get("projects") or []}


def ensure() -> dict:
    """Select (creating if needed) the shared project. A dict, never an exception."""
    want = SHARED_PROJECT
    try:
        st = state()
    except _ERRORS as e:
        return {"ok": False, "want": want, "action": "none", "why": f"Caido unreachable: {e}"}
    if st["current"] == want:
        return {"ok": True, "want": want, "action": "already-current", "current": want}
    try:
        pid = next((p["id"] for p in st["projects"] if p.get("name") == want), "")
        created = False
        if not pid:
            d = _gql("mutation($i: CreateProjectInput!) { createProject(input: $i) "
                     "{ project { id name } error { __typename } } }",
                     {"i": {"name": want, "temporary": False}})
            pr = (d.get("createProject") or {}).get("project") or {}
            pid, created = pr.get("id") or "", True
            if not pid:
                return {"ok": False, "want": want, "action": "create-failed",
                        "current": st["current"], "why": json.dumps(d.get("createProject"))}
        d = _gql("mutation($id: ID!) { selectProject(id: $id) { currentProject "
                 "{ project { id name } } error { __typename } } }", {"id": pid})
        got = ((((d.get("selectProject") or {}).get("currentProject") or {})
                .get("project") or {}).get("name") or "")
        return {"ok": got == want, "want": want, "previous": st["current"], "current": got,
                "action": ("created+selected" if created else "selected") if got == want
                else "select-failed"}
    except _ERRORS as e:
        return {"ok": False, "want": want, "action": "error", "current": st["current"],
                "why": str(e)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    # Accepted and ignored: callers written for the per-engagement version pass one.
    ap.add_argument("engagement", nargs="?", default="")
    ap.add_argument("--ensure", action="store_true", help="select/create the shared project")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.ensure:
        out = ensure()
    else:
        try:
            st = state()
            out = {"ok": st["current"] == SHARED_PROJECT, "want": SHARED_PROJECT,
                   "current": st["current"], "action": "report",
                   "projects": [p.get("name") for p in st["projects"]]}
        except _ERRORS as e:
            out = {"ok": False, "want": SHARED_PROJECT, "action": "none",
                   "why": f"Caido unreachable: {e}"}
    if a.json:
        print(json.dumps(out, ensure_ascii=False))
    else:
        mark = "OK" if out.get("ok") else "MISMATCH" if out.get("current") else "UNKNOWN"
        print(f"caido-project {mark}: want `{out['want']}`, current `{out.get('current', '?')}`"
              f" ({out.get('action')})" + (f" — {out['why']}" if out.get("why") else ""))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
