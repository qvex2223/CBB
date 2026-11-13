#!/usr/bin/env python3
"""Compact digest of hunt-memory/audit.jsonl — what actually flew, per host.

The audit log is raw request data; this turns it into the short summary that
belongs in `hosts/<host>.md`. Use it after a batch, and to catch up if the
written notes ever fall behind the trail.

  python3 scripts/audit-digest.py --engagement kruidvat
  python3 scripts/audit-digest.py --engagement kruidvat --since 2026-10-13
  python3 scripts/audit-digest.py --engagement kruidvat --interesting
"""
import argparse, json, os, collections
from urllib.parse import urlparse

def memory_dir():
    env = os.environ.get("CBH_MEMORY_DIR")
    if env:
        return env
    here = os.path.abspath(os.getcwd())
    while True:
        cand = os.path.join(here, "hunt-memory")
        if os.path.isdir(cand):
            return cand
        parent = os.path.dirname(here)
        if parent == here:
            return os.path.expanduser("~/.cbh/hunt-memory")
        here = parent

BORING = {"404", "403", "405", "000"}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engagement")
    ap.add_argument("--since", help="ISO date prefix, e.g. 2026-10-13")
    ap.add_argument("--interesting", action="store_true",
                    help="only rows whose status is not 404/403/405/000")
    a = ap.parse_args()
    path = os.path.join(memory_dir(), "audit.jsonl")
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if a.engagement:
        rows = [r for r in rows if r.get("engagement") == a.engagement]
    if a.since:
        rows = [r for r in rows if (r.get("timestamp") or "") >= a.since]
    if not rows:
        print("no matching rows")
        return
    print(f"{len(rows)} requests  {min(r['timestamp'] for r in rows)[:19]} .. "
          f"{max(r['timestamp'] for r in rows)[:19]}")
    per = collections.defaultdict(lambda: {"n": 0, "codes": collections.Counter(),
                                           "paths": collections.Counter()})
    for r in rows:
        url = (r.get("urls") or [r.get("url_effective") or ""])[0]
        u = urlparse(url)
        host = u.netloc or "?"
        code = str(r.get("http_code") or "")
        if a.interesting and code in BORING:
            continue
        d = per[host]
        d["n"] += 1
        d["codes"][code or "-"] += 1
        d["paths"][(u.path or "/") + ("?" + u.query.split("&")[0] if u.query else "")] += 1
    for host, d in sorted(per.items(), key=lambda kv: -kv[1]["n"]):
        codes = " ".join(f"{c}x{n}" for c, n in d["codes"].most_common())
        print(f"\n{host}  ({d['n']} req)  {codes}")
        notable = [(p, n) for p, n in d["paths"].most_common(12)]
        for p, n in notable:
            print(f"    {n:3d}  {p[:96]}")

if __name__ == "__main__":
    main()
