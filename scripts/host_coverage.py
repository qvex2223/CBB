#!/usr/bin/env python3
"""Offline: how much work does the record already hold for each host?

Written 2026-11-13 after an orchestrator brief called four hosts "never worked" that already had
measured rows (the worker had to re-plan its own lane). Run this BEFORE writing a brief that claims
a host is untouched. It sends nothing: it reads hosts/<name>.md and hunt-memory/audit.jsonl only.

  python3 scripts/host_coverage.py --project rteam/activ regform.kcell.kz jobs.kcell.kz
  python3 scripts/host_coverage.py --project rteam/activ --stdin < names.txt

Columns: rows = scan-log table rows in hosts/<name>.md, audit = lines in audit.jsonl naming the host
(the audit key is `urls`, not `url`, so this matches the raw line), verdict = UNWORKED / RECORD-ONLY
/ WORKED.
"""
import argparse, os, pathlib, sys

def count_rows(md: pathlib.Path) -> int:
    if not md.exists():
        return -1
    n = 0
    for line in md.read_text(errors="replace").splitlines():
        s = line.strip()
        # a scan-log row is a markdown table row that is neither the header nor the separator
        if s.startswith("|") and s.endswith("|") and "---" not in s and not s.lower().startswith("| when"):
            n += 1
    return n

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="engagement path under Targets/, e.g. rteam/activ")
    ap.add_argument("--targets-root", default=os.environ.get("CBH_TARGETS_ROOT", "Targets"))
    ap.add_argument("--memory-dir", default=os.environ.get("CBH_MEMORY_DIR", "hunt-memory"))
    ap.add_argument("--stdin", action="store_true", help="read names from stdin as well")
    ap.add_argument("names", nargs="*")
    a = ap.parse_args()

    names = list(a.names)
    if a.stdin:
        names += [l.strip() for l in sys.stdin if l.strip() and not l.startswith("#")]
    if not names:
        ap.error("no host names given")

    eng = pathlib.Path(a.targets_root) / a.project
    audit = pathlib.Path(a.memory_dir) / "audit.jsonl"
    audit_lines = audit.read_text(errors="replace").splitlines() if audit.exists() else []

    print(f"{'host':40s} {'rows':>5s} {'audit':>6s}  verdict")
    for n in names:
        rows = count_rows(eng / "hosts" / f"{n}.md")
        hits = sum(1 for l in audit_lines if n in l)
        if rows < 0 and hits == 0:
            verdict = "UNWORKED — no host file, no audit row"
        elif hits == 0:
            verdict = "RECORD-ONLY — host file exists but nothing was ever fired at it"
        elif rows <= 0:
            verdict = "WORKED — audit rows exist but the host file has no scan-log row (write it up)"
        else:
            verdict = "WORKED — read the host file before briefing it"
        print(f"{n:40s} {rows if rows >= 0 else '-':>5} {hits:>6}  {verdict}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
