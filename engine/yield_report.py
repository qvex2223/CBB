#!/usr/bin/env python3
"""yield_report — requests spent vs what came out of them, per engagement per day.

Written 2026-10-20. Ozon ran 22 waves and ~2 800 requests before anyone wrote down
"0 Medium+"; a per-day line would have said it at wave 5. This reads only local
files: audit.jsonl (requests) and the mtimes of files in leads/, primitives/,
findings/ (what the requests produced).

usage: yield_report.py [<engagement name>] [--days N]
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))
TIERS = ("leads", "primitives", "findings")
DRY_REQUESTS = 300       # this many requests with no new finding file is a warning


def _day(ts) -> str | None:
    try:
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except Exception:  # noqa: BLE001
        return None


def requests_by_day(memdir: Path):
    out = defaultdict(lambda: defaultdict(int))
    p = memdir / "audit.jsonl"
    if not p.is_file():
        return out
    with p.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            d = _day(r.get("timestamp"))
            if d:
                out[r.get("engagement") or "?"][d] += 1
    return out


def _born(f: Path) -> str:
    """When the file was created: date in its name, else birth time, else mtime.

    mtime alone lies — appending one line to an old primitive moves it to today.
    """
    import re
    m = re.match(r"(\d{4}-\d{2}-\d{2})", f.name)
    if m:
        return m.group(1)
    head = "\n".join(f.read_text(encoding="utf-8", errors="replace").splitlines()[:15])
    m = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", head)
    if m:
        return m.group(1)
    st = f.stat()
    ts = getattr(st, "st_birthtime", None) or st.st_mtime
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")


def outputs_by_day(eng_dir: Path):
    out = defaultdict(lambda: defaultdict(int))
    for tier in TIERS:
        d = eng_dir / tier
        if not d.is_dir():
            continue
        # a tier holds either flat files (legacy) or one folder per item:
        # findings/<slug>/<slug>.md  — count the folder's own .md, not its report/ drafts
        for f in sorted(list(d.glob("*.md")) + list(d.glob("*/*.md"))):
            if f.name.startswith(("SUBMIT-", "REPORT-", "ANNEX-")):
                continue
            if f.parent != d and f.stem != f.parent.name:
                continue  # an extra .md inside an item folder is not a second item
            day = _born(f)
            out[day][tier] += 1
    return out


def _engagement_dirs():
    from paths import targets_root
    root = targets_root()
    return {d.parent.name: d.parent for d in root.glob("**/profile.json") if "_TEMPLATE" not in d.parts}


def report(name: str, days: int = 14):
    from paths import memory_dir
    reqs = requests_by_day(memory_dir()).get(name, {})
    eng = _engagement_dirs().get(name)
    outs = outputs_by_day(eng) if eng else {}
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = []
    for day in sorted(set(reqs) | set(outs)):
        if day < cutoff:
            continue
        o = outs.get(day, {})
        rows.append({"day": day, "requests": reqs.get(day, 0),
                     **{t: o.get(t, 0) for t in TIERS}})
    return rows


def dry_streak(rows):
    """Requests since the last day that produced a finding file."""
    n = 0
    for r in reversed(rows):
        if r["findings"]:
            break
        n += r["requests"]
    return n


def brief_line(name: str) -> str:
    rows = report(name, days=30)
    if not rows:
        return ""
    total = sum(r["requests"] for r in rows)
    f = sum(r["findings"] for r in rows)
    p = sum(r["primitives"] for r in rows)
    dry = dry_streak(rows)
    line = f"YIELD (30d): {total} requests → {f} finding file(s), {p} primitive(s)"
    if dry >= DRY_REQUESTS:
        line += (f" · DRY: {dry} requests since the last new finding — "
                 "change host or class, not payload (`cbh yield " + name + "`)")
    return line


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    days = 14
    if "--days" in argv:
        days = int(argv[argv.index("--days") + 1])
    names = [a for a in argv if not a.startswith("--") and not a.isdigit()]
    if not names:
        from pacing import find_project_dir
        d = find_project_dir()
        names = [d.name] if d else sorted(requests_by_day(__import__("paths").memory_dir()))
    for name in names:
        rows = report(name, days)
        print(f"\n{name}" + (f"  · dry streak {dry_streak(rows)} requests" if rows else "  · no data"))
        if rows:
            print(f"  {'day':<11}{'requests':>9}{'leads':>7}{'prims':>7}{'finds':>7}")
            for r in rows:
                print(f"  {r['day']:<11}{r['requests']:>9}{r['leads']:>7}{r['primitives']:>7}{r['findings']:>7}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
