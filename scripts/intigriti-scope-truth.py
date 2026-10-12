#!/usr/bin/env python3
"""Emit the authoritative, latest-revision scope block for an Intigriti brief.

Both `assetsCollection` and `bountyTables` are LISTS OF DATED REVISIONS (oldest
first). Only [-1] is live. bountyRows carry an explicit bountyTierId, so the
tier -> reward-band mapping is in the data and never has to be guessed.
bountyTierId 5 == out of scope (no bounty row exists for it).
"""
import json, os, sys, datetime

BRIEFS = "/opt/Claude/Targets/_INTIGRITI-CANDIDATES/briefs"
TYPES = {1: "domain", 2: "Android", 3: "iOS", 4: "binary", 5: "source",
         6: "other/descriptive", 7: "wildcard/url"}

def d(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime("%Y-%m-%d") if ts else "?"

def latest(coll):
    return (coll or [None])[-1]

def bands(brief):
    """{tierId: [(minScore,maxScore,minB,maxB,currency), ...]} from the LAST revision."""
    rev = latest(brief.get("bountyTables"))
    if not rev:
        return {}, "?"
    out = {}
    for row in rev.get("content", {}).get("bountyRows", []):
        tid = row.get("bountyTierId")
        rows = []
        for r in row.get("bountyRanges", []):
            mn, mx = r.get("minBounty") or {}, r.get("maxBounty") or {}
            rows.append((r.get("minScore"), r.get("maxScore"),
                         mn.get("value"), mx.get("value"),
                         mn.get("currency") or rev.get("content", {}).get("currency") or ""))
        out[tid] = rows
    return out, d(rev.get("createdAt"))

def report(key):
    brief = json.load(open(os.path.join(BRIEFS, key + ".json"), encoding="utf-8"))
    ac = brief.get("assetsCollection") or []
    rev = latest(ac)
    assets = rev["content"]["assetsAndGroups"]
    bmap, bdate = bands(brief)
    print(f"\n##### {key}")
    print(f"assetsCollection: {len(ac)} revisions, live = {d(rev.get('createdAt'))}")
    print(f"bountyTables:     {len(brief.get('bountyTables') or [])} revisions, live = {bdate}")
    tiers = {}
    for a in assets:
        tiers.setdefault(a.get("bountyTierId"), []).append(a)
    for t in sorted(tiers, key=lambda x: (x is None, -(x or 0))):
        oos = " == OUT OF SCOPE (no bounty row)" if t == 5 or t not in bmap else ""
        print(f"  tier {t}{oos}")
        if t in bmap:
            bb = ", ".join(f"{r[0]}-{r[1]}: {r[2]:.0f}-{r[3]:.0f}" for r in bmap[t] if r[2] is not None)
            print(f"    bands: {bb} {bmap[t][0][4] if bmap[t] else ''}")
        for a in tiers[t]:
            print(f"    - [{TYPES.get(a.get('typeId'), a.get('typeId'))}] {(a.get('name') or '').strip()}")

for key in sys.argv[1:]:
    report(key)
