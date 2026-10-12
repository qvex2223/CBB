#!/usr/bin/env python3
"""Audit every Intigriti-derived Targets/<proj>/scope.md asset list against the
LATEST assetsCollection revision in _INTIGRITI-CANDIDATES/briefs/.

The capitalcom bug: scope.md was built from the UNION of all dated revisions of
`assetsCollection`, so assets removed from the program years ago still read as in scope.

Flags per project:
  STALE   - declared in scope.md, absent from latest revision, present in an older one
  PHANTOM - declared in scope.md, absent from every revision
  TIER5   - declared as in scope, but bountyTierId == 5 (program says out of scope)
  MISSING - host-shaped asset in latest revision, absent from scope.md
"""
import json, os, re, datetime

ROOT = "/opt/Claude/Targets"
BRIEFS = os.path.join(ROOT, "_INTIGRITI-CANDIDATES", "briefs")

HOSTISH = re.compile(r"^[*a-z0-9][a-z0-9.*_-]*\.[a-z]{2,}(?:/.*)?$")
PKGISH  = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,}$")

def norm(n):
    n = (n or "").strip().strip("`").strip().lower()
    n = re.sub(r"^https?://", "", n)
    return n.rstrip("/")

def asset_like(t):
    if not t or " " in t:
        return False
    if t.endswith(".json") and "/" in t and not HOSTISH.match(t):
        return False
    return bool(HOSTISH.match(t) or PKGISH.match(t))

def revisions(brief):
    out = []
    for rev in brief.get("assetsCollection") or []:
        ts = rev.get("createdAt")
        date = (datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime("%Y-%m-%d")
                if ts else "?")
        names = {}
        for a in rev.get("content", {}).get("assetsAndGroups", []):
            nm = norm(a.get("name"))
            if nm:
                names.setdefault(nm, a.get("bountyTierId"))
        out.append((date, names))
    return out

briefs = {}
for fn in os.listdir(BRIEFS):
    if fn.endswith(".json"):
        briefs[fn[:-5].lower()] = os.path.join(BRIEFS, fn)

def find_brief(text):
    m = re.search(r"intigriti\.com/(?:researcher/)?programs/([\w.-]+)/([\w.-]+)", text)
    if m:
        key = f"{m.group(1).lower()}__{m.group(2).lower()}"
        if key in briefs:
            return briefs[key], key
        for k, v in briefs.items():
            if k.endswith("__" + m.group(2).lower()):
                return v, k
    m = re.search(r"^Handle:\s*(\S+)", text, re.M)
    if m:
        h = m.group(1).strip("`").lower()
        for k, v in briefs.items():
            if k.endswith("__" + h):
                return v, k
    return None, None

def declared_assets(text):
    """(names, which_section). Prefer ## Assets, else ## In scope."""
    for head in ("## Assets", "## In scope"):
        m = re.search(r"^" + re.escape(head) + r"\b(.*?)(?=^## |\Z)", text, re.M | re.S)
        if not m:
            continue
        body = m.group(1)
        cut = re.search(r"^###.*(REMOVED|OUT OF SCOPE|OOS|TIER ?5).*$", body, re.M | re.I)
        if cut:
            body = body[: cut.start()]
        names, seen = [], set()
        for tok in re.findall(r"`([^`]+)`", body):
            t = norm(tok)
            if asset_like(t) and t not in seen:
                seen.add(t); names.append(t)
        if not names:   # unquoted bullet lists
            for line in body.splitlines():
                t = norm(re.sub(r"^[\s*\-|]+", "", line).split("—")[0].split("|")[0])
                if asset_like(t) and t not in seen:
                    seen.add(t); names.append(t)
        if names:
            return names, head
    return None, None

rows = []
for proj in sorted(os.listdir(ROOT)):
    sp = os.path.join(ROOT, proj, "scope.md")
    if not os.path.isfile(sp) or proj == "_TEMPLATE":
        continue
    text = open(sp, encoding="utf-8", errors="replace").read()
    if "intigriti" not in text.lower():
        rows.append((proj, "-", "NOT-INTIGRITI", {})); continue
    bp, key = find_brief(text)
    if not bp:
        rows.append((proj, "-", "BRIEF-NOT-FOUND", {})); continue
    revs = revisions(json.load(open(bp, encoding="utf-8")))
    if not revs:
        rows.append((proj, key, "NO-ASSETSCOLLECTION", {})); continue
    latest_date, latest = revs[-1]
    older = {}
    for d, names in revs[:-1]:
        for n in names:
            older[n] = d          # last date it was seen
    decl, section = declared_assets(text)
    if decl is None:
        rows.append((proj, key, "NO-ASSET-LIST-PARSED", {"revs": len(revs)})); continue
    stale   = [(n, older[n]) for n in decl if n not in latest and n in older]
    phantom = [n for n in decl if n not in latest and n not in older]
    tier5   = [n for n in decl if latest.get(n) == 5]
    missing = [n for n in latest if n not in decl and latest.get(n) != 5 and asset_like(n)]
    verdict = "DIRTY" if (stale or phantom or tier5) else "CLEAN"
    rows.append((proj, key, verdict, dict(
        latest_date=latest_date, revs=len(revs), section=section,
        declared=len(decl), live=len(latest),
        stale=stale, phantom=phantom, tier5=tier5, missing=missing)))

print("=" * 80)
print("INTIGRITI SCOPE AUDIT —", datetime.date.today().isoformat())
print("=" * 80)
for proj, key, verdict, d in rows:
    if verdict in ("NOT-INTIGRITI",):
        continue
    if not d:
        print(f"\n[{verdict}] {proj}   brief={key}")
        continue
    print(f"\n[{verdict:<5}] {proj}   brief={key}  revs={d.get('revs')}  "
          f"latest={d.get('latest_date')}  section='{d.get('section')}'  "
          f"declared={d.get('declared')} live={d.get('live')}")
    for label, items in (("STALE  (removed from program, still listed)", d.get("stale")),
                         ("PHANTOM(in no revision at all)", d.get("phantom")),
                         ("TIER5  (program says OUT OF SCOPE)", d.get("tier5"))):
        if items:
            print(f"   {label}:")
            for it in items:
                print("     - " + (f"{it[0]}   (last in revision {it[1]})"
                                   if isinstance(it, tuple) else str(it)))
    if d.get("missing"):
        ms = d["missing"]
        print(f"   MISSING from scope.md ({len(ms)}): " + ", ".join(ms[:14])
              + (" …" if len(ms) > 14 else ""))

print("\n" + "=" * 80)
for tag in ("DIRTY", "CLEAN", "NO-ASSET-LIST-PARSED", "BRIEF-NOT-FOUND", "NO-ASSETSCOLLECTION"):
    hits = [r[0] for r in rows if r[2] == tag]
    if hits:
        print(f"{tag} ({len(hits)}): {', '.join(hits)}")
skipped = [r[0] for r in rows if r[2] == "NOT-INTIGRITI"]
print(f"NOT-INTIGRITI, skipped ({len(skipped)}): {', '.join(skipped)}")
