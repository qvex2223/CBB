#!/usr/bin/env python3
"""program_scout — which Standoff 365 programme is worth the next week, and what changed.

Written 2026-10-20. Programme choice was manual and 66 of 70 programmes were never
touched; VK cut its payouts between two snapshots and we found out by accident.

Reads ONLY the platform (bugbounty.standoff365.com, the public programme pages a
browser loads) — never a programme's own assets. ~1 request/second.

  1. listing (10 pages) -> every published programme, open to any country;
  2. detail page only for programmes whose `updatedAt` moved since the last snapshot
     (or that are new) — reward bands, scopes, full text;
  3. snapshot -> Targets/standoff365/raw/programs-YYYYMMDD/;
  4. diff vs the previous snapshot: new / gone / reward changed / scope changed / text changed;
  5. score and write Targets/standoff365/PROGRAM-SCOUT.md.

The score is a ranking proxy, not a forecast:
    average bounty × acceptance rate × activity (recent accepted report) × freshness,
then reduced by walls this workspace already measured on that programme.

usage: program_scout.py [--offline]   (--offline re-scores the latest snapshot, no network)
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))
BASE = "https://bugbounty.standoff365.com"
UA = "Mozilla/5.0 (X11; Linux x86_64) cbh-program-scout"
DELAY = 1.0
WALL = re.compile(r"(egress|\bsms\b|phone|телефон|legal entity|юрлиц|login wall|@intigriti\.me|captcha)", re.I)


def _hub():
    from paths import targets_root
    return targets_root() / "standoff365"


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def _build_id() -> str:
    html = _get(f"{BASE}/en-US/programs/?allowedCountries=true").decode("utf-8", "replace")
    m = re.search(r'"buildId":"([^"]+)"', html)
    if not m:
        raise RuntimeError("buildId not found on the listing page")
    return m.group(1)


def fetch_listing(build: str):
    progs, page, pages = [], 1, 1
    while page <= pages:
        data = json.loads(_get(f"{BASE}/_next/data/{build}/en-US/programs.json"
                               f"?allowedCountries=true&page={page}"))["pageProps"]
        pages = int(data.get("total") or 1)
        progs += data.get("programs") or []
        page += 1
        time.sleep(DELAY)
    seen, out = set(), []
    for p in progs:                                   # `offset=` is ignored by the platform; `page=` works
        if p.get("status") == "published" and p["slug"] not in seen:
            seen.add(p["slug"])
            out.append(p)
    return out


def fetch_detail(build: str, slug: str) -> dict:
    return json.loads(_get(f"{BASE}/_next/data/{build}/en-US/programs/{slug}.json?slug={slug}"))


def _snapshots(hub: Path):
    """Dated snapshots, oldest first; the undated 2026-10-12 import counts as the first."""
    dated = sorted(p for p in (hub / "raw").glob("programs-2*") if p.is_dir())
    legacy = hub / "raw" / "programs"
    return ([legacy] if legacy.is_dir() else []) + dated


def _h(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]


def _fingerprint(detail: dict) -> dict:
    pp = detail.get("pageProps") or {}
    prog = pp.get("program") or {}
    return {"reward": _h(pp.get("reward")), "scopes": _h(pp.get("scopes")),
            "text": _h(prog.get("description")), "updatedAt": prog.get("updatedAt")}


def snapshot(hub: Path, today: str):
    build = _build_id()
    listing = fetch_listing(build)
    prev_dirs = [d for d in _snapshots(hub) if d.name != f"programs-{today}"]
    prev = prev_dirs[-1] if prev_dirs else None
    out = hub / "raw" / f"programs-{today}"
    out.mkdir(parents=True, exist_ok=True)
    fetched = 0
    for p in listing:
        slug = p["slug"]
        old = prev / f"{slug}.json" if prev else None
        cached = None
        if old and old.is_file():
            try:
                cached = json.loads(old.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                cached = None
        same = cached and (cached.get("pageProps") or {}).get("program", {}).get("updatedAt") == p.get("updatedAt")
        if same:
            detail = cached
            detail["pageProps"]["program"]["statistics"] = p.get("statistics")   # stats move daily
        else:
            detail = fetch_detail(build, slug)
            fetched += 1
            time.sleep(DELAY)
        (out / f"{slug}.json").write_text(json.dumps(detail, ensure_ascii=False), encoding="utf-8")
    (out / "_listing.json").write_text(json.dumps(listing, ensure_ascii=False), encoding="utf-8")
    return out, prev, fetched


def load_snapshot(d: Path):
    res = {}
    for f in sorted(d.glob("*.json")):
        if f.name.startswith("_"):
            continue
        try:
            res[f.stem] = json.loads(f.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            pass
    return res


def diff(prev: dict, cur: dict):
    rows = []
    for s in sorted(set(cur) - set(prev)):
        rows.append((s, "NEW programme"))
    for s in sorted(set(prev) - set(cur)):
        rows.append((s, "GONE (archived / unpublished / no longer open to any country)"))
    for s in sorted(set(cur) & set(prev)):
        a, b = _fingerprint(prev[s]), _fingerprint(cur[s])
        what = [k for k in ("reward", "scopes", "text") if a[k] != b[k]]
        if what:
            rows.append((s, "changed: " + ", ".join(what)))
    return rows


def _walls(slug: str, hub: Path):
    d = hub / slug
    walls = []
    if not d.is_dir():
        return walls
    scope = d / "scope.md"
    t = scope.read_text(encoding="utf-8", errors="replace") if scope.is_file() else ""
    if re.search(r"\b(TODO|DRAFT)\b", t[:4000]) and "READY" not in t[:4000]:
        walls.append("scope.md not filled")
    bt = d / "blocked-tests"
    if bt.is_dir():
        n = sum(1 for f in bt.glob("*.md") if WALL.search(f.read_text(encoding="utf-8", errors="replace")[:3000]))
        if n:
            walls.append(f"{n} identity/egress block(s) measured")
    return walls


SHRINK_K = 20         # pseudo-reports at the median: one 1.5M payout is not an average


def score(detail: dict, now: datetime, prior_avg: float = 0.0):
    prog = (detail.get("pageProps") or {}).get("program") or {}
    st = prog.get("statistics") or {}
    rub = ((st.get("rewards") or {}).get("rub") or {})
    avg = float(rub.get("averageBounty") or 0)
    acc, tot = st.get("reportsAccepted") or 0, st.get("reportsTotal") or 0
    rate = (acc + 1) / (tot + 4)                      # smoothed: a new programme is not 0%
    last = st.get("lastAcceptedReportDate")
    days = (now - datetime.fromisoformat(last.replace("Z", "+00:00"))).days if last else 365
    activity = math.exp(-days / 90)
    pub = prog.get("publishedAt")
    age = (now - datetime.fromisoformat(pub.replace("Z", "+00:00"))).days if pub else 9999
    fresh = 1.5 if age <= 30 else 1.0
    mx = float(rub.get("max") or 0)
    if not avg:                                       # no history yet: assume a tenth of the max
        avg = mx / 10
    if prior_avg:
        avg = (avg * acc + prior_avg * SHRINK_K) / (acc + SHRINK_K)
    return {"score": round(avg * rate * activity * fresh), "avg": int(avg), "max": int(mx),
            "accepted": acc, "total": tot, "days_since_accept": days, "age_days": age,
            "name": prog.get("name") or "", "terms": prog.get("terms") or "",
            "vendor": ((prog.get("vendor") or {}).get("name") or "")}


def render(cur: dict, changes, hub: Path, today: str, fetched=None) -> str:
    now = datetime.now(timezone.utc)
    avgs = sorted(float(((((d.get("pageProps") or {}).get("program") or {}).get("statistics") or {})
                         .get("rewards") or {}).get("rub", {}).get("averageBounty") or 0)
                  for d in cur.values())
    avgs = [a for a in avgs if a]
    prior = avgs[len(avgs) // 2] if avgs else 0.0
    rows = []
    for slug, det in cur.items():
        s = score(det, now, prior)
        s["slug"], s["walls"] = slug, _walls(slug, hub)
        if s["terms"] == "only_risks":
            s["walls"].append("risk-based programme (pays per business risk)")
        if s["vendor"] == "Positive Technologies" and re.match(r"(pt|mx)_", slug):
            s["walls"].append("vendor product (deploy it yourself), not a web estate")
        mult = 0.5 ** sum(1 for w in s["walls"] if "block" in w)
        mult *= 0.3 if any("vendor product" in w for w in s["walls"]) else 1.0
        s["adj"] = round(s["score"] * mult)
        rows.append(s)
    rows.sort(key=lambda r: -r["adj"])
    L = [f"# Standoff 365 — programme scout ({today})", "",
         "_Generated by `engine/program_scout.py` from the platform's public programme pages. "
         "Score = average bounty × smoothed acceptance × activity (last accepted report, 90-day decay) × "
         "freshness (×1.5 if published ≤30 days ago); the average is shrunk toward the median programme "
         f"({SHRINK_K} pseudo-reports) so one large payout does not top the table; then reduced by walls "
         "measured here (identity/egress block ×0.5 each, vendor product ×0.3). "
         "A ranking proxy, not a forecast._", ""]
    if fetched is not None:
        L += [f"Detail pages re-fetched this run: {fetched} (only programmes whose `updatedAt` moved).", ""]
    L += [f"## Changes since the previous snapshot — {len(changes)}", ""]
    L += [f"- **{s}** — {w}" for s, w in changes] or ["- none"]
    L += ["", "## Ranking", "",
          "| # | Programme | Adj. score | Avg ₽ | Max ₽ | Accepted / total | Last accept (days) | Age (days) | Walls |",
          "|---|---|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        n = lambda x: f"{x:,}".replace(",", " ")  # noqa: E731
        L.append(f"| {i} | `{r['slug']}` {r['name']} | {n(r['adj'])} | {n(r['avg'])} | {n(r['max'])} | "
                 f"{r['accepted']} / {r['total']} | {r['days_since_accept']} | {r['age_days']} | "
                 f"{'; '.join(r['walls']) or '—'} |")
    return "\n".join(L) + "\n"


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    hub = _hub()
    today = datetime.now().strftime("%Y%m%d")
    fetched = None
    if "--offline" in argv:
        snaps = _snapshots(hub)
        if not snaps:
            print("no snapshot yet — run without --offline", file=sys.stderr)
            return 1
        out, prev = snaps[-1], (snaps[-2] if len(snaps) > 1 else None)
    else:
        out, prev, fetched = snapshot(hub, today)
    cur = load_snapshot(out)
    changes = diff(load_snapshot(prev), cur) if prev else []
    (hub / "PROGRAM-SCOUT.md").write_text(render(cur, changes, hub, out.name[9:], fetched), encoding="utf-8")
    print(f"{len(cur)} programmes · {len(changes)} change(s) vs {prev.name if prev else '—'} · "
          f"wrote {hub / 'PROGRAM-SCOUT.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
