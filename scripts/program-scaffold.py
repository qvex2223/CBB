#!/usr/bin/env python3
"""Scaffold one normalized folder per Intigriti program.

Every program gets _INTIGRITI-CANDIDATES/programs/<companyHandle__handle>/ with:
  scope.md    - house-format scope, built ONLY from live (last) revisions
  program.json- machine-readable normalization (assets, tiers, bands, counts)
  _TEMPLATE engagement skeleton (findings/, hosts/, evidence/, recon/, ...)

Same revision discipline as intigriti-scope-truth.py: assetsCollection and
bountyTables are LISTS OF DATED REVISIONS, only [-1] is live. tier 5 == out of
scope; a tier with no bounty row == in scope but UNPAID.

  python3 program-scaffold.py --all
  python3 program-scaffold.py waterlink__water-link capitalcom__capitalcom
  python3 program-scaffold.py --key waterlink__water-link --force
"""
import argparse, json, os, re, shutil, sys, datetime, html as H

CAND   = "/opt/Claude/Targets/_INTIGRITI-CANDIDATES"
BRIEFS = os.path.join(CAND, "briefs")
OUT    = os.path.join(CAND, "programs")
TMPL   = "/opt/Claude/Targets/_TEMPLATE"
ROOT   = "/opt/Claude/Targets"

TYPES = {1: "domain", 2: "Android", 3: "iOS", 4: "binary", 5: "source",
         6: "other/descriptive", 7: "wildcard/url"}

def d(ts):
    return (datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime("%Y-%m-%d")
            if ts else "?")

def latest(coll):
    coll = coll or []
    return coll[-1] if coll else None

def section_text(section):
    """Flattened text of the LAST revision of a dated section."""
    rev = latest(section)
    if not rev:
        return ""
    parts = []
    def flat(v):
        if isinstance(v, str): parts.append(v)
        elif isinstance(v, list):
            for x in v: flat(x)
        elif isinstance(v, dict):
            for x in v.values(): flat(x)
    flat(rev.get("content", rev))
    t = H.unescape("\n".join(p for p in parts if isinstance(p, str)))
    return re.sub(r"\s+", " ", t.strip())

def bands(brief):
    """({tierId: [(minScore,maxScore,minB,maxB,cur),...]}, live_rev_date)."""
    rev = latest(brief.get("bountyTables"))
    if not rev:
        return {}, "?"
    out = {}
    cur_default = rev.get("content", {}).get("currency") or ""
    for row in rev.get("content", {}).get("bountyRows", []):
        rows = []
        for r in row.get("bountyRanges", []):
            mn, mx = r.get("minBounty") or {}, r.get("maxBounty") or {}
            rows.append((r.get("minScore"), r.get("maxScore"),
                         mn.get("value"), mx.get("value"),
                         mn.get("currency") or mx.get("currency") or cur_default))
        out[row.get("bountyTierId")] = rows
    return out, d(rev.get("createdAt"))

def fmt_bands(rows):
    return " · ".join(
        f"{r[0]}-{r[1]}: {r[2]:.0f}-{r[3]:.0f}" for r in rows if r[2] is not None
    ) + (f" {rows[0][4]}" if rows and rows[0][4] else "")

def active_project(key, url_handle):
    """Targets/<proj> already running this program, if any (match scope.md URL/handle)."""
    hits = []
    for proj in sorted(os.listdir(ROOT)):
        sp = os.path.join(ROOT, proj, "scope.md")
        if not os.path.isfile(sp):
            continue
        try:
            text = open(sp, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        low = text.lower()
        if "intigriti" not in low:
            continue
        if url_handle and url_handle.lower() in low:
            hits.append(proj)
            continue
        m = re.search(r"intigriti\.com/(?:researcher/)?programs/([\w.-]+)/([\w.-]+)", text)
        if m and f"{m.group(1).lower()}__{m.group(2).lower()}" == key:
            hits.append(proj)
    return hits

def load_programs_card():
    """minBounty/maxBounty from the public programs snapshot, keyed by company__handle."""
    path = os.path.join(CAND, "intigriti_programs.json")
    try:
        cards = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    out = {}
    for c in cards:
        out[f"{(c.get('companyHandle') or '').lower()}__{(c.get('handle') or '').lower()}"] = c
    return out

def build(key, card, force):
    src = os.path.join(BRIEFS, key + ".json")
    brief = json.load(open(src, encoding="utf-8"))
    dst = os.path.join(OUT, key)

    if os.path.isdir(dst) and not force:
        return f"SKIP  {key} (exists)"
    route = None
    if os.path.isdir(dst):
        rp = os.path.join(dst, "route.md")
        if os.path.isfile(rp):
            route = open(rp, encoding="utf-8").read()   # --force must not eat hunt work
        shutil.rmtree(dst)
    shutil.copytree(TMPL, dst)
    if route is not None:
        open(os.path.join(dst, "route.md"), "w", encoding="utf-8").write(route)

    ac_revs = brief.get("assetsCollection") or []
    ac = latest(ac_revs)
    assets = (ac or {}).get("content", {}).get("assetsAndGroups", []) if ac else []
    bmap, bdate = bands(brief)
    paid_tiers = set(bmap)
    today = datetime.date.today().isoformat()

    url = f"https://app.intigriti.com/programs/{brief.get('companyHandle')}/{brief.get('handle')}/detail"
    act = active_project(key, brief.get("handle"))

    # --- program.json: normalized machine view --------------------------------
    norm_assets = []
    for a in assets:
        tier = a.get("bountyTierId")
        norm_assets.append({
            "name": (a.get("name") or "").strip(),
            "type": TYPES.get(a.get("typeId"), a.get("typeId")),
            "tier": tier,
            "paid": tier in paid_tiers and tier != 5,
        })
    program = {
        "platform": "intigriti",
        "key": key,
        "company": brief.get("companyName"),
        "handle": brief.get("handle"),
        "name": brief.get("name"),
        "industry": brief.get("industry"),
        "status": brief.get("status"),
        "program_url": url,
        "generated": today,
        "revisions": {"assets": len(ac_revs), "assets_live": d(ac and ac.get("createdAt")),
                      "bounty_live": bdate},
        "submissions": {"total": brief.get("submissionCount"),
                        "accepted": brief.get("acceptedSubmissionCount")},
        "payouts_total": brief.get("totalPayout"),
        "payouts_average": brief.get("averagePayout"),
        "card_bounties": ({k: v for k, v in (card or {}).items()
                           if k in ("minBounty", "maxBounty", "lastSubmissionAt")}
                          if card else None),
        "tiers": {str(t): {"bands": [list(r) for r in bmap.get(t, [])],
                           "assets": [a["name"] for a in norm_assets if a["tier"] == t]}
                  for t in sorted({a["tier"] for a in norm_assets}, key=lambda x: (x is None, -(x or 0)))},
        "active_project": act[0] if len(act) == 1 else act,
    }
    json.dump(program, open(os.path.join(dst, "program.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)

    # --- scope.md: house format, live revisions only ---------------------------
    L = []
    L.append(f"# {brief.get('name')} — scope")
    L.append("")
    L.append(f"Platform: Intigriti")
    L.append(f"Program URL: {url}")
    L.append(f"Snapshot: generated {today} from brief `{key}.json` "
             f"(assets live rev {d(ac and ac.get('createdAt'))}, bounty live rev {bdate}). "
             f"Перед сабмитом перепроверить в дашборде.")
    if act:
        L.append(f"**УЖЕ В РАБОТЕ: `Targets/{act[0]}/`** — эта папка = справочник, находки туда." if len(act) == 1
                 else f"**ВНИМАНИЕ: похоже активна в {act} — сверить.**")
    L.append("")

    by_tier = {}
    for a in norm_assets:
        by_tier.setdefault(a["tier"], []).append(a)

    L.append("## In scope")
    for t in sorted(by_tier, key=lambda x: (x is None, -(x or 0))):
        if t == 5:
            continue
        tag = "PAID" if t in paid_tiers else "IN SCOPE, NO BOUNTY ROW = unpaid"
        band = f" · {fmt_bands(bmap[t])}" if t in bmap else ""
        L.append(f"\n### tier {t} — {tag}{band}")
        for a in by_tier[t]:
            L.append(f"- `{a['name']}` [{a['type']}]")
    L.append("")

    L.append("## Out of scope")
    for a in by_tier.get(5, []):
        L.append(f"- `{a['name']}` [{a['type']}] (tier 5)")
    oos_text = section_text(brief.get("outOfScopes"))
    if oos_text:
        L.append("")
        L.append("### Текст программы (последняя ревизия)")
        L.append("> " + oos_text[:4000])
    L.append("- Стандартный OOS Intigriti: `../README.md` (программный список выше приоритетнее)")
    L.append("")

    L.append("## Rules / limits")
    roe = section_text(brief.get("rulesOfEngagements"))
    L.append("> " + (roe[:4000] if roe else "(в брифе пусто — читать на странице программы)"))
    L.append("")

    ins_text = section_text(brief.get("inScopes"))
    if ins_text:
        L.append("## Focus (program)")
        L.append("> " + ins_text[:4000])
        L.append("")

    L.append("## VERIFIED SCOPE")
    L.append(f"Source: `briefs/{key}.json`. assetsCollection: {len(ac_revs)} revisions, "
             f"live = {d(ac and ac.get('createdAt'))}. bountyTables live = {bdate}. "
             f"Только этот блок верен; всё, что выше — его рендер.")
    L.append("")
    L.append("Tier semantics: **tier 5 = OUT OF SCOPE**; **tier без bounty row = unpaid**; "
             "tiers with bands = paid. `bountyTierId` ≠ номер тира в UI Intigriti — "
             "верить числам выплат, не ярлыку.")
    L.append("")

    counts = (f"{brief.get('submissionCount')} подано / {brief.get('acceptedSubmissionCount')} принято"
              if brief.get("submissionCount") is not None else "счётчики неизвестны")
    pay = f"total {brief.get('totalPayout')} / avg {brief.get('averagePayout')}" \
        if brief.get("totalPayout") is not None else "выплаты неизвестны"
    L.append(f"## Счётчики (из брифа)")
    L.append(f"- {counts} · {pay}")
    if card:
        mn, mx = card.get("minBounty") or {}, card.get("maxBounty") or {}
        if mn.get("value") is not None:
            L.append(f"- Карточка программы: {mn.get('value'):.0f}–{mx.get('value'):.0f} "
                     f"{mn.get('currency') or ''} · последний сабмит {d(card.get('lastSubmissionAt'))}")
    L.append("")

    open(os.path.join(dst, "scope.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")

    # per-program notes stub
    with open(os.path.join(dst, "notes.md"), "a", encoding="utf-8") as fh:
        fh.write(f"\n## Скаффолд {today}\nСоздан `program-scaffold.py` из `{key}.json`. "
                 f"Заполнять при старте.\n")
    return f"OK    {key}  assets={len(norm_assets)} tiers={sorted(t for t in by_tier if t is not None)}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("keys", nargs="*", help="brief keys company__handle")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--force", action="store_true", help="rebuild existing folders")
    a = ap.parse_args()

    os.makedirs(OUT, exist_ok=True)
    keys = a.keys
    if a.all:
        keys = sorted(fn[:-5] for fn in os.listdir(BRIEFS) if fn.endswith(".json"))
    if not keys:
        ap.error("give keys or --all")
    cards = load_programs_card()
    for key in keys:
        if not os.path.exists(os.path.join(BRIEFS, key + ".json")):
            print(f"MISS  {key} — нет брифа")
            continue
        card = cards.get(key.lower())
        try:
            print(build(key, card, a.force))
        except Exception as e:
            print(f"FAIL  {key}: {e}")

if __name__ == "__main__":
    sys.exit(main())
