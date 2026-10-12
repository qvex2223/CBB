#!/usr/bin/env python3
"""Scaffold one normalized folder per Standoff 365 program.

Reads the per-program .md files the recon pass wrote into
/opt/Claude/Targets/_STANDOFF-CANDIDATES/ (flat) and promotes each into
programs/<slug>/ with the full engagement skeleton (findings/, hosts/, ...).
The .md becomes scope.md as-is (it already carries URL, non-resident verdict,
bounty table, scope, focus, OOS) plus an ACTIVE banner when a Targets/ project
already runs this program. program.json gets the machine-readable fields.

  python3 standoff-scaffold.py            # scaffold all .md files
  python3 standoff-scaffold.py --force    # rebuild existing folders
"""
import argparse, json, os, re, shutil, sys, datetime

CAND = "/opt/Claude/Targets/_STANDOFF-CANDIDATES"
OUT  = os.path.join(CAND, "programs")
TMPL = "/opt/Claude/Targets/_TEMPLATE"
ROOT = "/opt/Claude/Targets"

# picks from the 2026-10-12 analysis (README.md verdict section)
PICKS = {"cloud_ru": 1, "hh_setka": 2, "tbki": 3,
         "anyquery": "reserve", "MyReviews": "reserve", "pt_ngfw": "reserve"}
# slug -> Targets/<proj> already running it. Explicit beats substring matching:
# "cu" substring-matched flowwow's scope.md in the first run — wrong link.
ACTIVE_ALIAS = {"hh_setka": "setka", "flowwow": "flowwow"}
# RF-only programs with no .md — folder stub so the check is not lost
RF_ONLY = [
    ("epgu-vybory", "ЕПГУ-Выборы (Минцифры)", "«Участниками могут быть только граждане РФ от 18 лет»"),
    ("logika-moloka", "Логика Молока", "allowedCountries:[643] — Only citizens of Russia"),
    ("portal-kontraktov-mo", "Портал контрактов МО (pik.mosreg.ru)", "allowedCountries:[643]; программа до 13.10.2026"),
]

def slug_of(text):
    m = re.search(r"bugbounty\.standoff365\.com/(?:[a-z-]+/)?programs/([a-z0-9_-]+)/?", text, re.I)
    return m.group(1) if m else None

def active_project(slug):
    if slug in ACTIVE_ALIAS:
        return ACTIVE_ALIAS[slug]
    n = slug.replace("_", "-")
    for proj in sorted(os.listdir(ROOT)):
        if proj.startswith("_") or not os.path.isdir(os.path.join(ROOT, proj)):
            continue
        sp = os.path.join(ROOT, proj, "scope.md")
        if not os.path.isfile(sp):
            continue
        try:
            t = open(sp, encoding="utf-8", errors="replace").read().lower()
        except OSError:
            continue
        if "standoff365" in t and re.search(r"\b" + re.escape(n) + r"\b", t):
            return proj
    return None

def build(md_path, force):
    text = open(md_path, encoding="utf-8").read()
    slug = slug_of(text) or os.path.splitext(os.path.basename(md_path))[0].lower()
    dst = os.path.join(OUT, slug)
    if os.path.isdir(dst) and not force:
        return f"SKIP  {slug} (exists)"
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    shutil.copytree(TMPL, dst)

    title = text.splitlines()[0].lstrip("# ").strip()
    # "Нерезидентам:** **да**…" / "нерезидентам: да (`allowedCountries…`" — take the
    # verdict word from whichever line mentions the topic.
    nonresident, nr_src = "неясно", ""
    for line in text.splitlines():
        if "ерезидент" not in line:
            continue
        m = re.search(r"\b(да|нет|формально)\b", line, re.I)
        if m:
            nonresident = m.group(1).lower()
            src = re.search(r"(`[^`]+`|«[^»]+»)", line)
            nr_src = src.group(1).strip("`«»") if src else line.strip()[:120]
            break
    today = datetime.date.today().isoformat()

    act = active_project(slug)
    banner = ""
    if act:
        banner = (f"\n**УЖЕ В РАБОТЕ: `Targets/{act}/`** — эта папка = справочник, находки туда.\n")

    open(os.path.join(dst, "scope.md"), "w", encoding="utf-8").write(
        f"> normalized {today} from `{os.path.basename(md_path)}` · "
        f"платформа: Standoff 365 · выплаты нерезиденту: Konsol (Foreign citizen), ₽, НДФЛ РФ удерживают\n"
        f"{banner}\n" + text + "\n")

    program = {
        "platform": "standoff365",
        "slug": slug, "title": title,
        "program_url": f"https://bugbounty.standoff365.com/programs/{slug}/",
        "generated": today,
        "nonresident": nonresident, "nonresident_source": nr_src,
        "payout_nonresident": "Konsol (Foreign citizen flow), RUB, RF NDFL withheld",
        "pick_2026_10_12": PICKS.get(slug),
        "active_project": act,
        "source_md": os.path.basename(md_path),
    }
    json.dump(program, open(os.path.join(dst, "program.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    with open(os.path.join(dst, "notes.md"), "a", encoding="utf-8") as fh:
        fh.write(f"\n## Скаффолд {today}\nСоздан `standoff-scaffold.py` из `{os.path.basename(md_path)}`.\n")
    return f"OK    {slug}  nonresident={nonresident} pick={PICKS.get(slug)} active={act}"

def build_rf_stub(slug, name, why, force):
    dst = os.path.join(OUT, slug)
    if os.path.isdir(dst) and not force:
        return f"SKIP  {slug} (exists)"
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    shutil.copytree(TMPL, dst)
    today = datetime.date.today().isoformat()
    open(os.path.join(dst, "scope.md"), "w", encoding="utf-8").write(
        f"# {name}\n\n**ВЕРДИКТ: НЕ ДЛЯ НАС — RF-only.** {why}.\n"
        f"Проверено 2026-10-12, подробности: `../../README.md`.\nНЕ ТЕСТИРОВАТЬ.\n")
    json.dump({"platform": "standoff365", "slug": slug, "title": name,
               "generated": today, "nonresident": "нет", "nonresident_source": why,
               "pick_2026_10_12": None, "verdict": "RF-ONLY, DO NOT TEST"},
              open(os.path.join(dst, "program.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    return f"OK    {slug}  RF-only stub"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    for fn in sorted(os.listdir(CAND)):
        if fn.endswith(".md") and fn != "README.md":
            try:
                print(build(os.path.join(CAND, fn), a.force))
            except Exception as e:
                print(f"FAIL  {fn}: {e}")
    for slug, name, why in RF_ONLY:
        print(build_rf_stub(slug, name, why, a.force))

if __name__ == "__main__":
    sys.exit(main())
