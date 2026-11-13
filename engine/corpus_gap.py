#!/usr/bin/env python3
"""corpus_gap.py — "would our toolkit have found this?" for every disclosed report.

Reads a structured corpus (docs/disclosed-reports/corpus-*/corpus.json, schema:
{"meta": {...}, "reports": [{"id", "classes", "keywords", "lesson", ...}]}) and
asks three questions of the toolkit's own text, for each report:

  1. skill:     does a hunt-* skill exist for one of the report's classes?
  2. technique: do the report's technique keywords appear in what the toolkit
                actually hands an agent: that skill, the vector mutation matrix and
                consumer table, hunt-dispatch, /chain, the doctrine?
  3. lesson:    coverage grouped by the lesson the report teaches.
  4. landed:    for a record that names a `landed_in` file, is the check still IN that
                file? Questions 1-3 read the whole toolkit, so a keyword that drifted
                into another skill still scores -- which is how corpus-2026-11-13 could
                have reported 100% coverage against a checkout that held none of its
                checks (measured 2026-11-13, both arms 100%). This one reads only the
                named file, so deleting a check FAILS the run. A record with no
                `landed_in` is counted apart, as `unlanded`: 161 of the 171 records in
                this folder predate the field, so failing them all would have been one
                mark covering two different states — a check that was deleted and a
                record that never named one.

Every "no" is a backlog item: a mutation, a signal row or a consumer entry to add.
Deterministic and offline. `--root` points at another copy of the toolkit (an
untarred snapshot) so the same corpus measures before vs after.

    cbh corpus-gap                                   # newest corpus, this checkout
    cbh corpus-gap --root /path/to/old/BugHunter --json
    cbh corpus-gap --write                           # GAP.md next to corpus.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

REPO = Path(__file__).resolve().parent.parent

EXTRA_SKILLS = {
    "oauth": "hunt-oauth", "saml": "hunt-saml", "lfi": "hunt-lfi", "request-smuggling": "hunt-http-smuggling",
    "cspt": "hunt-cspt", "idor": "hunt-idor", "xss": "hunt-xss", "ssrf": "hunt-ssrf", "rce": "hunt-rce",
    "sqli": "hunt-sqli", "ssti": "hunt-ssti", "xxe": "hunt-xxe", "csrf": "hunt-csrf", "cors": "hunt-cors",
    "graphql": "hunt-graphql", "file-upload": "hunt-file-upload", "deserialization": "hunt-deserialization",
    "business-logic": "hunt-business-logic", "race-condition": "hunt-race-condition",
    "auth-bypass": "hunt-auth-bypass", "missing_authorization": "hunt-auth-bypass",
    "api-misconfig": "hunt-api-misconfig", "host-header": "hunt-host-header",
    "cache-poison": "hunt-cache-poison", "open-redirect": "hunt-open-redirect", "info-leak": "hunt-source-leak",
    "sibling-interface": "hunt-differential", "secret-exposure": "hunt-source-leak",
    "filter-injection": "hunt-api-misconfig", "parser-differential": "hunt-differential",
    "nosqli": "hunt-nosqli", "ato": "hunt-ato", "mfa": "hunt-mfa-bypass", "websocket": "hunt-websocket",
    "subdomain-takeover": "hunt-subdomain", "dom": "hunt-dom", "nextjs": "hunt-nextjs",
}


def all_corpora(root: Path = REPO) -> List[Path]:
    """Every corpus under docs/disclosed-reports, oldest name first.

    The default run measures all of them. It used to measure only the newest, and on
    2026-11-13 that silently became a 10-record technique digest instead of the
    120-report corpus the coverage figures are quoted from — a file added for one
    purpose changed what the headline number meant.
    """
    cands = sorted((root / "docs" / "disclosed-reports").glob("corpus-*/corpus.json"))
    if not cands and root != REPO:
        cands = sorted((REPO / "docs" / "disclosed-reports").glob("corpus-*/corpus.json"))
    return cands


def newest_corpus(root: Path = REPO) -> Optional[Path]:
    cands = all_corpora(root)
    return cands[-1] if cands else None


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return ""


def toolkit_text(root: Path) -> Dict[str, str]:
    """The text an agent is actually handed, keyed by where it lives."""
    out = {
        "vectors": _read(root / "engine" / "vectors.py"),
        "dispatch": _read(root / "skills" / "hunt-dispatch" / "SKILL.md"),
        "chain": _read(root / "commands" / "chain.md"),
        "doctrine": _read(root / "engine" / "doctrine.py"),
        "methodology": _read(root / "skills" / "bb-methodology" / "SKILL.md"),
    }
    for d in sorted((root / "skills").glob("*/SKILL.md")):
        out["skill:" + d.parent.name] = _read(d)
    return out


def _norm(k: str) -> List[str]:
    """A keyword plus its loose forms: 'execution-after-redirect' also matches 'execution after redirect'."""
    k = k.lower().strip()
    forms = {k, k.replace("-", " "), k.replace("_", " "), k.replace(" ", "-")}
    return [f for f in forms if len(f) >= 3]


_STOP = {"the", "and", "for", "with", "from", "into", "via", "not", "does", "one", "two", "its", "own",
         "that", "this", "only", "as", "of", "to", "in", "on", "by", "an", "a", "or", "no", "is"}


def _tokens(s: str) -> List[str]:
    return [t for t in re.findall(r"[a-z0-9$_.:/{}\[\]-]{3,}", s.lower()) if t not in _STOP]


def _hit(keyword: str, text: str) -> bool:
    """Exact phrase, or >=60% of the phrase's significant words present (min 2).

    Corpus keywords are descriptive phrases ('redis cache keyed on user-agent'); an
    exact-substring test scores almost nothing anywhere, which measures phrasing,
    not coverage. The same rule is applied to every toolkit copy compared.
    """
    if any(f in text for f in _norm(keyword)):
        return True
    toks = _tokens(keyword)
    if len(toks) < 2:
        return False
    found = sum(1 for t in toks if t in text)
    return found >= 2 and found / len(toks) >= 0.6


LANDED_PATH_RE = re.compile(r"[\w./-]+?SKILL\.md|[\w./-]+\.(?:py|md)")


def landed_paths(report: Dict) -> List[str]:
    """The files a record says its check lives in (`landed_in`, one or several)."""
    raw = report.get("landed_in") or ""
    if isinstance(raw, list):
        raw = " ".join(str(x) for x in raw)
    return sorted(set(LANDED_PATH_RE.findall(str(raw))))


def landed_check(report: Dict, root: Path, kws: List[str]) -> Dict:
    """Is the check still in the file the record names? (question 4 in the docstring)

    `landed_ok` is None when the record names no file (unlanded: nothing to check yet),
    False when the named file no longer carries the technique's keywords (the check was
    deleted or reworded past recognition), True when it is still there.
    """
    paths = landed_paths(report)
    if not paths:
        return {"landed_in": [], "landed_ok": None, "landed_reason": "no landed_in field",
                "landed_found": []}
    missing_files = [p for p in paths if not (root / p).exists()]
    if missing_files:
        return {"landed_in": paths, "landed_ok": False, "landed_found": [],
                "landed_reason": "file(s) not in this checkout: " + ", ".join(missing_files)}
    text = "".join(_read(root / p) for p in paths)
    found = [k for k in kws if _hit(k, text)]
    ratio = len(found) / len(kws) if kws else 0.0
    ok = bool(kws) and ratio >= 0.34
    return {"landed_in": paths, "landed_ok": ok, "landed_found": found,
            "landed_reason": "" if ok else f"{len(found)}/{len(kws)} keyword(s) in the named file(s)"}


def assess(report: Dict, kit: Dict[str, str], root: Path = REPO) -> Dict:
    classes = [c for c in (report.get("classes") or []) if c]
    skills = sorted({EXTRA_SKILLS.get(c, f"hunt-{c}") for c in classes})
    have = [s for s in skills if "skill:" + s in kit]
    shared = kit["vectors"] + kit["dispatch"] + kit["chain"] + kit["doctrine"] + kit["methodology"]
    scoped = "".join(kit.get("skill:" + s, "") for s in have) + shared
    everywhere = "".join(kit.values())
    kws = [k for k in (report.get("keywords") or []) if k and len(k.strip()) >= 3]
    in_scoped = [k for k in kws if _hit(k, scoped)]
    in_any = [k for k in kws if _hit(k, everywhere)]
    ratio = len(in_scoped) / len(kws) if kws else 0.0
    landed = landed_check(report, root, kws)
    return {
        "id": report.get("id"), "lesson": report.get("lesson") or "other",
        "classes": classes, "skills": skills, "skill_exists": bool(have),
        "keywords": kws, "found_where_routed": in_scoped, "found_anywhere": in_any,
        "technique_covered": bool(kws) and ratio >= 0.34,
        "misrouted": bool(kws) and ratio < 0.34 and len(in_any) / len(kws) >= 0.34,
        "missing": [k for k in kws if k not in in_any],
        "source_url": report.get("source_url"),
        **landed,
    }


def run(corpus: Path, root: Path = REPO) -> Dict:
    doc = json.loads(corpus.read_text(encoding="utf-8"))
    reports = doc.get("reports") or []
    kit = toolkit_text(root)
    rows = [assess(r, kit, root) for r in reports]
    by_lesson: Dict[str, List[Dict]] = defaultdict(list)
    for r in rows:
        by_lesson[r["lesson"]].append(r)

    def pct(xs, key):
        return round(100 * sum(1 for x in xs if x[key]) / len(xs), 1) if xs else 0.0
    return {
        "corpus": str(corpus), "toolkit_root": str(root), "reports": len(rows),
        "skill_coverage_pct": pct(rows, "skill_exists"),
        "technique_coverage_pct": pct(rows, "technique_covered"),
        "misrouted": sum(1 for r in rows if r["misrouted"]),
        "by_lesson": {k: {"n": len(v), "technique_coverage_pct": pct(v, "technique_covered")}
                      for k, v in sorted(by_lesson.items(), key=lambda kv: -len(kv[1]))},
        "landed_ok_pct": (round(100 * sum(1 for r in rows if r["landed_ok"] is True)
                                / sum(1 for r in rows if r["landed_ok"] is not None), 1)
                          if any(r["landed_ok"] is not None for r in rows) else 0.0),
        "unlanded": sum(1 for r in rows if r["landed_ok"] is None),
        "landed_failures": [{"id": r["id"], "landed_in": r["landed_in"],
                             "reason": r["landed_reason"]} for r in rows
                            if r["landed_ok"] is False],
        "gaps": [r for r in rows if not r["technique_covered"]],
        "rows": rows,
    }


def render_md(rep: Dict) -> str:
    lines = [f"# Corpus gap report — would the toolkit have found these?", "",
             f"Corpus: `{rep['corpus']}` · toolkit: `{rep['toolkit_root']}` · {rep['reports']} reports", "",
             f"- skill exists for the class: **{rep['skill_coverage_pct']}%**",
             f"- technique keywords present where the agent is routed: **{rep['technique_coverage_pct']}%**",
             f"- misrouted (technique exists, but in a skill the class does not route to): {rep['misrouted']}",
             f"- still in the file the record names (`landed_in`): **{rep['landed_ok_pct']}%** "
             f"of {rep['reports'] - rep['unlanded']} record(s) that name one; "
             f"{rep['unlanded']} name none", "",
             "| lesson | n | technique coverage |", "|---|---|---|"]
    for k, v in rep["by_lesson"].items():
        lines.append(f"| {k} | {v['n']} | {v['technique_coverage_pct']}% |")
    if rep["landed_failures"]:
        lines += ["", "## FAIL — the check is not in the file the record names", ""]
        for f in rep["landed_failures"]:
            lines.append(f"- `{f['id']}` {', '.join(f['landed_in']) or '(no landed_in)'} — {f['reason']}")
    lines += ["", "## Gaps — each is a backlog item (mutation, signal row or consumer entry)", ""]
    for g in rep["gaps"]:
        lines.append(f"- `{g['id']}` [{g['lesson']}] classes={','.join(g['classes'])} "
                     f"missing: {', '.join(g['missing'][:6]) or '(found, but not where this class routes)'}"
                     + (f" — {g['source_url']}" if g.get("source_url") else ""))
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="corpus-gap", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, help="corpus.json (default: newest under docs/disclosed-reports)")
    ap.add_argument("--root", type=Path, default=REPO, help="toolkit checkout to measure (default: this one)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--write", action="store_true", help="write GAP.md next to the corpus")
    a = ap.parse_args(argv)
    corpora = [c for c in ([a.corpus] if a.corpus else all_corpora(a.root)) if c and c.exists()]
    if not corpora:
        print("corpus-gap: no corpus.json found under docs/disclosed-reports/corpus-*/", file=sys.stderr)
        return 3
    if len(corpora) > 1:
        if a.json:
            print(json.dumps([{k: v for k, v in run(c, a.root.resolve()).items() if k != "rows"}
                              for c in corpora], indent=2, ensure_ascii=False))
            return 0
        rc = 0
        for c in corpora:
            print(f"--- {c.parent.name}")
            rc = main(["--corpus", str(c), "--root", str(a.root)]
                      + (["--write"] if a.write else [])) or rc
        return rc
    corpus = corpora[0]
    rep = run(corpus, a.root.resolve())
    if a.write:
        dest = corpus.parent / "GAP.md"
        dest.write_text(render_md(rep), encoding="utf-8")
        rep["written"] = str(dest)
    if a.json:
        rep = {k: v for k, v in rep.items() if k != "rows"}
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return 0
    print(f"corpus-gap: {rep['reports']} reports · skill coverage {rep['skill_coverage_pct']}% · "
          f"technique coverage {rep['technique_coverage_pct']}% · misrouted {rep['misrouted']}")
    named = rep["reports"] - rep["unlanded"]
    if named:
        print(f"  landed: {rep['landed_ok_pct']}% of {named} record(s) naming a file"
              + (f" · {rep['unlanded']} name none" if rep["unlanded"] else ""))
    elif rep["unlanded"]:
        print(f"  landed: no record names a file yet ({rep['unlanded']} unlanded)")
    if rep["landed_failures"]:
        print(f"  FAIL landed: {len(rep['landed_failures'])} record(s) — "
              f"the check is not in the file the record names")
        for f in rep["landed_failures"][:12]:
            print(f"    {f['id']:9s} {', '.join(f['landed_in']) or '(no landed_in)'}: {f['reason']}")
    for k, v in rep["by_lesson"].items():
        print(f"  {k:24s} n={v['n']:3d}  {v['technique_coverage_pct']}%")
    print(f"\n{len(rep['gaps'])} gap(s); `--write` puts the list in GAP.md")
    if rep.get("written"):
        print(f"written: {rep['written']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
