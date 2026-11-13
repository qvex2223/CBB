#!/usr/bin/env python3
"""
report-harvest.py — turn disclosed reports into a dataset the engine can learn from.

`report_intel.py` is a bounded retrieval over a local disclosed-report dataset,
and deliberately ships with **no dataset** — provenance is the operator's to
supply. That left the whole "learn from what other researchers actually got
paid for" half of the loop unused.

This fills it from local files the operator is authorised to hold. It is
offline on purpose: no scraping, no fetching. You drop reports in a directory
(marked-down write-ups, exported JSON, whatever the platform gave you), declare
where they came from, and this turns them into

  * a `report_intel`-compatible dataset (with a `meta` block — the module
    refuses to search one that declares nothing, and that is correct),
  * a **novel-techniques** extract: phrases and mechanics that do not appear in
    this bundle's `technique_classifier` pattern table.

The second output is the point. A disclosed report's value is not its class
name — `hunt-xss` already exists — it is the *shape* of the bug that no class
covers yet. Those are what the hunt keeps missing on live targets, and what
this is meant to surface.

Usage:
    scripts/report-harvest.py --in ~/reports/kcell-2026 \\
        --source 'https://bb.rteam.kz/...' --licence 'program disclosure' \\
        --out docs/disclosed-reports/dataset.json

    scripts/report-harvest.py --in ~/reports --scaffold meta.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

SCHEMA_VERSION = "1.0"
TEXT_SUFFIXES = {".md", ".txt", ".json", ".html", ".rst"}
SKIP_NAMES = {"meta.json", "NOVEL.md", "dataset.json"}

# Phrases that describe *mechanics*, not class names. Deliberately written as
# observable behaviour, so a report whose title is just "IDOR" still yields
# something when its steps describe a real mechanic.
MECHANIC_RES: List[Tuple[str, re.Pattern]] = [
    ("header-supplied-identity",
     re.compile(r"(?i)(x-msisdn|x-forwarded-user|x-subscriber|x-original-url|x-remote-user|"
                r"trusted header|identity header|header injection.*auth)")),
    ("version-skew",
     re.compile(r"(?i)(older api version|/v1/.*still|legacy endpoint|deprecated endpoint.*still|"
                r"previous version.*accepts)")),
    ("client-supplied-value",
     re.compile(r"(?i)(price.*parameter|amount.*client|total.*manipulat|discount.*appl|"
                r"balance.*manipulat|negative (amount|value|quantity)|quantity.*-1)")),
    ("state-machine-abuse",
     re.compile(r"(?i)(skip(ping)? (a )?step|out of order|replay.*transition|status.*backwards|"
                r"state.*manually|terminal state|workflow bypass|step skip)")),
    ("parser-differential",
     re.compile(r"(?i)(content-type.*confus|json.*form.*differ|xml.*json.*accept|"
                r"mass assignment|extra field.*accept|hidden field.*writab)")),
    ("lookup-before-authz",
     re.compile(r"(?i)(404 vs 403|existence (oracle|disclosure)|enumerat.*via (status|response)|"
                r"authorization after (lookup|fetch)|idor.*blind)")),
    ("race-on-one-time-value",
     re.compile(r"(?i)(race condition.*(coupon|voucher|refund|bonus|limit|transfer|balance)|"
                r"double[- ]?(spend|apply|redeem|withdraw)|concurrent.*redeem)")),
    ("ssrf-via-parsed-url",
     re.compile(r"(?i)(ssrf.*(url param|webhook|callback|import|fetch|preview|pdf|avatar)|"
                r"server[- ]side request.*user)")),
    ("oauth-token-mixup",
     re.compile(r"(?i)(oauth.*(code.*reus|token.*swap|redirect.*manipulat|state.*missing|"
                r"nonce.*replay|pkce.*bypass)|sso.*confus)")),
    ("cache-key-confusion",
     re.compile(r"(?i)(cache poisoning|web cache|cache key|unkeyed header|unkeyed input|"
                r"cached response.*user)")),
    ("desync-and-smuggle",
     re.compile(r"(?i)(http request smuggling|desync|cl\.te|te\.cl|http/2.*downgrade)")),
    ("business-logic-chaining",
     re.compile(r"(?i)(chain(ed|ing)?.*(recon|info leak|low severity)|combine[d]? with|"
                r"escalat.*via.*chaining|from .* to (account takeover|privilege))")),
]


def _read_meta(in_dir: Path, meta_arg: Optional[Path]) -> dict:
    if meta_arg and meta_arg.exists():
        return json.loads(meta_arg.read_text(encoding="utf-8"))
    side = in_dir / "meta.json"
    if side.exists():
        return json.loads(side.read_text(encoding="utf-8"))
    return {}


def _collect(in_dir: Path) -> List[Path]:
    out = []
    for p in sorted(in_dir.rglob("*")):
        if not p.is_file() or p.name in SKIP_NAMES:
            continue
        if p.suffix.lower() not in TEXT_SUFFIXES:
            continue
        out.append(p)
    return out


def _title_of(text: str, fallback: str) -> str:
    for line in text.splitlines()[:12]:
        m = re.match(r"^#\s+(.*)", line.strip())
        if m:
            return m.group(1).strip()[:160]
    return fallback[:160]


def _snippet(text: str, pat: re.Pattern, width: int = 180) -> str:
    m = pat.search(text)
    if not m:
        return ""
    start = max(0, m.start() - width // 3)
    return re.sub(r"\s+", " ", text[start:m.end() + width // 2]).strip()[:width]


def harvest(in_dir: Path, meta: dict) -> Tuple[dict, dict]:
    files = _collect(in_dir)
    reports = []
    mechanics: Dict[str, List[dict]] = {name: [] for name, _ in MECHANIC_RES}

    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if path.suffix.lower() == ".json":
            # keep JSON reports as searchable text, but preserve their ids
            try:
                obj = json.loads(text)
                text = json.dumps(obj, ensure_ascii=False, indent=1)
            except Exception:
                pass
        if len(text.strip()) < 80:
            continue
        rid = hashlib.sha256(str(path).encode()).hexdigest()[:16]
        reports.append({
            "id": rid,
            "title": _title_of(text, path.stem),
            "source_file": str(path.relative_to(in_dir)),
            "text": text[:20000],
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
        })
        for name, pat in MECHANIC_RES:
            if pat.search(text):
                mechanics[name].append({
                    "report_id": rid,
                    "title": _title_of(text, path.stem),
                    "source_file": str(path.relative_to(in_dir)),
                    "snippet": _snippet(text, pat),
                })

    dataset = {
        "meta": {
            "source": meta.get("source", ""),
            "licence": meta.get("licence", ""),
            "retrieved": meta.get("retrieved", datetime.now(timezone.utc).strftime("%Y-%m-%d")),
            "notes": meta.get("notes", "local harvest; operator-supplied copies"),
            "schema_version": SCHEMA_VERSION,
        },
        "reports": reports,
    }
    extract = {k: v for k, v in mechanics.items() if v}
    return dataset, extract


def known_mechanics() -> List[str]:
    """Mechanics the classifier can already name — anything else is novelty."""
    names = []
    try:
        import technique_classifier as TC  # type: ignore
        table = getattr(TC, "TECHNIQUE_PATTERNS", {}) or {}
        names = [str(k).lower() for k in table.keys()]
    except Exception:
        pass
    return names


def novel_only(extract: dict) -> dict:
    known = " ".join(known_mechanics())
    out = {}
    for name, rows in extract.items():
        # A mechanic is novel when neither its slug nor its evidence phrases
        # already appear in the classifier's pattern table.
        slug_tokens = [t for t in re.split(r"[-_]", name) if len(t) > 3]
        if slug_tokens and all(t in known for t in slug_tokens):
            continue
        out[name] = rows
    return out


def to_novel_md(novel: dict, total_reports: int) -> str:
    out = ["# Novel mechanics — outside this bundle's pattern table", "",
           f"Harvested from {total_reports} local report(s). A mechanic below is one the "
           "`technique_classifier` cannot currently name. Each is raw material for a new "
           "`hunt-*` fragment or a new entry in the mutation matrix — not a finding.", ""]
    if not novel:
        out.append("Nothing new here. Either the corpus is thin, or the map is current.")
        return "\n".join(out) + "\n"
    for name, rows in sorted(novel.items(), key=lambda kv: -len(kv[1])):
        out.append(f"## `{name}` — {len(rows)} report(s)")
        out.append("")
        for r in rows[:6]:
            out.append(f"- **{r['title']}** (`{r['source_file']}`)")
            if r.get("snippet"):
                out.append(f"  > {r['snippet']}")
        out.append("")
        out.append("Suggested action: write the probe this mechanic implies as a "
                   "`vectors.py` mutation, and add a `TECHNIQUE_PATTERNS` entry so the "
                   "next `/remember` lands in analytics instead of in `generic`.")
        out.append("")
    return "\n".join(out) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="in_dir", type=Path, required=True,
                    help="directory of local disclosed reports you are authorised to hold")
    ap.add_argument("--out", type=Path, default=None,
                    help="dataset.json path (default: <in>/dataset.json)")
    ap.add_argument("--meta", type=Path, default=None,
                    help="provenance JSON; otherwise reads <in>/meta.json")
    ap.add_argument("--source", default="", help="provenance: where these came from")
    ap.add_argument("--licence", default="", help="provenance: the terms they are under")
    ap.add_argument("--notes", default="", help="provenance: free text")
    ap.add_argument("--scaffold", type=Path, default=None,
                    help="write a meta.json template here and exit")
    ap.add_argument("--format", choices=("md", "json"), default="md",
                    help="format for the novel-mechanics extract on stdout")
    args = ap.parse_args(argv)

    if args.scaffold:
        template = {
            "source": "https://…  (where these disclosures came from)",
            "licence": "CC-BY-4.0 / program disclosure terms / …",
            "retrieved": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "notes": "who exported these, and under what authorisation",
        }
        args.scaffold.parent.mkdir(parents=True, exist_ok=True)
        args.scaffold.write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8")
        print(f"{args.scaffold}: provenance template written. "
              "report_intel refuses a dataset that declares nothing — fill it in.")
        return 0

    in_dir = args.in_dir.expanduser().resolve()
    if not in_dir.is_dir():
        print(f"[error] not a directory: {in_dir}", file=sys.stderr)
        return 2

    meta = _read_meta(in_dir, args.meta)
    if args.source:
        meta["source"] = args.source
    if args.licence:
        meta["licence"] = args.licence
    if args.notes:
        meta["notes"] = args.notes

    if not meta.get("source") or not meta.get("licence"):
        print("[error] provenance is not optional. Pass --source and --licence, or "
              "write <in>/meta.json (see --scaffold). A dataset nobody can check the "
              "terms of is a dataset nobody may use.", file=sys.stderr)
        return 2

    dataset, extract = harvest(in_dir, meta)
    novel = novel_only(extract)

    out_path = args.out or (in_dir / "dataset.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(dataset, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    novel_path = out_path.parent / "NOVEL.md"
    novel_path.write_text(to_novel_md(novel, len(dataset["reports"])), encoding="utf-8")

    print(f"{out_path}: {len(dataset['reports'])} reports")
    print(f"{novel_path}: {sum(len(v) for v in novel.values())} novel mechanic hits "
          f"across {len(novel)} mechanic(s)")
    if args.format == "md":
        sys.stdout.write("\n" + to_novel_md(novel, len(dataset["reports"])))
    else:
        sys.stdout.write(json.dumps(novel, indent=2, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
