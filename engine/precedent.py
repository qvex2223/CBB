#!/usr/bin/env python3
"""precedent — what a paid disclosed report did first, for the lane in front of you.

Written 2026-11-11. `docs/disclosed-reports/` holds 161 disclosed reports distilled to the
five fields that matter — `first_signal` (what the hunter noticed before they knew it was a
bug), `mechanic`, `impact_proof`, `chain`, `lesson` — and `cbh corpus-gap` says the toolkit
has a skill for 99.2% of their classes. The corpus was not the gap. Session a0053cc0
(wildberries, six days, 138 subagents, 8400 requests) NAMED `cbh report-intel` in 103 worker
briefs and ran it ZERO times. Measured in that session's transcript: 103 mentions, 0 shell
invocations.

The reason is friction, not reluctance: `report_intel.py` takes a dataset PATH and a
free-text QUERY, so a worker has to pick one of two corpus files and invent search terms
before it learns anything. This module removes both. It merges every corpus under
`docs/disclosed-reports/*/corpus.json` (deduped by `source_url`, provenance kept), and it
derives the query from what the worker already has in its hand — a lead file, a host file, a
stack string, a captured response body.

    cbh precedent "graphql filter json"           # free text
    cbh precedent --lead leads/x-idor.md          # query derived from the lead
    cbh precedent --signals <file>                # which disclosed OPENING this body resembles
    cbh precedent --class idor --severity high    # class filter

Nothing here sends a request and nothing here refuses anything: it is retrieval over files
the operator already holds, printed where the lane is chosen.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))
CORPUS_GLOB = "docs/disclosed-reports/*/corpus.json"

# Words that carry no retrieval signal in this corpus: they appear in most reports, so a
# query built from a lead file would rank on them instead of on the lead's own shape.
STOP = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with", "is", "was", "it",
    "this", "that", "by", "as", "at", "from", "not", "but", "its", "their", "which", "when",
    "http", "https", "www", "com", "ru", "net", "org", "url", "host", "path", "request",
    "response", "status", "header", "headers", "body", "lead", "primitive", "finding",
    "notes", "md", "json", "yyyy", "mm", "dd", "what", "why", "how", "fired", "so", "far",
    # This workspace's own vocabulary. A lead file is full of it, and without these the
    # query ranked on our tooling instead of on the target's shape.
    "bbcurl", "cbh", "cbh_project", "project", "targets", "scope", "audit", "pacing",
    "poc", "poc_runtime", "curl", "sha256", "corpus", "opened", "confirmed", "evidence",
    "chain", "needs", "gives", "surface", "interesting", "prove", "proven", "refuted",
    "status", "previous", "note", "next", "hook", "row", "rows", "log", "date", "exact",
}
WORD_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_\-]{2,}")


def _load_one(path: Path) -> tuple[list[dict], dict]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return [], {}
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)], {}
    rows = [r for r in (doc.get("reports") or []) if isinstance(r, dict)]
    return rows, (doc.get("meta") or {})


_LOAD_CACHE: dict[str, dict] = {}


def load(root: Path | None = None) -> dict:
    """Every corpus under docs/disclosed-reports/, merged and deduped by source_url.

    A worker should never have to choose a dataset file. Provenance is kept per corpus so
    `--describe` can still say where each half came from — the reports are other people's
    work and the licence lives with them.
    """
    root = root or REPO
    # `cbh leads` asks for a precedent once per NEXT row; without this the corpus JSON is
    # re-read and re-tokenised for every row.
    cached = _LOAD_CACHE.get(str(root))
    if cached is not None:
        return cached
    reports: list[dict] = []
    seen: set[str] = set()
    metas: list[dict] = []
    for path in sorted(root.glob(CORPUS_GLOB)):
        rows, meta = _load_one(path)
        if meta:
            metas.append({**meta, "corpus": str(path.relative_to(root)), "reports": len(rows)})
        for r in rows:
            key = (r.get("source_url") or r.get("id") or "").strip()
            if key and key in seen:
                continue
            seen.add(key)
            reports.append({**r, "corpus": path.parent.name})
    ds = {"meta": {"corpora": metas}, "reports": reports}
    _LOAD_CACHE[str(root)] = ds
    return ds


_DF_CACHE: dict[int, dict[str, int]] = {}


def _doc_freq(dataset: dict) -> dict[str, int]:
    """How many corpus reports contain each term. Cached per dataset object."""
    key = id(dataset)
    if key in _DF_CACHE:
        return _DF_CACHE[key]
    df: dict[str, int] = {}
    for r in dataset["reports"]:
        blob = " ".join(str(r.get(k) or "") for k in
                        ("first_signal", "mechanic", "impact_proof", "lesson", "chain"))
        blob += " " + " ".join(str(x) for x in (r.get("classes") or []))
        blob += " " + " ".join(str(x) for x in (r.get("keywords") or []))
        for w in set(WORD_RE.findall(blob.lower())):
            df[w] = df.get(w, 0) + 1
    _DF_CACHE[key] = df
    return df


def query_from_text(text: str, limit: int = 18, dataset: dict | None = None) -> str:
    """A retrieval query built from a lead/host file, not from the worker's imagination.

    Terms are ranked by count x rarity IN THE CORPUS, not by count then alphabet. Ranking
    by count alone put a count-1 alphabetical tail into the query ("all answers api app
    bbcurl certificate ...") and retrieved on it; a term that half the corpus contains
    cannot discriminate between its reports, and a term the corpus never saw cannot
    retrieve at all. Title terms count triple: the heading is the author's own summary.
    """
    ds = dataset or load()
    df = _doc_freq(ds)
    n = max(1, len(ds["reports"]))
    title = ""
    for line in text.splitlines():
        if line.startswith("# "):
            title = line[2:]
            break
    counts: dict[str, float] = {}
    for blob, weight in ((text, 1.0), (title, 3.0)):
        for w in WORD_RE.findall(blob.lower()):
            if w in STOP or len(w) > 32:
                continue
            counts[w] = counts.get(w, 0.0) + weight
    import math as _math
    scored = []
    for w, c in counts.items():
        d = df.get(w, 0)
        if d == 0:
            continue                      # the corpus has never seen it: it cannot retrieve
        if d > n * 0.4:
            continue                      # in most reports: it cannot discriminate
        scored.append((c * _math.log(n / d), w))
    scored.sort(key=lambda t: (-t[0], t[1]))
    return " ".join(w for _, w in scored[:limit])


def match(query: str, limit: int = 3, min_severity: str = "", dataset: dict | None = None,
          cls: str = "") -> list[dict]:
    """Closest disclosed reports. `cls` keeps only reports that carry that class."""
    from report_intel import search  # type: ignore
    ds = dataset or load()
    if cls:
        ds = {"meta": ds.get("meta", {}),
              "reports": [r for r in ds["reports"]
                          if cls.lower() in [str(c).lower() for c in (r.get("classes") or [])]]}
        if not query:
            query = cls
    return search(ds, query, limit=limit, min_severity=min_severity)


def _money(v) -> str:
    """`report_intel.search` normalises `bounty` to a float, so the row that reaches a lane
    carries `90000.0` where the corpus file says `$90,000`."""
    if isinstance(v, (int, float)):
        return f"${v:,.0f}"
    return str(v or "").strip() or "—"


def _opening(r: dict) -> str:
    """The row's opening move.

    21 of the 155 reports predate the corpus rebuild and carry no `first_signal`; `wu-09`'s
    is `None`, which printed `FIRST SIGNAL:` followed by whatever came next on the line —
    its own `source_url`, the prose note `https://simonkoeck blog (site and title only;
    slug lost to compaction)` — so the lane read as if its precedent were a dead link. The
    mechanic and the chain's first step are the same report's own words and are usable
    precedent, so they are the fallback, each under its own label: a lane is never told a
    mechanic is a first signal.
    """
    for key, label in (("first_signal", "FIRST SIGNAL"), ("mechanic", "MECHANIC")):
        v = str(r.get(key) or "").strip()
        if v:
            return f"{label}: {v}"
    steps = [str(c).strip() for c in (r.get("chain") or []) if str(c).strip()]
    return f"STEP 1: {steps[0]}" if steps else ""


def _source(r: dict) -> str:
    """A link only when it IS one: a corpus source can be a prose note whose spaces make it
    unfetchable, and printing it bare put a fake URL at the end of the lane's line."""
    raw = str(r.get("source_url") or r.get("url") or "").strip()
    if not raw:
        return ""
    return raw if not re.search(r"\s", raw) else f"(unresolved source: {raw})"


def _one_line(r: dict) -> str:
    sev = (r.get("severity") or "?")[:8]
    classes = ", ".join(str(c) for c in (r.get("classes") or [])[:3]) or "?"
    return f"[{sev}/{_money(r.get('bounty'))}] {classes} — {_opening(r)}"


def lane_line(text: str, limit: int = 1) -> str:
    """One line of paid precedent for a lane, from the lane's own file text.

    This is what `cbh leads` prints under a NEXT row: the opening move that a paid report
    made on this shape. It is a hint, never a filter — the lane is still whatever the
    ledger ranked.
    """
    # Over-fetch and drop the rows with no opening move at all: a precedent that cannot say
    # what the hunter noticed is not a hint, and it would take the lane's only slot.
    hits = [r for r in match(query_from_text(text), limit=limit + 3) if _opening(r)]
    return "\n".join(f"        precedent: {_one_line(r)}  {_source(r)}".rstrip()
                     for r in hits[:limit])


def signals(text: str, limit: int = 5, dataset: dict | None = None) -> list[dict]:
    """Which disclosed OPENINGS this body/bundle resembles.

    `first_signal` is the one field in the corpus written from the hunter's point of view
    before they knew what they had. Matching a captured response against those openings is
    the mechanical half of "think like the person who got paid".
    """
    ds = dataset or load()
    low = text.lower()
    scored = []
    for r in ds["reports"]:
        terms = set()
        for k in (r.get("keywords") or []):
            terms.update(w for w in WORD_RE.findall(str(k).lower()) if w not in STOP)
        for w in WORD_RE.findall((r.get("first_signal") or "").lower()):
            if w not in STOP and len(w) > 3:
                terms.add(w)
        hit = sorted(t for t in terms if t in low)
        if len(hit) >= 2:
            scored.append({"report": r, "hits": hit, "score": len(hit)})
    scored.sort(key=lambda s: (-s["score"], s["report"].get("id", "")))
    return scored[:limit]


def describe() -> str:
    ds = load()
    out = [f"precedent corpus: {len(ds['reports'])} disclosed report(s) merged"]
    for m in ds["meta"]["corpora"]:
        out.append(f"  {m.get('corpus')}  {m.get('reports')} report(s)  "
                   f"source={m.get('source') or '?'}  licence={m.get('licence') or '?'}  "
                   f"retrieved={m.get('retrieved') or '?'}")
    return "\n".join(out)


def _print(hits: list[dict], verbose: bool) -> None:
    if not hits:
        print("no close precedent in the corpus — that is information too: the shape is not "
              "one of the 161 paid reports here.")
        return
    for r in hits:
        print(f"\n{_one_line(r)}")
        print(f"  mechanic:     {(r.get('mechanic') or '').strip()}")
        print(f"  impact proof: {(r.get('impact_proof') or '').strip()}")
        if verbose and r.get("chain"):
            print(f"  chain:        {r.get('chain')}")
        print(f"  lesson:       {r.get('lesson')}   "
              f"{r.get('source_url') or r.get('url') or ''}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="precedent", description=__doc__.split("\n")[0])
    ap.add_argument("query", nargs="*", help="free text; omit when using --lead/--signals")
    ap.add_argument("--lead", help="lead/primitive/host file — the query is derived from it")
    ap.add_argument("--signals", help="a captured body/bundle: which disclosed OPENING it resembles")
    ap.add_argument("--class", dest="cls", default="", help="keep only this vuln class")
    ap.add_argument("--severity", default="", help="minimum severity")
    ap.add_argument("--limit", type=int, default=3)
    ap.add_argument("--describe", action="store_true", help="corpora and their provenance")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)

    if a.describe:
        print(describe())
        return 0
    if a.signals:
        p = Path(a.signals)
        if not p.exists():
            print(f"not found: {p}")
            return 2
        hits = signals(p.read_text(encoding="utf-8", errors="replace"), limit=a.limit)
        if not hits:
            print("no disclosed opening matches this body (>=2 shared terms).")
            return 1
        for s in hits:
            r = s["report"]
            print(f"\n{s['score']} shared term(s): {', '.join(s['hits'][:8])}")
            print(f"  {_one_line(r)}")
            print(f"  mechanic: {(r.get('mechanic') or '').strip()}")
            print(f"  {r.get('source_url') or r.get('url') or ''}")
        return 0
    if a.lead:
        p = Path(a.lead)
        if not p.exists():
            print(f"not found: {p}")
            return 2
        text = p.read_text(encoding="utf-8", errors="replace")
        q = query_from_text(text)
        print(f"query derived from {p.name}: {q}")
        _print(match(q, limit=a.limit, min_severity=a.severity, cls=a.cls), a.verbose)
        return 0
    q = " ".join(a.query)
    if not q and not a.cls:
        ap.print_help()
        return 2
    _print(match(q, limit=a.limit, min_severity=a.severity, cls=a.cls), a.verbose)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
