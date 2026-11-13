#!/usr/bin/env python3
"""skill_graph.py — the 68 skills as a graph, and the chains the corpus says pay.

Why this exists. The arsenal grew to 68 skills and every one of them was addressed
one at a time: `engine/skill_signals.py` maps a URL to ONE skill so a hook can gate
a request, and `engine/skill_map.py` maps a class to a skill and a first curl. Both
are flat lookups. Nothing in the workspace knew that `hunt-open-redirect` is a step
on the way to `hunt-oauth` and then `hunt-ato`, or that in 120 disclosed reports
`auth-bypass` and `info-leak` appear together five times for $25,300 while
`auth-bypass` alone is usually a Medium. So a lane proved one primitive, wrote it to
`primitives/`, and stopped — the escalation that turns it into a High was a thing the
operator had to remember, per lane, every time.

Two independent sources, kept separate on purpose:

1. DOCTRINE edges — parsed from each `skills/<name>/SKILL.md` frontmatter
   description, which this workspace writes in a fixed shape:

       TRIGGER — <when this skill is the right one>.
       SKIP — <other-skill> for <condition>; <other-skill> once <condition>.

   A SKIP clause is one of two things, and the difference is the whole point:
     * `owns`     — lateral. That skill owns this surface, so working it here is
                    wasted budget ("hunt-cors for Access-Control-* issues").
     * `escalate` — vertical. Once THIS skill proves its thing, the named skill is
                    where the chain continues and the severity goes up ("hunt-ato
                    once a SAML bug is confirmed and being chained into a takeover").
   Reversing the `escalate` edges gives, for any skill, the list of primitives that
   feed it — which is the answer to "what do I still need to reach Critical".

2. CORPUS edges — mined from `docs/disclosed-reports/corpus-2026-11/corpus.json`
   (120 disclosed reports, 94 of them multi-class, with `severity`, `bounty`,
   `classes` and an ordered `chain`). A pair of classes that co-occurs there is an
   observed chain, with a report id and a dollar figure behind it. These are facts
   about disclosed reports, not a prediction about this engagement — which is why
   every chain this module prints carries its evidence ids.

Nothing here sends a request or decides a severity. It answers three questions:
  * which skills apply to this surface, in what order  -> `ladder()`
  * this primitive is proven; where does it go next    -> `escalations()`
  * what pays when combined with it, and on what proof -> `chains()`

usage:
    python3 engine/skill_graph.py                      # census + the top chains
    python3 engine/skill_graph.py hunt-idor            # one skill's row
    python3 engine/skill_graph.py --chains --top 20    # corpus chains by payout
    python3 engine/skill_graph.py --ladder "/api/v2/orders/42?redirect=..."
    python3 engine/skill_graph.py --lint               # dangling refs, unmapped classes
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

SKILLS_DIR = REPO / "skills"
CORPUS = REPO / "docs" / "disclosed-reports" / "corpus-2026-11" / "corpus.json"

SKILL_REF_RE = re.compile(r"\b((?:hunt|api|bb|web2|poc)-[a-z0-9][a-z0-9-]*)\b")
# A SKIP clause is vertical — a chain step — only when its condition says the
# chain CONTINUES somewhere, in so many words. The first version of this accepted
# a bare "once ... confirmed" and that is the wording of an ownership clause as
# often as a chain one: `hunt-ldap` says "hunt-sqli once the backend is confirmed
# relational", which identifies the backend and hands the surface over, and
# `hunt-auth-bypass` says "hunt-saml ... once a /saml endpoint is confirmed". Both
# scored as escalations, and `hunt-saml` then ranked as an escalation hub with
# three feeders — a skill whose own doctrine sends it onward to `hunt-ato`. These
# eight markers are the explicit ones; a clause without any of them is lateral,
# which costs a lane nothing (it still gets the edge, as `owns`) and keeps
# "escalate" meaning "severity goes up if you go there".
ESCALATE_RE = re.compile(
    r"being\s+chained|chained\s+into"
    r"|log\s+the\s+(?:full\s+|confirmed\s+)?chain"
    r"|chain\s+there"
    r"|escalat\w+"
    r"|the\s+next\s+step\s+is"
    r"|the\s+work\s+is\s+(?:proving|escalating)"
    r"|do\s+the\s+[a-z ]{0,20}there"
    r"|leads\s+directly\s+to",
    re.I)
# hunt-ato inverts the shape: its SKIP names the single-path skills and then says
# "use this skill when combining 2+ of those". Read literally that would make the
# feeders look like lateral owners and the one skill whose whole job is chaining
# would have no inbound edges at all.
INVERTED_RE = re.compile(r"use\s+this\s+skill\s+when\s+combin|when\s+combining\s+2\+", re.I)

SEV_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------------------------------------------------------------------------
# frontmatter
# ---------------------------------------------------------------------------
def _frontmatter(path: Path) -> dict:
    """The YAML-ish frontmatter of a SKILL.md as a flat dict.

    Deliberately not a YAML parse: `description` is a long quoted one-liner with
    colons, em-dashes and backticks inside it, and a continuation line is anything
    that does not open a new `key:`.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    if not text.startswith("---"):
        return {}
    body = text.split("---", 2)
    if len(body) < 3:
        return {}
    out: dict[str, str] = {}
    key = ""
    for line in body[1].splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$", line)
        if m:
            key = m.group(1)
            out[key] = m.group(2).strip()
        elif key and line.strip():
            out[key] = (out[key] + " " + line.strip()).strip()
    for k, v in out.items():
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            out[k] = v[1:-1]
    return out


def _split_description(desc: str) -> tuple[str, str]:
    """(TRIGGER text, SKIP text). Either may be empty."""
    d = desc or ""
    trig = skip = ""
    m = re.search(r"TRIGGER\s*[—\-:]\s*(.*?)(?=\bSKIP\s*[—\-:]|$)", d, re.I | re.S)
    if m:
        trig = m.group(1).strip()
    m = re.search(r"SKIP\s*[—\-:]\s*(.*)$", d, re.I | re.S)
    if m:
        skip = m.group(1).strip()
    if not trig and not skip:
        trig = d.strip()
    return trig, skip


def load_skills() -> dict:
    """{name: {trigger, skip, report_count, sources, present}} for every skill on disk."""
    out: dict[str, dict] = {}
    if not SKILLS_DIR.is_dir():
        return out
    for d in sorted(SKILLS_DIR.iterdir()):
        f = d / "SKILL.md"
        if not f.is_file():
            continue
        fm = _frontmatter(f)
        trig, skip = _split_description(fm.get("description", ""))
        out[d.name] = {
            "name": d.name,
            "trigger": trig,
            "skip": skip,
            "report_count": int(fm.get("report_count") or 0),
            "sources": fm.get("sources", ""),
        }
    return out


# ---------------------------------------------------------------------------
# doctrine edges
# ---------------------------------------------------------------------------
def doctrine_edges(skills: dict) -> list[dict]:
    """Edges parsed from the SKIP clauses. kind is `owns` (lateral) or `escalate`."""
    edges: list[dict] = []
    for name, row in skills.items():
        skip = row["skip"]
        if not skip:
            continue
        inverted = bool(INVERTED_RE.search(skip))
        for clause in re.split(r";|(?<=\))\s+and\s+", skip):
            clause = clause.strip()
            if not clause:
                continue
            refs = [r for r in dict.fromkeys(SKILL_REF_RE.findall(clause)) if r != name]
            if not refs:
                continue
            kind = "escalate" if ESCALATE_RE.search(clause) else "owns"
            why = re.sub(r"\s+", " ", clause)[:200]
            for ref in refs:
                if inverted:
                    # the named skills FEED this one
                    edges.append({"src": ref, "dst": name, "kind": "escalate",
                                  "why": why, "source": "doctrine(inverted)"})
                else:
                    edges.append({"src": name, "dst": ref, "kind": kind,
                                  "why": why, "source": "doctrine"})
    return edges


# ---------------------------------------------------------------------------
# corpus edges
# ---------------------------------------------------------------------------
# `bounty` in the corpus is prose, not a number: 62 of 120 rows are null, one is
# "$525 and $400", one is "six figures across fintech, crypto and e-commerce
# programs", and one technique write-up aggregates whole programs — "$7,000
# Cloudflare, $7,000 GitLab, $12,000 T-Mobile; 74 bounties / $221k on the Akamai
# case; over $350k total". Stripping non-digits concatenated those into
# $700,070,001,200,074,229,850 and that row then topped every ranking. So: parse
# each `$amount` separately, take the largest, and tell the caller when a row
# carried more than one — an aggregate is evidence that a CLASS pays, not that one
# report did, and it is kept out of the per-pair totals for that reason.
_AMOUNT_RE = re.compile(r"\$\s*([0-9][0-9,]*(?:\.[0-9]+)?)\s*([kKmM])?")


def _amounts(value) -> list[int]:
    out = []
    for num, suffix in _AMOUNT_RE.findall(str(value or "")):
        try:
            n = float(num.replace(",", ""))
        except ValueError:
            continue
        n *= {"k": 1_000, "m": 1_000_000}.get(suffix.lower(), 1)
        out.append(int(n))
    return out


def _money(value) -> int:
    """The largest single dollar figure in the field; 0 when it names none."""
    amounts = _amounts(value)
    return max(amounts) if amounts else 0


def _is_aggregate(value) -> bool:
    """True when the field names several payouts, so it is a class total."""
    return len(_amounts(value)) > 1


def load_corpus(path: Path | None = None) -> list[dict]:
    p = path or CORPUS
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - a missing corpus must not break the graph
        return []
    rows = doc.get("reports") if isinstance(doc, dict) else doc
    return [r for r in (rows or []) if isinstance(r, dict)]


def corpus_pairs(rows: list[dict] | None = None, min_n: int = 2) -> list[dict]:
    """Class pairs that co-occur in the disclosed-report corpus.

    `other` is excluded: 11 reports carry it and they share no mechanic, so it
    co-occurs with everything and would top any ranking by count.
    """
    rows = rows if rows is not None else load_corpus()
    n: Counter = Counter()
    pay: Counter = Counter()
    agg: Counter = Counter()
    sev: dict[tuple, str] = {}
    ids: dict[tuple, list[str]] = defaultdict(list)
    for r in rows:
        classes = sorted({c for c in (r.get("classes") or []) if c and c != "other"})
        aggregate = _is_aggregate(r.get("bounty"))
        for a, b in itertools.combinations(classes, 2):
            k = (a, b)
            n[k] += 1
            if not aggregate:
                pay[k] += _money(r.get("bounty"))
            else:
                agg[k] += 1
            ids[k].append(r.get("id") or "")
            s = (r.get("severity") or "").lower()
            if SEV_RANK.get(s, -1) > SEV_RANK.get(sev.get(k, ""), -1):
                sev[k] = s
    out = []
    for k, count in n.items():
        if count < min_n:
            continue
        out.append({"classes": list(k), "n": count, "bounty": pay[k],
                    "aggregate_rows": agg[k], "top_severity": sev.get(k, ""),
                    "reports": [i for i in ids[k] if i][:6]})
    # Count first, severity second, money third. Ranking on money put a single
    # research write-up that aggregates many programs above a pair with five
    # reports behind it; the number of disclosed reports is the part that does not
    # depend on how a bounty happened to be written down.
    out.sort(key=lambda r: (-r["n"], -SEV_RANK.get(r["top_severity"], 0), -r["bounty"],
                            r["classes"]))
    return out


def corpus_chains(rows: list[dict] | None = None, top: int = 12,
                  min_severity: str = "") -> list[dict]:
    """Whole reports as chain templates: ordered steps, classes, skills, evidence.

    A chain here is one disclosed report, not a synthesis of several. That is the
    honest unit: the `chain` array is the sequence that actually paid, and keeping
    it whole means the skills named per step can be checked against the report.
    """
    import skill_map  # local: keeps skill_graph importable when skill_map moves

    rows = rows if rows is not None else load_corpus()
    floor = SEV_RANK.get(min_severity.lower(), -1)
    out = []
    for r in rows:
        if SEV_RANK.get((r.get("severity") or "").lower(), -1) < floor:
            continue
        classes = [c for c in (r.get("classes") or []) if c]
        skills: list[str] = []
        for c in classes:
            for s in skill_map.CLASS_SKILL.get(c, []):
                if s not in skills:
                    skills.append(s)
        out.append({
            "id": r.get("id", ""), "url": r.get("source_url", ""),
            "severity": (r.get("severity") or "").lower(), "bounty": _money(r.get("bounty")),
            "classes": classes, "skills": skills,
            "steps": [str(s) for s in (r.get("chain") or [])],
            "first_signal": r.get("first_signal", ""),
            "impact_proof": r.get("impact_proof", ""),
            "lesson": r.get("lesson", ""),
        })
    out.sort(key=lambda r: (-SEV_RANK.get(r["severity"], 0), -r["bounty"], r["id"]))
    return out[:top] if top else out


# ---------------------------------------------------------------------------
# the graph
# ---------------------------------------------------------------------------
def _dedupe(edges: list[dict]) -> list[dict]:
    """One edge per (src, dst, kind), keeping every justification written for it.

    `hunt-ato` names its feeders in its own inverted SKIP clause and each feeder
    names `hunt-ato` again in theirs, so four of the arsenal's chain edges existed
    twice. Counting raw edges then reported eight feeders into `hunt-ato` when
    there are four, and a hub count that double-counts agreement is worse than no
    hub count.
    """
    merged: dict[tuple, dict] = {}
    for e in edges:
        k = (e["src"], e["dst"], e["kind"])
        if k in merged:
            if e["why"] not in merged[k]["why"]:
                merged[k]["why"] = f"{merged[k]['why']} | {e['why']}"
            if e["source"] not in merged[k]["source"]:
                merged[k]["source"] += f"+{e['source']}"
            continue
        merged[k] = dict(e)
    return list(merged.values())


def build(corpus_path: Path | None = None) -> dict:
    skills = load_skills()
    edges = _dedupe(doctrine_edges(skills))
    rows = load_corpus(corpus_path) if corpus_path else load_corpus()
    return {"skills": skills, "edges": edges, "pairs": corpus_pairs(rows),
            "corpus_rows": len(rows)}


def _edges_of(graph: dict, name: str, kind: str, direction: str) -> list[dict]:
    key = "src" if direction == "out" else "dst"
    other = "dst" if direction == "out" else "src"
    seen: set[str] = set()
    out = []
    for e in graph["edges"]:
        if e[key] != name or e["kind"] != kind or e[other] in seen:
            continue
        seen.add(e[other])
        out.append(e)
    return out


def escalations(name: str, graph: dict | None = None) -> list[dict]:
    """Where a proven `name` goes next, per the doctrine (vertical, out-edges)."""
    g = graph or build()
    return _edges_of(g, name, "escalate", "out")


def feeders(name: str, graph: dict | None = None) -> list[dict]:
    """Which primitives feed `name` — the inbound half of the vertical edges."""
    g = graph or build()
    return _edges_of(g, name, "escalate", "in")


def owners(name: str, graph: dict | None = None) -> list[dict]:
    """Skills that own an adjacent surface: working it under `name` wastes budget."""
    g = graph or build()
    return _edges_of(g, name, "owns", "out")


# Words that carry no class information but are long enough to pass the length floor.
STOP_TERMS = {"trigger", "endpoint", "endpoints", "request", "requests", "response",
              "responses", "parameter", "parameters", "whenever", "something",
              "another", "instead", "already", "testing", "assessing", "especially",
              "attacker", "controlled", "suspected", "confirmed", "application",
              "also", "with", "that", "this", "when", "once", "from", "into", "into",
              "than", "them", "then", "they", "what", "which", "while", "whose",
              "needs", "need", "goes", "goal", "work", "works", "rather", "itself",
              "every", "whole", "there", "their", "here", "some", "more", "most",
              "only", "same", "both", "each", "over", "under", "about", "across",
              "being", "before", "after", "against", "without", "within", "inside",
              "check", "checks", "look", "looks", "start", "straight", "specific",
              "issue", "issues", "bugs", "skill", "skills", "wearing", "costume",
              "plain", "pure", "real", "true", "false", "good", "best", "known",
              "never", "always", "often", "usually", "turns", "comes", "case", "cases",
              # Generic once the floor dropped to four characters: `public` scored
              # `hunt-rce` on "a public prod bundle", and `server`/`user` scored
              # `hunt-lfi` on "makes the server fetch a user-supplied URL".
              "public", "private", "server", "servers", "client", "clients", "user",
              "users", "data", "file", "files", "page", "pages", "path", "paths",
              "name", "names", "code", "codes", "site", "sites", "host", "hosts",
              "call", "calls", "send", "sent", "text", "type", "types", "value",
              "values", "field", "fields", "input", "based", "makes", "made", "take",
              "takes", "taken", "give", "gives", "returns", "return", "level",
              "point", "points", "step", "steps", "flow", "flows", "stack", "side",
              # Prose glue, measured by how many of the 68 TRIGGERs contain each term:
              # `target` is in 27 of them ("target fingerprints as Laravel", "target
              # exposes /saml"), `covers` opens the second sentence of every stack skill's
              # description, `auth` is in 6 as a fragment of `/auth/v1` and "auth flow",
              # and `apps` is in one only because `firebase.apps` splits on the dot. On
              # `finance.acme.com/apps/auth/verify-person-update posts an auth token to
              # window.parent with target origin *` that gave `hunt-firebase` 3 points
              # (apps + auth + target) and `hunt-supabase` 2, so a postMessage lead was
              # briefed with Firestore security rules and a Supabase `anon` key while
              # `hunt-dom` and `hunt-cors` scored 1 each on `origin`. A term in a quarter
              # of the bundle's triggers carries no routing information. Terms with a high
              # spread that ARE vocabulary stay: `header` (9), `session` (5), `cookie` (5),
              # `injection` (5), `redirect_uri` (4), `oauth` (3), `login` (3), `next` (3,
              # which is how `hunt-nextjs` matches `_next/`).
              "target", "targets", "covers", "hunt", "recon", "finding", "findings",
              "fingerprints", "behind", "exposes", "where", "plus", "candidate", "runs",
              "whether", "fires", "moves", "still", "class", "includes", "present",
              "reachable", "accepts", "shows", "might", "apps", "auth", "live"}


# Skills whose TRIGGER describes having no class rather than a surface. A term hit on
# one of these says nothing about the item, so they are ranked last (see `ladder`).
CATCH_ALL_SKILLS = {"hunt-misc", "hunt-dispatch", "bb-methodology", "bug-bounty"}


def _trigger_terms(trigger: str) -> set[str]:
    """Distinctive terms from a TRIGGER text.

    Backticked tokens are taken whole. Bare words are taken from four characters up,
    and `_trigger_score` matches them on WORD BOUNDARIES. The two rules are one
    decision: the floor used to be seven characters because matching was plain
    substring, and a short token matched inside longer words (`dom` inside
    `subdomain`, `/api` inside `/api/v2/user/orders/4821`, which is how
    `hunt-mfa-bypass` once outranked `hunt-idor`). A seven-character floor buys that
    safety by discarding the most diagnostic words in the whole table — `fetch`,
    `.env`, `token`, `bundle`, `upload`, `cache` — and a skill whose vocabulary is
    short then scores 0 and loses a tie to one incidental hit. Measured 2026-11-12:
    "a webhook parameter makes the server fetch a user-supplied URL" scored
    `hunt-ssrf` 1, on `webhook` alone, because `fetch` was invisible.

    A term containing `/` or `.` is a path or a filename and is still matched as a
    substring: `.js.map` and `/swagger.json` have to hit inside a URL.
    """
    terms: set[str] = set()
    for t in re.findall(r"`([^`]{2,40})`", trigger):
        terms.add(t.lower())
    for t in re.findall(r"/[A-Za-z0-9_.\-]{5,}|[A-Za-z0-9_\-]{4,}=|\b[A-Za-z][A-Za-z0-9_\-]{3,}\b",
                        trigger):
        low = t.lower()
        if low in STOP_TERMS:
            continue
        terms.add(low)
    return terms


# This workspace opens a lead/primitive title with its own tier word, and those
# words appear inside TRIGGER texts too: `hunt-rce`'s reads "a confirmed primitive
# (deserialization, LFI, SSTI, file upload, command injection) is being escalated".
# So `Primitive — selfreg.acme.com/api route space confirmed live` scored `hunt-rce`
# top and the lane was briefed with two Marshal-gadget chains for a route-space
# census. The scaffolding is stripped from the blob before anything is scored.
HOUSE_WORDS_RE = re.compile(
    r"^\s*(?:\*\*)?(?:primitive|lead|finding|candidate|brief|note)s?(?:\*\*)?\s*[—:\-]\s*"
    r"|\b(?:primitive|primitives|chain|status|verdict|ledger|lane)\b",
    re.I)


def _clean_blob(blob: str) -> str:
    return HOUSE_WORDS_RE.sub(" ", blob or "")


def _term_hits(low: str, terms) -> set[str]:
    """The terms of `terms` present in an already-cleaned, lowercased blob.

    Word-boundary for a bare word, substring for a path or filename term. The
    boundary is what makes a four-character floor safe.
    """
    hits = set()
    for t in terms:
        if not t:
            continue
        if "/" in t or "." in t:
            if t in low:
                hits.add(t)
        elif re.search(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9])", low):
            hits.add(t)
    return hits


def _trigger_score(blob: str, trigger: str) -> int:
    return len(_term_hits(_clean_blob(blob).lower(), _trigger_terms(trigger)))


def ladder(blob: str, graph: dict | None = None, top: int = 6) -> list[dict]:
    """Ordered skills for a surface blob (a URL, a lead title, a recon note).

    Two stages, strongest evidence first:

    1. `engine/skill_signals.PATH_SIGNALS` — the hand-tuned URL table the two
       hooks already run. It is the measured answer for a URL and it is why this
       does not re-derive path matching: a `/graphql` or an `?redirect=` is not a
       judgement call.
    2. TRIGGER-term overlap for whatever stage 1 did not name — which is the only
       thing that works on a lead title or a recon note, where there is no URL.

    Each row then carries the graph layer neither table has: the skills this one
    must defer to (lateral owners — working their surface here is wasted budget)
    and where a proof escalates to.
    """
    g = graph or build()
    rows: list[dict] = []
    seen: set[str] = set()

    try:
        import skill_signals  # noqa: PLC0415 - optional at import time
        for vclass, skill, block in skill_signals.signals_for(blob):
            if skill in seen or skill not in g["skills"]:
                continue
            seen.add(skill)
            rows.append({"skill": skill, "via": "url-signal", "vuln_class": vclass,
                         "gated": bool(block), "score": 0})
    except Exception:  # noqa: BLE001 - the graph must work without the hook table
        pass

    # `hunt-misc` is the bundle's catch-all: its TRIGGER describes the ABSENCE of a
    # class ("a finding doesn't cleanly fit any other hunt-* class"), so a term hit on
    # it is not evidence about the surface. It also carries the highest report_count in
    # the bundle (225), which is the tie-break — so once it scored at all it won. It
    # stays eligible, because a lane with nothing else is better off with it than with
    # nothing, but it ranks after every skill that matched on its own vocabulary.
    scored = []
    for name, row in g["skills"].items():
        if name in seen:
            continue
        score = _trigger_score(blob, row["trigger"])
        if score:
            scored.append((0 if name in CATCH_ALL_SKILLS else 1,
                           score, row["report_count"], name))
    scored.sort(key=lambda t: (-t[0], -t[1], -t[2], t[3]))
    for _rank, score, _rc, name in scored:
        rows.append({"skill": name, "via": "trigger", "vuln_class": "", "gated": False,
                     "score": score})

    for r in rows[:top]:
        r["report_count"] = g["skills"][r["skill"]]["report_count"]
        r["defer_to"] = [e["dst"] for e in owners(r["skill"], g)]
        r["escalates_to"] = [e["dst"] for e in escalations(r["skill"], g)]
    return rows[:top]


def chains_for(name_or_class: str, graph: dict | None = None, top: int = 6) -> list[dict]:
    """Corpus chains whose classes map onto this skill (or that name this class)."""
    import skill_map

    g = graph or build()
    want = {name_or_class}
    for cls, skills in skill_map.CLASS_SKILL.items():
        if name_or_class in skills:
            want.add(cls)
    out = [c for c in corpus_chains(top=0)
           if want & set(c["classes"]) or name_or_class in c["skills"]]
    return out[:top]


def partners(cls: str, graph: dict | None = None, top: int = 6) -> list[dict]:
    g = graph or build()
    out = [p for p in g["pairs"] if cls in p["classes"]]
    return out[:top]


def lint(graph: dict | None = None) -> list[str]:
    """Refs that point nowhere, and corpus classes no skill covers."""
    import skill_map

    g = graph or build()
    names = set(g["skills"])
    problems = []
    for e in g["edges"]:
        for side in ("src", "dst"):
            if e[side] not in names:
                problems.append(f"edge {e['src']} -> {e['dst']}: {e[side]} is not an installed skill")
    for cls, skills in sorted(skill_map.CLASS_SKILL.items()):
        for s in skills:
            if s not in names:
                problems.append(f"skill_map class {cls}: {s} is not an installed skill")
    seen_classes = {c for r in load_corpus() for c in (r.get("classes") or [])}
    for c in sorted(seen_classes):
        if c not in skill_map.CLASS_SKILL:
            problems.append(f"corpus class {c}: no skill_map entry")
    no_skip = [n for n, r in g["skills"].items() if not r["skip"]]
    for n in sorted(no_skip):
        problems.append(f"{n}: frontmatter description has no SKIP clause — no edges from it")
    return sorted(dict.fromkeys(problems))


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------
def render_skill(name: str, graph: dict | None = None) -> str:
    g = graph or build()
    row = g["skills"].get(name)
    if not row:
        near = [n for n in g["skills"] if name in n]
        return f"no such skill: {name}" + (f" — did you mean {', '.join(near[:5])}?" if near else "") + "\n"
    L = [f"SKILL {name}" + (f"  ({row['report_count']} disclosed reports curated)"
                            if row["report_count"] else "")]
    if row["trigger"]:
        L.append(f"  trigger   {re.sub(r'\\s+', ' ', row['trigger'])[:300]}")
    esc = escalations(name, g)
    fed = feeders(name, g)
    own = owners(name, g)
    if esc:
        L.append("  escalates to (prove this, then go there):")
        L += [f"    -> {e['dst']:<22} {e['why'][:110]}" for e in esc]
    if fed:
        L.append("  fed by (these proven, this skill is the chain):")
        L += [f"    <- {e['src']:<22} {e['why'][:110]}" for e in fed]
    if own:
        L.append("  defer to (that skill owns the surface):")
        L += [f"    .. {e['dst']:<22} {e['why'][:110]}" for e in own]
    ch = chains_for(name, g, top=4)
    if ch:
        L.append("  corpus chains that include it:")
        for c in ch:
            L.append(f"    {c['id']:<7} {c['severity']:<8} ${c['bounty']:<7,} "
                     f"{' + '.join(c['classes'])}")
    return "\n".join(L) + "\n"


def render_census(graph: dict | None = None) -> str:
    g = graph or build()
    kinds = Counter(e["kind"] for e in g["edges"])
    L = [f"skill_graph: {len(g['skills'])} skills · {len(g['edges'])} doctrine edges "
         f"({kinds.get('escalate', 0)} escalate, {kinds.get('owns', 0)} owns) · "
         f"{len(g['pairs'])} corpus class pairs from {g['corpus_rows']} reports"]
    hubs = Counter(e["dst"] for e in g["edges"] if e["kind"] == "escalate")
    if hubs:
        L.append("  escalation hubs (most primitives feed these — a chain ends here):")
        for name, n in hubs.most_common(6):
            L.append(f"    {name:<22} {n} feeder(s)")
    L.append("  class pairs in the corpus (reports behind them, then payout):")
    for p in g["pairs"][:8]:
        agg = f" +{p['aggregate_rows']} aggregate" if p["aggregate_rows"] else ""
        L.append(f"    {p['classes'][0]:>20} + {p['classes'][1]:<22} "
                 f"n={p['n']:<2} ${p['bounty']:,}{agg} {p['top_severity']}")
    return "\n".join(L) + "\n"


def render_chains(top: int, min_severity: str = "") -> str:
    out = ["corpus chains — one disclosed report each, ordered by severity then payout"]
    for c in corpus_chains(top=top, min_severity=min_severity):
        out.append(f"\n{c['id']}  {c['severity'].upper():<9} ${c['bounty']:,}  "
                   f"{' + '.join(c['classes'])}")
        if c["skills"]:
            out.append(f"  skills   {' -> '.join(c['skills'])}")
        if c["first_signal"]:
            out.append(f"  signal   {c['first_signal'][:160]}")
        for i, s in enumerate(c["steps"], 1):
            out.append(f"    {i}. {s[:170]}")
        if c["impact_proof"]:
            out.append(f"  proof    {c['impact_proof'][:160]}")
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="cbh skill-graph",
        description="the skill arsenal as a graph, plus the chains the disclosed corpus says pay")
    ap.add_argument("skill", nargs="?", default="", help="print one skill's row")
    ap.add_argument("--chains", action="store_true", help="corpus chains as templates")
    ap.add_argument("--ladder", default="", help="rank skills for a surface blob (URL / lead title)")
    ap.add_argument("--partners", default="", help="classes that co-occur with this class")
    ap.add_argument("--min-severity", default="", help="with --chains: high|critical …")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--lint", action="store_true", help="dangling refs and unmapped classes")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    g = build()
    if a.lint:
        problems = lint(g)
        if a.json:
            print(json.dumps(problems, indent=2))
        else:
            print(f"skill_graph lint: {len(problems)} problem(s)")
            for p in problems:
                print(f"  - {p}")
        return 1 if problems else 0
    if a.ladder:
        rows = ladder(a.ladder, g, top=a.top)
        if a.json:
            print(json.dumps(rows, indent=2))
            return 0
        print(f"ladder for: {a.ladder[:120]}")
        for r in rows:
            mark = "GATED" if r["gated"] else ("url" if r["via"] == "url-signal" else f"t{r['score']}")
            print(f"  {mark:<6} {r['skill']:<24} {r['vuln_class'] or '-':<22} "
                  f"defer:{','.join(r['defer_to']) or '-':<28} then:{','.join(r['escalates_to']) or '-'}")
        return 0
    if a.partners:
        rows = partners(a.partners, g, top=a.top)
        print(json.dumps(rows, indent=2) if a.json else "".join(
            f"  {' + '.join(p['classes']):<44} n={p['n']:<2} ${p['bounty']:,} {p['top_severity']}\n"
            for p in rows) or "  no pair with n>=2\n")
        return 0
    if a.chains:
        if a.json:
            print(json.dumps(corpus_chains(top=a.top, min_severity=a.min_severity), indent=2))
        else:
            sys.stdout.write(render_chains(a.top, a.min_severity))
        return 0
    if a.skill:
        if a.json:
            print(json.dumps({"skill": g["skills"].get(a.skill, {}),
                              "escalates_to": escalations(a.skill, g),
                              "fed_by": feeders(a.skill, g),
                              "defer_to": owners(a.skill, g),
                              "chains": chains_for(a.skill, g, top=a.top)}, indent=2))
        else:
            sys.stdout.write(render_skill(a.skill, g))
        return 0
    if a.json:
        print(json.dumps(g, indent=2))
    else:
        sys.stdout.write(render_census(g))
    return 0


if __name__ == "__main__":
    sys.exit(main())
