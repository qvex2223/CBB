#!/usr/bin/env python3
"""chain_graph — which missing capability unlocks the most of what we already have.

Written 2026-10-20. On ozon, ~6 primitives were each stuck on the same missing
precondition ("content on some *.acme.com origin"), and nobody saw it until every
file was read by hand. This makes that visible from the files themselves.

Any lead / primitive / finding may carry one line:

    **Chain:** needs `cap-a`, `cap-b` · gives `cap-c`

Capabilities are free-form slugs; reuse the same slug across files. The graph:
  * a capability is HAVE when some findings/ or primitives/ file gives it and that
    file is not itself waiting on a missing capability;
  * every needed capability that is not HAVE is MISSING;
  * MISSING capabilities are ranked by how many items they unblock (directly and
    through what those items then give), with the files that could supply them.

usage: chain_graph.py [<engagement dir>] [--json]
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

TIERS = {"findings": 3, "primitives": 2, "leads": 1}
CHAIN_RE = re.compile(r"^\**Chain:\**\s*(.*)$", re.I | re.M)
CAP_RE = re.compile(r"`([a-z0-9][a-z0-9._-]*)`")


# "needs `nothing`" is this workspace's own convention for an item that is already closed or
# needs no further capability, and it was being counted as a capability nobody supplies: on
# yukki-lk 2026-10-28 the literal `nothing` ranked third in the hub, "unblocking" three closed
# leads. These spellings mean "no need", so they parse to an empty needs list.
NO_NEED = {"nothing", "none", "nothing-more", "nothing-else", "nothing-we-do-not-have",
           "nothing-further", "n-a", "na"}


def _parse(line: str):
    needs, gives = [], []
    for part in re.split(r"\s*[·|;]\s*", line):
        low = part.strip().lower()
        caps = CAP_RE.findall(part)
        if low.startswith("needs"):
            needs += [c for c in caps if c.lower() not in NO_NEED]
        elif low.startswith("gives"):
            gives += caps
    return needs, gives


# A refuted item keeps its `Chain:` line -- the record of a kill is kept, not deleted -- so
# without this the graph goes on treating a dead primitive as a live supplier of capabilities
# and ranks the chains built on it. Only a dedicated marker counts, never prose: a `Status:`
# line whose value carries one of these words, a `Chain:` line that is literally DEAD, or a
# heading that opens with SUPERSEDED.
# Deliberately NOT in this list, both tried and rejected:
#   "NOT A FINDING" -- the primitives/ template header itself reads "Still not a finding",
#     so it would have killed every item written to the house style. That is live-but-
#     unproven, which is the whole point of the tier.
#   "MOOT" -- in a Status line it as often means "the blocker is moot" (the item got MORE
#     alive) as "the item is moot". Ambiguous, so it is not a marker.
# An item that really is dead says DEAD or REFUTED; both are cheap to write.
#
# REMEDIATION is a SEPARATE state from refutation, and leaving it out cost a real ranking
# distortion (Wildberries, 2026-11-05): a confirmed XSS on a trusted origin was submitted,
# reproduced by the vendor and PATCHED, yet its `findings/` file still carried
# `gives xss-on-trusted-origin`, so the graph listed that capability under `have:` and ranked
# everything downstream of it -- including a 1,000,000 RUB account-takeover scenario -- as
# already unblocked. The damage is the inverse of the refuted-lead case: the graph
# UNDER-ranks hunting for a new instance of the capability you just lost. A fixed finding was
# never wrong, so it must not be marked REFUTED; it simply no longer supplies anything.
#
# Only unambiguous PHRASES are markers here. Bare "FIXED" and "PATCHED" were tried and
# rejected: `is_dead` substring-matches the Status value, so "the guard is broken, not fixed"
# and "Status: primitive -- unpatched" would both kill a live item.
REMEDIATED_WORDS = ("REMEDIATED", "FIXED BY VENDOR", "PATCHED BY VENDOR", "FIX CONFIRMED")
# A bare word like REFUTED/DEAD/KILLED is ordinary narrative vocabulary in these write-ups --
# "hypothesis REFUTED" about ONE arm, "not a dead host", "capability proven, impact REFUTED" --
# so matching it anywhere in the Status value kills live items. Measured 2026-11-13 on
# rteam/activ: 47 items flagged dead, >=6 of them false, including a primitive whose status
# said "stands PROVEN and keeps supplying" three slugs and a STALLED lead that said "not a
# dead host". The same hazard was already recognised for FIXED/PATCHED just above and solved
# by requiring a PHRASE; it was never applied to these. So: bare verdict words match only as
# the LEADING token of the Status value, phrases match anywhere (a phrase cannot be negated,
# which is the property the comment above relies on).
VERDICT_DEAD_WORDS = ("DEAD", "REFUTED", "KILLED", "SUPERSEDED", "WITHDRAWN")
PHRASE_DEAD_WORDS = ("CLOSED NEGATIVE", *REMEDIATED_WORDS)
DEAD_WORDS = (*VERDICT_DEAD_WORDS, *PHRASE_DEAD_WORDS)
# Where the verdict token ends: a date, a dash, a bullet, a colon or a comma starts the prose.
_VERDICT_HEAD_RE = re.compile(r"^[^(\[\u2014\u2013:;,.\u00b7|]+")
STATUS_RE = re.compile(r"^\**Status:?\**:?\s*(.+)$", re.I | re.M)
DEAD_HEADING_RE = re.compile(r"^#+\s*\**(?:SUPERSEDED|DEAD|REFUTED|KILLED)\b", re.I | re.M)


def is_dead(text: str, chain_line: str = "") -> bool:
    """True when the item itself says it is refuted, superseded or dead."""
    if DEAD_HEADING_RE.search(text):
        return True
    if chain_line.strip().upper().lstrip("*").startswith("DEAD"):
        return True
    for m in STATUS_RE.finditer(text):
        value = m.group(1).upper()
        if any(w in value for w in PHRASE_DEAD_WORDS):
            return True
        head = _VERDICT_HEAD_RE.match(value.strip().lstrip("*").strip())
        head = head.group(0).strip() if head else ""
        if any(head.startswith(w) for w in VERDICT_DEAD_WORDS):
            return True
    return False


def _tier_files(d: Path):
    """Markdown in the tier, plus one-folder-per-item READMEs.

    `findings/<slug>/README.md` is the layout this workspace actually uses; a bare
    `*.md` glob does not see it, so a folder-form item was silently absent from the
    graph -- it contributed no capability and nothing said so.
    """
    yield from sorted(d.glob("*.md"))
    for sub in sorted(p for p in d.iterdir() if p.is_dir()):
        # README.md OR finding.md: the folder form is written both ways in this
        # workspace, and stop_gate.py reads `finding.md`. Looking for README.md alone
        # meant a CONFIRMED finding was invisible here -- its capability still showed as
        # MISSING with "nothing on file supplies it", which is the opposite of the truth
        # (www.acme.com XSS supplying `xss-on-trusted-origin`, 2026-11-03).
        for name in ("README.md", "finding.md"):
            f = sub / name
            if f.is_file():
                yield f
                break


def load(eng: Path, include_dead: bool = False):
    items = []
    for tier in TIERS:
        d = eng / tier
        if not d.is_dir():
            continue
        for f in _tier_files(d):
            text = f.read_text(encoding="utf-8", errors="replace")
            # The LAST `Chain:` line wins, not the first. An item that gets re-measured
            # appends an UPDATE block carrying a corrected Chain line and leaves the
            # original in place as the observation trail -- that is the house style. With
            # `search()` the stale first line won, so on yukki-lk the strongest capability
            # on the engagement (the image optimizer's RFC1918 fetch) contributed NOTHING
            # to the graph in either direction, silently, because its first line spelled
            # the capabilities out as prose that CAP_RE cannot match. Found 2026-10-28.
            ms = list(CHAIN_RE.finditer(text))
            if not ms:
                continue
            m = ms[-1]
            needs, gives = _parse(m.group(1))
            rel = f.relative_to(eng).as_posix()
            dead = is_dead(text, m.group(1))
            if dead and not include_dead:
                continue
            items.append({"file": rel, "tier": tier, "needs": needs,
                          "gives": gives, "dead": dead})
    return items


def analyse(items):
    have = set()
    changed = True
    while changed:                      # a primitive whose needs are met can supply its gives
        changed = False
        for it in items:
            if it["tier"] == "leads":
                continue
            if all(n in have for n in it["needs"]) and not set(it["gives"]) <= have:
                have |= set(it["gives"])
                changed = True
    missing = {}
    for it in items:
        for n in it["needs"]:
            if n not in have:
                missing.setdefault(n, {"cap": n, "unblocks": [], "suppliers": []})
                missing[n]["unblocks"].append(it["file"])
    for it in items:
        for g in it["gives"]:
            if g in missing:
                missing[g]["suppliers"].append(it["file"])

    def reach(cap, seen=None):
        """Items unblocked by `cap`, including the ones those items then unblock."""
        seen = seen if seen is not None else set()
        got = have | {cap}
        progress = True
        while progress:
            progress = False
            for it in items:
                if it["file"] in seen:
                    continue
                if all(n in got for n in it["needs"]) and any(n == cap or n in got - have for n in it["needs"]):
                    seen.add(it["file"])
                    got |= set(it["gives"])
                    progress = True
        return seen

    tier_of = {it["file"]: TIERS[it["tier"]] for it in items}
    for m in missing.values():
        r = reach(m["cap"])
        m["reach"] = sorted(r)
        m["score"] = sum(tier_of[f] for f in r)
    ranked = sorted(missing.values(), key=lambda m: (-m["score"], m["cap"]))
    return {"have": sorted(have), "missing": ranked, "annotated": len(items)}


OPERATOR_CAP = re.compile(r"^(programme-approval|program-approval|operator)-")


def _no_supplier(cap: str) -> str:
    if OPERATOR_CAP.match(cap):
        return "(operator action — ask the programme / the operator; see Targets/OPERATOR-QUEUE.md)"
    return "(nothing on file supplies it — finding it is the next hunt)"


def brief_line(eng: Path) -> str:
    res = analyse(load(eng))
    if not res["missing"]:
        return ""
    top = res["missing"][0]
    who = ", ".join(Path(f).stem for f in top["suppliers"][:2]) or _no_supplier(top["cap"])
    return (f"CHAIN HUB: `{top['cap']}` would unblock {len(top['reach'])} item(s) "
            f"— supplier: {who}  (cbh chain-graph)")


def _resolve_engagement(argv) -> Path | None:
    """Resolve the engagement folder from argv, then $CBH_PROJECT, then the cwd.

    The value can arrive as a bare positional or as `--project <name>` / `--project=<name>`,
    and in either form it is usually an engagement NAME (`standoff365/mail_vk`) rather than
    a usable path. Taken literally that is a RELATIVE path which only resolves when the cwd
    happens to be the `Targets` root, so `cbh chain-graph --project standoff365/mail_vk`
    printed `mail_vk: 0 annotated item(s) · have: -` while `CBH_PROJECT=standoff365/mail_vk
    cbh chain-graph` printed 127 items (reported by a scout lane 2026-11-13). That is the
    dangerous shape: the RIGHT project name beside a zero reads as "nothing is annotated"
    rather than "I could not find this folder", and a reader then concludes the chain graph
    is empty and stops annotating. Worse, the old code stripped every `--*` token but kept
    `--project`'s value as a positional, so naming the flag was what broke it.

    Anchoring a name against the workspace `Targets` root is already solved once, in
    `pacing.find_project_dir` for $CBH_PROJECT, including the nested `platform/program`
    layout. A name is therefore delegated to it instead of being re-resolved here. Returns
    None when nothing resolves, so the caller can say so instead of printing a zero.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from pacing import find_project_dir  # noqa: PLC0415 - sibling module

    cand = None
    skip = False
    for i, a in enumerate(argv):
        if skip:
            skip = False
            continue
        if a == "--project":
            cand = argv[i + 1] if i + 1 < len(argv) else None
            skip = True
        elif a.startswith("--project="):
            cand = a.split("=", 1)[1]
        elif not a.startswith("--") and cand is None:
            cand = a

    if cand:
        direct = Path(cand)
        if direct.is_dir():
            return direct
        # A name, not a path: anchor it exactly as $CBH_PROJECT is anchored.
        prev = os.environ.get("CBH_PROJECT")
        os.environ["CBH_PROJECT"] = cand
        try:
            found = find_project_dir()
        finally:
            if prev is None:
                os.environ.pop("CBH_PROJECT", None)
            else:
                os.environ["CBH_PROJECT"] = prev
        return found  # may be None -> caller reports it
    return find_project_dir() or Path.cwd()


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    eng = _resolve_engagement(argv)
    if eng is None or not eng.is_dir():
        named = next((a.split("=", 1)[1] for a in argv if a.startswith("--project=")), None)
        if named is None:
            rest = [a for a in argv if not a.startswith("--")]
            named = rest[0] if rest else "(none)"
        print(f"chain-graph: no engagement folder for {named!r} — "
              f"expected a directory inside Targets/ (try `cbh chain-graph` from inside the "
              f"engagement, or CBH_PROJECT=<platform>/<program>)", file=sys.stderr)
        return 2
    res = analyse(load(eng))
    if "--json" in argv:
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    print(f"{eng.name}: {res['annotated']} annotated item(s) · have: {', '.join(res['have']) or '—'}")
    if not res["missing"]:
        print("no missing capability (or nothing annotated — add `**Chain:** needs `x` · gives `y`` lines)")
    for m in res["missing"]:
        print(f"\nMISSING `{m['cap']}` — unblocks {len(m['reach'])} item(s), score {m['score']}")
        for f in m["reach"]:
            print(f"   unblocks  {f}")
        for f in m["suppliers"] or [_no_supplier(m["cap"])]:
            print(f"   supplier  {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
