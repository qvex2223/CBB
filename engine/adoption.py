#!/usr/bin/env python3
"""
adoption.py — did a vector class we registered actually get used, or is it a dead file?

A `SKILL.md` edit changes nothing a worker ever runs. Lanes come from `cbh leads` and
`cbh vectors next`, and `cbh vectors next` reads a per-host ledger seeded from
`engine/vectors.py`. A class that is not in that module's tables is never seeded, never
ranked, never offered and never fired — the skill describing it sits on disk unread. This
module answers that question from artifacts instead of from memory:

    cbh adoption                 every registered class, one row each
    cbh adoption --lint          only the rows that are wrong, with the reason
    cbh adoption --class idor    one class in detail, per host and per mutation
    cbh adoption --project <eng> restrict the funnel half to one engagement

How to read a row:

  registered 0        the class is in no table at all — nothing can route it
  ROUTE                the class is registered but missing from lead_queue.known_classes(),
                       so `**Class:** <name>` on a finding is SILENTLY DROPPED and the
                       class-proof gate grades a guessed class instead of the declared one
  seeded 0             registered and never seeded: the registration half of its item was
                       never done, or no host's surface justified it
  offered>0 fired 0    the queue offers it and workers skip it — the skill text or the
                       brief is the problem, not the registration
  fired>0 closed 0     lanes fire it and nothing closes: the oracle is missing

Three traps this module exists to respect:

  * `fired` comes from `hunt-memory/audit.jsonl`, NEVER from a vector's own `status` or
    `requests_fired`. A ledger marking is a record of what someone wrote down, not evidence
    of what was sent; the two disagree, and the ledger is the one that lies. Where they
    disagree this prints `LEDGER?`.
  * The audit key is `urls`, PLURAL. A row with no `urls` is not a row that sent nothing.
  * Audit attribution is per HOST, not per endpoint, because a ledger is keyed per host and
    an audit row carries no class. A per-endpoint count is only honest inside `--class`,
    where the candidate set is small enough to match without guessing.

It reads only. It sends nothing and writes nothing.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Dict, Iterator, List, Tuple

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import funnel  # noqa: E402  the one definition of an item and its name
import lead_queue  # noqa: E402  known_classes / declared_class / closure reading
import vectors  # noqa: E402  the four registration tables


# ---------------------------------------------------------------- registration

def registered() -> Dict[str, List[str]]:
    """Every class any table knows, mapped to the tables that carry it.

    These are the four tables a class must pass through to become a lane, plus the two
    that make its name legible to the funnel. A class missing from `class_words`/`skill_map`
    is the silent failure: `lead_queue.declared_class` returns "" for an unknown name.
    """
    tables: Dict[str, List[str]] = {}

    def mark(name: str, table: str) -> None:
        tables.setdefault(name, [])
        if table not in tables[name]:
            tables[name].append(table)

    for c in vectors.CATALOG:
        mark(c, "catalog")
    for c in vectors.CLASS_MUTATIONS:
        mark(c, "mutations")
    for c in vectors.CONSUMERS:
        mark(c, "consumers")
    for classes in vectors.HINT_CLASSES.values():
        for c in classes:
            mark(c, "hints")
    for c in vectors.HYPOTHESIS_CLASSES.values():
        mark(c, "hypotheses")
    for _rx, c in lead_queue.CLASS_WORDS:
        mark(c, "class_words")
    try:
        import skill_map  # noqa: PLC0415
        for c in skill_map.CLASS_SKILL:
            mark(c, "skill_map")
    except Exception:  # noqa: BLE001 - a missing skill_map must not end the report
        pass
    return tables


# ---------------------------------------------------------------- ledgers

def ledgers(memdir: Path | None = None) -> Iterator[Tuple[str, dict]]:
    """(host, vector) for every vector in every per-host ledger."""
    d = (memdir or vectors.resolve_dir()) / "vectors"
    if not d.is_dir():
        return
    for f in sorted(d.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 - one unreadable ledger must not end the sweep
            continue
        host = str(data.get("target") or f.stem)
        for v in data.get("vectors") or []:
            if isinstance(v, dict):
                yield host, v


# ---------------------------------------------------------------- audit

def audit_by_host(memdir: Path | None = None) -> Counter:
    """Requests actually sent, counted per host, over the live log and its rotations.

    The rotations are included on purpose: a class fired three weeks ago was still fired,
    and leaving them out would print `fired 0` for work that is in the record.
    """
    base = (memdir or vectors.resolve_dir())
    out: Counter = Counter()
    for name in ("audit.jsonl", "audit.jsonl.1", "audit.jsonl.2", "audit.jsonl.3"):
        f = base / name
        if not f.is_file():
            continue
        with f.open(encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:  # noqa: BLE001 - a malformed row is not a fired request
                    continue
                for u in row.get("urls") or []:   # `urls`, plural — see the module docstring
                    h = (urllib.parse.urlparse(str(u)).hostname or "").lower()
                    if h:
                        out[h] += 1
    return out


def audit_window(memdir: Path | None = None) -> Tuple[str, str]:
    """(earliest, latest) timestamp in the RETAINED audit log, or ("", "").

    This is the whole reason a `LEDGER?` flag is not an accusation: the log rotates, so a
    ledger can honestly record requests that no retained file still holds. Measured
    2026-11-17: the retained window started 2026-11-02, while `new.ykky.ru` carried 79
    ledger-recorded requests from before it and appeared in no retained file at all.
    """
    base = (memdir or vectors.resolve_dir())
    first, last = "", ""
    for name in ("audit.jsonl.3", "audit.jsonl.2", "audit.jsonl.1", "audit.jsonl"):
        f = base / name
        if not f.is_file():
            continue
        with f.open(encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                try:
                    ts = str(json.loads(line).get("timestamp") or "")
                except Exception:  # noqa: BLE001
                    continue
                if not ts:
                    continue
                if not first or ts < first:
                    first = ts
                if ts > last:
                    last = ts
    return first[:10], last[:10]


def audit_urls(memdir: Path | None = None) -> List[str]:
    """Every url in the audit log, for the per-endpoint detail of `--class`."""
    base = (memdir or vectors.resolve_dir())
    out: List[str] = []
    for name in ("audit.jsonl", "audit.jsonl.1", "audit.jsonl.2", "audit.jsonl.3"):
        f = base / name
        if not f.is_file():
            continue
        with f.open(encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                out += [str(u) for u in (row.get("urls") or [])]
    return out


# ---------------------------------------------------------------- funnel

def funnel_by_class(project: str = "") -> Dict[str, Counter]:
    """Per class: how many items are open, and how each closed one closed.

    The class is the file's own declaration when it has one, and the inferred class
    otherwise — exactly what `lead_queue.scan` ranks on, so a count here cannot disagree
    with the queue. Item names come from `funnel.item_name`, never `Path.stem`, or a
    folder-form write-up is counted under the name "README".
    """
    root = lead_queue._targets_root()  # noqa: SLF001 - one definition of the corpus root
    out: Dict[str, Counter] = {}
    engs = []
    if project:
        e = lead_queue.resolve_engagement(project)
        if e:
            engs = [e]
    else:
        engs = [d for d in sorted(root.glob("*/*")) if d.is_dir() and d.parent.name != "_TEMPLATE"]
    for eng in engs:
        for kind in ("findings", "primitives", "leads"):
            for f in funnel.tier_items(eng / kind):
                try:
                    text = f.read_text(encoding="utf-8", errors="ignore")
                except Exception:  # noqa: BLE001
                    continue
                cls = lead_queue.declared_class(text) or \
                    lead_queue._class_of(funnel.item_name(f), (text.splitlines() or [""])[0])  # noqa: SLF001
                c = out.setdefault(cls, Counter())
                if lead_queue._is_closed(text):  # noqa: SLF001
                    verdict = next((b.split()[0] for b in lead_queue._banners(text)  # noqa: SLF001
                                    if b.startswith(lead_queue.CLOSURE_WORDS)), "closed")
                    c[verdict] += 1
                    c["closed"] += 1
                else:
                    c["open"] += 1
    return out


# ---------------------------------------------------------------- report

OFFERABLE = ("untried", "active")


def rows(project: str = "", memdir: Path | None = None) -> List[dict]:
    reg = registered()
    seeded: Dict[str, int] = {}
    offered: Dict[str, int] = {}
    led_fired: Dict[str, int] = {}
    hosts: Dict[str, set] = {}
    for host, v in ledgers(memdir):
        cls = str(v.get("class") or "?")
        seeded[cls] = seeded.get(cls, 0) + 1
        hosts.setdefault(cls, set()).add(host)
        if str(v.get("status") or "") in OFFERABLE:
            offered[cls] = offered.get(cls, 0) + 1
        led_fired[cls] = led_fired.get(cls, 0) + int(v.get("requests_fired") or 0)

    ahosts = audit_by_host(memdir)
    fun = funnel_by_class(project)
    routable = lead_queue.known_classes()

    out = []
    for cls in sorted(set(reg) | set(seeded) | set(fun)):
        # Per-class audit attribution is the sum over the hosts whose ledger carries this
        # class. It over-counts (a host's requests are not all this class) and is printed as
        # `host-req`, not as this class's own request count, so nobody reads it as one.
        host_req = sum(ahosts.get(h, 0) for h in hosts.get(cls, ()))
        f = fun.get(cls, Counter())
        out.append({
            "class": cls,
            "tables": reg.get(cls, []),
            "routable": cls in routable,
            "seeded": seeded.get(cls, 0),
            "offered": offered.get(cls, 0),
            "ledger_fired": led_fired.get(cls, 0),
            "host_req": host_req,
            "hosts": len(hosts.get(cls, ())),
            "open": f.get("open", 0),
            "closed": f.get("closed", 0),
            "proven": f.get("proven", 0),
            "refuted": f.get("refuted", 0),
        })
    return out


def flags(r: dict) -> List[str]:
    """Why this row is wrong, in the order it matters. Empty = nothing to fix."""
    out = []
    if not r["tables"]:
        out.append("registered 0 — in no table; nothing can route it")
    elif not r["routable"]:
        out.append("ROUTE — missing from lead_queue.known_classes(): a `**Class:** "
                   f"{r['class']}` declaration is silently dropped")
    if r["tables"] and not r["seeded"]:
        out.append("seeded 0 — registered but no ledger carries it")
    if r["offered"] and not r["ledger_fired"] and not r["host_req"]:
        out.append("offered but never fired — the skill text or the brief, not the registration")
    if r["ledger_fired"] and not r["host_req"]:
        # NOT an accusation: the audit log rotates. Read it against the retained window in
        # the footer — a class whose work predates that window is rotation, and only a
        # class fired INSIDE it with no audit row is a channel that did not audit.
        out.append("LEDGER? — the ledger claims requests no RETAINED audit file shows "
                   "(rotation, or a channel that did not audit)")
    # `host_req` deliberately does NOT enter this one: it counts every request to every host
    # carrying the class, so it would fire for any class seeded on a busy host and the flag
    # would read as "nothing records what this found" for classes nobody ever fired.
    if r["ledger_fired"] and not r["closed"] and not r["open"]:
        out.append("fired with no funnel item — nothing records what it found")
    return out


def render(rs: List[dict], lint_only: bool) -> str:
    # The first header said `tables  route` with a COUNT under `tables` and yes/no under
    # `route`, and a reader (a Grok verification run, 2026-11-17) assigned the count to `route`
    # and reported "route=4". Name the unit in the header so the column cannot be mis-read.
    L = ["class                    #tbl route seeded offer led-req host-req hosts open closed  prov/ref",
         "-" * 108]
    shown = 0
    for r in rs:
        fl = flags(r)
        if lint_only and not fl:
            continue
        shown += 1
        L.append(f"{r['class'][:24]:<24} {len(r['tables']):>4} {'yes' if r['routable'] else 'NO':>5} "
                 f"{r['seeded']:>6} {r['offered']:>5} {r['ledger_fired']:>7} {r['host_req']:>8} "
                 f"{r['hosts']:>5} {r['open']:>4} {r['closed']:>6}  {r['proven']:>4}/{r['refuted']:<4}")
        for f in fl:
            L.append(f"    ! {f}")
    if not shown:
        L.append("    (nothing to report)")
    first, last = audit_window()
    L += ["", f"{shown} row(s). `led-req` is the ledger's own claim; `host-req` is audit rows for "
              "every host carrying the class, so it over-counts and is a presence signal, not a "
              "per-class total.",
          f"retained audit window: {first or '?'} .. {last or '?'} — a `LEDGER?` row whose work "
          "predates it is rotation, not a bypass."]
    return "\n".join(L)


def detail(cls: str, memdir: Path | None = None) -> str:
    urls = audit_urls(memdir)
    L = [f"class {cls}", ""]
    reg = registered().get(cls, [])
    L.append(f"  tables     {', '.join(reg) if reg else 'NONE — nothing can route this class'}")
    L.append(f"  routable   {'yes' if cls in lead_queue.known_classes() else 'NO — declaration dropped'}")
    cat = vectors.CATALOG.get(cls) or {}
    if cat:
        L.append(f"  catalog    impact={cat.get('impact')} skill={cat.get('skill')}")
    muts = vectors.CLASS_MUTATIONS.get(cls) or []
    tried: Counter = Counter()
    per_host: Counter = Counter()
    per_ep: Dict[str, dict] = {}
    for host, v in ledgers(memdir):
        if str(v.get("class") or "") != cls:
            continue
        per_host[host] += 1
        ep = str(v.get("endpoint") or "")
        d = per_ep.setdefault(ep, {"n": 0, "fired": 0, "status": Counter()})
        d["n"] += 1
        d["fired"] += int(v.get("requests_fired") or 0)
        d["status"][str(v.get("status") or "?")] += 1
        for m in v.get("mutations_tried") or []:
            tried[str(m)] += 1
    L.append("")
    L.append(f"  mutation matrix ({len(muts)} class entries + generic)")
    for m in muts:
        L.append(f"    {tried.get(m, 0):>5}x  {m[:88]}")
    untried_labels = [m for m in muts if not tried.get(m)]
    if untried_labels:
        L.append(f"    {len(untried_labels)} matrix entr(y/ies) never recorded as tried")
    L.append("")
    L.append(f"  hosts ({len(per_host)})  top: " +
             ", ".join(f"{h}={n}" for h, n in per_host.most_common(6)))
    L.append("")
    L.append("  endpoints (top 12 by ledger-claimed requests)")
    for ep, d in sorted(per_ep.items(), key=lambda kv: -kv[1]["fired"])[:12]:
        # Per-endpoint audit match: honest here because the candidate set is this one class.
        hit = sum(1 for u in urls if ep and ep in u)
        L.append(f"    n={d['n']:<3} led-req={d['fired']:<5} audit={hit:<5} "
                 f"{'/'.join(f'{k}:{v}' for k, v in d['status'].items())[:28]:<28} {ep[:46]}")
    return "\n".join(L)


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cbh adoption",
                                 description=__doc__.strip().splitlines()[0])
    ap.add_argument("--class", dest="cls", default="", help="one class, in detail")
    ap.add_argument("--lint", action="store_true", help="only the rows that are wrong")
    ap.add_argument("--project", default="", help="restrict the funnel half to one engagement")
    a = ap.parse_args(list(sys.argv[1:] if argv is None else argv))
    if a.cls:
        print(detail(a.cls))
        return 0
    rs = rows(a.project)
    print(render(rs, a.lint))
    return 1 if (a.lint and any(flags(r) for r in rs)) else 0


if __name__ == "__main__":
    sys.exit(main())
