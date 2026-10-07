#!/usr/bin/env python3
"""
learn.py — close the loop: what did we learn, and what is the taxonomy missing?

`pattern-analytics` answers "what works on this stack". It cannot see the thing
that most needs seeing: **findings that fit no existing class**. Those either
get logged as `generic` and disappear, or get forced into a nearby class and
teach the classifier the wrong shape. Either way the map stops growing exactly
where it should grow fastest.

Three reads, one artefact:

  * **novel techniques** — journal rows whose technique/vuln_class matches no
    known pattern in `technique_classifier`. These are the honest signals that
    the taxonomy is stale, and they are the raw material for a new skill.
  * **mutation yield** — which mutations from `vectors.py rotate` actually
    turned into confirmed results, per stack. The rotation matrix is generic on
    purpose; this is what makes its *order* specific to the target in front of
    you.
  * **suggestions** — concrete next steps: a skill to write, a pattern to add,
    a mutation to try first. Printed as prose, because a suggestion an operator
    will act on is prose, not a chart.

Everything is derived from rows the operator already logged with `/remember`.
It invents nothing, and a technique with no rows behind it is reported as
unknown rather than as zero.

CLI:
    python3 engine/learn.py
    python3 engine/learn.py --target kcell
    python3 engine/learn.py --format md --out learnings.md
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

SCHEMA_VERSION = "1.0"

# Slugs the classifier and /remember already use for "we don't have a name for
# this yet". Anything in this family is a novelty signal, not a real class.
PLACEHOLDER = re.compile(r"(?i)^(generic|unspecified|other|unknown|unclassified)"
                         r"($|__|[-_])")


def _memdir(explicit: Optional[Path] = None) -> Path:
    if explicit:
        return Path(explicit)
    env = os.environ.get("CBH_MEMORY_DIR")
    if env:
        return Path(env)
    for cand in (ROOT / "hunt-memory", Path.cwd() / "hunt-memory"):
        if cand.exists():
            return cand
    return Path.home() / ".cbh" / "hunt-memory"


def _tail_jsonl(path: Path, limit: int = 20000) -> List[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


def _known_techniques() -> List[str]:
    """Pattern names the classifier can already assign — the current map."""
    try:
        import technique_classifier as TC  # type: ignore
    except Exception:
        return []
    names: List[str] = []
    for key in ("TECHNIQUE_PATTERNS", "PATTERNS"):
        table = getattr(TC, key, None)
        if isinstance(table, dict):
            names.extend(str(k) for k in table.keys())
    return sorted(set(names))


def _known_classes() -> List[str]:
    try:
        from memory import normalize_vuln_class  # type: ignore
    except Exception:
        return []
    # normalize_vuln_class maps anything, so the real list is the skill set.
    skills = ROOT / "skills"
    out = []
    if skills.exists():
        for p in skills.iterdir():
            if p.name.startswith("hunt-"):
                out.append(p.name[len("hunt-"):])
    return sorted(set(out))


def _is_novel(technique: str, vuln_class: str, known_tech: List[str],
              known_cls: List[str]) -> bool:
    t = (technique or "").strip().lower()
    v = (vuln_class or "").strip().lower()
    if not t and not v:
        return True
    if PLACEHOLDER.match(t) or PLACEHOLDER.match(v):
        return True
    if t and t not in {k.lower() for k in known_tech}:
        # unknown technique slug, but a known vuln class is not novel — it is
        # just an unnormalised technique name.
        if v and v in {c.lower() for c in known_cls}:
            return False
        return True
    return False


def analyze(memdir: Optional[Path] = None, target: str = "") -> dict:
    mem = _memdir(memdir)
    journal = _tail_jsonl(mem / "journal.jsonl")
    patterns = _tail_jsonl(mem / "patterns.jsonl")
    if target:
        journal = [r for r in journal if r.get("target") in (None, "", target)]
        patterns = [r for r in patterns if r.get("target") in (None, "", target)]

    known_tech = _known_techniques()
    known_cls = _known_classes()

    novel = []
    for r in journal:
        tech = r.get("technique") or ""
        cls = r.get("vuln_class") or r.get("class") or ""
        if _is_novel(str(tech), str(cls), known_tech, known_cls):
            novel.append({
                "target": r.get("target"), "endpoint": r.get("endpoint"),
                "technique": tech, "vuln_class": cls,
                "result": r.get("result") or r.get("outcome"),
                "notes": (r.get("notes") or "")[:300],
            })

    # Mutation yield: technique → outcome counts, then per stack when tagged.
    by_tech: Dict[str, Counter] = defaultdict(Counter)
    by_stack: Dict[str, Counter] = defaultdict(Counter)
    for r in journal + patterns:
        tech = (r.get("technique") or "unspecified").strip() or "unspecified"
        outcome = (r.get("result") or r.get("outcome") or "confirmed").strip().lower()
        by_tech[tech][outcome] += 1
        stack = r.get("tech") or r.get("stack") or ""
        if isinstance(stack, list):
            stack = ",".join(str(s) for s in stack)
        if stack:
            by_stack[str(stack)][f"{tech}:{outcome}"] += 1

    def _yield(counter: Counter) -> dict:
        total = sum(counter.values())
        good = counter.get("confirmed", 0) + counter.get("accepted", 0) + counter.get("paid", 0)
        bad = counter.get("rejected", 0) + counter.get("na", 0) + counter.get("duplicate", 0)
        return {"total": total, "confirmed": good, "rejected": bad,
                "rate": round(good / total, 3) if total else None}

    techniques = []
    for tech, counter in sorted(by_tech.items(), key=lambda kv: -sum(kv[1].values())):
        row = {"technique": tech}
        row.update(_yield(counter))
        row["outcomes"] = dict(counter)
        techniques.append(row)

    stacks = []
    for stack, counter in sorted(by_stack.items(), key=lambda kv: -sum(kv[1].values())):
        stacks.append({"stack": stack, "signals": dict(counter.most_common(12))})

    # ---- suggestions -----------------------------------------------------
    suggestions: List[dict] = []
    if novel:
        suggestions.append({
            "kind": "grow-the-map",
            "priority": 95,
            "action": (f"{len(novel)} row(s) fit no known class. Draft a new `hunt-*` "
                       f"fragment (or extend one) from them — starting with "
                       f"`{novel[0].get('technique') or novel[0].get('vuln_class') or 'unclassified'}`. "
                       "A find with no class is the map being stale, not the find being weak."),
            "rows": novel[:10],
        })
    strong = [t for t in techniques if t["rate"] and t["rate"] >= 0.4 and t["total"] >= 2]
    if strong:
        suggestions.append({
            "kind": "mutation-order",
            "priority": 90,
            "action": ("Lead with the techniques that already convert here: "
                       + ", ".join(f"{t['technique']} ({t['confirmed']}/{t['total']})"
                                   for t in strong[:5])
                       + ". Put them first in the rotate order for this stack."),
            "rows": strong[:5],
        })
    dead = [t for t in techniques if t["total"] >= 3 and t["rate"] == 0.0]
    if dead:
        suggestions.append({
            "kind": "stop-repeating",
            "priority": 70,
            "action": ("These have burned at least three attempts here with no conversion — "
                       "stop leading with them: "
                       + ", ".join(t["technique"] for t in dead[:5])),
            "rows": dead[:5],
        })
    if not techniques and not novel:
        suggestions.append({
            "kind": "feed-the-corpus",
            "priority": 60,
            "action": ("No rows yet. `/remember` every closed thread — confirmed AND "
                       "rejected — because a rejected result is what stops the next "
                       "session repeating a dead move."),
            "rows": [],
        })

    suggestions.sort(key=lambda s: -s["priority"])
    return {
        "schema_version": SCHEMA_VERSION,
        "target": target or "(all)",
        "counts": {
            "journal_rows": len(journal),
            "pattern_rows": len(patterns),
            "novel": len(novel),
            "techniques": len(techniques),
            "known_techniques": len(known_tech),
            "known_classes": len(known_cls),
        },
        "novel": novel,
        "techniques": techniques,
        "stacks": stacks,
        "suggestions": suggestions,
    }


def to_markdown(result: dict) -> str:
    c = result["counts"]
    out = [f"# Learnings — {result['target']}", "",
           f"Journal rows: **{c['journal_rows']}** · patterns: **{c['pattern_rows']}** · "
           f"taxonomy knows {c['known_techniques']} techniques and {c['known_classes']} classes.",
           ""]
    if result["suggestions"]:
        out.append("## Suggestions")
        out.append("")
        for s in result["suggestions"]:
            out.append(f"- **{s['kind']}** (p{s['priority']}): {s['action']}")
        out.append("")
    if result["novel"]:
        out.append("## Novel — fits no known class")
        out.append("")
        out.append("These are the map's blind spots. Do not force them into a nearby "
                   "class; write the class they are.")
        out.append("")
        for n in result["novel"][:25]:
            out.append(f"- `{n.get('technique') or 'unclassified'}` / "
                       f"{n.get('vuln_class') or '?'} on `{n.get('endpoint') or n.get('target')}` "
                       f"[{n.get('result')}] — {n.get('notes') or ''}")
        out.append("")
    if result["techniques"]:
        out.append("## Technique yield")
        out.append("")
        out.append("| technique | total | confirmed | rejected | rate |")
        out.append("|---|---|---|---|---|")
        for t in result["techniques"][:30]:
            rate = "—" if t["rate"] is None else f"{t['rate']:.0%}"
            out.append(f"| `{t['technique']}` | {t['total']} | {t['confirmed']} | "
                       f"{t['rejected']} | {rate} |")
        out.append("")
    return "\n".join(out) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="", help="limit to one engagement")
    ap.add_argument("--dir", type=Path, default=None, help="hunt-memory directory")
    ap.add_argument("--format", choices=("json", "md"), default="json")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    result = analyze(memdir=args.dir, target=args.target)
    text = to_markdown(result) if args.format == "md" else \
        json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"{args.out}: {result['counts']['novel']} novel, "
              f"{len(result['suggestions'])} suggestions")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
