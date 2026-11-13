#!/usr/bin/env python3
"""
freeroam.py — the second agent, the one that knows nothing, and the merge that
makes the pair worth more than either half.

Every role in `/parallel` is a *skilled* role: it gets the methodology, the
`hunt-*` taxonomy, the mutation ladder. N skilled hunters share one blind spot,
which is precisely the thing `/parallel` already warns about, and the taxonomy is
survivorship bias by construction — a class only has a skill because it already
paid, which means the program has a known-issues entry for it.

The published fix is asymmetric on purpose: agent A gets everything, agent B gets
**the URL and the authorization and nothing else**, then the two outputs are
diffed and whatever only B saw is promoted into the methodology. This module is
the B half plus the diff.

What makes B honest:

* `agent.run_agent(..., skills_on=False)` already cannot load a skill — `Skill` is
  absent from `ALLOWED_TOOLS` and `--disable-slash-commands` closes the other door.
  So "no methodology" is enforced by the runner, not promised in a prompt.
* the prompt below names no vulnerability class, no payload, no tool beyond the
  transport, and no ranking. It says what the target is, what it may touch, and
  that a claim needs a response behind it. That is all.
* the brakes are unchanged: requests leave through `bbcurl` and the gated MCP
  servers, so scope, pacing, mandatory headers and the audit log all still apply.
  `--project` is passed through as `CBH_PROJECT` so a worker started from the repo
  root is still inside the right engagement.

The merge is mechanical: items are keyed by (surface, claim-shape), so "only B saw
this" is a fact about two JSON files rather than an impression. `B-only` is the
output that matters — it is the list of things the taxonomy would have missed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List

ENGINE = Path(__file__).resolve().parent
sys.path.insert(0, str(ENGINE))

from agent import extract_json, run_agent  # noqa: E402
from pacing import Engagement  # noqa: E402

# No class names, no payloads, no ranking, no "check for X" list. Anything that
# names a vulnerability class here would re-introduce exactly the prior this agent
# exists to avoid.
PROMPT = """You are testing a web application you have never seen, under written
authorization. Target: {target}

{identity}

What you may do:
- send HTTP requests with `bbcurl` (same flags as curl). It is the only transport:
  it carries the program's scope check, its rate budget and its audit log, so every
  request you make is already within the rules.
  **Two transport facts that have cost earlier runs their whole budget.** First, the
  engagement is resolved from the working directory, so every call needs the prefix
  `CBH_PROJECT={project} ` and you must stay in the repository — from `/tmp` or any
  path outside it nothing resolves and `bbcurl` refuses every non-local URL. Second,
  this estate's edge serves a cookie-less redirect to a challenge on first contact:
  if a request comes back as a small `307` to a URL carrying `__rr`, that is the
  cookie-less branch and it tells you nothing about the host — not a refusal, not an
  answer.
- drive the browser through the playwright MCP tools when a page's behaviour, not
  its bytes, is the question.
- read anything the application serves you.
- read exactly two local files: this engagement's `scope.md` (what you may touch)
  and its `identity.json` (your own credentials, if it exists).

What you may not do:
- touch any host other than the target above. Not a sibling, not a host you find
  mentioned in a page or a file. The target above, and nothing else.
- read this engagement's own record: `notes.md`, `hosts/`, `leads/`, `primitives/`,
  `findings/`, `blocked-tests/`, `recon/`, or the hunt memory. This is the point of
  the whole exercise and it is not negotiable. Those files hold another agent's
  conclusions about this target, and once you have read them you are checking its
  homework instead of looking at the application. A run that read them produces
  what is already written down, which is worth nothing: the only output anyone
  wants from you is the thing the methodology did not think to look for.
- act on another person's account or data, degrade the service, or do anything
  destructive. Your own account only.
- claim anything you have not seen in a response.

Nobody has told you what kind of bug to look for, and that is deliberate. Form your
own view of what this application is, how it decides things, and where its own logic
disagrees with itself. Follow what looks wrong to you, not what is usually wrong.

Work for at most {turns} turns. Then end your reply with a fenced ```json``` block:

[
  {{"surface": "<method + URL or flow>",
    "claim": "<what you believe is wrong, in one sentence>",
    "evidence": "<the response fact that supports it: status, header, body fragment>",
    "fired": true,
    "confidence": "high|medium|low"}}
]

Rules for that block: one object per thing you actually probed. `fired: false` for
anything you only reasoned about — those are still worth listing, clearly marked.
An empty array is a legitimate answer. Do not inflate; the array is read by a diff,
not by a person who can be impressed.

**Emit that block at the end of EVERY message once you have anything to report, not
only in your final one — and re-emit it, complete, in each later message.** Only the
last message is parsed, and two runs on this workspace lost a complete set of fired
results because the agent was pushed to continue past the message that carried the
block: a stop gate can refuse your first attempt to finish, and the reply you write
to that refusal then becomes the last message. Re-emitting costs a few lines; not
re-emitting throws the whole run away. If a gate refuses your stop, treat that as
"append the block again", not as "explain yourself in prose"."""

_NORM = re.compile(r"[^a-z0-9]+")


def _key(item: Dict) -> str:
    """Identity of a reported item: the **surface** it touches, nothing else.

    An earlier version folded the claim's keywords into the key, and the first real
    pair of inputs showed why that is wrong: "Another user's profile is returned" and
    "the profile of a different user comes back" are the same bug in different words,
    and keyword overlap put them in different buckets — the merge reported a
    disagreement that did not exist. Paraphrase cannot be matched mechanically, so it
    is not attempted: agreement here means *both runs went at the same surface*, and
    both claims are printed side by side so the wording is judged by whoever reads it.
    """
    surface = _NORM.sub(" ", str(item.get("surface", "")).lower()).strip()
    # collapse ids and hashes so /users/41 and /users/42 are one surface
    surface = re.sub(r"\b\d+\b", "#", surface)
    surface = re.sub(r"\b[0-9a-f]{8,}\b", "#", surface)
    return surface


def load_items(path: Path) -> List[Dict]:
    """Items from a freeroam result file, or from any agent reply containing a block."""
    raw = path.read_text(encoding="utf-8")
    try:
        doc = json.loads(raw)
    except ValueError:
        doc = extract_json(raw)
    if isinstance(doc, dict):
        doc = doc.get("items") or doc.get("findings") or []
    return [x for x in (doc or []) if isinstance(x, dict)]


def merge(skilled: List[Dict], naive: List[Dict]) -> Dict:
    """Symmetric difference of two runs, keyed by (surface, claim-shape)."""
    a: Dict[str, Dict] = {}
    for x in skilled:
        a.setdefault(_key(x), x)
    b: Dict[str, Dict] = {}
    for x in naive:
        b.setdefault(_key(x), x)
    both = sorted(set(a) & set(b))
    return {
        "both": [{"key": k, "skilled": a[k], "naive": b[k]} for k in both],
        "skilled_only": [a[k] for k in a if k not in b],
        "naive_only": [b[k] for k in b if k not in a],
        "counts": {"skilled": len(a), "naive": len(b), "both": len(both),
                   "skilled_only": len(a) - len(both), "naive_only": len(b) - len(both)},
    }


def run(target: str, project: str | None = None, turns: int = 30,
        model: str | None = None, timeout: int = 1800,
        identity_line: str | None = None) -> Dict:
    """Launch the naive agent against one target. Scope is checked before it starts."""
    eng = Engagement.detect() if project is None else Engagement.detect()
    if project is None and eng.name:
        project = eng.name
    identity = identity_line or (
        "You have no account on it. Work the unauthenticated surface."
        if not (eng.project_dir and (eng.project_dir / "identity.json").is_file())
        else "Credentials for your own test account are in this engagement's "
             "identity.json — read it before assuming the surface is anonymous.")
    # The prompt's work budget and the hard kill must not be the same number, and
    # the kill must not be tight either. `claude -p --max-turns N` terminates the run
    # without a final assistant message, so an agent told "work for at most N turns,
    # then emit your ```json``` block" is killed on the turn it would have reported
    # in. A cap of `turns + max(10, turns // 2)` was not enough headroom: measured on
    # konsol, the agent overran it by one turn every time (68 against 67, then 46
    # against 45), because a "turn" here counts tool calls and the prompt budget it
    # is given is only advisory. So the turn cap stops being the bound: wall-clock
    # `timeout` is, and the cap is only a runaway stop. `agent.run_agent` streams, so
    # an overrun that still happens is salvaged rather than lost.
    hard_cap = max(3 * turns, 90)
    task = PROMPT.format(target=target, identity=identity, turns=turns,
                         project=project or eng.name or '<engagement>')
    out = run_agent(task, skills_on=False, model=model, max_turns=hard_cap,
                    timeout=timeout, project=project)
    items = extract_json(out.get("result") or "") or []
    if isinstance(items, dict):
        items = [items]
    # Keep the raw reply. An agent that hits --max-turns never reaches its closing
    # ```json``` block, so `items` comes back empty and the whole run used to be
    # discarded: 41 turns and $1.52 of real probing thrown away with an "exited 1"
    # (konsol, 2026-10-17). The prose is still the work product; parse failure is not.
    return {"target": target, "project": project, "items": items,
            "raw": out.get("result") or "",
            # `partial` marks a run salvaged from the stream after --max-turns killed
            # it: the prose is real work, but the agent never reached its closing
            # block, so `items` may be short or empty and must not be read as "the
            # naive agent found nothing here".
            "partial": out.get("partial", False),
            "agent": {k: out.get(k) for k in ("error", "cost_usd", "num_turns", "duration_s")}}


def _print_merge(m: Dict) -> None:
    c = m["counts"]
    print(f"skilled {c['skilled']} · naive {c['naive']} · agreed {c['both']} · "
          f"skilled-only {c['skilled_only']} · naive-only {c['naive_only']}")
    print()
    if m["naive_only"]:
        print("NAIVE ONLY — what the methodology did not look at. This is the output:")
        for x in m["naive_only"]:
            fired = "fired" if x.get("fired") else "NOT FIRED"
            print(f"  - [{x.get('confidence', '?'):<6} {fired:<9}] {x.get('surface')}")
            print(f"      {x.get('claim')}")
            if x.get("evidence"):
                print(f"      evidence: {x['evidence']}")
        print()
        print("  Each of these is a lead, not a finding: write it to Targets/<p>/leads/ and")
        print("  fire the one request that settles it. Anything that survives belongs in a")
        print("  hunt-* skill — that is how the taxonomy grows instead of repeating itself.")
        print()
    if m["skilled_only"]:
        print("SKILLED ONLY — found by methodology the naive run had no reason to try:")
        for x in m["skilled_only"]:
            print(f"  - {x.get('surface')}  ::  {x.get('claim')}")
        print()
    if m["both"]:
        print(f"SAME SURFACE in both runs — {len(m['both'])}. Two independent runs arriving at")
        print("one surface is the strongest prior this pair produces; take these first.")
        print("The claims are printed as written: agreement here is about the surface, not")
        print("the wording, and two different claims on one surface is itself a signal.")
        for row in m["both"]:
            print(f"  - {row['naive'].get('surface')}")
            print(f"      skilled: {row['skilled'].get('claim')}")
            print(f"      naive:   {row['naive'].get('claim')}")


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="freeroam",
        description="the no-methodology agent (B) and the A/B merge that makes the pair pay")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="launch the naive agent against one in-scope target")
    p_run.add_argument("target")
    p_run.add_argument("--project", help="engagement name (defaults to the detected one)")
    p_run.add_argument("--turns", type=int, default=30)
    p_run.add_argument("--model", default=None)
    p_run.add_argument("--timeout", type=int, default=1800)
    p_run.add_argument("--out", help="write the result JSON here")

    p_merge = sub.add_parser("merge", help="diff a skilled run against a naive run")
    p_merge.add_argument("skilled", help="JSON file: the skilled run's items")
    p_merge.add_argument("naive", help="JSON file: the naive run's items")
    p_merge.add_argument("--json", action="store_true", dest="as_json")
    p_merge.add_argument("--out", help="write the merge JSON here")

    a = ap.parse_args(argv)

    if a.cmd == "run":
        res = run(a.target, project=a.project, turns=a.turns, model=a.model,
                  timeout=a.timeout)
        text = json.dumps(res, indent=2, ensure_ascii=False)
        if a.out:
            Path(a.out).write_text(text + "\n", encoding="utf-8")
            print(f"{len(res['items'])} item(s) → {a.out}")
            if res["agent"].get("error"):
                print(f"agent error: {res['agent']['error']}")
                return 1
            return 0
        print(text)
        return 1 if res["agent"].get("error") else 0

    m = merge(load_items(Path(a.skilled)), load_items(Path(a.naive)))
    if a.out:
        Path(a.out).write_text(json.dumps(m, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")
    if a.as_json:
        print(json.dumps(m, indent=2, ensure_ascii=False))
    else:
        _print_merge(m)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
