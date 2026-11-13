#!/usr/bin/env python3
"""Turn a fired PoC artifact into a short triager-facing reproduction."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

VARS = re.compile(r"\{\{([A-Za-z0-9_.-]+)\}\}")
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Names that mark a step as structurally necessary even when nothing depends on its
# output: the identity setup, the honest control request, the exploit itself.
KEEP_NAME_HINTS = ("control", "owner", "login", "auth", "exploit", "attack", "verify")


def required_steps(spec: dict) -> list[dict]:
    """The shortest chain that still shows the bug.

    Minimizing on capture-dependencies alone drops the exploit: the verification step
    reads state back and therefore references nothing, so a login -> exploit -> verify
    chain minimized to "steps something depends on" keeps login and verify and throws
    away the request that causes the bug. A reproduction missing its own exploit is
    worse than the verbose one.

    So three things are always kept, then dependencies are pulled in transitively:
      * the final step (the verification — reading the state back is the proof),
      * every state-changing request (the exploit is a write, essentially always),
      * explicitly named setup/control/exploit steps.
    """
    steps = spec.get("steps") or [spec]
    if len(steps) <= 2:
        return steps

    keep = {len(steps) - 1}
    for i, step in enumerate(steps):
        if str(step.get("method", "GET")).upper() in WRITE_METHODS:
            keep.add(i)
        if any(h in (step.get("name") or "").lower() for h in KEEP_NAME_HINTS):
            keep.add(i)

    # Pull in whatever the kept steps depend on, transitively and backwards.
    changed = True
    while changed:
        changed = False
        needed: set[str] = set()
        for i in sorted(keep):
            needed |= set(VARS.findall(json.dumps(steps[i])))
        for i, step in enumerate(steps):
            if i in keep:
                continue
            if set((step.get("capture") or {}).keys()) & needed:
                keep.add(i)
                changed = True
    return [steps[i] for i in sorted(keep)]


def render(spec: dict, result: dict, title="Reproduction") -> str:
    steps = required_steps(spec)
    run = (result.get("runs") or [{}])[-1]
    records = run.get("steps") or []
    lines = [f"# {title}", "", "## Impact", "",
             spec.get("impact") or spec.get("note") or "Describe the demonstrated security impact.",
             "", "## Minimal reproduction", ""]
    for i, step in enumerate(steps, 1):
        lines.append(f"{i}. Send `{step.get('method', 'GET').upper()} {step.get('url', '')}`.")
        if step.get("body") is not None:
            lines.append(f"   Body: `{str(step['body'])[:300]}`")
        if step.get("expect"):
            lines.append(f"   Expected proof: `{json.dumps(step['expect'], ensure_ascii=False)[:300]}`")
    lines += ["", "## Observed result", "",
              f"Final deterministic verdict: **{result.get('final_verdict', 'UNKNOWN')}**."]
    if records:
        for rec in records:
            lines.append(f"- {rec.get('name')}: HTTP {rec.get('result', {}).get('status')} — {rec.get('verdict')}")
    lines += ["", "## Technical artifact", "",
              f"Full machine-readable evidence: `{result.get('spec_file', '')}` / fired result JSON.", ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("spec", type=Path); ap.add_argument("result", type=Path)
    ap.add_argument("--title", default="Reproduction"); ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    text = render(json.loads(args.spec.read_text()), json.loads(args.result.read_text()), args.title)
    args.out.write_text(text, encoding="utf-8")
    print(f"{args.out}: {len(required_steps(json.loads(args.spec.read_text())))} minimal steps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
