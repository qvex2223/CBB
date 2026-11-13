#!/usr/bin/env python3
"""
decision_replay.py — replay every gated decision over the corpus that is already on disk.

A change to a gate is a change to what the agent is told to do next, and the only honest
way to see that is to run the gates twice: once on the code as it stands, once on the code
before the change, over the SAME corpus, and diff the two reports. This script is the
left-hand side of that: deterministic, read-only, and it sends nothing.

    python3 scripts/decision_replay.py --out /tmp/new.txt

It fires no requests and writes nothing but `--out`. Every list is sorted, no timestamps
and no temp paths are printed, so two runs on unchanged code produce byte-identical files.

The decision points, in the order a hunt meets them:

  queue      lead_queue.scan   — what is open, and the ranked head the lanes are picked from
  stop       stop_gate.assess  — proven / claimed-but-unproven / unrefuted / next hosts
  evidence   evidence.check    — the status of every finding on disk
  coverage   refute.claim_coverage — which hops of a claim its own controls reach
  wave       autohunt.wave     — the lane mix, the role, and how big each brief is

To compare against an earlier commit, give that commit a worktree, point its runtime dirs
at this one (they are gitignored, so a fresh worktree has none), and run the same script
there:

    git worktree add /tmp/before <commit>
    ln -s "$PWD/Targets" "$PWD/hunt-memory" /tmp/before/
    cp scripts/decision_replay.py /tmp/before/scripts/
    (cd /tmp/before && python3 scripts/decision_replay.py --out /tmp/before.txt)
    diff -u /tmp/before.txt /tmp/new.txt

The script must be the same file in both runs — only `engine/` is allowed to differ, or the
diff measures the harness instead of the change.
"""
from __future__ import annotations

import argparse
import io
import os
import sys
import traceback
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import funnel  # noqa: E402  the one definition of an item and its name

SLOTS = 3  # the real crew size here; the lane mix is only interesting at the real number


def _engagements(root: Path) -> list[Path]:
    """Engagements with something in the funnel, in a fixed order."""
    out = []
    for d in sorted(root.glob("*/*")):
        if not d.is_dir() or d.parent.name == "_TEMPLATE" or d.name == "raw":
            continue
        items = 0
        for tier in ("findings", "leads", "primitives"):
            t = d / tier
            if t.is_dir():
                items += len(list(t.glob("*.md"))) + len(list(t.glob("*/*.md")))
        if items:
            out.append(d)
    return out


def _quiet(fn, *a, **kw):
    """Run a gate with its chatter captured: some of them print."""
    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(buf):
        return fn(*a, **kw)


def _err(where: str, exc: BaseException) -> list[str]:
    return [f"    !! {where}: {type(exc).__name__}: {str(exc)[:160]}"]


def replay(eng: Path) -> list[str]:
    import autohunt
    import evidence
    import lead_queue
    import refute
    import stop_gate

    name = f"{eng.parent.name}/{eng.name}"
    L = [f"### {name}"]

    # -- queue: what is open and in what order -------------------------------------
    try:
        q = _quiet(lead_queue.scan, eng.resolve())
        openq = q.get("open") or []
        L.append(f"  queue    open={len(openq)}")
        for it in openq[:8]:
            # The ranked head decides which lane is picked. Class and band are what rank it.
            L.append(f"    {it.get('kind','?'):<10} {it.get('class','-'):<14}"
                     f"{int(it.get('reward') or 0):>9} score={int(it.get('score') or 0):>9}"
                     f"  {funnel.item_name(it.get('file',''))}")
    except BaseException as e:  # noqa: BLE001
        L += _err("lead_queue.scan", e)

    # -- stop gate: what it says is left -------------------------------------------
    try:
        a = _quiet(stop_gate.assess, eng)
        L.append("  stop     " + " ".join(
            f"{k}={len(a.get(k) or [])}" for k in
            ("proven", "claimed_but_unproven", "older_findings", "untried",
             "next_hosts", "unrefuted")))
        for u in (a.get("unrefuted") or [])[:6]:
            L.append(f"    unrefuted {u.get('tier','?'):<10} {u.get('severity') or '-':<9}"
                     f"{funnel.item_name(u.get('file',''))}")
            L.append(f"              why: {str(u.get('why',''))[:110]}")
        fn = a.get("funnel") or {}
        if fn:
            L.append("    funnel   " + " ".join(f"{k}={v if not isinstance(v, list) else len(v)}"
                                                for k, v in sorted(fn.items())))
    except BaseException as e:  # noqa: BLE001
        L += _err("stop_gate.assess", e)

    # -- evidence: the status of every finding --------------------------------------
    fdir = eng / "findings"
    files = []
    if fdir.is_dir():
        files = sorted(set(list(fdir.glob("*.md")) + list(fdir.glob("*/*.md"))))
        files = [f for f in files if f.name.lower() != "readme.md"]
    for f in files:
        try:
            rep = _quiet(evidence.check, f)
            cp = rep.get("class_proof") or {}
            cls = cp.get("class") or "-"
            mark = ("ok" if cp.get("ok") else "MISSING") if cp.get("checked") else "n/a"
            L.append(f"  evidence {rep['status']:<15}{cls:<14}{mark:<8}{funnel.item_name(f)}")
        except BaseException as e:  # noqa: BLE001
            L += _err(f"evidence.check {funnel.item_name(f)}", e)

    # -- coverage: does a refutation reach the claim it is aimed at ------------------
    for f in files:
        folder = f.parent if f.parent != fdir else fdir
        try:
            spec = _quiet(refute.find_spec, folder)
            if not spec:
                continue
            import json
            sp = json.loads(Path(spec).read_text(encoding="utf-8", errors="replace"))
            cov = _quiet(refute.claim_coverage, folder, sp, refute.build_controls(sp))
            L.append(f"  coverage checked={bool(cov.get('checked')):<6}"
                     f"untested={len(cov.get('untested_hops') or [])}  {funnel.item_name(f)}")
        except BaseException as e:  # noqa: BLE001
            L += _err(f"claim_coverage {funnel.item_name(f)}", e)

    # -- wave: the lanes this engagement would be given right now --------------------
    for role in ("", "refuter", "deep-hunter"):
        try:
            w = _quiet(autohunt.wave, name, SLOTS, role)
            if w.get("error"):
                L.append(f"  wave     role={role or 'auto':<12} error={w['error'][:90]}")
                continue
            lanes = w.get("briefs") or w.get("lanes") or []
            roles: dict[str, int] = {}
            for ln in lanes:
                roles[str(ln.get("role") or "?")] = roles.get(str(ln.get("role") or "?"), 0) + 1
            L.append(f"  wave     role={role or 'auto':<12} "
                     f"picked={w.get('role','?'):<12} lanes={len(lanes)} "
                     f"req/lane={w.get('requests_per_lane','?')} "
                     f"allow_stop={w.get('allow_stop')} bar_met={w.get('bar_met')} "
                     + " ".join(f"{k}={v}" for k, v in sorted(roles.items())))
            why = str(w.get("role_why") or w.get("why") or "")
            if why:
                L.append(f"           why: {why[:110]}")
            for ln in lanes:
                # What a lane actually hands the worker: which skills it must load, the
                # requests it may spend, and the reason it was given this item at all.
                sk = ",".join(sorted(str(x.get("name")) for x in (ln.get("skills") or [])
                                     if isinstance(x, dict)))
                L.append(f"           lane {str(ln.get('role','?')):<12}"
                         f"req={int(ln.get('requests') or 0):<5}"
                         f"{funnel.item_name(ln.get('file',''))[:52]}")
                L.append(f"                skills={sk}")
                if ln.get("refute_reason"):
                    L.append(f"                refute_reason={str(ln['refute_reason'])[:90]}")
                if ln.get("close"):
                    L.append(f"                close={str(ln['close'])[:110]}")
            try:
                L.append(f"           render={len(_quiet(autohunt.render, w))}ch")
            except BaseException as e:  # noqa: BLE001
                L += _err("autohunt.render", e)
        except BaseException as e:  # noqa: BLE001
            L += _err(f"autohunt.wave role={role or 'auto'}", e)
    return L


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--out", default="-", help="file to write the report to ('-' = stdout)")
    ap.add_argument("--only", default="", help="one engagement, as platform/program")
    ap.add_argument("--corpus", default=str(REPO / "Targets"),
                    help="corpus root (default: this tree's Targets/)")
    args = ap.parse_args(list(sys.argv[1:] if argv is None else argv))

    # Deterministic: a wave reads CBH_PROJECT when no program is passed, and an inherited
    # value from the operator's shell would silently replay a different engagement.
    os.environ.pop("CBH_PROJECT", None)

    # Resolved: this workspace is reachable through a symlinked name, and an unresolved
    # root made every `eng.relative_to(targets_root())` inside the engine raise ValueError
    # on 10 of 12 engagements — a harness artefact that reads as a code regression.
    root = Path(args.corpus).resolve()
    engs = _engagements(root)
    if args.only:
        engs = [e for e in engs if f"{e.parent.name}/{e.name}" == args.only]
    lines = [f"decision replay · {len(engs)} engagement(s) · slots={SLOTS}", ""]
    for e in engs:
        try:
            lines += replay(e)
        except BaseException:  # noqa: BLE001 - one broken engagement must not end the sweep
            lines += [f"### {e.parent.name}/{e.name}", "  !! replay aborted",
                      *(f"    {ln}" for ln in traceback.format_exc().splitlines()[-3:])]
        lines.append("")
    text = "\n".join(lines) + "\n"
    if args.out == "-":
        sys.stdout.write(text)
    else:
        Path(args.out).write_text(text, encoding="utf-8")
        sys.stderr.write(f"wrote {args.out} ({len(text)} bytes, {len(lines)} lines)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
