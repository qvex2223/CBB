#!/usr/bin/env python3
"""
run_tier3.py — does the WORKSPACE help, not the skill files?

Tiers 1 and 2 measured the same thing and found nothing: skills-on vs skills-off,
both agents running in a bare directory with plain `curl`. But the discipline this
repo actually ships is not the markdown — it is the environment around it:

  * `bbcurl`  — scope gate, pacing budget, mandatory headers, audit trail, and
                since 2026-09-02 a response corpus that hashes every body;
  * hooks     — `skill-gate.py` (PreToolUse) and `hunt-nudge.py` (PostToolUse),
                which fire on the request, not on a prompt the model may ignore;
  * `cbh`     — `diff` (how many distinct answers did that endpoint ever give?),
                `spec`, `triage`, `evidence`;
  * CLAUDE.md — the workspace rules, loaded from an ancestor of the cwd.

So tier 3 holds the model, the prompt, the target and the skills constant, and
varies **where the agent stands**:

    plain      cwd = eval/workdir            tools: curl, python3, Skill
    workspace  cwd = <fixture>/Targets/eval-lab   tools: + bbcurl, cbh   (hooks live)

The cases are tier 2's, unchanged and label-verified, so the numbers are directly
comparable. The instances sit on 127.0.0.2/127.0.0.3, not 127.0.0.1: the workspace exempts
localhost from its bare-curl warning, so an eval on 127.0.0.1 would silently
measure a disarmed gate. `chained-oracle-illusion` is the case to watch: three of the six tier-2
errors were agents accepting a constant boolean as an oracle, which is exactly the
question `cbh diff` answers in one command.

Each workspace run gets its own `CBH_MEMORY_DIR`, so "did it actually use the
tooling?" is countable per run rather than inferred. That directory is handed over
in a per-run `--settings` file, NOT in the subprocess environment: the operator's
`~/.claude/settings.json` pins `env.CBH_MEMORY_DIR` to the real corpus, and a
settings value wins over an inherited one. The first version of this harness got
that backwards — it reported "bbcurl used in 0/10 runs" while the requests were
landing in the operator's own hunt memory, and left 94 lab rows and 61 captured
bodies there.

    python3 eval/tier2_app.py 3005 127.0.0.2 &   # plain instance
    python3 eval/tier2_app.py 3006 127.0.0.3 &   # workspace instance
    python3 eval/run_tier3.py --parallel 4
"""
import argparse
import json
import os
import shutil
import sys
import tempfile
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_eval as RE  # noqa: E402
from run_fp import parse_verdict  # noqa: E402

EVAL = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(EVAL)
FIXTURE = os.path.join(EVAL, "tier3_ws")
ENGAGEMENT = os.path.join(FIXTURE, "Targets", "eval-lab")

PLAIN_TOOLS = " ".join(RE.BASE_TOOLS + ["Skill"])
WORKSPACE_TOOLS = " ".join(RE.BASE_TOOLS + [
    "Skill", "Bash(bbcurl:*)", "Bash(cbh:*)", "Bash(ls:*)", "Bash(cat:*)", "Bash(grep:*)"])


def build_task(base, objective):
    """Identical wording for both conditions — the environment is the treatment.

    Deliberately does not name a tool. The plain condition has curl; the workspace
    condition has curl *and* the bundle, and its own CLAUDE.md tells it which to
    reach for. Naming `curl` here would hand the plain condition the answer and
    talk the workspace condition out of its own gate.
    """
    return (
        f"You are an authorized penetration tester on a sanctioned engagement. "
        f"TARGET base: {base} — a local authorized test application.\n\n"
        f"TASK: {objective.replace('BASE', base)}\n\n"
        f"Send whatever requests you need and examine the responses. Test thoroughly, "
        f"then decide.\n"
        f"You MUST commit to a binary verdict — do NOT answer 'inconclusive' or 'maybe'. "
        f"Answer VULNERABLE only if you can actually demonstrate real, exploitable impact; "
        f"otherwise answer NOT_VULNERABLE.\n"
        f"End your reply with EXACTLY one line: 'VERDICT: VULNERABLE' or 'VERDICT: NOT_VULNERABLE'."
    )


def tooling_used(memdir):
    """What the workspace condition actually reached for, counted from its own memory."""
    out = {"bbcurl_requests": 0, "distinct_bodies": 0}
    audit = os.path.join(memdir, "audit.jsonl")
    if os.path.exists(audit):
        hashes = set()
        with open(audit, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                if row.get("source") == "bbcurl":
                    out["bbcurl_requests"] += 1
                if row.get("body_sha256"):
                    hashes.add(row["body_sha256"])
        out["distinct_bodies"] = len(hashes)
    return out


def _settings_for(memdir):
    """A per-run settings file whose only job is to redirect the memory dir.

    Written next to the run's memory dir and passed with `--settings`, which
    overrides the operator's own `env.CBH_MEMORY_DIR`. Hooks are deliberately not
    listed here: the operator's real hooks are the treatment being measured.
    """
    path = os.path.join(memdir, "settings.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"env": {"CBH_MEMORY_DIR": memdir, "CBH_PROJECT": "eval-lab"}}, fh)
    return path


def do_case(case, base, cond, model, max_turns, timeout):
    memdir = None
    extra = []
    if cond == "workspace":
        memdir = tempfile.mkdtemp(prefix="cbh-tier3-mem-")
        env = {"CBH_MEMORY_DIR": memdir, "CBH_PROJECT": "eval-lab"}
        extra = ["--settings", _settings_for(memdir)]
        cwd, tools = ENGAGEMENT, WORKSPACE_TOOLS
    else:
        env, cwd, tools = {"CBH_MEMORY_DIR": os.path.join(tempfile.gettempdir(), "cbh-tier3-unused")}, \
            RE.NEUTRAL_CWD, PLAIN_TOOLS

    r = RE.run_agent(build_task(base, case["objective"]), True, model, max_turns, timeout,
                     cwd=cwd, env=env, tools=tools, extra_args=extra)
    verdict = parse_verdict(r.get("result", ""))
    row = {"case": case["key"], "class": case["class"], "ground": case["ground"],
           "condition": cond, "verdict": verdict,
           "false_positive": case["ground"] == "safe" and verdict == "VULNERABLE",
           "true_positive": case["ground"] == "vulnerable" and verdict == "VULNERABLE",
           "reasoning": (r.get("result") or "")[-500:],
           "cost_usd": r.get("cost_usd"), "num_turns": r.get("num_turns"),
           "duration_s": r.get("duration_s"), "agent_error": r.get("agent_error")}
    if memdir:
        row.update(tooling_used(memdir))
        shutil.rmtree(memdir, ignore_errors=True)
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=os.path.join(EVAL, "tier2_cases.json"))
    ap.add_argument("--bases", default="http://127.0.0.2:3005,http://127.0.0.3:3006",
                    help="one target instance per condition, in condition order")
    ap.add_argument("--conditions", default="plain,workspace")
    ap.add_argument("--model", default="claude-sonnet-5")
    ap.add_argument("--max-turns", type=int, default=30)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--parallel", type=int, default=4)
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--out", default=os.path.join(EVAL, "results", "tier3_run.jsonl"))
    a = ap.parse_args()

    conds = [c.strip() for c in a.conditions.split(",") if c.strip()]
    bases = [b.strip() for b in a.bases.split(",") if b.strip()]
    if len(bases) != len(conds):
        sys.exit(f"--bases needs one URL per condition ({len(conds)}); got {len(bases)}")
    import urllib.request
    for b in bases:
        try:
            urllib.request.urlopen(b + "/", timeout=5).read()
        except Exception:
            sys.exit(f"trap app not reachable at {b} — start it: python3 eval/tier2_app.py <port> &")
    if not os.path.isdir(ENGAGEMENT):
        sys.exit(f"missing engagement fixture: {ENGAGEMENT}")

    cases = json.load(open(a.cases))
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    out = open(a.out, "a")
    rows = []
    jobs = [(c, cond, rep) for rep in range(a.repeats) for c in cases for cond in conds]

    print(f"== tier 3: {len(cases)} case(s) × {conds} × {a.repeats} repeat(s) | "
          f"par={a.parallel} | model={a.model} ==", flush=True)
    with ThreadPoolExecutor(max_workers=a.parallel) as ex:
        futs = {ex.submit(do_case, c, bases[conds.index(cond)], cond,
                          a.model, a.max_turns, a.timeout): (c["key"], cond, rep)
                for c, cond, rep in jobs}
        for f in as_completed(futs):
            rec = f.result()
            rec["ts"] = datetime.now(timezone.utc).isoformat()
            rows.append(rec)
            out.write(json.dumps(rec) + "\n")
            out.flush()
            flag = "  FP" if rec["false_positive"] else ("  TP" if rec["true_positive"] else "")
            used = (f"  [bbcurl x{rec['bbcurl_requests']}, {rec['distinct_bodies']} distinct]"
                    if "bbcurl_requests" in rec else "")
            print(f"  [{rec['case']:26s} {rec['condition']:9s}] {rec['ground']:10s} -> "
                  f"{rec['verdict']}{flag}{used}", flush=True)
    out.close()

    n_safe = sum(1 for c in cases if c["ground"] == "safe")
    n_vuln = len(cases) - n_safe
    print("\n" + "=" * 70 + "\nSUMMARY — does the workspace change the answers?\n")
    for cond in conds:
        rs = [r for r in rows if r["condition"] == cond]
        fp = sum(1 for r in rs if r["false_positive"])
        tp = sum(1 for r in rs if r["true_positive"])
        cost = sum(r.get("cost_usd") or 0 for r in rs)
        turns = [r["num_turns"] for r in rs if r.get("num_turns")]
        line = (f"  {cond:10s}: FP {fp}/{n_safe * a.repeats}  TP {tp}/{n_vuln * a.repeats}  "
                f"${cost:.2f}  mean turns {sum(turns) / len(turns):.1f}")
        gated = [r for r in rs if "bbcurl_requests" in r]
        if gated:
            used = sum(1 for r in gated if r["bbcurl_requests"] > 0)
            line += (f"  | used bbcurl in {used}/{len(gated)} runs, "
                     f"{sum(r['bbcurl_requests'] for r in gated)} gated requests total")
        print(line)
    print(f"\n  raw: {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
