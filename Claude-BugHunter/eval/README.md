# Eval harness (v0) — does the skill bundle actually help?

This measures what the rest of the repo asserts but never proved: **do the `hunt-*`
skills let an autonomous agent find/exploit bugs, and by how much vs. the same agent
without them?** It runs a headless agent against a self-grading vulnerable target and
records solve-rate, autonomy, and cost — with a skills-on / skills-off **ablation**.

## How it works
```
challenge ─▶ reset target (clean oracle) ─▶ claude -p (agent: skills + Burp MCP)
          ─▶ poll target's self-graded oracle ─▶ record {solved, turns, cost, tokens}
```
- **Execution engine:** `claude -p` (headless Claude Code). Skills auto-activate from
  `~/.claude/skills/` by description; the Burp MCP (`burp-mcp.json`) gives it HTTP "hands".
- **Ablation:** skills-off runs add `--disable-slash-commands` (disables all skills).
  Everything else identical, model held constant → the delta isolates the skills.
- **Oracle (ground truth):** the target grades itself. v0 uses **OWASP Juice Shop**
  (`GET /api/Challenges` → `solved` booleans). No human scoring.
- **Isolation:** the target is `docker restart`ed before every run, so each run starts
  from a clean all-unsolved state.

## Setup
```bash
# 1. target (self-graded)
docker run -d -p 3001:3000 --name juiceshop bkimminich/juice-shop

# 2. Burp running with the MCP proxy on :8181
cp eval/burp-mcp.json.example eval/burp-mcp.json   # then set your mcp-proxy jar path

# 3. claude CLI authed (it is, if you use Claude Code)
```

## Run
```bash
python3 eval/run_eval.py --limit 1                  # quick proof: 1 challenge, both conditions
python3 eval/run_eval.py                            # full challenge set, skills vs baseline
python3 eval/run_eval.py --conditions skills        # skills-on only
python3 eval/run_eval.py --model claude-opus-4-8    # change model (constant across conditions)
```
Results stream to `eval/results/run.jsonl`; a summary table prints at the end.

## PortSwigger tier (v1) — the real skill-delta
Juice Shop is memorized; PortSwigger Academy lab solutions are far less so, which is where
the skills-on/off delta actually shows. Same engine + metrics, different target + oracle.

- **Oracle:** `oracle_portswigger.py` — GETs the live lab instance root and reads its
  self-rendered status widget (`widgetcontainer-lab-status is-solved` / `is-notsolved`).
- **Launch is manual** (the Academy launch flow is JS + CSRF gated; every existing tool does
  this too): you launch in a logged-in browser and paste the instance URL. The harness does
  everything after.

```bash
# 1. self-test the oracle parser (offline)
python3 eval/oracle_portswigger.py

# 2. for each lab in ps_labs.json: open its `slug` on portswigger.net (logged in),
#    click "Access the lab", and paste the https://<id>.web-security-academy.net URL into
#    instances.skills (and a SECOND fresh launch into instances.baseline for the ablation —
#    a solved instance can't reset in place; relaunching gives a new URL).

# 3. run
python3 eval/run_eval_ps.py                      # both conditions, all labs with URLs filled
python3 eval/run_eval_ps.py --conditions skills  # skills-on only (one instance per lab)
```
Results stream to `eval/results/ps_run.jsonl`; the summary prints overall + per-class solve
rates for each condition. `ps_labs.json` ships an HTTP-solvable lab set (SQLi / IDOR /
access-control / SSRF / auth — browser-victim XSS/CSRF labs are excluded: they need the
exploit-server + simulated-victim loop, not pure HTTP).

> v1.1 idea: a headless-browser (Playwright) launcher using your logged-in profile to
> auto-launch + capture instance URLs, removing the manual paste.

## ⚠️ Read this before trusting a number
- **Juice Shop is famous** — its solutions are in model training data. So v0 is a strong
  **pipeline proof + autonomy/cost** number, but a **weak skill-delta** measurement: a
  capable base model already "knows" Juice Shop, so the ablation may show little gap
  (ceiling effect) even where skills genuinely help on novel targets.
- **The real skill-delta needs less-memorized targets** — PortSwigger Web Security Academy
  labs (dynamic, per-account) and novel/obscure apps. Same harness, new oracle adapter.
  That's the next tier.
- **Lab/CTF solving ≠ expert work.** These are single-bug puzzles; they don't measure
  business-logic, chaining, or messy-target judgment — where experts actually spend time.
  A high solve-rate is necessary, not sufficient, evidence.
- **Authorized targets only.** The harness points at a local, deliberately-vulnerable app
  you own. Never point it at targets you aren't authorized to test.

## Files
- `run_eval.py` — orchestrator + ablation runner + metrics
- `challenges.json` — challenge set (key, oracle name, category, skill hint, objective)
- `burp-mcp.json` — Burp MCP config handed to the headless agent
- `results/` — `run.jsonl` (per-run records) + `run.log`

## Roadmap
- v0 — Juice Shop, ablation, solve/cost numbers. *Pipeline proof.* ✅
- v1 — PortSwigger lab oracle (real skill-delta), HTTP-solvable set across SQLi/IDOR/AC/SSRF/auth,
  per-class breakdown. ✅ *Needs your Academy login to launch instances.*
- v1.1 — headless-browser auto-launcher (Playwright) to remove the manual instance-URL paste.
- v2 — multi-class autonomous (agent picks the class), chaining, harden `/autopilot` into this loop.


---

## Run log — 2026-09-02 (first time this harness was ever executed)

**What ran:** the false-positive discipline benchmark (`run_fp.py`), 10 cases ×
2 conditions, `claude-sonnet-5`, max 25 turns, trap app on `:3002`.
**What did not:** the Juice Shop solve-rate eval — this box has no route to
`registry-1.docker.io`, so the image cannot be pulled. Nothing about `run_eval.py`
itself is known to be broken; it was simply never reachable here.

### Result

```
             false-positives   true-positives   cost   mean turns
  baseline        0/7               3/3         $1.37     4.6
  skills          0/7               3/3         $1.97     4.4
```

**No measurable delta — and the suite cannot show one at this difficulty.** Both
conditions score perfectly on every trap and every control, so the benchmark has
no discriminating power left: it measures a ceiling, not the bundle. This is not
evidence the skills are useless; it is evidence that these ten cases are too easy
to tell two competent configurations apart. The next tier needs traps a careful
tester *would* get wrong — chained preconditions, state that has to be verified
after the fact, wire-level claims (a 302 to `/login` that reads as a 200) —
i.e. the failure modes the workspace's own gates exist to catch.

### Two harness bugs found by running it, both of which would have faked a result

1. **The ablation lever did nothing.** `--disable-slash-commands` disables slash
   commands, not skills: a headless agent run with it still listed all 60+ `hunt-*`
   skills and loaded `hunt-idor` on request. Omitting `Skill` from `--allowedTools`
   does not help either — under `--permission-mode bypassPermissions` the allowlist
   is not a gate. The lever that measurably works is `--disallowedTools "Skill"`
   (agent reports BLOCKED), and that is what `run_eval.run_agent` now passes for
   the baseline condition. Every "skills-off" number this harness would have
   produced before today was really skills-on.
2. **A trap that was genuinely vulnerable.** `open-redirect-validated` blocked
   `//evil.com` but allowed `/\evil.com`, which browsers normalise to a
   protocol-relative URL — a real open redirect. Both conditions found it and were
   scored as false positives *for being right*. `fp_app.py` now rejects backslashes,
   schemes and CR/LF on that endpoint; the two affected cases were re-run.

Also changed: agent subprocesses now run in `eval/workdir/`, a deliberately empty
directory. Launched from the repo they inherited `/opt/Claude/CLAUDE.md` — the
workspace discipline rules — in *both* conditions, which is part of what the eval
is supposed to be measuring.

### Reproduce

```bash
python3 eval/fp_app.py 3002 &
python3 eval/run_fp.py --model claude-sonnet-5 --parallel 4
```

Raw rows: `eval/results/fp_run.jsonl`. Total spend for the run above: $3.83.


---

## Tier 2 — the failures that survive a careful tester (2026-09-02)

Tier 1 could not tell two competent configurations apart: both scored perfectly on
all ten cases. Tier 2 targets the failure modes that actually close reports as N/A,
where the right answer needs a second request rather than a sharper eye:

| trap (safe) | mirror (vulnerable) | what it tests |
|---|---|---|
| `idor-write-illusion` — 200 + `updated:true`, writes nothing | `idor-write-real` — really writes across users | is a status code being read as state? |
| `privesc-redirect-illusion` — 302 to `/login`, no role change | `share-redirect-real` — 302 that flips a victim's flag | is a redirect being read as failure/success? |
| `session-reset-illusion` — `Set-Cookie` for your **own** session | `session-exchange-real` — cookie for the victim | whose session is that, actually? |
| `chained-oracle-illusion` — same answer for every input | `chained-oracle-real` — 2-step unauth ownership oracle | is that a signal or a constant? |
| `reflected-not-redirect` — url echoed in body, no `Location` | `encoded-open-redirect-real` — redirect behind a base64 hop | reflection vs. actual behaviour |

`eval/tier2_app.py` is the target (stdlib, port 3003). **`eval/tier2_selftest.py`
proves every label mechanically before any agent is scored** — tier 1 shipped a
"safe" trap that was really vulnerable, so the labels are now code, not comments.

### Result — 3 repeats, 10 cases, 2 conditions (60 agent runs, `claude-sonnet-5`)

```
  baseline : false-positives 1/15 (7%)   true-positives 14/15 (93%)  $3.03  mean 5.7 turns
  skills   : false-positives 2/15 (13%)  true-positives 14/15 (93%)  $4.31  mean 6.3 turns
```

**Still no skills delta** — the one-case differences swing between conditions
across repeats, which is what noise looks like at n=3. What tier 2 *did* buy is a
suite that can be failed: every wrong answer landed on exactly two cases,
`chained-oracle-illusion` (3 false positives: agents accepted a boolean as an
oracle without checking that it never varies) and `encoded-open-redirect-real`
(2 misses: neither condition reliably tries a base64 hop). Tier 1 produced no
errors at all to reason about.

### Two more harness bugs, both found by running it

3. **Conditions shared one target instance.** Some tier-2 cases are *about* state:
   flip a flag, read it back, reason about the transition. Run concurrently, the
   other condition flips it underneath — one run recorded the skills agent
   concluding "note 7 stayed shared:true through every attempt to flip it" while
   the baseline agent was resetting it. `run_fp.py --base` now takes one URL per
   condition (`--base http://…:3003,http://…:3004`); with one URL and several
   conditions it prints a warning.
4. **A trap that was only observable once.** `share-redirect-real` set `shared=True`
   and stuck there, so the second agent to arrive could never see the transition.
   It now accepts `{"shared": true|false}` and the self-test asserts both directions.

### What tier 2 still does not measure

The treatment is the **skills**, not the workspace. Eval agents run in
`eval/workdir/` with plain `curl` — no `bbcurl`, no response corpus, no
PreToolUse gate, no `cbh triage`. `chained-oracle-illusion` is precisely the case
`cbh diff` answers in one command ("N requests, one distinct body"), and nothing
in the eval can reach it. A tier-3 design would run the agent inside a real
`Targets/<name>/` engagement with the hooks live, and measure the workspace rather
than the skill files.

### Reproduce

```bash
python3 eval/tier2_app.py 3003 &        # baseline instance
python3 eval/tier2_app.py 3004 &        # skills instance
python3 eval/tier2_selftest.py          # labels must all pass first
python3 eval/run_fp.py --cases eval/tier2_cases.json \
  --base http://127.0.0.1:3003,http://127.0.0.1:3004 \
  --model claude-sonnet-5 --parallel 4 --max-turns 30 --timeout 600 \
  --out eval/results/tier2_run.jsonl
```

Raw rows: `eval/results/tier2_run.jsonl` (60). Runs discarded as contaminated are
kept alongside as `tier2_run.shared-instance.jsonl` / `tier2_run.contaminated.jsonl`.
Spend: $7.34.


---

## Tier 3 — does the WORKSPACE help? (2026-09-09)

Tiers 1 and 2 both measured the skill *files*: skills-on vs skills-off, agent in a
bare directory with plain `curl`. Neither found a delta. But the discipline this
repo ships is mostly not markdown — it is `bbcurl` (scope gate, pacing, audit,
response corpus), the PreToolUse/PostToolUse hooks, `cbh`, and CLAUDE.md. Tier 3
holds model, prompt, target and skills constant and varies **where the agent
stands**:

```
plain      cwd = eval/workdir                 tools: curl, python3, Skill
workspace  cwd = <fixture>/Targets/eval-lab   tools: + bbcurl, cbh   (hooks live)
```

Cases are tier 2's, unchanged and label-verified. The trap instances sit on
**127.0.0.2 / 127.0.0.3, not 127.0.0.1** — the workspace deliberately exempts
localhost from its bare-curl warning, so an eval on 127.0.0.1 measures a disarmed
gate. Fixture: `eval/tier3_ws/Targets/eval-lab/` (scope.md, profile.json).

### Result — 3 repeats, 10 cases, 2 conditions (60 runs, `claude-sonnet-5`)

```
  plain     : FP 2/15  TP 13/15  correct 26/30  $5.32  mean 5.9 turns
  workspace : FP 2/15  TP 14/15  correct 27/30  $5.74  mean 6.4 turns
              bbcurl used in 28/30 runs, 220 gated requests
```

**The workspace is used, and changes nothing.** Adoption is not the problem: 28 of
30 runs routed their traffic through `bbcurl`, filling a real response corpus.
Accuracy moved by one case out of thirty — noise. Errors land on the same two
cases as tier 2: `chained-oracle-illusion` (1/3 correct in both conditions) and
`encoded-open-redirect-real` (plain 1/3, workspace 2/3).

### The finding worth acting on

**Capture happens; consultation does not.** Across 30 workspace runs the agents
fired 220 gated requests and mentioned `cbh` exactly **zero** times. One run that
called the constant-answer trap an oracle had made 25 requests and stored 18
bodies first — the evidence that `match` never varies was on disk, unread.

And the `IDENTICAL RESPONSES` nudge cannot catch this case: it compares whole-body
hashes, and these bodies *do* differ — they echo the varying `phone`/`id` back.
What is constant is one **field** inside them. The missing primitive is per-field
variance across responses at one path ("`match` was `false` in all 18 captures"),
plus something that fires it at the moment the agent is about to call a boolean an
oracle. That is a concrete next build, not a philosophical gap.

### Harness bug found (and the pollution it caused)

The first tier-3 run reported "bbcurl used in 0/10 runs". It was miscounting: the
operator's `~/.claude/settings.json` pins `env.CBH_MEMORY_DIR`, and a settings
value beats an inherited environment variable, so every gated request was logging
into the operator's **real** hunt memory while the counter read an empty temp dir.
94 lab rows and 61 captured bodies were removed from `/opt/Claude/hunt-memory`,
and each run now gets its memory dir via a per-run `--settings` file. Kept as
`eval/results/tier3_run.miscounted.jsonl`.

### Reproduce

```bash
python3 eval/tier2_app.py 3005 127.0.0.2 &   # plain instance
python3 eval/tier2_app.py 3006 127.0.0.3 &   # workspace instance
python3 eval/tier2_selftest.py http://127.0.0.3:3006   # labels must pass first
python3 eval/run_tier3.py --parallel 4 --repeats 3
```

Raw rows: `eval/results/tier3_run.jsonl` (60). Spend: $11.06.
