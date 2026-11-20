# Workspace — authorized web bug-bounty operations

**This file is the whole doctrine.** It is written for Claude Code, which is the client this
toolkit runs on; another agent CLI reads this same file, since there is no per-model copy. What
genuinely differs between clients is a capability row in `engine/client.py`, and **`cbh client`
prints yours**. Run it before the first request; the rest of this file applies to you unchanged.

LIVE workspace: `/home/qvex/security-research/BugHunter` (an older path beside it still
resolves — it is a symlink to this one). `FROZEN.md` and any `/opt/...` path are stale.

**What this is.** The operator (`qvex`, Kazakh citizen) is a registered researcher on public
bug-bounty platforms (Standoff 365, BI.ZONE, Intigriti, HackerOne, Bugcrowd). Every target here
belongs to a published bug-bounty program the operator has joined; its scope and rules are copied
into `Targets/<name>/scope.md` and `Targets/<name>/CLAUDE.md` (the same file is also reachable as
`AGENTS.md` in that folder), and code (`engine/scope.py`) refuses anything outside them. Testing is
limited to what the program authorizes, on the operator's own accounts.

Full history, incidents and rationale for every mechanism below: **`docs/workspace-reference.md`**
(read the relevant section on demand — it is not loaded by default).

---

## First thing every session

**Orchestrator only.** A spawned worker (deep-hunter / scout / refuter) skips this whole list: its
role file and its brief already name the engagement, the file and the budget. Measured over four
Grok sessions (2026-11-14..18): workers re-ran it — `cbh client` 433 times, `ls leads/ primitives/`
584 times, `PROJECTS.md` 90 — at ~75 KB of output each, ~19% of all worker input tokens.

1. **`cbh client`** — your client's row: crew size, whether you may send, which gates are live, how
   `skills/`, `commands/` and subagents load for you. Do not assume another client's rules.
2. `Targets/PROJECTS.md` — project index (name · status · scope one-liner).
3. Unclear which project → ask the operator.
4. Read that project's `Targets/<name>/CLAUDE.md` + `notes.md` + `scope.md` first — authoritative
   for scope, program rules and where we left off. Per-host detail: `Targets/<name>/hosts/<host>.md`.
   Clients that do not auto-load those files read them as files; `Targets/` is git-ignored.
5. Outside Claude Code, start the hunt with **`cbh hunt-start <program>`**: it resolves the folder,
   arms hunt mode, prints the standing orders, the crew size and the env to export
   (`CBH_PROJECT`, `CBH_SESSION_ID`). `cbh hunt-stop` when the operator says stop.

One engagement at a time. Never seed a new project from an old one: copy `Targets/_TEMPLATE/`, fill
scope from the program page. Only the safety floor below carries across engagements.

---

## Safety floor (always, every client)

- **Authorized targets only.** In the program's scope, or not touched — even if the domain matches.
- **Own accounts/data only.** Never access other users' data.
- **Minimal PoC.** Anything that could affect other users or availability → stop, park it with
  `**Park:** availability`, and continue elsewhere. No exploitation beyond proof. This is a floor, not
  a permission queue: it covers blast radius on people outside the engagement, **not** a write, a
  POST or an approval question on our own account (`cbh autonomy`).
- **Respect rate limits.** No DoS / MITM / social engineering / physical. No disclosure before fix.
- Harness or classifier denials are respected, never routed around via another tool or agent.
- **Every request aimed at a target goes through `CBH_PROJECT=<name> bbcurl …`** (scope + pacing +
  mandatory headers + audit). Bare `curl` is a gate bypass and cannot back a report.

---

## Client adaptation — the only thing that differs

`cbh client` prints the row; `cbh client --list` prints all of them; `engine/client.py` is the
source. Detection: `CBH_AGENT=claude` wins, else the client's own env
(`CLAUDECODE=1`), else process ancestry, else `generic`.

| | Claude Code | any other client (`generic`) |
|---|---|---|
| crew | 3 concurrent workers | 6 concurrent workers |
| may the main thread send? | **no** — you plan and merge, workers fire (`crew-gate` enforces it) | **yes** — you send, and so do your subagents |
| gates | PreToolUse hooks live (`crew-gate`, `skill-gate`, `agent-gate`) | no hooks; scope and pacing bind through `bbcurl` and whatever wrapper that client has |
| skills | `Skill("hunt-xss")` | read `skills/hunt-xss/SKILL.md` as a file |
| commands | `/pickup`, `/remember`, … | read `commands/<name>.md`; most have a `cbh <name>` twin |
| subagents | `Agent` tool, `subagent_type` from `.claude/agents/` | your own parallel subagents, roles from the client's own registry |

`"hunt_agents"` in `Targets/<name>/profile.json` overrides any crew number. Pacing is one global
`flock`'d budget per engagement, so extra workers queue instead of adding requests — never relax
pacing to make a fan-out faster.

---

## Enforcement is in code — don't re-implement it by hand

| Mechanism | What it does |
|---|---|
| `engine/client.py` (`cbh client`) | The one client-capability table; every detector delegates to it. |
| `engine/scope.py` (`/scope`, `--resolve`, `--whois`) | Default-deny scope gate; netblock programs require DNS resolution into declared ranges. `UNVERIFIED` ≠ approved. `--selftest` after edits. |
| `engine/pacing.py` + `Targets/<name>/profile.json` | Global per-engagement request budget (`min_interval_seconds`, `max_concurrency`, `required_headers`, `required_cookie` — a mandated cookie CANNOT be a required header: `-H "Cookie:"` replaces what `-b` sent and drops the lane's jar), `flock`'d across processes. Change numbers in `profile.json`, not prose. No profile → 10 s default. |
| `scripts/bbcurl` | curl with scope check, pacing, mandatory headers, audit, response corpus. `--bb-dry-run`, `--resolve`/`--connect-to` supported (scope checked on the pinned address). `--bb-caido` routes a proof request through Caido (refuses if Caido is down or a pin would not hold; `docs/caido.md`). Don't use `-o /dev/stdout` (deadlocks). |
| `scripts/bbscan sqlmap …` / `bbscan nmap …` | Gated wrapper for tools that send their own traffic. Details `docs/bbscan.md`. |
| `engine/poc_runtime.py` (`/poc-run`) | Fires a PoC spec, captures redirect chain + `Set-Cookie`, judges in code, writes `.result.json`. Multi-step `steps` with captures. A followed redirect without `final_url_contains`/`no_redirect` → INCONCLUSIVE. |
| `engine/evidence.py` (`cbh evidence`, `cbh triage`) | DEMONSTRATED / MISMATCH / NOT-PROVEN / NO-EVIDENCE / WIRE-UNPROVEN / CLASS-UNPROVEN / REFUTED from artifacts, not wording. |
| `engine/class_proof.py` | The oracle a class needs: execution for XSS, a delay or DB output for SQLi, an OOB hit for SSRF/XXE, two identities for IDOR. |
| `engine/funnel.py` | What counts as an item in `leads/`/`primitives/`/`findings/`, and its name: flat `<slug>.md`, folder-form `<slug>/README.md` or `<slug>/<one>.md`, never the tier's own README. Read by `lead_queue` and `stop_gate` both, so a count and a queue cannot disagree. |
| `engine/refute.py` (`/refute`) | Fires controls whose PASS kills the finding. Needs `"refute": {"attack","control"}` in the spec; the attack value must be load-bearing. |
| `engine/memory.py` (`/remember`, `/pickup`, `/memory-gc`) | Hunt memory in `hunt-memory/` (`journal`/`patterns`/`audit.jsonl`, `responses/`). Log confirmed **and** rejected results. |
| `engine/vectors.py` (`cbh vectors next\|rotate\|revisit\|mark`) | Impact-ranked untried vectors per host, mutation matrix, refuses `dead` with 0 requests fired. |
| `engine/stop_gate.py` (Stop hook, Claude Code) | Continuous mode: a Medium+ finding is banked and the session continues on the next vector until the operator stops it. Never inflate severity to satisfy it. |
| `engine/responses.py` | Response corpus + PII scrub (`iin`, `msisdn`, `phone*`, …) on every write path. `cbh diff <url> [--fields]`, `cbh spec <url>`. |
| `scripts/mcp-gate.py` + `runtime/inline-gate.mjs` | Scope/pacing/audit for Caido and Playwright MCP calls — the hook version under Claude Code, the inline version everywhere else. Browser control URLs (`about:blank`, `data:`, `blob:`, `chrome://`, `file://`) send nothing and pass ungated; `view-source:` is gated on the URL it fetches; pausing Caido's intercept queue is refused while a proxied browser is live. |
| `engine/browser_hints.py` (`cbh browser hint`, `scripts/mcp-hint.py`) | A browser/proxy failure arrives with the remedy attached. `cbh browser doctor` prints the live lane state: engagement, Caido route, profile holder, Chrome, display. |
| `scripts/sync_clients.py` | One `skills/` + `commands/` + `agents/roles/` source → every installed client's own location. `--check` is in the test suite. |

Claude Code hooks (`skill-gate`, `crew-gate`, `hunt-nudge`, `hunt-stop-gate`, `session-brief`,
`hunt-arm`, `agent-gate`, `control-guard`, `error-log`) run only if installed in
`~/.claude/settings.json`: config `docs/setup/hooks.json`, install
`python3 docs/setup/apply-hooks.py --apply`, restart. **A Claude session inside `Targets/<name>/`
must open with the `session-brief` line; no brief → run `cbh doctor`.**

---

## Commands worth knowing

`cbh autohunt` (**the wave**: ranked item + the skills that lane loads + the disclosed chain it
could become + its slice of the request budget, one brief per slot — re-run it after a wave lands and
it reads the closures and emits the next) · `cbh skill-graph` (the 68 skills as a graph: `--ladder
<url|lead title>` orders the skills for a surface, `<skill>` shows what it defers to and where a
proof escalates, `--chains` prints the disclosed reports whose class sets paid, `--lint` fails when a
new skill has no SKIP clause) · `cbh client` (your row) · `cbh autonomy` (the four reasons a vector may still be parked; `--reclassify <eng> --reopen` returns the rest to the queue) · `cbh precedent --lead <file>` / `--class <c>` / `--signals <body>` (what a
PAID disclosed report noticed first on this shape; 155 merged reports — `cbh leads` prints one line
of it per lane) · `cbh doctor` (workspace health) · `cbh browser doctor` (browser lane state before
re-firing a failed navigation) · `cbh tools doctor [--start]` (Caido/Playwright handshake; `burpmcp`
always FAILED — Burp not installed) · `cbh queue` · `cbh chain-graph` (add
`**Chain:** needs \`x\` · gives \`y\`` to every primitive) · `cbh vectors next` · `cbh yield` ·
`cbh errors` · `cbh limits` · `cbh crew` · `cbh identity new <url>` ·
`cbh freeroam` · `cbh census --project <eng> --seed` · `cbh diffprobe <url>` · `/cve` +
`Targets/CVE-DIGEST.md` (ledger rows are keyword matches, fingerprint before believing) ·
`python3 scripts/pattern-analytics.py --stack "<stack>" --recommendations` ·
`python3 engine/program_scout.py` · `heavy-run -- <cmd>` (**mandatory** for
jadx/apktool/gowitness/big ffuf).

Regression tests: `python3 -m unittest discover -s tests` after touching `engine/` or
`scripts/*-gate.py`.

---

## Skills

One source: `skills/` (68) and `commands/` (22) in this repo, deployed to each client by
`python3 scripts/sync_clients.py` (`--check` verifies they are in sync; `--targets` also refreshes
the per-program `AGENTS.md` pointers). After add/remove: `python scripts/gen_skill_index.py &&
python scripts/gen_skill_catalog.py && python scripts/lint_skills.py`.

- Load the matching `hunt-*` / `bb-*` skill before hand-rolling a vuln-class check. New host with no
  class in mind → `bb-methodology`; fingerprinting → `hunt-dispatch`; mapping a frontend's API and
  parameter surface → `api-recon`, then `api-security`; breadth-first recon → `web2-recon`.
- **Don't pick the skill by hand.** `cbh skill-graph --ladder "<url or lead title>"` orders them for
  that surface — the URL-signal table first, then TRIGGER-term overlap — and marks which ones
  `skill-gate` will demand anyway. `cbh autohunt` already puts that ladder in every brief.
- **A proven primitive is a step, not an end.** `cbh skill-graph <skill>` names where the proof
  escalates (`hunt-lfi` → `hunt-rce`, `hunt-saml`/`hunt-oauth`/`hunt-session`/`hunt-mfa-bypass` →
  `hunt-ato`) and which skills own an adjacent surface, so a lane does not spend budget on a class
  another skill covers. Leaving a proven primitive without walking its escalation is how a Critical
  is written up as a Medium.
- On every confirmed finding or anomaly → `/chain` before closing the thread. Before any report →
  `/validate`.
- Under Claude Code, `skill-gate` denies requests to a surface whose skill isn't loaded while a hunt
  is armed; the deny prints the `Skill(...)` call to make. Other clients read the `SKILL.md` instead
  — the obligation to read it first is the same.

---

## How to work

- **A conclusion read from JS/source is a hypothesis (open thread)**, not a closed one, until a real
  request answered it. Prefer sending the in-scope, non-destructive request on your own account over
  more analysis. Pacing and scope are enforced in code — no need to hand-throttle.
- **A lane is a lead taken to proof or refutation — not a host census.** Open leads come first
  (`cbh leads`, `primitives/` with a `**Chain:**` line, `cbh vectors next`). A census (`GET /` +
  invented leaf) is allowed only when no open lead is left, and then **one worker takes 15–30 hosts
  in one lane**, never one worker per host. (Measured 2026-11-10: a 243M-token session spent its
  whole budget on a census and bookkeeping, 362 GETs, 0 findings.)
- **Funnel:** `Targets/<name>/leads/` (hypothesis) → `primitives/` (capability proven, impact not) →
  `findings/<slug>/` (impact demonstrated, `.result.json` behind it). Impact unproven = not a
  finding. `cbh triage <f> --demote` knocks a claim down a tier. **Lanes come from `cbh leads`**
  (ranked by payout + staleness, a lead needing an account marked `REGISTER FIRST` rather than held
  back); every lane ends with
  `cbh leads close <file> --as proven|refuted|exhausted|blocked|stalled --note "why"`. `blocked` =
  one of `cbh autonomy`'s four reasons, declared on the file with a `**Park:**` line (held back for
  the operator; a `blocked` banner with no declaration stays workable and says so); `stalled` = our own tooling did not
  finish the lane (stays in the queue, flagged `RETRY`). Swapping them emptied a queue on
  2026-11-11: `cbh leads reopen <file> --note "why"` undoes it.
- **One wave at a time, and the wave is decided from state, not from memory.** `cbh autohunt` reads
  the queue, the unproven claims, the chain hub and the remaining budget, then emits one brief per
  slot: the item, the skills to load, the skills to defer to, where a proof escalates, the disclosed
  reports whose class set this item belongs to (with their steps and payout), the second class that
  turned it into a Critical in the corpus, and the lane's request slice. Roles are mixed in one wave
  — a claim with no PoC gets a `refuter` lane while the rest hunt — and no two lanes share a host or
  wait on the same missing capability. Dispatch the briefs; re-run it when they land.
- **Every wave fires a kill attempt while an unattacked claim exists.** A refuter lane comes from
  two sources: a finding claimed in this hunt with no PASSing PoC (first, always), and any live
  finding or primitive carrying no `<stem>.refute.json`, a record older than the claim's last edit,
  or a verdict of `INCOMPLETE`. Refutation takes at most a third of a wave for the never-attacked
  ones and leaves at least one hunter lane; with nothing else workable it takes the whole wave.
  `--role deep-hunter` or `--role scout` fires none. Measured 2026-11-12: a session emitted 125
  hunter lanes to 1 refuter, and 395 of 408 live primitives had never faced an arm.
- **Read the paid precedent before the first payload:** `cbh precedent --lead <file>` prints the
  FIRST SIGNAL, the mechanic and the accepted impact proof; `cbh precedent --signals <captured body>`
  names which disclosed opening a response you are holding resembles. A precedent is a hint, never a
  scope. The crit/high doctrine is CARRIED BY THE ROLE (`agents/roles/<role>.md`), not pasted
  into each brief: re-sending an identical prefix per spawn is the Strix antipattern (145.1M
  tokens, 41 subagents, 97% of input tokens re-submitted). `cbh doctrine` prints the same text
  for you; a Freeroam slot reads none of it, deliberately.
- **A code-only sink is not closed until a browser has tried it.** `href`/`location`/`innerHTML`/
  `window.open` fed by a URL, query, hash, postMessage or stored field: drive the page in Playwright
  with a marker in the controllable input and read the DOM/navigation back. "Needs Playwright" is a
  reason to use Playwright, not to skip the lane.
- **Five-minute rule:** no progress on a vector → `vectors.py rotate`, then `revisit`, then `next`;
  host exhausted → next in-scope host. Log the vector as tried in `hosts/<host>.md`.
- **Continuous hunting, and a finding is FINISHED before the crew moves on** (operator directive
  2026-11-14). A finding is never a reason to stop: bank it (`findings/`, `/remember --result
  confirmed`, `/chain`) and continue with the next vector. The hunt ends when the operator says so.
  But "continue" queues behind the proof — while a finding THIS hunt claimed is not fully
  confirmed (no PASSing `.result.json`, or no current `<stem>.refute.json`) the wave may go
  **entirely** to confirmation: `refuter_share` drops its one-hunter floor, `cbh autohunt` prints
  `CONFIRM FIRST`, and hunting resumes in that same wave the moment the confirmation lanes run
  out. The never-attacked BACKLOG keeps its one-third cap, so 400-odd old primitives cannot
  swallow every wave. `stop_gate` continuous mode is the workspace default
  (`CONTINUOUS_DEFAULT = True`); it was found OFF on 2026-11-14 with an empty note, which would
  have let a demonstrated Medium+ open the stop door — turning it off needs a reason in the note.
  Report progress as statements, not questions. Severity is rated honestly regardless.
  **A client with no `Stop` hook gets none of this from the gate** — measured 2026-11-14: 0 of 59
  sessions in `hunt-memory/pacing/stop_gate.json` were Grok-shaped, so its stop gate has never
  run. Such a client reads the verdict off `cbh autohunt`'s `Stop gate:` line instead, every wave.
- **Nothing waits for the operator except four things** (operator directive 2026-11-14 — `cbh
  autonomy` prints them, `engine/autonomy.py` is the source every gate and every role file reads):
  `other-user-data` · `availability` · `out-of-scope` · `human-inbox`. **Everything else is fired
  without asking** — a write, a POST/PUT/PATCH/DELETE, an account the engagement does not hold
  (`cbh identity new`, and a wall there is ONE vector), a programme-approval question, and our own
  tooling failing (`--as stalled`, which stays in the queue flagged RETRY). A parked vector goes to
  `blocked-tests/` and **declares its reason on a `**Park:** <reason>` line**; with no declaration it
  is not parked and `cbh leads` hands it to the next lane. Per programme:
  `"autonomy": {"unpark": ["human-inbox"]}` in `profile.json`. Measured 2026-11-14: 431 parked files,
  ~11 on the floor, 36 of wildberries' 74 parked for being a POST — `cbh autonomy --reclassify <eng>
  --reopen` puts the fireable ones back in the queue.
- **Arming:** a plain hunting order ("начни хантить X", "start hunting") arms analysis mode
  (`scripts/hunt-arm.py` under Claude Code, `cbh hunt-start` elsewhere); "стоп охота" /
  "stop hunting" disarms. Questions never arm it.
- **Crew:** an armed hunt is orchestrator + workers. The orchestrator plans, merges, writes
  `notes.md` and `/remember`; whether it may also send is the one client difference (`cbh client`).
  Launch the whole crew in ONE message and keep every slot filled from the queue.
  **`agent-gate` holds the cap now** (2026-11-13: a session ran 7 lanes against
  `"hunt_agents": 3`): a spawn is denied while the crew is full, a single message carrying more
  lanes than the cap is denied as a batch, and a brief whose every `leads/`/`primitives/`
  file is already closed is denied — pick the lane from `cbh leads`, never from `ls leads/`.
  Nothing a worker backgrounds may outlive its hand-back: a background job that ends later
  revives the finished worker and holds its crew slot until it does (measured: 106 minutes).
  **Spawn a ROLE, not `general-purpose`:** `deep-hunter` (one lead to proof or refutation) ·
  `scout` (15–30 hosts → ranked leads) · `refuter` (kill a candidate finding before it is reported).
  One source, `agents/roles/<role>.md` → `.claude/agents/` via
  `python3 agents/gen_role_agents.py` (`--check` is in the test suite). **A client with no role
  registry reads `agents/roles/<role>.md` AS A FILE before spawning the lane** — the same way it
  reads `skills/` and `commands/`, because `scripts/sync_clients.py` deploys roles only into
  `.claude/agents`. The role files carry the crit/high doctrine, the
  forbidden-action list, the named-victim rule and the handback-citation rule, so a brief cannot drop
  them; **your brief still names the engagement, the program, the scope summary, the file/host list
  and the budget** — workers do not see this file. Freeroam stays a `cbh freeroam run` slot (no
  methodology, `skills_on=False`) and never gets the doctrine.
- **The budget is a stop, not a suggestion.** At the stated tool-call budget a worker hands back
  what it has with the verdict it can defend. The lanes killed on 2026-11-11 were at 77, 63 and 61
  tool calls against a brief that said ~40, and their work was lost with them. A worker with no tool
  call for ~5 minutes is dead: kill it once, give the slot a different lane, note it — and check
  `hunt-memory/audit.jsonl` before believing it died at the target.
- **Browser** work (forms, SPA flows, rendered content) is done by the agent through Playwright MCP,
  with a persistent per-engagement profile at `Targets/<name>/browser-profile/` (start inside the
  engagement folder or set `CBH_PROJECT`). Don't ask the operator to open pages. **One browser per
  profile, so ONE browser lane per engagement at a time** (`runtime/browser-lock.mjs`); the rest of
  the crew fires `bbcurl`. An unauthenticated render may run concurrently with
  `CBH_PLAYWRIGHT_ISOLATED=1`. Never call `browser_tabs {"action":"list"}` to find your own tab —
  tab 0 is the operator's. A failed navigation is diagnosed, not re-fired:
  `net::ERR_TOO_MANY_RETRIES` in under a second is a refusal, and through this workspace it is
  usually Caido — a PAUSED intercept queue holds every proxied request. `cbh browser doctor`.
- **Caido** (`127.0.0.1:8080`, auto-started by `scripts/caido-up.sh`) for wire-level questions:
  redirect chains, cookies, replay. Land the final proof in a `poc_runtime` spec. Details
  `docs/caido.md`.
- **Accounts:** `identity.json` → `cbh identity new <url>` + self-registration via Playwright → if
  blocked (CAPTCHA, government ID, a phone the operator doesn't have), that is ONE vector: log it in
  `blocked-tests/` and continue on the unauthenticated surface. Never wait for the operator for an account: if `cbh leads`
  holds leads back for one and the program allows self-registration, spend ONE lane registering a
  throwaway and record it in `identity.json` with a `"role"`. The operator has no Russian phone or
  accounts.
- **Wire claims** (redirect/session/cookie) need a multi-step spec, a Caido/`.burp.txt` capture, or a
  cited corpus `sha256` with headers — else `WIRE-UNPROVEN`.
- **The class of a claim names the oracle, and a PASS is not the oracle.** A fired PoC proves the
  request went out and matched its `expect`; for several classes that is not the effect. A reflected
  marker is a sink, not execution; a 500 on a quote is not a database; a 200 from a fetcher is not an
  outbound request; one identity cannot show an ownership boundary. `engine/class_proof.py` reads the
  oracle off the artifacts and the gate returns `CLASS-UNPROVEN` while it is missing: XSS needs a
  browser/proxy artifact (screenshot, console record, Caido export), SQLi a delta between two arms of
  one PoC (>= 2000 ms and >= 3x) or the driver's own error, SSRF/XXE an OOB hit log, RCE command
  output or an OOB hit, LFI the file's bytes, IDOR two identities in one spec, CSRF an `.html` PoC,
  open-redirect a hop whose host is not the host we asked. Classes with no rule are reported as
  `not checked` — never silently passed. Declare the class (`**Class:** idor`) so the gate grades the
  right question instead of guessing from the title.
- **An item is what `engine/funnel.py` says it is.** A tier holds flat `<slug>.md` and folder-per-item
  write-ups side by side; the one rule is flat file, then `<slug>/README.md`, then `<slug>/<folder
  name>.md`, then the single `.md` in the folder. A tier's own `README.md` is its instructions and is
  never an item, and a folder with several unnamed markdowns is skipped, not guessed at. Name an item
  by `funnel.item_name`, not `Path.stem`, or a folder-form item is called `README` everywhere.
- **A change to a gate is a change to what a worker is told next, so replay it.** Before touching
  `lead_queue`, `stop_gate`, `evidence`, `class_proof`, `refute` or `autohunt`, run
  `python3 scripts/decision_replay.py --out /tmp/new.txt --corpus "$(readlink -f Targets)"`, give the
  previous commit a worktree, point it at this corpus with `CBH_TARGETS_ROOT` / `CBH_MEMORY_DIR` on
  the **resolved** path (a symlink pointing here resolves to a different string, and an
  unresolved path raises
  `ValueError: ... is not in the subpath of ...` on every engagement), replay there, and diff. The
  suite proves the code does what it was written to do; only the replay shows whether a lane, a brief
  or a verdict moved — and it fires no requests.
- Before any report: `/poc-run` → `/refute` → `cbh dedup` → `/validate`.
- **Every candidate finding goes through `cbh triage <f>.md` the moment its write-up exists**
  (operator directive 2026-11-12), not at submission time — the gate decides what a finding is, not
  the worker's confidence, and not a PASSing `.result.json` on its own. A `KILL` is answered with
  `cbh triage <f>.md --demote`, never with an argument. Nothing is submitted without proven impact:
  an inference about what a disclosed value would mean is not a demonstrated consequence. Note the
  trap this directive came from — on an **unauthenticated**-exposure claim `cbh refute`'s
  `credentials-removed` control passes by construction (the request carried no credential), and the
  gate reads that as Q1/Q6 overturned, so a claim of that shape cannot pass while it is framed as an
  authorization failure.

---

## Tool stand

Installed list is generated: `skills/bb-local-toolkit/SKILL.md` (`scripts/gen_toolstand.py --check`).
Restricted although installed: `nuclei`, `dalfox` (one targeted check on a confirmed finding, never a
sweep); `interactsh-client` (public server — confirm the program permits OOB; forbidden on
`*.rteam.kz`).
Not installable here (no pip/docker/cargo): `semgrep`, `trufflehog`, `arjun`/`paramspider`/`x8`/`uro`,
`jwt_tool`, `bbot` — use `gitleaks`+`trivy`+`jsluice`, `ffuf`+`katana`+`qsreplace`, manual JWT work,
and say so in write-ups.
Reference data: `~/security-research/tools/data/` (`keyhacks.md`, takeover fingerprints, platform
scope dumps). The repo is git-tracked (`main`); commit only when the operator asks.

---

## Logging discipline

Every step run against a target (request, PoC, browser action, exploit attempt) is logged in the
project's own files as it happens: `hosts/<host>.md` scan-log row, `notes.md` open threads,
`findings/` draft. Each worker writes its own rows and ONE `notes.md` bullet, then hands back ≤10
lines (verdict, counts, file paths); the orchestrator spot-checks one claim per hand-back instead of
re-reading the worker's files line by line. When a write-up mixes executed and predicted steps,
confirm with the operator which is which before logging anything as fact.

## Chat style

caveman `ultracave` is on for chat replies only. Files (`notes.md`, findings, hosts, reports, memory)
stay in full prose.
