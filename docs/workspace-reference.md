# Workspace reference — full history and rationale

> Moved out of `CLAUDE.md` on 2026-11-10 to cut per-session context (~60 KB loaded into every session and every subagent). Rules live in `CLAUDE.md`; this file keeps the dated history, incidents and the "why" behind each mechanism. Read the section you need, not the whole file.

> **LIVE workspace — `/home/qvex/security-research/BugHunter`.** `FROZEN.md` and any
> `/opt/...` path in it are stale: those directories do not exist on this box. Verified
> 2026-10-15: the tests, the cron and `engine/paths.py` all resolve here.

# Workspace — web bug-bounty operator

This is a **web-application bug-bounty / pentest** workspace. Everything here serves that.
Read this file for *how we operate globally*; read the **project folder** for *what we're doing right now*.

---

## FIRST THING EVERY SESSION — which project?

Work always happens inside one engagement. Before testing anything:

1. Open **`Targets/PROJECTS.md`** — the project index (name · status · scope one-liner).
2. If it's not obvious which one we're on, **ask the user** ("Kcell or Allur?").
3. Then read that project's own **`Targets/<name>/CLAUDE.md` + `notes.md` + `scope.md` FIRST** — those are authoritative for scope, rules, pacing, and where we left off. Per-host detail lives in `Targets/<name>/hosts/<host>.md`.

**Each engagement's rules live inside its own folder — not here.** Scope, pacing numbers, host lists, reward bands, recon-log discipline, per-program limits: all in `Targets/<name>/CLAUDE.md`. This file stays project-neutral on purpose.

**Never seed a new project from an old one.** Don't copy another project's `notes.md`, `hosts/`, `findings/`, or its assumptions/priors/"this stack is hardened"-type conclusions into a fresh engagement — that anchors you and you miss what's actually there. New project = copy `Targets/_TEMPLATE/`, fill scope from scratch. Only the universal safety floor below carries over.

---

## Skills / tooling — `BugHunter/`

### Local tool runtime

Before a hunt or after a reconnect, run `cbh tools doctor` (add `--start` to
bring up Caido). It verifies the real `tools/list` handshake for `caido` and
`playwright`; a listening TCP port alone is not considered healthy. `burpmcp`
always reports FAILED here — Burp is not installed on this box (2026-10-20), and it
is disabled in `.claude/settings.local.json`; ignore that row. The project MCP config uses wrappers under
`BugHunter/runtime/`, which keep tool names and timeouts stable. Ambiguous
Burp calls are never replayed automatically; inspect history before retrying.

Web-only fork of [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter), stripped to web-app pentest (removed enterprise-identity, cloud/infra, Web3, mobile, red-team, general-OSINT skills + `/web3-audit`). **This is the base for all vuln work** (picked over shuvonsec/claude-bug-bounty for deeper per-vuln context).

- **Installed as plain copies, not as a plugin (verified 2026-10-20).** The bundle is NOT registered as `bughunter@elementalsouls` — `enabledPlugins` holds only `caveman@caveman`, and `/opt/BugHunter` does not exist. Skills and commands are copies in `~/.claude/skills/` and `~/.claude/commands/`, so they load **unprefixed** (`hunt-idor`, not `bughunter:hunt-idor`; the gates normalise either form). **The copies drift:** on 2026-10-20 the home copy was from 2026-10-12 while `skills/` had edits from 10-14/10-16 (17 files, `refute` missing entirely). After editing anything under `skills/` or `commands/`, re-sync: `cp -a skills/. ~/.claude/skills/ && cp -a commands/. ~/.claude/commands/` and check with `diff -rq skills ~/.claude/skills`.
- **Mandatory: reach for the matching skill before hand-rolling curl/bash.** Before manually scripting a vuln-class check (IDOR probing, SSRF payloads, auth-bypass, business-logic abuse, framework-specific attacks, recon, write-ups, …), check the available-skills list for a `hunt-*`/`bb-*`/`report-writing`/`triage-validation` skill that already covers it and invoke it via `Skill` first. Only fall back to raw curl/bash for the parts a skill doesn't cover (this workspace's curl-first / no-scanner rules still apply *inside* whatever the skill does — skills don't override `Targets/<name>/CLAUDE.md` pacing or scope rules, they just supply the methodology).
- **Mandatory: the bundle already has a "dig deeper" mechanism — use it, don't reinvent it.** Picking a new lead/host with no clear vuln class in mind → consult `bb-methodology` first (it routes by phase, not just vibes). Fingerprinting a live host → `hunt-dispatch`'s signal table maps headers/HTML markers (`PHPSESSID`+OTP → `hunt-brute-force`, `__NEXT_DATA__` → `hunt-nextjs`, `Access-Control-Allow-Origin` → `hunt-cors`) to the right `hunt-*` skill instead of guessing. **On every confirmed finding or anomaly — before closing the thread or declaring it "good hygiene, not a finding" — check `/chain`'s A→B signal table** (e.g. rate-limited OTP found → immediately check password-reset-token brute force; IDOR closed on GET → check PUT/DELETE same path; SSRF found → check DNS-only variant before giving up). This is exactly the "could've dug deeper" gap to close — the table already encodes it, invoking it is the fix, not writing new heuristics. Before any report → `/validate` (7-Question Gate).
- **66 skills / 22 commands** — all `hunt-*` web vuln classes (XSS, SQLi, IDOR, SSRF, OAuth, GraphQL, SSTI, deserialization, CSPT, …), framework skills (Next.js/Node/Laravel/Spring/ASP.NET/SharePoint), web recon, reporting + validation gates.
- **`/scope` now resolves, and that is not optional for netblock-scoped programs (2026-08-06).** `engine/scope.py` matched DNS names only, so a subdomain matching `*.example.com` that resolved into somebody else's datacenter came back `IN-SCOPE` — the failure that got a submission closed as "Вне Скоупа". Two things changed: `--resolve` resolves each host (DNS only, target untouched) and requires the IP to land inside the program's declared netblocks, and `--whois` prints the netblock owner (local `whois`, else RDAP) for programs that judge host-ownership by hand instead of publishing ranges. A netblock-scoped program checked *without* `--resolve` now returns `UNVERIFIED`, not `IN-SCOPE` — **`UNVERIFIED` is not approval to test.** `engine/poc_runtime.py` enforces the same gate before firing. Also fixed: the `scope.md` parser ignored markdown decoration, so every backtick-wrapped pattern parsed as garbage and the gate was unusable — all four project `scope.md` files now parse, IP ranges included (`195.47.255.208–255` en-dash form). Run `python3 engine/scope.py --selftest` after touching it.
- **Pacing + mandatory headers are enforced in code (2026-08-09) — `engine/pacing.py`.** Each engagement carries a machine-readable `Targets/<name>/profile.json`: `min_interval_seconds` (a **global** budget across the whole target set, not per host), `max_concurrency`, and `required_headers`. `poc_runtime.py` sleeps against that budget before every request — state is a `flock`'d file under `hunt-memory/pacing/`, so concurrent sessions queue instead of each concluding it's within budget — and injects the program's mandatory headers (RTEAM's `X-Bug-Bounty: qvex`), refusing to fire if a required header has no value. Numbers came from each program's own CLAUDE.md; **change the number in `profile.json`, not in prose**. No `profile.json` still gets a 10s default — being inside `Targets/<name>/` means a live program is on the other end. `python3 engine/pacing.py --status` shows the active budget, `--selftest` checks the gate. Because this is enforced, the per-project files no longer restate pacing rules and **you don't need to hand-throttle** — see "How to work" below.
- **`bbcurl` is the curl-first path, gated the same way (2026-08-09).** `scripts/bbcurl` (on PATH) takes plain curl arguments and, before exec'ing curl, scope-checks every URL against the engagement's `scope.md` (resolution gate included — it refuses `fc.activ.kz` on netblock-scoped Kcell, the host whose report came back "Вне Скоупа"), waits out the pacing budget, injects mandatory headers, and logs to `hunt-memory/audit.jsonl`. **Use `CBH_PROJECT=<name> bbcurl` instead of `curl` for anything aimed at a target** — the prefix is not optional: cwd resets between calls, and without it `bbcurl` used to degrade to ungated plain curl, saying so only on stderr (which callers discard). Since 2026-08-28 it refuses a non-local URL when no engagement resolves (`--bb-ungated` is the audited opt-out); bare `curl` bypasses all of it. Outside a `Targets/<name>/` folder it degrades to plain curl with a warning, so lab work stays frictionless. `--bb-dry-run` shows the resolved command without sending. **`--resolve` / `--connect-to` are understood (2026-08-25):** when a host is pinned to an address, scope is verified against the *pinned address* and the name is treated as SNI/Host content. Before that fix the gate resolved the URL's name in DNS, got NXDOMAIN for any vhost without a public record and refused addresses plainly inside the program's ranges — silently blocking SNI-correct vhost hunting, the technique that found `websfa.kcell.kz`.
- **Hunt memory is real now (2026-08-06) — `engine/memory.py`.** `/remember`, `/pickup`, `/memory-gc` and `/surface`'s memory layer pointed at a `hunt-memory/` dir and a `tools.memory_gc` module that **did not exist** — nothing was written. Implemented as `journal.jsonl` (everything) / `patterns.jsonl` (confirmed only) / `audit.jsonl` (every request `poc_runtime` fires) / `targets/<t>.json` profiles, with auto-rotation on write and credential-shaped keys redacted before disk. Deterministic backing is `cbh remember|pickup|memory-gc`. Memory dir for this workspace is **`hunt-memory/` in this repo** (`python3 engine/paths.py` prints it; `CBH_MEMORY_DIR` is pinned to it in `~/.claude/settings.json` `env`) — resolution walks up from cwd, so it works from any `Targets/<name>/` subdirectory; `$CBH_MEMORY_DIR` overrides. **Log findings with `/remember` as they close** — `/pickup <target>` is what makes "where did we leave off" answerable across sessions, and pattern carry-over only works if the corpus gets fed.
- **Session brief runs automatically (2026-08-10).** `scripts/session-brief.py` is wired as a `SessionStart` hook in `~/.claude/settings.json` (**re-wired 2026-10-20** — see "Hooks" below); inside a `Targets/<name>/` folder it prints the engagement, its pacing budget and mandatory headers, the open threads from `notes.md`, and fails loudly if `scope.py --selftest` breaks. Nothing outside an engagement. `CBH_MEMORY_DIR` is pinned there too, so hunt memory cannot fork into a second corpus.
- **`cbh` is on PATH** — `~/.local/bin/cbh` → `scripts/cbh.py` (the shim used `abspath`, which lost the repo root through a symlink; fixed to `realpath`).
- **CVE freshness is automated (2026-08-13).** `scripts/refresh-cve-index.py` (CISA KEV, scoped to Apache/Atlassian/GitLab/Jenkins/SharePoint-Exchange/WebLogic/ColdFusion/WordPress/Drupal/Joomla) runs daily via cron (2:30 AM) and writes `docs/cve-coverage.md`. Mid-hunt, `hunt-dispatch` checks CVEs inline the moment a fingerprint returns an exact product **version** — a stronger signal than the generic class hunt-\* set. `/intel target.com` is the on-demand per-engagement version. **A daily slot alone does not fire on this box:** WSL is off at 02:30/07:00/07:30 and cron here has no anacron catch-up, so an 8-day silent gap once hid two live Tomcat CVEs on `web.kcell.kz`. `scripts/cve-boot-catchup.sh` at `@reboot` is the fix (mechanism in the 2026-10-14 entry below). Check `logs/cve-boot-catchup.log` when `docs/cve-coverage.md` or a project's `recon/cve-watch-state.json` looks stale.
- **CVE leads are a queryable ledger + a standing digest (2026-08-27).** `cve_watch.py` kept only CVE *ids* in state and wrote hits to `notes.md` as prose, so "which CVEs are still unchecked on which host" needed re-reading notes by eye. It now appends one record per hit to `Targets/<name>/recon/cve-ledger.jsonl` (cve_id · cvss · product/version · hosts · status). `scripts/cve-digest.py` prints every engagement's ledger host-grouped and CVSS-ranked; `--mark <CVE> --status checked|dismissed --note '<why>'` closes a lead (append-only, newest row wins). Snapshot: **`Targets/CVE-DIGEST.md`**, daily 07:45 and on boot. **`/cve` is the command** — digest, then scope-check, then confirm the live version, then route to the `hunt-*` skill, then `/poc-run`. `scripts/cve-ledger-backfill.py` rebuilt the ledger from the older notes.md blocks (idempotent; those hits are marked seen and never re-emit). **Every ledger row is an NVD keyword match, not a finding** — the watchlist version may be months stale, so fingerprint the host before believing any row.
- **Technique auto-classification (2026-08-13).** `engine/technique_classifier.py` classifies findings from patterns.jsonl (50+ mappings). **Auto-runs during `/remember`**; bulk: `python3 engine/technique_classifier.py`.
- **Pattern analytics are live (2026-08-13).** `scripts/pattern-analytics.py` reads hunt-memory for which techniques work on which stacks (success rates, payout averages) and ranks hosts by vulnerability density. **Before a new target:** `python3 scripts/pattern-analytics.py --stack "<detected_stack>" --recommendations`.
- **Working on the bundle itself:** edit `skills/<name>/SKILL.md`; after add/remove run `python scripts/gen_skill_index.py` + `python scripts/gen_skill_catalog.py`, then `python scripts/lint_skills.py` (must be 0 errors). **Not a git repo, and `git` is not installed on this box** (no `.git` here) — `.gitattributes`/`.gitignore`/`.github/workflows/` are vendored from upstream but inert here; `git init` first if you want history or want the `cve-refresh`/`skill-lint` GitHub Actions workflows to ever actually run (they're dead YAML on a non-repo, non-pushed directory).

## Hooks — the enforcement layer is only real if `~/.claude/settings.json` has it (re-verified 2026-10-20)

Everything below called "enforced in code" by a hook — `mcp-gate` (scope/pacing/audit/mandatory headers for **Caido and Playwright**), `skill-gate`, `hunt-recall`, `hunt-nudge`, `skill-track`, `hunt-stop-gate`, `session-brief`, `hunt-arm`, `agent-gate` — **runs only when installed in `~/.claude/settings.json`.** On 2026-10-20 none were, since at least 2026-10-13: browser and Caido traffic that whole window went out **without** scope check, pacing, audit or `X-Bug-Bounty`. `bbcurl` and `poc_runtime` gate themselves, unaffected.

- Config is versioned at `docs/setup/hooks.json`; install with `python3 docs/setup/apply-hooks.py` (dry run) then `--apply` (timestamped backup of `settings.json`). **Restart Claude Code** — hooks load at session start.
- **Check at the start of every hunt:** the session must open with the `session-brief` line (`Engagement: … · pacing … · mandatory headers …`) when started inside `Targets/<name>/`. No brief line ⇒ hooks are not loaded ⇒ re-run `apply-hooks.py` before firing anything through the browser or Caido.
- Re-apply after any machine move, settings reset or Claude Code reinstall.
- **`cbh doctor`** (`engine/workspace_check.py`) checks, locally and in <0.1 s: all 12 hooks wired (incl. `control-guard`, `agent-gate`, `error-log`) under the right event/matcher, `~/.claude/skills` + `~/.claude/commands` byte-identical to the repo, every `0 | 0` reward band carries an `onlyMaxPayment` verdict, every `CLAUDE.md` under 60 KB, and **every binary the tool stand declares is on PATH** (`tool-stand`). `session-brief` prints one `WORKSPACE FAIL [...]` line per failure — also outside an engagement. It cannot report its own absence: **no brief at all ⇒ run `cbh doctor` by hand.**

## Decision tooling added 2026-10-20 — use these instead of re-deriving by hand

| Command | What it answers | Where it shows up |
|---|---|---|
| `cbh doctor` | the 7 checks above, each one named in its own output | `WORKSPACE FAIL` lines in the session brief |
| `cbh queue` | reports with a passing PoC not yet submitted · blocks only the operator can clear · operator approvals that unblock chains | `Targets/OPERATOR-QUEUE.md`, `OPERATOR QUEUE:` brief line, regenerated daily |
| `cbh chain-graph` | which missing capability unlocks the most primitives — from `**Chain:** needs \`x\` · gives \`y\`` lines in leads/primitives/findings. **Add that line to every new primitive.** | `CHAIN HUB:` brief line |
| `cbh vectors next` | now ranked with the programme's own payout: `reward_by_class` (+ up to 25) and `downrank_classes` (−40, classes the programme excludes without impact) from `profile.json` | the `next` output names the payout and the downrank reason |
| `cbh yield [eng]` | requests per day vs leads/primitives/findings; dry streak since the last finding | `YIELD (30d):` brief line, `DRY:` at ≥300 requests |
| `python3 engine/program_scout.py` | Standoff 365 programme ranking (avg bounty × acceptance × activity × freshness, shrunk to the median, minus measured walls) + diff vs the last snapshot (new programmes, reward/scope/text changes) | `Targets/standoff365/PROGRAM-SCOUT.md`, daily via `cve-boot-catchup.sh` |
| `cbh errors` | every tool error the `error-log` hook recorded (main thread + subagents), grouped by signature: failures, permission denials, gate refusals, non-zero exits | `ERRORS (24h):` brief line |
| `cbh limits` | the plan's own counters: 5-hour and 7-day windows read from the harness, with reset times, plus measured consumption 5h/today/7d/30d | `LIMITS:` brief line |
| `heavy-run [--max-gb N] -- <cmd>` | runs a memory-hungry tool (jadx, apktool, gowitness, big ffuf) in a cgroup cap derived from free RAM; exports `JAVA_TOOL_OPTIONS=-Xmx…`, `HEAVY_THREADS` | **mandatory** for anything that can eat GBs — a bare `jadx -Xmx12g -j 8` crashed this box |

**Worker agents cannot touch controls (2026-10-20).** `engine/agent.py` starts workers with
`--disallowedTools Edit Write NotebookEdit MultiEdit` and `CBH_AGENT_ROLE=worker`; `scripts/control-guard.py`
denies them any write to `profile.json`, `scope.md`, settings, stop-gate/hunt-mode state and the gates. Cause:
konsol incident, a freeroam worker set `continuous_hunt: false` to end its own run.

## Tool stand — what is installed, and what policy still forbids

Re-audited live **2026-10-21**, and the 2026-08-10 list had rotted: `amass` `gowitness` `nuclei` `dalfox` were gone (the home `~/.local/bin` had been rebuilt), so four skills were pointing at `command not found` again. All four are back, plus the tools our own skills already name. **A skill whose command returns `command not found` is a skill the agent silently abandons** — that is why this section is a live audit and not a wish list.

**The list of what is installed lives in ONE place, generated:** the tool tables in
`skills/bb-local-toolkit/SKILL.md`, rendered from live PATH by
`scripts/gen_toolstand.py` (`--check` says whether they are stale). Duplicating that list
here is what rotted it last time, so this file does not. Shape of the stand as of
2026-10-21: ProjectDiscovery recon (`subfinder` `dnsx` `amass` `assetfinder` `alterx`
`tlsx` `asnmap` `mapcidr` `httpx` `katana`), fuzz/probe (`ffuf` `gau` `waybackurls`
`gowitness` `grpcurl`), plumbing (`anew` `qsreplace` `unfurl` `gf` `jq`), **JS
comprehension** (`jsluice` — tree-sitter AST, extracts by how a value is used, not by
regex; `wakaru` — decompiles webpack/esbuild bundles into modules, `wakaru extract` reads
a `.map`'s `sourcesContent`), secrets/SCA (`gitleaks` `trivy`), 403 bypass (`nomore403`),
takeover (`subzy`), OOB (`interactsh-client`), notification (`notify`), and the restricted
scanners (`nuclei` `dalfox`).

**Reference data (local, no request cost) — `~/security-research/tools/data/`:**
`keyhacks.md` (how to *validate* a leaked API key per provider — the lead -> demonstrated-impact step that otherwise leaves a secret in `primitives/`), `takeover-fingerprints.json`, and the `bounty-targets-data` hourly scope dumps `bt-hackerone.json` / `bt-bugcrowd.json` / `bt-intigriti.json` (platform-published scope: a second source for a scope claim, instead of trusting a worker's summary).

**Installed but policy-restricted — availability is not permission:**

- `nuclei`, `dalfox` — automated vuln scanners. Every project file forbids broad automated scanning: one targeted template/payload against a confirmed finding, never a sweep.
- `interactsh-client` (pre-installed since 2026-07-16) — the OOB channel, since Burp CE has no Collaborator. It resolves through a **public third-party server**, so the callback data leaves this machine. **RTEAM forbids DNS exfiltration outright — do not use it on `*.rteam.kz`.** For other programs, self-host or confirm the program permits OOB before relying on it.

**`sqlmap` + `nmap` installed 2026-10-29 (operator instruction) — call them as `bbscan sqlmap …` / `bbscan nmap …`.** Both send their own traffic, so `bbcurl` cannot cover them; `scripts/bbscan` is their gate: scope, pacing as the tool's own throttle flags, mandatory headers, audit, and a refusal for only the four things a permission to test cannot cover: another user's rows, a write to production, code execution, availability. Throughput, technique, scan type and evasion are the operator's call. Raw `sqlmap`/`nmap` stay ungated. **`docs/bbscan.md`**.

**Wanted but NOT installable on this box (2026-10-21) — substitute, do not treat the skill as blocked:**
- `semgrep` — pip/docker only, and there is no `pip`, no `pipx` and no `docker` here. It is the single most-referenced missing binary in our own skills (31 call sites, almost all in `hunt-source-aware-sast`), so **that skill's static-triage baseline does not run here**: use `gitleaks` + `trivy fs` + `grep`/`jsluice` and say so in the write-up rather than implying a SAST pass happened.
- `trufflehog` — its module tree has `replace` directives, so `go install` refuses it, and the release-tarball install path is blocked by the sandbox. `gitleaks` finds secrets; it does **not** verify them, so pair it with `keyhacks.md` by hand.
- `arjun` / `paramspider` / `x8` / `uro` — hidden-parameter discovery and URL decluttering. No `pip`, no `cargo`, and x8's prebuilt tarball is blocked. Substitute: `ffuf` against a param wordlist, `katana` + `qsreplace`, `unfurl keys | anew` for the declutter step.
- `jwt_tool` — needs `pycryptodomex`. Do JWT work by hand per `hunt-api-misconfig`.

Skills referencing anything in this list still describe the methodology; substitute the manual equivalent.

## Machine model

Pentest tooling (ProjectDiscovery/ffuf binaries, PayloadsAllTheThings) runs here — the operator's own work machine, no AV/EDR. `Orizon-eu/claude-code-pentest` (43 zero-dep Python scripts) is fine to run here; three other agent bundles were skipped as duplicates of the fork.

---

## Universal safety floor (applies always — this is ethics/legal, not hunting bias)

These are the only rules that carry across every engagement. They never bias what you'll find — they're guardrails:

- **Authorized targets only.** Test only what a program's scope authorizes. Out-of-scope = don't touch even if the domain matches.
- **Own accounts/data only** — never access other users'.
- **Minimal PoC.** If a check could affect other users or availability → STOP, get program approval first. No exploitation beyond proof without approval.
- **Don't hammer.** Respect each program's rate limits (the number lives in the project file). No DoS/MITM/social-eng/physical. No public disclosure pre-fix.

Everything else — scanner policy, curl-first, recon-log format, evidence hygiene, reward focus — is **per-project**, in `Targets/<name>/CLAUDE.md`. Pacing numbers and mandatory headers are **no longer prose anywhere** — see below.

---

## How to work — bias toward executing (this section is the counterweight)

The safety floor above is a set of brakes. Brakes alone produce a hunter that reads JavaScript bundles all day and never sends a request, because analysis is free and every request looks like a chance to break a rule. That failure has a signature in this workspace's own data — hunt-memory entries tagged `CODE-DERIVED, NOT EXECUTED`, threads closed as "good hygiene" with nothing fired at them. These rules exist to push the other way, and they carry the same weight as the floor.

**NEW TARGET WORKFLOW (auto-instruments historical data):**
1. **Fingerprint → `hunt-dispatch`** loads matching skills, checks CVEs for exact versions
2. **Pattern analytics** runs automatically: `python3 scripts/pattern-analytics.py --stack "<detected_stack>" --recommendations` tells you what techniques work on this stack
3. **Hunt → `/remember`** auto-classifies technique, writes to hunt memory, feeds next target's analytics
4. **Validate → `/validate`** 7-Question Gate before reporting

**EXISTING TARGET RESUMPTION:**
- `/pickup <target>` reads hunt-memory, shows tested endpoints + open threads
- Pattern analytics prioritizes by vulnerability density across your history

**CROSS-TARGET LEARNING (automatic):**
- Techniques from Kcell inform RTEAM hunting (same Next.js stack = shared patterns)
- Success rates update automatically as `/remember` writes confirmed findings
- `/memory-gc` cleans stale data, keeps signal high

**EXTRACTION DISCIPLINE:**
- **The brakes are in code now, so stop carrying them.** `engine/scope.py` blocks out-of-scope targets (deny-wins, default-deny, DNS-resolution gate for netblock programs) and `engine/pacing.py` sleeps for you before every request, per engagement, across processes. You cannot exceed a program's rate limit by trying, and you cannot touch an out-of-scope host by accident. **Hesitating "to be safe" buys nothing that the code isn't already buying** — it only costs findings.
- **An unfired request is not a result.** A conclusion read out of a JS bundle, a route table or a source file is a *hypothesis*: an **open thread**, never a closed one. Nothing is written down as "not a finding" or "good hygiene" until a real request came back and said so.
- **Confirmed and rejected findings both need a `.result.json`.** Use `/poc-run` (`engine/poc_runtime.py`), not a remembered curl output: it captures the real bytes, judges them in code, logs to `hunt-memory/audit.jsonl`. A report built on recollection is how N/A submissions happen.
- **Five-minute rule.** No progress on a vector after ~5 minutes of real attempts → switch vector. Switching is not closing the host: log the vector as tried in `hosts/<host>.md`, leave the host open.
- **When the choice is "analyze more" vs "send the request", send it** — if the target is in scope, the request is non-destructive, and it touches your own account or unauthenticated surface. The floor still governs anything that could affect other users, degrade a service, or go beyond minimal proof; that always needs explicit approval first.
- **Impact first.** Rank by what it would pay if true, not by what is easy to check.
- **There is no stop condition but the operator (2026-09-21, user directive — supersedes the
  2026-08-28 "a pass ends at a confirmed Medium+" rule).** A confirmed Medium-or-higher finding is
  **banked, not an exit**: write it to `Targets/<name>/findings/` with its `.result.json`, log it
  with `/remember --result confirmed`, mark the vector `confirmed` in the ledger, run `/chain` on
  it — and **carry straight on to the next vector**. Recon, new surface, a mapped flow, an open
  thread finish nothing either. Vector stalls → `vectors.py rotate`, then `revisit`, then `next`;
  mutations exhausted on a host → next in-scope host; every ledger closed → fresh `/recon` + `/cve`
  pass, not a summary. Report progress as fact along the way, never as a question — "should I go on
  to those next pass?" is the exact anti-pattern. The only exits: the operator stops the hunt, or a
  hard external block on *that vector* (needs someone else's data/identity, program approval, or an
  action only the operator can take — name it, log it under `blocked-tests/`, and route around it;
  a blocked vector is not a blocked session). **This raises how long you hunt, never how you rate
  what you found** — Low/Info stays Low/Info, "primitive confirmed, impact inferred" stays
  unsubmittable, and the safety floor is not a dial to turn to reach Medium.
  Enforced in code, not here: `engine/stop_gate.py` continuous mode, which is **the default in
  code** since 2026-10-15 (`CONTINUOUS_DEFAULT = True`) — it no longer depends on
  `hunt-memory/continuous.json` existing, so a fresh clone, a new engagement or a re-pointed
  `CBH_MEMORY_DIR` inherits it instead of silently falling back to the one-finding-and-stop gate.
  Switches, highest precedence first: `CBH_HUNT_CONTINUOUS=on|off` · `"continuous_hunt": true|false`
  in an engagement's `profile.json` · `python3 engine/stop_gate.py --continuous on|off|status`
  (writing the state file) · the default. Push cap: 500 per session, `"max_stop_blocks": -1` in
  `profile.json` removes it entirely.
- **A plain-language order arms the hunt — `scripts/hunt-arm.py` (2026-10-15, operator directive).**
  Everything above only runs while analysis mode is **armed**, and the only things that armed it
  were a slash command or a `hunt-*` skill. So "начни хантить ozon" — an unmistakable order —
  armed nothing: no skill gate, no nudge, and **no stop gate**, which is how a session that was
  told to hunt until Medium+ was free to stop after three requests. The `UserPromptSubmit` hook
  reads the operator's own words (ru + en): hunt intent (`хантить`, `охоть`, `ищи баги`,
  `start hunting`, `go deep`, `пентест`, …) arms it and injects the standing orders for the
  session; a stand-down (`стоп охота`, `хватит хантить`, `stop hunting`, `stand down`) disarms it.
  A question is not an order — a prompt that opens with `как/почему/что/why/how/what` never arms
  the gate, because arming it means the session cannot end until a Medium+ is proven or the ledger
  is exhausted. Opt out for one shell with `CBH_HUNT_ARM=off`; `engine/hunt_mode.py on|off` is
  still the manual control.
- **Caido comes up by itself before every hunt — `scripts/caido-up.sh` (2026-10-16, operator
  directive).** It does not survive a reboot, so sessions after a restart hunted with
  `ECONNREFUSED 127.0.0.1:8080` — no tool to prove a redirect chain, a cookie or a session state.
  Three idempotent callers start it (bash `/dev/tcp` probe first, so no second instance fights
  over one project directory): `scripts/hunt-arm.py` when a hunt arms, `scripts/session-brief.py`
  at `SessionStart` inside an engagement, `cbh tools doctor --start`. Runs `setsid nohup caido-cli
  --listen 127.0.0.1:8080 --no-open --no-sync`, so it outlives its session; log `logs/caido.log`.
  A failure is reported and never blocks the hunt — `bbcurl` is the request path. Overrides:
  `CBH_CAIDO_PORT`, `CBH_CAIDO_HOST`, `CBH_CAIDO_BIN`, `CBH_CAIDO_WAIT`,
  `CBH_CAIDO_AUTOSTART=off`; `--status` reports without starting anything.
- **A hunt is orchestrator + crew by default, never one agent alone (2026-10-16, operator
  directive).** `/parallel` is the shape of every armed hunt, not a command to reach for when
  things feel slow: **you orchestrate and stay out of the request path** — the plan, the merge,
  `notes.md`, the vector ledger and the `/remember` calls are yours — and the workers fire the
  requests. Default crew: **Scout** (surface/recon) · **Hunter** (the top-ranked vector with its
  `hunt-*` skill) · **Freeroam** (`cbh freeroam run`, `skills_on=False`, no methodology — its
  naive-only items are the leads the taxonomy would have missed). Fan out as soon as `/pickup`
  says where you are, before the first request. `"hunt_agents": N` in an engagement's
  `profile.json` overrides it. **Crew size is derived, not fixed — `cbh crew`** (`engine/crew.py`):
  the engagement's `1/min_interval_seconds` ceiling / a worker's measured 0.08 req/s, capped
  at 6, halved under 25% of whichever window the crew spends — 6 for a 30-rps programme, 1 on
  the 10s default. **At most 3 concurrent:** past three, compaction truncates an `Agent`
  mid-run and the merge reads half an answer. `hunt-arm` prints it on arming; beyond it rotate
  roles through the queue, not more agents. Pacing is global per engagement and `flock`'d, so
  the crew queues behind one budget — **never relax pacing to make a fan-out faster.**
  **The crew and the orchestrator run on this plan (2026-11-13).** Until then every worker
  ran on a second provider through a local router, which is why a worker could be a separate
  process at all. That provider is gone: a worker is now an in-process `Agent` subagent on
  this session's own connection, visible and openable in the UI, and the crew spends **this
  plan's** 5h/7d quota, which `cbh crew` sizes against. `scripts/agent-gate.py` denies the
  background-process spellings (`claude -p`, `cbh worker`) on Bash and prints the `Agent(...)`
  call instead; reads (`--status`/`--health`/`--show-log`) pass, and the gate reads the command
  position, so grepping the string is not a spawn. `cbh doctor` FAILs on a settings file that
  still routes `ANTHROPIC_BASE_URL` at the deleted router or pins a non-Claude subagent model.
  **Enforced in code since 2026-10-21 — `scripts/crew-gate.py` (PreToolUse, Bash + MCP).** Four armed
  hunts on 2026-10-20 ran with zero workers while this was prose. While armed in an engagement, the
  **main thread** is denied request-firing calls (`SENDER_RE`, Caido send/batch/race, Playwright
  navigate/click/type); the deny prints the `Agent(...)` call. Worker = `agent_id` in hook input
  (subagent) or `CBH_AGENT_ROLE=worker` (CLI). Merge work stays with the orchestrator. Audited
  escapes: `# crew-gate: override <reason>`, `CBH_CREW_GATE=off`. Worker model:
  `engine/agent.py::worker_model()` — `CBH_WORKER_MODEL` > `profile.json` `"worker_model"` >
  `claude-sonnet-5-5`.

### NO DEAD ENDS — the push half is in code too now (2026-08-14)

Prose loses to prose. The brakes were moved into `scope.py`/`pacing.py` and the pushes stayed as bullets, so "keep going, rotate, use the skills" kept losing to ten prohibitions. `engine/vectors.py` + the `hunt-nudge` hook fix that:

- **`python3 engine/vectors.py next <host>`** (also `cbh vectors next`) — impact-ranked list of what has *not* been attacked yet, each with the `hunt-*` skill that covers it and the concrete next move. **"I am stuck" is not a state you can be in: `next` always returns something.** Seed a host once with `vectors.py seed <host> --endpoints '<paths>'`.
- **`vectors.py rotate <class>`** — the mutation matrix. When a vector stalls, the answer is the next mutation, not a new host: method swap · `/v2`→`/v1` downgrade · auth strip · auth downgrade · content-type swap · param pollution · path normalization · `X-Original-URL`/`X-Forwarded-*` override · case+encoding · sibling routes in the same controller · mobile/partner surface. ~12 generic moves plus class-specific ones. **Burning all of them is what "дошёл до конца" means.**
- **`vectors.py revisit <host>`** — every past non-confirmed finding with a method never tried on it. A `rejected` result is one burned mutation, not a closed door. Go back through old findings with new methods before opening a new host.
- **A vector cannot be marked `dead` while requests_fired is 0 or mutations remain.** `vectors.py mark … dead` refuses and prints the next mutation. `--force` exists but demands a reason. This is the code version of "nothing gets closed as good hygiene without a fired request".
- **`scripts/hunt-nudge.py` is a `PostToolUse` Bash hook** (wired in `~/.claude/settings.json`, backup `settings.json.bak-2026-08-14`). It fires on its own, mid-hunt, and: flags bare `curl` inside an engagement (gate bypass — invisible to audit, cannot back a report), **names the `hunt-*` skill matching the URL you are probing** (only while analysis mode is armed — path-signal table: `/graphql`→`hunt-graphql`, `/payment|order|invoice`→`hunt-business-logic`, `/external|internal|worker`→`hunt-auth-bypass`, …), and when ≥12 requests go out with zero hunt-memory writes it prints the rotate/next/revisit sequence with the untried vectors filled in. Rate-limited to one nudge per 12 requests.
- **Session brief opens on the next untried vector**, not a blank page, and shouts `GRINDING:` if the last session ground without logging.
- **The matching `hunt-*` skill is MANDATORY during analysis, and only during analysis.** The gate is armed, not always-on (`engine/hunt_mode.py`): a hunt entry point — `/hunt`, `/autopilot`, `/recon`, `/pickup`, `/chain`, `/surface`, or any `hunt-*` skill — arms it for the rest of the session. Outside that, the session is idle: **answer the operator's question directly, plain prose, no skill required**, and a one-off request fired to check something they asked about goes out unblocked. `/validate`, `/triage`, `/report`, `/remember`, `/scope`, `/view`, `/intel` are neutral — reasoning about a finding never arms the gate. Manual control: `python3 engine/hunt_mode.py on|off|status --session <id>`, or `CBH_HUNT_MODE=on|off`. While armed, `scripts/skill-gate.py` **denies** a Bash command that fires a request (`bbcurl`/`curl`/`httpx`/`ffuf`/…) at a surface whose skill is not loaded in this session — `/graphql` needs `hunt-graphql`, `/payment|order|invoice` needs `hunt-business-logic`, and so on — the whole table is `engine/skill_signals.py`. The deny message prints the exact `Skill(skill="bughunter:hunt-X")` call — load it, re-send the same command. Scoped tight so it never blocks unrelated work: engagement folders only, real senders only, non-local URLs only; recon surfaces (`.js`, `.map`, `robots.txt`) are advisory and never blocked. Escape hatches, both audited: `CBH_SKILL_GATE=off`, or append `# skill-gate: override <reason>` to the command (logged to `audit.jsonl` with the skipped skill, so gate-dodging is countable). `scripts/skill-track.py` (PostToolUse on `Skill`) plus a transcript scan are what the gate reads to know a skill is loaded.
- **The last mile is where PoCs die — so it is now checked in code.** Identifying a bug and proving it are different jobs, and the second one fails quietly: a 302 to `/login` reads as "200 OK", a `Set-Cookie` that killed the session is invisible, "the POST returned 200" gets reports closed as N/A.
  - `engine/poc_runtime.py` captures the **full redirect chain, final URL, and every `Set-Cookie`** (repeated headers included), and **downgrades a PASS on a followed redirect to INCONCLUSIVE** unless the spec says where the response should land (`final_url_contains`, `no_redirect`, or `"follow_redirects": false` for the raw 3xx).
  - **Multi-step PoCs**: a spec may carry `steps` — login → exploit → *verify the state changed*. One cookie jar for the whole chain, `capture` lifts a CSRF token / id / reset link out of one response into `{{placeholders}}` in the next, every step judged against its own `expect`, and the chain **stops at the first failing step** (a capture that matches nothing is a failure, not an empty string). Every step's URL passes the scope gate before the first one fires. The `verify` step is the point: read the state back instead of trusting the 200.
  - **`cbh triage` answers Q1/Q6 from a fired PoC, not from the finding's wording.** `engine/evidence.py` looks for the `.result.json` artifact: PASS whose URL appears in the finding = DEMONSTRATED; PASS for some other endpoint = MISMATCH (catches evidence pasted from another bug); FAIL/INCONCLUSIVE = NOT-PROVEN; nothing = NO-EVIDENCE. Standalone: `cbh evidence <finding.md|dir>`. `--no-evidence` falls back to the old keyword check, for drafts only.
- **Every response body is kept — `bbcurl` writes a response corpus (2026-09-02).** The transport logged URL, status and timings and threw the body away, so three things were impossible at once: telling grinding apart from probing, proving anything later without re-firing, generating a PoC spec from a request that had already flown. Now each body is hashed and stored at `hunt-memory/responses/<engagement>/<sha256>.txt` (headers included, first 256 KB, one file per distinct body), and the audit row carries `body_sha256`, `body_bytes` and the **redacted** command line. What this buys, in order of how often it matters:
  - **`cbh diff <url-substring>`** — how many distinct answers that endpoint ever gave, and a unified diff of the last two. *N requests, one distinct body* is a rotate signal, not persistence.
  - **`cbh spec <url-substring> [--steps] [--out f.json]`** — rebuilds a `poc_runtime` spec from the request that already flew: method, headers, body, and an `expect` block taken from what the server actually returned. Credentials are redacted at capture time, so any auth header comes back as a placeholder you fill in deliberately.
  - **`scripts/hunt-nudge.py` now says "IDENTICAL RESPONSES"** when most of the last ten requests returned byte-identical bodies — the signal a request *count* cannot carry.
  - Bodies are other people's data by nature: `hunt-memory/responses/` is `.gitignore`d like `Targets/*/evidence/`, and it is a working cache, not an archive — prune with `cbh memory-gc --prune-responses <days> --rotate`. Opt out per request with `bbcurl --bb-no-store`, globally with `CBH_NO_RESPONSE_STORE=1`.
- **The class of a claim decides which oracle counts (2026-11-13).** `evidence.py` graded one question — was a spec fired and did it match its `expect` — and that question is class-blind: a reflected marker passed as an XSS, a `500` on a quote as an SQL injection, a `200` from a fetcher as an SSRF. `engine/class_proof.py` holds a class -> required-oracle table and reads the answer off the **artifacts**, never the prose: XSS wants a browser or proxy artifact (a `.png`/`.har`/Caido export, or a console record — the script that *produces* the proof, `*-proof.sh`/`.mjs`, is not the proof); SQLi a time delta between two arms of **one** PoC (>= 2000 ms and >= 3x apart — the run-level aggregate is not a second arm) or the driver's own error, not the app's 500; SSRF and XXE an OOB hit log (`scripts/oob-responder.py --log <dir>/oob.jsonl`), because the effect is a request the target makes and the response that triggered it cannot witness it; RCE command output or an OOB hit; LFI the file's own bytes; IDOR two identities in one spec (two credentials, or a credential and none); CSRF an `.html` document on another origin; open-redirect a hop whose host is not the host we asked. A missing oracle on an otherwise passing PoC is **CLASS-UNPROVEN** — exit code 1, ranked with WIRE-UNPROVEN in the operator queue, one artifact away from reportable. A class with no rule prints `not checked` rather than `ok`, because a silent pass and a checked pass must not look the same. The class comes from the finding's `**Class:**` line when it has one, else from its title and file name through the same vocabulary that ranks the lead queue (`lead_queue.CLASS_WORDS`) — never from its body, so a write-up that argues about redirects cannot classify itself. Measured on the 16 live findings the day it landed: **zero** false downgrades, and the one XSS that the first draft would have downgraded was caught by making the artifact scan recursive — its screenshot sits in `evidence/`, one level below the finding. The engine's own candidate path (`check_blob`) is exempt: it grades a blob of url + param + a hunter's one-line note against a shared `evidence/` directory, with no per-finding folder to read an oracle out of.
- **A brief must not announce spent requests as a budget, and a tier's README is not work (2026-11-13).** Composing the gates and replaying every decision over the corpus on disk (`scripts/decision_replay.py`) surfaced two defects that had nothing to do with the new gate and everything to do with what a worker is told. First: `autohunt.wave` read `stop_gate.budget()["requests"]` — the count of requests **already fired this hunt** — and printed it as the requests *left*, so on 8 of 12 engagements the brief opened with `0 request(s) left, 0 per lane` after a single fired request, and a worker reading its own brief has been told to do nothing. The number left is `max_requests - fired`, and when `profile.json` carries no `max_requests` there is no per-lane number at all: the brief now says so and points at `AGENTS.md` for the pacing rule instead of printing a zero. Second: a tier's own `README.md` — the instructions for using `leads/` — was scanned as an item in it, ranked at `DEFAULT_REWARD` like any lead, and on rowi took 2 of 21 open slots and one of three lanes, so a deep-hunter was briefed to attack `primitives/README.md`.
- **One definition of a funnel item, or the count and the queue disagree (2026-11-13).** `leads/` holds two layouts at once: a flat `<slug>.md` and a folder per item with its write-up beside its evidence. `lead_queue.scan` globbed `*.md`, so **no folder-form item ever entered the queue the lanes are picked from** — 10 of yukki-lk's 22 primitives, invisible; `stop_gate._tier_item_files` looked for `<slug>/README.md`, which is 4 of the 9 folder-form items on disk, the rest naming their write-up `report.md`, `finding.md`, `primitive.md`. `engine/funnel.py` is now the one rule and both read it: flat `<slug>.md`, then `README.md`, then `<folder-name>.md`, then the single `.md` in the folder; a folder with several unnamed markdowns is **not** an item (`leads/refuted/` holds two closed write-ups) and is skipped rather than guessed at, because guessing briefs a worker to attack an archive. The item's name comes from the same place: `Path(f).stem` is the literal word `README` for a folder-form item, and that word was feeding the class guesser, the skill picker and the brief's own title, so three yukki-lk primitives ranked and were briefed as `README`. Replayed over the corpus: the queue gained 9 items (timewebcloud 75 -> 79, wildberries 205 -> 207, yukki-lk 34 -> 37), no evidence status moved and no `allow_stop` flipped. `cbh view`'s own `_collect_*` listings still glob `*.md` only, so a folder-form item is absent from that display — a display, not a decision, and not yet fixed.
- **Burp is REQUIRED, not suggested, for wire-level claims.** `cbh triage` / `/validate` return **WIRE-UNPROVEN** when a finding mentions a redirect, a session, or a cookie and the only evidence is a single request with no chain and no `Set-Cookie` recorded. Two ways to clear it, both real evidence: re-fire as a multi-step `steps` spec through `poc_runtime`, capture the exchange in Burp and save request+response beside the finding as `<finding>.burp.txt` (`.burp.json` / `.har` count too), or **cite the response-corpus `sha256` of a capture that has the header block** — the finding must quote the hash itself, because matching a stored capture to a finding by URL alone would hand today's report yesterday's evidence. This is where Burp is worth starting — not during recon, where `bbcurl` is strictly better because it carries scope, pacing and audit.
- **A hunt does not end because momentum ran out — the stop is gated (2026-09-10; continuous mode 2026-09-21).** Everything else here gates the *start* of an action; nothing gated the end, and that is exactly where a session quits with untried vectors sitting in its own ledger. `scripts/hunt-stop-gate.py` runs as a **Stop hook**: in analysis mode, inside an engagement, it **refuses the agent's own decision to stop** until this hunt has produced a finding of **severity ≥ medium with a PASSing PoC behind it** (`engine/stop_gate.py`, severity parsed from `Severity:`/`Критичность:`/CVSS, evidence from `engine/evidence.py`). The refusal names what to do next: the unproven finding closest to done, the untried vectors from that host's own ledger with their next mutation, and the rotation ladder. Findings from earlier sessions do not pay for today — the bar is scoped to when the mode armed (`hunt_mode.armed_since`).
  - **The bar is never met by inflating severity.** A Low written up as Medium clears the gate and burns the validity ratio the gate exists to protect. The block message says so every time.
  - **The honest exit is always open:** prove exhaustion — every vector class marked dead with requests actually fired (`vectors.py mark … dead` refuses otherwise), rejected attempts logged with `/remember --result rejected`.
  - **Continuous mode changes which doors are open, never the bar.** With it on (the default here since 2026-09-21), both the *finding* and the *exhaustion* door are closed: a proven Medium+ is banked and the sweep continues, an exhausted ledger routes to the next host. The refusal text switches accordingly — it opens with what was banked and what to do with it, so a real finding never reads as a failure. A budget explicitly written into `profile.json` (`max_requests` / `max_minutes` / `no_new_information_window`) still ends a hunt, because that number is the operator's own instruction set in advance; none of the current engagements set one.
  - **Bounded:** six pushes per session by default, 500 in continuous mode (`max_stop_blocks` in `profile.json` overrides both), then it stands down with a note. The operator's own stop is never blocked — this only refuses the agent quitting on itself.
- **Subscriber identity is masked on every write path (2026-09-11).** `redact()` only ever matched
  credential-shaped *headers*, so on a telecom program the actual PII walked straight past it:
  `?iin=<national id>&contact_phone=<number>` in a URL, the same pair in a JSON body, an `msisdn:`
  header, and — worst — the **response** to the Aitu link minter, which repeats both *inside the URL
  it returns*: four places on disk, plus git. Now `engine/responses.py`
  exports **`scrub_text()`** (keys: `iin` `msisdn` `phone*` `contact_*` `passport` `imsi` `icc*`
  `login` `email` `birth*`; the key survives, the value becomes `<redacted>`), and it is wired into
  the three writers so they cannot drift: `redact()` (URLs, `-d/--data/--form` bodies, PII headers),
  `responses.save()` (the stored body — **the digest is still taken over the original bytes**, so
  dedup and `cbh diff` keep working, and a scrubbed file says so in its first line), and
  `memory._append()` (every `journal`/`patterns`/`audit` row, including free-text notes — that is how
  an IIN got into `journal.jsonl` with `redact()` already in place). `hunt-memory/audit.jsonl` and
  `Targets/*/findings/*.result.json` are now `.gitignore`d and untracked; the `.poc.json` **spec**
  stays versioned and must never carry a real identity (synthetic `777000xxxx` + a locally generated
  IIN). Regression tests: `test_subscriber_identity_never_reaches_disk`,
  `test_identity_inside_a_returned_url_is_masked_too`,
  `test_stored_body_is_scrubbed_but_hash_still_identifies_the_original`.
  **Still open, needs the operator:** commit `b0d5155` holds the pre-scrub `audit.jsonl` with 2
  identity-shaped values. No remote exists, so it never left the machine; removing it rewrites
  history and is the operator's call.
- **A body that changed is not an answer that changed — `cbh diff <url> --fields` (2026-09-09).** The whole-body hash answers "did anything move?"; it cannot answer the question that decides a finding: "did the part that *decides* move?" Measured in the tier-3 eval: an agent called a constant boolean an ownership oracle after storing 18 captures in which `match` was `false` every time — every body differed, because they echoed the varying phone/id back, so no hash-level check could have caught it. `--fields` groups the corpus by path and prints, per field, whether it ever changed across captures. When a **decisive** field (`match`, `valid`, `exists`, `found`, `allowed`, `success`, `status`, `is*`, `has*`, `can*`) is constant across ≥6 captures with ≥2 distinct request URLs, `hunt-nudge` fires **ANSWER NEVER MOVED**, once per surface and only while you are still on it. A field that does not react to input is a stub: the finding is the absence of a check, not a disclosure.
- **The enforcement layer has regression tests now — `python3 -m unittest discover -s BugHunter/tests`.** Both bugs this workspace shipped in that layer (a gate that demanded the wrong skill, a runner that reported a 302 as a 200) were found on a live target instead of on a bench. The suite covers the response corpus, credential redaction, the wire-evidence rule and the URL→skill table. Run it after touching `engine/` or `scripts/*-gate.py`.
- **Hooks no longer read heredoc bodies as command lines.** Writing a fixture, a patch or a note that merely *mentions* `bbcurl` and a URL used to trip both the PreToolUse gate (which denied the patch) and the nudge. `skill_signals.strip_heredocs()` cuts heredoc bodies out before anything is matched; a real request next to a heredoc still gates normally.
- **Caido is the proxy for the last mile, not for recon (2026-10-14).** `~/security-research/tools/caido/bin/caido-cli --listen 127.0.0.1:8080 --no-open --no-sync` runs it headless; the MCP server is `runtime/caido-mcp.mjs` (declared as `caido` in `.mcp.json`), and `node runtime/health.mjs --only=caido` says whether it is up. Reach for it when the question is **what actually happened on the wire**: redirect chains, cookie/session state across a flow, replaying and mutating a captured request. Not a scanner. It bypasses `bbcurl`, so `scripts/mcp-gate.py` scope-checks, paces and audits it — every request inside a `caido_batch_send` included; bulk tools (`caido_batch_send`, `caido_race_window_send`, Automate `start`) need `"allow_bulk_tools": true` in the engagement profile, and `caido_forward_intercept` / active `caido_run_workflow` / `caido_edit_request` without a `host` are refused as UNVERIFIED. One Caido project per engagement. Land the final proof in a `poc_runtime` spec so there is a `.result.json` behind the report. Setup, provenance and the one remaining operator step (the dashboard.caido.io login): **`docs/caido.md`**.
- **Burp is gone from this box** (`burpmcp` = `ECONNREFUSED 127.0.0.1:8181`); the gate still covers its tool names. Do not plan a hunt around it — use Caido above.
- **Try to kill a finding before the gate does — `cbh refute <finding>` / `/refute` (2026-10-14).** Every other gate here rewards a yes, and the model that wrote the finding answers them; the only measured fix for that is a pass rewarded for *disproving* (rez0 + xssdoctor: 80% -> 60% false positives). `engine/refute.py` fires the controls whose PASS means the finding is wrong — credentials stripped (**MIS-FRAMED**), the attack value swapped for your own and judged against the **original** `expect` (**KILLED** — the answer does not react to input), the exploit step deleted from a `steps` chain (**KILLED**), plus the free one: the corpus saying the decisive field never moved. The value controls need `"refute": {"attack": "...", "control": "..."}` in the spec, because guessing which token is the payload is how a confident wrong answer gets made; without it they say SKIPPED and print the line to add. Controls fly through `poc_runtime` (scope, pacing, mandatory headers, audit) and land in `refutations/<finding>/`, which `evidence.py` **excludes** from the evidence pool. A KILLED/MIS-FRAMED verdict makes `cbh evidence` return **REFUTED**, outranking the exploit's own PASS.
- **The funnel is directories now, not sections in `notes.md` (2026-10-14).** `Targets/<name>/leads/` (unproven hypothesis) and `primitives/` (capability confirmed by a fired request, impact NOT demonstrated) sit below `findings/`. `stop_gate.py` reads only `findings/`, so a lead can never satisfy the severity bar — and its refusal message now names the leads nobody has fired at and the primitives worth chaining. `cbh triage <finding> --demote` is the knock-back: it moves the file (and its artifacts) down a tier with the reason appended instead of leaving an unproven claim in `findings/` or deleting the observation. `cbh view` shows all three tiers; `notes.md` is the one-line index.
- **The naive second agent — `cbh freeroam` (2026-10-14).** Every `/parallel` role is a skilled role, so N of them share one blind spot, and the `hunt-*` taxonomy is survivorship bias: a class has a skill because it already paid, which is why the program has a known-issues entry for it. `freeroam` gets the URL and the authorization and **nothing else** — no methodology, no class names, no payloads — enforced by `skills_on=False`, not promised in a prompt. `cbh freeroam merge <skilled> <naive>` keys items by **surface** (paraphrase cannot be matched mechanically) and the `naive-only` list is the output: each is a lead, and whatever survives a fired request belongs in a `hunt-*` skill.
- **Layout is resolved, not hard-coded — `engine/paths.py` (2026-10-14).** The workspace moved off `/opt/Claude` and eleven scripts kept the old layout written into them (`/opt/Claude/Targets`, or `parents[2] / "Targets"`, which meant the same). **Nothing crashed** — they resolved under a root that does not exist, reported an empty workspace and exited clean, which is why a scheduled run was a no-op that logged success. `targets_root()` / `memory_dir()` / `template_dir()` resolve the three possible layouts in order, `$CBH_TARGETS_ROOT` and `$CBH_MEMORY_DIR` override, and `tests/test_paths.py` fails the build on a new hard-coded `/opt/Claude` in any script. Run `python3 engine/paths.py` to see what resolved.
- **The CVE cron is installed and proven (2026-10-14).** Two entries, both `scripts/cve-boot-catchup.sh` — `@reboot` and `0 7 * * *` — idempotent through the stamps in `logs/stamps/` (20h window), so the boot run and the daily run no-op each other. It waits for DNS (5 min cap: WSL networking is not up when `@reboot` fires), refreshes `docs/cve-coverage.md` from CISA KEV, **discovers** every engagement carrying `recon/cve-watchlist.txt` (nested `platform/program/` included) and writes the snapshot to `Targets/CVE-DIGEST.md`. Verified firing. Backups: `logs/crontab.bak-20261014`, `scripts/cve-boot-catchup.sh.bak-20261014`. Nothing scheduled sends a request at a live program; `install-recon-snapshot.sh` stays uninstalled until an engagement has a recon manifest to diff.
- **Log rejections** — `result=rejected` in `/remember` resets the grind counter and feeds pattern analytics, so the next session does not repeat a dead move.
- **Browser work is the agent's job, always (2026-09-23, user directive).** The Playwright MCP (`mcp__playwright__*`, headless Chromium, scoped/paced by `scripts/mcp-gate.py`) handles ANY page opening, form filling, clicking, rendered-content reading, OAuth/SPA/multi-step UI flow. **Sessions survive between runs (2026-10-14):** inside an engagement the browser gets a persistent per-engagement profile at `Targets/<name>/browser-profile/`, so a login is spent once, not once per session. Its flags are fixed at launch and it inherits the session's cwd, so **the engagement must be resolvable at launch**: start Claude Code inside `Targets/<name>/` or set `CBH_PROJECT`. `cbh tools doctor` prints which mode is live (`SESSION playwright persistent for <name>` vs `isolated`). Per-program opt-out: `"browser_session_reuse": false` in `profile.json`; force the old behaviour with `CBH_PLAYWRIGHT_ISOLATED=1`. The profile holds live session cookies — credential material, git-ignored like `identity.json`. **Never tell the operator to open a browser, look at a page, or "Copy as cURL" — do it yourself.** The request layer stays curl-first (`bbcurl`): Playwright is for UI work, not a `bbcurl` replacement.
- **One browser per engagement, and the lock says so out loud (2026-11-11).** Chromium serialises a `--user-data-dir` behind its own SingletonLock: a second Playwright MCP server on the same `Targets/<name>/browser-profile/` does not queue, it waits for the first browser to exit, which is the length of the first lane. From inside the lane that is invisible — no error, no output, a tool call that never returns. Measured 2026-11-11 on `mail_vk`: six browser lanes at once, **19 of 38 subagents killed after 20–53 minutes, every one of them a browser lane**, while every `bbcurl`-only lane finished; the orchestrator read the queueing as hanging and closed seven leads `--as blocked`, which took the most valuable class on a webmail target out of the queue (`0 workable · 21 blocked`). `runtime/browser-lock.mjs` now makes the contention explicit: the first server takes `.cbh-browser.lock` inside the profile (pid, lane label, start time), a second waits `CBH_BROWSER_LOCK_WAIT_SECONDS` (default 25 s) and then exits naming the holder and the three ways forward — fire the lane with `bbcurl`, restart with `CBH_PLAYWRIGHT_ISOLATED=1` for an in-memory profile that takes no lock and may run concurrently, or hand the lane back. A lock whose pid is gone is broken immediately, so a killed lane never strands the profile; `CBH_BROWSER_LOCK=off` disables the whole thing. **Crew consequence: at most one browser lane at a time per engagement**, the rest fire `bbcurl`. Tests: `tests/test_browser_lock.py`.
- **A browser failure arrives with its remedy attached (2026-11-11).** Measured 2026-11-11
  `01a1c94a-58ac-7ca1-ae17-e37c6cc38f9b`: four `browser_navigate` calls returned
  `net::ERR_TOO_MANY_RETRIES` in 182–2658 ms — fast refusals, not slow hosts — with a
  `caido_intercept_control {"action":"pause"}` in the middle, which guaranteed the rest would fail
  because the browser is Caido-proxied and a PAUSED queue holds every request it carries; the one
  recovery move left, `browser_navigate about:blank`, was then refused by our own gate with "no
  engagement resolved". Three defects, all fixed in code: (1) `engine/request_broker.py` read
  `about:blank` as REMOTE (`"://" not in url` re-parsed it as `//about:blank`, hostname `about`)
  while `view-source:https://target/` passed as local — `NON_NETWORK_SCHEMES` + `unwrap_url()` now
  classify on what actually leaves the browser, and `scripts/mcp-gate.py` lets control URLs through
  ungated while gating `view-source:` on its inner URL; (2) nothing told the model what the error
  meant, so it re-fired — `engine/browser_hints.py` holds the remedy table (ERR_TOO_MANY_RETRIES,
  proxy/tunnel, `ERR_CERT_`, `ERR_NAME_NOT_RESOLVED`, timeout-on-a-throttled-identity,
  blocked-by-client, profile held, gate denial = final), delivered to Claude as a `PostToolUse`
  hook (`scripts/mcp-hint.py`, exit 2) and, for a client that gates inline, as a second text
  block on the tool result; (3) a client whose per-tool timeout defaults to **6000 s** makes one
  wedged navigation look like a hang — such a client's config must pin
  `tool_timeout_sec` to 180 (playwright) / 300 (caido) with per-tool overrides, each above the 25 s
  profile-lock wait and above the gate's `BULK_WAIT_CAP_SECONDS = 120`. `cbh browser doctor`
  prints the live lane state (engagement, Caido route, profile holder, Chrome, display);
  `engine/browser_state.py` is the one reader of `.cbh-browser.lock` that the gate and the doctor
  share. Tests: `tests/test_browser_lane.py` (20), `tests/test_mcp_gate.py` (44).
- **`blocked` and `stalled` are different verdicts (2026-11-11).** `cbh leads close <file> --as proven|refuted|exhausted|blocked|stalled`. `blocked` means the target or the programme blocks the lane (an account nobody holds, a phone OTP the operator cannot receive, an action the programme forbids): the lead leaves the queue and waits for the operator. `stalled` means **our own** tooling did not finish the lane (browser profile busy, worker killed, MCP server gone): the lead stays workable and its row is printed `RETRY`, because nothing was learned about the target. Writing a tooling failure as `blocked` is what emptied the mail_vk queue, so `cbh leads reopen <file> --note "why"` exists to undo it — it writes a `STALLED` banner on top and demotes the old one to `Previous status: …`, which no status regex matches, so the row genuinely returns to the queue with its history intact. Tests: `tests/test_lead_queue.py::StalledVerdict`.
- **Crew roles are definitions, not briefs (2026-11-11).** Session a0053cc0 (wildberries, six days) spawned 138 subagents, every one of them `general-purpose`, each with a hand-written brief whose median length was 7351 characters. Those briefs carried the mechanics reliably — `bbcurl` in 137 of 138, `CBH_PROJECT` in 137, `scope.md` in 136, `poc_runtime` in 131 — and the judgement unreliably: the word `victim` appeared in 15 of 138 and `forbidden` in 15 of 138. A hand-written brief carries whatever the orchestrator remembered that minute, so the two rules that must never be dropped were the two most often dropped. They now live in the role definition: `agents/roles/{deep-hunter,scout,refuter}.md` is the single source, and `python3 agents/gen_role_agents.py` renders each one into `.claude/agents/` (Claude Code `subagent_type`). Per-client difference is two placeholders — `{{SKILL}}` (`Skill(hunt-<class>)` against `skills/hunt-<class>/SKILL.md`) and a one-paragraph client note about who may send requests; `{{SAFETY}}` (the forbidden-action list) and `{{VICTIM}}` (a finding needs a named party and what they lose) are shared text, asserted byte-identical between clients so a rule cannot drift to one client only. `--check` fails the test suite on a hand-edited copy. `scripts/agent-gate.py::ROLE_BY_TYPE` maps the three `subagent_type` names onto the role keys (`hunter`, `scout`, `review`), and a test asserts the mapping lands on a key that is known, because an unknown role silently degrades a worker to `general`. Tests: `tests/test_role_agents.py`.
- **The operator queue ranks by the item's own severity (2026-11-11).** The same wildberries session wrote the three most valuable files it produced into `blocked-tests/` as `OPERATOR-DECISION-*.md` — an unauthenticated Critical RCE with all three preconditions measured and nothing sent, the 1 000 000 ₽ financial-gain scenario reduced to one decisive request, and one POST that would mint an ESIA state — and none of them was visible to the operator. Three causes, all fixed in `engine/operator_queue.py`: section 2 ranked by the ENGAGEMENT's maximum payout, so 195 rows tied at the programme ceiling and sorted alphabetically by filename; an `OPERATOR-DECISION-*` file carried no extra weight over any other blocked test; and closures were read case-sensitively from the first six lines, so a header saying "Unblocked 2026-11-11 …" and a worker's `## Status — **CLOSED**` appended at the END of the file both stayed in the queue. Decisions are now section 0, ranked by the severity the file claims for itself, `brief_line()` NAMES the top one instead of counting it, closure detection goes through `lead_queue`'s five banner forms, and `cbh queue resolve <file> --as approved|refused|asked-programme --note "why"` writes the verdict into the file so it leaves the queue. Reading an item's own severity needed two fixes: headings count as a claim (`# … an unauthenticated Critical RCE …`), body prose does not ("critical path", "Low-consequence as far as I can tell"), and `stop_gate.CVSS_VERSION_RE` now drops only a KNOWN spec version (2.0/3.0/3.1/4.0) — the old `v?(\d\.\d)` read the score in "CVSS 9.5" as the version, left no score, and rendered a measured Critical as `unrated`. Tests: `tests/test_severity_and_queue.py`.
- **A finding names its victim, or it is held (2026-11-11).** The same session's funnel is the argument: 134 primitives against 1 finding on wildberries, 363 primitives against 28 findings across the workspace, and the word `victim` in 15 of 138 worker briefs. `engine/evidence.py::has_victim` looks for a LABELLED line only — `**Victim:**`, `Who is harmed:`, `Жертва:` — because prose about "an attacker" is exactly what the tier confusion is made of. It is deliberately NOT a verdict: `evidence.py` grades whether a fired request proved the claim, and a proven Critical stays DEMONSTRATED with `report["victim"] = False`, since downgrading proof over a missing heading would teach the next session to distrust the gate. The hold is in `cbh triage`: a 7/7 pass with no victim line returns 3 as `PASS-PENDING-VICTIM` and prints the remedy (one line naming a party that is not the operator and what they lose, or `--demote`), the same shape as PASS-PENDING-REFUTE — a hunter can clear it unattended, so it blocks nothing an unattended hunt cannot finish. `CBH_VICTIM_GATE=off` lifts it. The rule is also in `Targets/_TEMPLATE/primitives/README.md` (a `## Victim if weaponized` section in the primitive template), `Targets/_TEMPLATE/CLAUDE.md`'s funnel line, `engine/engine.py::_roe()` and the shared `{{VICTIM}}` block of the role agents, so a worker meets it before it writes rather than after. Tests: `tests/test_crit_high_tooling.py::TriageRequiresVictim`.
- **Paid precedent arrives unasked (`cbh precedent`, 2026-11-11).** `docs/disclosed-reports/` holds 171 records (165 after dedupe by `source_url`) distilled to `first_signal` — what the hunter noticed before they knew it was a bug — plus `mechanic`, `impact_proof`, `chain` and `lesson`, and `cbh corpus-gap` reports a skill for 99.2% of their classes. The corpus was never the gap: in session a0053cc0's transcript `cbh report-intel` is NAMED in 103 worker briefs and invoked 0 times. The reason is friction — `report_intel.py` takes a dataset PATH and a free-text QUERY, so a worker must pick one of two corpus files and invent search terms before it learns anything. `engine/precedent.py` removes both: it merges every `docs/disclosed-reports/*/corpus.json` (provenance kept per corpus, cached per root) and derives the query from the file the worker already holds. `cbh precedent --lead <file>`, `--class <class>`, `--signals <captured body>` (which disclosed OPENING a response resembles, needs >=2 shared terms), `--describe` (provenance). Query building is `count x log(N/df)` over the corpus, not count-then-alphabet: ranking by count alone put a count-1 alphabetical tail into the query ("all answers api app bbcurl certificate chain…") and retrieved on it, a term in more than 40% of reports cannot discriminate, and a term the corpus has never seen cannot retrieve at all. Title terms count triple, and this workspace's own vocabulary (`bbcurl`, `cbh_project`, `poc_runtime`, `scope`, `audit`…) is in `STOP`. `report_intel.search()` now also returns `source_url`, `classes` and `chain`, without which a caller printed a precedent nobody could open. `cbh leads` prints one precedent line per NEXT row through `lead_queue._precedent`, which swallows every exception: a broken corpus costs the hint, never the lane (measured 0.26 s for a 207-lead queue). It is retrieval only — it sends nothing, refuses nothing, and a precedent authorises nothing `scope.md` does not. Also in the shared `{{PRECEDENT}}` block of the role agents and in the hunt ORDERS. Tests: `tests/test_precedent.py`.
- **A technique the corpus knows and no skill checks (`landed_in`, 2026-11-13).** `docs/disclosed-reports/corpus-2026-11-13/` had held 155 research URLs since the day it was built; a measurement on 2026-11-13 found 8 of 10 techniques from the operator's digest with no check in any skill — `filename*`, the RSC Flight framing, the cached-OAuth-302 chain and the CSS token-limit stitching had zero occurrences under `skills/`. `corpus_gap`'s first three questions could not see it: they read the whole toolkit, so a keyword that lives anywhere scores, and both arms of a before/after run returned 100% technique coverage. A record may now carry `landed_in: <file>`, and question 4 reads ONLY that file: the ten records of that corpus pass here and all ten FAIL against a checkout without the checks (measured both arms). A record naming no file is counted as `unlanded`, not failed — 161 of the 171 records predate the field, and one mark cannot cover both "the check was deleted" and "this record never named one". `cbh corpus-gap` with no `--corpus` now measures EVERY corpus, one block each: the default used to be the newest by name, which the new 10-record file silently became. Tests: `tests/test_corpus_gap.py`.
- **Accounts: self-service first, ask the operator only as a last resort (2026-09-23, user directive, revised same day).** Order of work on an authenticated surface: (1) read `Targets/<name>/identity.json` if it exists; (2) self-provision a throwaway identity with `cbh identity new <url>` (temp email via mail.tm; temp phone when `profile.json` configures an `sms_provider`) and self-register **via Playwright**; (3) if registration is blocked (CAPTCHA wall, government-ID gate like IIN/ЭЦП, provider down, program forbids it), log it under `Targets/<name>/blocked-tests/` and keep hunting the unauthenticated surface. **Only when those are exhausted — or the flow needs something only the operator can supply (real phone number, existing real account, government ID) — ask the operator ONCE, stating exactly what data is needed and what was already tried.** Per-program opt-out: `"self_registration": false` in `profile.json`.
  **In continuous mode that last step is closed (2026-10-15, operator directive): do not ask at all** — the mode is the operator saying "do not come back to me", and an agent that stops to ask for a phone number has ended the hunt. A registration that cannot be completed blocks **one vector**: write it under `blocked-tests/` with the reason and rotate — another temp-mail/SMS provider, another registration route (mobile app, partner, social login), the unauthenticated surface, another host. `cbh identity new` prints exactly that instead of the ask when continuous mode is on, and `engine/engine.py::_roe()` injects an `UNATTENDED RUN` clause into every subagent for the same reason.

- **The arsenal is a graph now, and the wave is decided from state (`cbh skill-graph`, `cbh autohunt`, 2026-11-12).** 68 skills were each addressed one at a time: `engine/skill_signals.py` maps a URL to ONE skill so a hook can gate a request, `engine/skill_map.py` maps a class to a skill and a first curl. Both are flat lookups, so nothing knew that `hunt-lfi` ends in `hunt-rce`, that `hunt-saml`/`hunt-oauth`/`hunt-session`/`hunt-mfa-bypass` all feed `hunt-ato`, or that in the 120-report corpus `auth-bypass` + `info-leak` co-occur five times at Critical for $25,300 while `auth-bypass` alone is usually a Medium — so a lane proved one primitive, wrote it to `primitives/`, and stopped. `engine/skill_graph.py` builds the graph from two independent sources kept separate on purpose: DOCTRINE edges parsed from each `SKILL.md` frontmatter (`TRIGGER — … SKIP — <skill> for/once <condition>`, which all 68 descriptions carry), split into `owns` (lateral: that skill owns the surface, working it here is spent budget) and `escalate` (vertical: prove this and the chain continues there, severity goes up); and CORPUS edges mined from `docs/disclosed-reports/corpus-2026-11/corpus.json` — class pairs with their report count, top severity, payout and report ids, plus whole reports as chain templates with their ordered steps. Four parse defects were real wrong answers before they were tests: stripping non-digits from a bounty field turned "$7,000 Cloudflare, $7,000 GitLab, $12,000 T-Mobile; 74 bounties / $221k on the Akamai case; over $350k total" into $700,070,001,200,074,229,850 and that one research write-up topped every ranking (now: largest single `$amount`, aggregates flagged and kept out of pair totals, pairs ranked by report count then severity then money); a bare "once … confirmed" scored as an escalation, so `hunt-ldap` → `hunt-sqli` ("once the backend is confirmed relational") and `hunt-auth-bypass` → `hunt-saml` read as chains and `hunt-saml` ranked as a hub with three feeders (now: eight explicit chain markers only — `being chained`, `chained into`, `log the chain`, `chain there`, `escalat*`, `the next step is`, `the work is proving|escalating`, `do the … there`, `leads directly to`); `hunt-ato`'s inverted clause ("use this skill when combining 2+ of those") needed its arrows reversed or the one skill whose whole job is chaining had no inbound edges; and edges existed twice wherever both ends named each other, reporting eight feeders into `hunt-ato` where there are four. `cbh skill-graph --ladder "<url or lead title>"` orders the skills for a surface — the hand-tuned URL-signal table first, then TRIGGER-term overlap for a prose lead with no URL — after two fixes: the term `/api` (from `hunt-mfa-bypass`'s "recovery codes leak via /api/me") outranked `hunt-idor` on `/api/v2/user/orders/4821`, and this workspace's own tier words collided with skill triggers, so `Primitive — selfreg.acme.com/api route space confirmed live` scored `hunt-rce` top (its trigger reads "a confirmed primitive (deserialization, LFI, SSTI, …)") and that lane was briefed with two Marshal-gadget chains for a route-space census. `cbh autohunt` is the driver: one call reads `lead_queue.scan`, `stop_gate.assess`, `chain_graph.brief_line` and this graph, and emits one brief per client slot carrying the item, the skills to load (GATED-marked), the skills to defer to, where a proof escalates, the disclosed chains of that class with their steps and payout, the corpus partner class that made it Critical, the precedent line, the lane's slice of the remaining request budget and the close command that matches what the role actually writes. Roles mix within one wave — a finding claimed without a PASSing PoC takes a `refuter` lane while the rest hunt, because giving the whole wave to the top-priority role sent one refuter out with five idle slots over 53 workable items — and `spread()` keeps any two lanes off the same host and off the same missing capability, since both collisions return copies of one refusal. It sends nothing and rates no severity: every brief names `CBH_PROJECT=<eng> bbcurl` as the transport, and under Claude Code the output is explicitly briefs to dispatch. `cbh skill-graph --lint` fails the suite when a new skill ships without a SKIP clause (it would have no edges), when `skill_map` names an uninstalled skill, or when the corpus grows a class no skill covers — which is also how the ten corpus classes that were unmapped until now (`missing_authorization` alone appears in 17 reports) were found. Tests: `tests/test_skill_graph.py` (30).

---

## 2026-11-12 — the first live `cbh autohunt` wave, and the four things it got wrong

The wave built for `standoff365/ozon` (3 slots, 53 open items) was read line by line
against the engagement's own files. It routed correctly — one refuter lane on the single
finding claimed without a PoC, two deep-hunter lanes, roles mixed as designed — and then
four claims in it turned out not to survive being checked.

**A lane was dispatched at a wall the same screen printed.** Lane 2 was
`primitives/selfreg-api-mux-routes-ozonid-gated.md`, whose `needs` is
`live-ozonid-session-sr-crm`, three lines under a header that listed "a valid staff
Ozon-ID session (employee principal)" as waiting on the operator. `lead_queue` had not
split it off because `_account_need` reads ROLE words out of the slug (`buyer`, `staff`,
`admin`, …) and defaults to `user` when it finds none — and this engagement holds a user
account. Nine of the 53 open items were in that state. `autohunt.operator_wall()` now
matches an item's needs against the engagement's own account groups on *distinctive*
tokens only (`ozonid` is inside "a valid staff Ozon-ID session"; the shared word
`session` is not enough, so `antibot-jar-for-the-sigma-static-fence`, which our own
browser lane can get, is not walled). A matched item is **demoted, never dropped** — the
unauthenticated arms of a gated route space are still work, and handing over an account
is the operator's decision — and its brief carries a `WALL` block saying to fire only the
session-free arms and to close `--as stalled`, not `--as blocked`, because nothing about
the target blocked it.

**The chains were drawn from the skill, not from the mechanic.** The same lane was briefed
with `h1-47` (".env left in an application bundle", $50,000) and `h1-48` ("certificate in
a git repo", $39,999) for a primitive whose finding is "every route is authz-gated". Two
causes compounded: the lookup keyed on the loaded skill, and `chains_for(<skill>)` expands
to *every* class that maps to that skill — `hunt-source-leak` reaches `secret-exposure`,
so the widest class won. Underneath it, `_corpus_class` accepted any class `CLASS_SKILL`
knew, and `data-exposure` is in `CLASS_SKILL` and in **0 of the 120 reports** while
`info-leak` is in 24. Two vocabularies had met and neither was wrong: `lead_queue` labels
items with its own `CLASS_WORDS`, the corpus uses the disclosed-report class names. So
`skill_map.CLASS_TO_CORPUS` now holds the aliases (9 of them, every target asserted to be
a class the corpus actually has), `_corpus_class` requires a corpus-known class before a
skill-map-known one, and chains are selected by class with the skill only as a fallback —
a fallback that now labels itself in the rendered brief ("matched on the LOADED SKILL, not
on this item's class"), and a lane with no chain at all is told so by name instead of
being handed scenery. An off-mechanic chain is worse than no chain: it reads as evidence.

**Truncation ate the clause that carried the signal.** `…carrying the Next-Action header,
wh` and `…a 12-character hex token in the earli` — hard slices, mid-word, with no mark
that anything was missing. There are now no raw `[:N]` slices on display text: one
`lead_queue.cut()` cuts on a word boundary and appends ` …`, used for the queue's stored
titles (which were being halved at 110 before `autohunt` ever saw them), the brief title,
each chain step, the account prose and the precedent line (widened 170 → 230).

**The browser lane could not show the operator anything.** `cbh browser doctor` reported
`display :0 -> headless`, and it was right for the wrong reason: the browser runs in the
MCP server's process, which takes its environment from `.mcp.json`, and the doctor was
answering from the shell it happened to be run in. `.mcp.json` now sets
`CBH_PLAYWRIGHT_HEADED=1` for the playwright server, the doctor reads that file as the
authority and says that headless is bound at server start so a running server is still
headless until restart. The operator asked for one thing — "show me the page and I will
log in" — so `cbh browser login <program> --url <page>` opens a headed window on the
engagement's own profile dir, scope-checks the URL **in the command** (this lane drives
Chrome over CDP, so `scripts/mcp-gate.py` never sees the navigation: no pacing, no audit
rows, default deny or no window), and waits for the session cookie.
`scripts/operator-login.mjs` gained the two things that made it unusable next to the
hunting lane: it takes the same `runtime/browser-lock.mjs` profile lock, so it cannot sit
invisibly inside Chromium's `SingletonLock` for the length of an MCP lane, and it launches
the same installed Chrome the MCP wrapper uses, so the profile it writes is read back by
the browser that reuses it.

Caido was verified live in the same pass: v0.58.3, intercept `RUNNING`, listening on
127.0.0.1:8080, current project `standoff365-konsol`.

**The ladder loaded one skill, and it was the wrong one.** The same wave's third lane,
`leads/msg-o3-ru-mattermost-webhooks-in-public-bundle.md` — "7 Mattermost incoming-webhook
URLs hardcoded in a public prod bundle" — loaded `hunt-ssrf` and nothing else. It scored
**1**, on the single word `webhook`, which `hunt-ssrf`'s TRIGGER lists as an SSRF entry
point; `hunt-source-leak`, whose whole subject is a secret read out of a client-reachable
artifact, scored **0**, because its trigger enumerated artifact FILENAMES (`.js.map`,
`/swagger.json`, `.env`) and never the thing being hunted. Two fixes, and they are one
decision:

* `hunt-source-leak`'s trigger now carries that vocabulary — a `hardcoded` API key,
  access token, `credential`, connection string or `webhook` URL read out of a public JS
  `bundle`, chunk or config. Editing the trigger fixes the hook table too, not only the
  graph, and the skill was re-synced to both clients.
* Term matching moved from substring-with-a-7-character-floor to **word boundary with a
  4-character floor**. The floor existed to stop `dom` matching inside `subdomain` and
  `/api` matching inside `/api/v2/user/orders/4821` — it bought that safety by discarding
  the most diagnostic words in the whole table (`fetch`, `.env`, `token`, `bundle`,
  `cache`, `upload`), so a skill with a short vocabulary scored 0 and lost a tie to one
  incidental hit. `_term_hits()` matches a bare word on a boundary and a term containing
  `/` or `.` as a substring, because `.js.map` has to hit inside a URL.

The lower floor then made four-character generic words into terms: `public` scored
`hunt-rce` on "a public prod bundle", `server` and `user` scored `hunt-lfi` on "makes the
server fetch a user-supplied URL". Those are in `STOP_TERMS` now. The control that
matters is the other direction: "a webhook parameter makes the server fetch a
user-supplied URL" still resolves to `hunt-ssrf` (2 terms) over `hunt-source-leak` (1),
and the measured lead resolves to `hunt-source-leak` (3 terms) over `hunt-ssrf` (1). A
shared word must not hand one skill's surface to the other, in either direction.

**The second wave found the next placeholder behaving like evidence.** With the ladder
fixed, lane 2 — `leads/finance-mf-ssr-render-route-url.md`, 262 server-side render
endpoints taking a client-supplied `route-url` — loaded `hunt-misc` first, and lost its
corpus chains with it, because the chain lookup keys on the primary rung. `lead_queue`
labels an item `other` when no CLASS_WORDS rule matched (33 of ozon's 53 open items),
`brief_for` appended that label to the blob the ladder scores, and `other` is the literal
word in `hunt-misc`'s TRIGGER: "a finding doesn't cleanly fit any other hunt-* class".
The 1-1 tie that followed was decided by report_count, and the catch-all carries the
highest in the bundle (225) — so once it scored at all it won. The placeholder is now
dropped before scoring (a real label still reaches it — asserted), and
`CATCH_ALL_SKILLS` (`hunt-misc`, `hunt-dispatch`, `bb-methodology`, `bug-bounty`, each
asserted to have a trigger that describes routing or the absence of a class rather than a
surface) ranks after every skill that matched on its own vocabulary. Still eligible, never
first while anything else matched: a lane with nothing else is better off with the
catch-all than with nothing.

Tests: tests/test_skill_graph.py (59, +29), tests/test_browser_lane.py (27, +7). Suite 1005.

---

## Logging discipline — executable steps always go in per-client context

Any step actually **run against a client target** — a request sent, a PoC triggered, a browser-automation action taken, an exploit attempted (successful or not) — gets logged into that project's own files (`hosts/<host>.md` scan-log row, `notes.md` open threads, `findings/` draft) as it happens, not just relayed in chat. Chat isn't durable across sessions; the per-project files are the source of truth for "what did we actually do" and "where did we leave off." This applies globally, on top of whatever per-project recon-log format is defined in `Targets/<name>/CLAUDE.md`.

Corollary: when a write-up or repro-steps list mixes things actually executed with things only predicted/analyzed from code, **verify with the user which is which before logging anything as fact** — especially for any step that could be destructive/irreversible (see safety floor above).

---

## 2026-11-12 — a record can declare its own class (`**Class:**`), and that outranks its title

`lead_queue` had no explicit class input at all: `_class_of()` matched the `CLASS_WORDS`
regexes against the filename and the title and returned `other` when nothing hit, which is
what 33 of ozon's 53 open items got. A guess from the title is all most records have, but it
cannot see what a fired control already closed. The measured case is
`leads/finance-mf-ssr-render-route-url.md`, whose title is "262 server-side micro-frontend
render endpoints taking a client-supplied `route-url`" — so every reader, the ladder
included, calls it SSRF, and that file's own STATUS banner closes the SSRF hypothesis with
three `_mf/render/MFFileViewer` controls that returned byte-identical bodies (sha256
`b836b69806052c22`, 3691 B): `route-url` never reaches the component's `url` prop, the fetch
is client-side through `window.__foundation_files_api__.open()`, and the chain partner
`files.finance.acme.com` does not exist (five negatives). What is still open there is authz —
`_mf/context` answers anonymously on 5 of 5 services and 11 `MFJointAccount*` components each
have to decide "is this caller a member of this account" — so the honest class is
`missing_authorization` (17 corpus reports), and a lane that loads `hunt-ssrf` first spends
its budget re-killing a dead hypothesis.

`**Class:** <name>` on its own line is now read by `lead_queue.declared_class()` and wins over
the guess. An unknown name is **ignored, not adopted**: `known_classes()` is the union of
`CLASS_WORDS`' own outputs, `skill_map.CLASS_SKILL` and `CLASS_TO_CORPUS`' targets, because a
typo'd class that silently became the class would route the item nowhere while looking
declared. The scanned row carries `class_declared: true` so the consumer can tell a
declaration from a guess, and `autohunt.brief_for()` puts that class's `CLASS_SKILL` entries at
the head of the ladder with `via: "class-declared"` — a guessed class never gets this, since it
was derived from the same filename and title the ladder already read and is therefore not a
second source. The title's reading is **demoted, not dropped** (`hunt-ssrf` stays on the load
line in third place), and the brief prints a `class` block telling the lane the leading skill
came from the declaration and to read the record's banner before working the class its title
suggests.

Both live ozon records were then declared: `missing_authorization` on the finance `_mf` lead and
`secret-exposure` on `msg-o3-ru-mattermost-webhooks-in-public-bundle` (the 26-character webhook
path token *is* the credential, shipped in a publicly cached 688 003-byte bundle; the blocked
half, reaching `msg.o3.ru`, is a network restriction and not a different class). Both briefs now
report `chains_via=class` with on-mechanic chains — `h1-30`/`h1-35` and `h1-47`/`h1-48` — instead
of the "matched on the LOADED SKILL, not on this item's class — the item has none" caveat.
Tests: `tests/test_lead_queue.py` (21, +6), `tests/test_skill_graph.py` (64, +5), each with a
positive control that the undeclared record still guesses `ssrf` and loads `hunt-ssrf` first.
Suite 1016.

---

## 2026-11-12 — a verdict written as a heading, and trigger glue routing a lane

Two defects the second live `cbh autohunt` wave printed, both fixed at the root.

**A record adjudicated in a heading counted as open work.** Lane 3 of the wave was
`leads/pci-finance-nativebridge-postmessage-relay.md`, whose first line is `# LEAD —
ADJUDICATED 2026-10-16 (wave17 / HUNTER-36). Both hypotheses in this file are DEAD.` and
whose body says the tier moved to `primitives/pci-finance-crossorigin-postmessage-control.md`.
The banner reader handles five spellings of `**Status:** X` — all of which contain the word
"status" — and a worker closing a record at the top writes a heading instead:
`## CLOSED 2026-10-16 (wave 10, HUNTER-3) — hypothesis 3 REFUTED by 31 fired requests` on
`sigma-iap-nginx-oidc-codexch`, `## KILLED — 2026-10-16, wave 14, HUNTER-20` on the two
parked primitives. `_heading_verdict()` now reads those, and `adjudicated` joined
`CLOSURE_WORDS`.

The guard against closing a row on an ordinary section heading is a **date**, not position
and not the word. Position fails: the two parked primitives adjudicate at lines 59 and 36,
while `## Blocked` at line 119 of `ozonid-auth-request-jwt-hs256` and `## Not a finding,
explicitly` at line 66 of `fa-gateway-route-existence-oracle` are sections of records whose
banner says STALLED, i.e. workable — a first cut that accepted any closure word followed by
whitespace closed both of those plus `## Proven capability, as fired` and `## Dead ends
worth recording`, and an earlier one accepted `## Closed-loop verification of the oracle`.
Every adjudication in this workspace carries its date, so the verdict word must be followed
by a 4-digit year through at most one bracket or dash; an undated `## REFUTED: …` leaves the
row open and the mark has to go in the banner, where `cbh leads close` writes it. Emphasis is
stripped from anywhere in the heading (`## **REFUTED**: 2026-10-16` puts `**` between the word
and its date) and leading `>`/`#` are stripped, so a blockquoted banner reads the same. Net on
standoff365/ozon: 53 open → 49, and the four that moved are exactly the four dated
adjudications, with the two section-heading records still in the queue.

**Trigger glue, not vocabulary, picked the skills for lane 2.**
`finance-verify-person-update-token-postmessage-wildcard` — an auth token posted to
`window.parent` with target origin `*` — loaded `hunt-firebase, hunt-http-smuggling,
hunt-supabase, hunt-rce`. Measured cause: `target` appears in **27 of the 68** TRIGGERs
("target fingerprints as Laravel", "target exposes `/saml`"), `auth` in 6 as a fragment of
`/auth/v1` and "auth flow", and `apps` in `hunt-firebase`'s only because `firebase.apps`
splits on the dot — so the title's `/apps/auth/` path segments and the word `target` gave
`hunt-firebase` 3 points and `hunt-supabase` 2, while `hunt-dom` and `hunt-cors` scored 1
each on `origin`. Those words plus the rest of the prose glue (`covers`, which opens the
second sentence of every stack skill's description, `fingerprints`, `behind`, `exposes`,
`reachable`, `live`, …) are in `STOP_TERMS`. Terms with a high spread that ARE vocabulary
stay: `header` (9), `session` (5), `cookie` (5), `injection` (5), `redirect_uri` (4), `oauth`
(3), `login` (3), and `next` (3), which is how `hunt-nextjs` matches `_next/`. Controls:
Firebase, Supabase, Next.js and Laravel fingerprints still rank their own skill first (8, 5,
4, 7 points).

No corpus class and no `CLASS_SKILL` entry covered a postMessage bug, so that lead had no
routable class either: `postmessage` now maps to `["hunt-dom", "hunt-cors"]` — doctrine splits
the surface, `hunt-dom` owning the channel and `hunt-cors` owning credentials crossing the
origin boundary — and aliases onto the corpus's `cors` through `CLASS_TO_CORPUS`. The lead
declares it. One fix to the declaration mechanic fell out of this: a declared class's skills
are **promoted, not prepended**, because `hunt-cors` and `hunt-dom` were both already on the
ladder at 1 point each and the skip-if-present rule left `hunt-source-leak` (which scored on
`bundle`) leading the lane anyway. `DEFAULT_WEIGHTS` also gained `missing_authorization` and
`secret-exposure` at 300 000 and `postmessage` at 200 000 — all three were falling to the
50 000 default, which is a ranking change: both declared leads now take the wave's two
deep-hunter lanes, with `h1-30`/`h1-35` and `h1-47`/`h1-48` as their chains.

Tests: `tests/test_lead_queue.py` (27, +6), `tests/test_skill_graph.py` (69, +5). Suite 1027.

---

## 2026-11-12 — three defects in the third wave: a lost precedent, an egress wall, a finding named by its filename

**A precedent row printed its own source note where the signal goes.** Lane 2 read
`[unknown/90000.0] missing_authorization — FIRST SIGNAL: https://simonkoeck blog (site and
title only; slug lost to compaction)`. Two causes, both in `engine/precedent.py`: 21 of the
155 reports predate the corpus rebuild and carry no `first_signal` (`wu-09`'s is `None`), so
the line ran straight into the `source_url` that followed it; and `report_intel.search`
normalises `bounty` to a float, so `$90,000` printed as `90000.0`. `_opening()` now falls
back to the row's `mechanic`, then to its chain's first step, each under its own label so a
lane is never told a mechanic is a first signal — `wu-09` reads `MECHANIC: An internal admin
API was reachable with a normal account`, which is usable precedent. A row with none of the
three is dropped and the next hit takes the slot. `_money()` formats the float. `_source()`
prints a link only when it is one: a source containing whitespace is unfetchable, so it is
labelled `(unresolved source: …)` instead of sitting there looking clickable.

**A lane was given 509 requests to re-measure a `403`.** Lane 3 was
`msg-o3-ru-mattermost-webhooks-in-public-bundle`, whose `needs` is `POST /hooks/{token} from
an egress that clears the .o3.ru edge challenge`. That record's own body says the `403`
«Доступ ограничен» 4 705 B was confirmed twice, from both lanes this workspace has — bbcurl
and headed Chrome carrying valid antibot cookies — with no antibot challenge in the
response, i.e. an edge network/IP restriction. `operator_wall()` only matches account needs,
so an egress read as workable. `network_wall()` is the second wall, kept separate because
the remedy is different: an account is the operator's to hand over, a network position is
nobody's here. It matches a short phrase list (`egress`, `allowlisted network`, `ip
allowlist`, `corporate/office/internal network`, `vpn`, `residential proxy`, `another asn`,
`from inside the perimeter`, …) and it catches 1 of the 49 open items, not a band of them.
The ranking is three stable bands — firable, account-walled, egress-walled — and the brief
says nothing in this workspace supplies it, to fire only the arms that work from this
egress, to re-measure the refusal once to date it, and to close `--as blocked`, because it
is the target's edge that refuses us.

**A refuter lane was keyed on a filename.** `title url minifier s.acme.com` was the file
stem: `_title_of_file` skips this template's placeholder headings (`[ЧЕРНОВИК …]`, the
literal `Title`, `Program / scope`) and `## Title` is a section LABEL whose BODY is the
claim, so the claim went out with the label. `TITLE_SECTION_RE` reads the first non-empty
line under that label, with the same 25-character floor and a reject for a line still
holding a `<placeholder>`; the lane now says "Анонимное неаутентифицированное создание
персистентных коротких ссылок на домене сокращателя s.acme.com (POST
…/url-minifier/create)".

That fix regressed the same lane, which is why the wave was re-read: a real claim line scores
stray trigger terms where a file stem scored none, so `POST …/document-manager/…` scored
`hunt-csrf` on `post` and `hunt-llm-ai` on `document`, those two led the lane, and
`chains_for(primary)` attached an auxclickjacking chain (`rs-19`) and a CSPT chain (`rs-20`)
to a Low open-redirect claim. A refuter's own tooling now leads whatever the prose scores —
`triage-validation`, `poc-runtime`, then at most two scored skills behind them — and the
skill-matched chain fallback is off for that role: a refuter fires the three arms whose PASS
means the claim is wrong, and it follows the claim in front of it, not a corpus mechanic.

Tests: `tests/test_precedent.py` (+5), `tests/test_skill_graph.py` (74, +7). Suite 1039.

---

## Chat-compression plugins — caveman ON (ultracave), ponytail NOT installed (verified 2026-10-20)

- **caveman is enabled** (`caveman@caveman`, local directory marketplace `~/.claude/local-plugins/caveman-src`, default mode `ultracave` via `~/.config/caveman/config.json`) — operator directive 2026-10-12, which supersedes the 2026-09-15 decision to deregister it. **It compresses chat replies only:** `notes.md`, `findings/*.md`, `hosts/*.md`, reports and memory files stay in full prose, because they are read back by `cbh view`, `/pickup` and `session-brief`.
- **ponytail is not installed** (not in `enabledPlugins`, no marketplace entry). If reinstalled, keep it off during hunts.
