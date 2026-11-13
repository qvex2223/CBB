# How crit/high web bugs are actually found: lessons wired into the toolkit (2026-11-02)

**Corpus:** 51 disclosed HackerOne reports, 36 public write-ups from 2025–2026 and about 30
research pieces from 2024–2026 (PortSwigger, Orange Tsai, Assetnote/Searchlight, Doyensec,
zhero, watchTowr, …). Raw notes are in `corpus-2026-11/`. Every claim there cites its source.
Where a figure was not re-verified, the note says so.

**Our own baseline at the time:** 14,688 audited requests, 1,247 journal rows, 773 rejected,
30 confirmed at Medium or above, 7 confirmed High, 5 submitted.
- Most rejected Highs were one-shot CVE checks on edge appliances (Check Point, Exchange,
  SNMP, DNS).
- Every confirmed High came from business flows on one target: a single-factor repayment
  login, unauthenticated SIP provisioning, and an SSRF that reached Vault.
- Those match the corpus's dominant patterns exactly.

## The finding, in one line

Crit/high hunters did not use better payloads than a checklist agent. They:
1. composed two or three individually-Low primitives;
2. read response **bodies**, including refusals, rather than status codes;
3. set up multiple identities and tenants before the first payload;
4. built an oracle where none was visible;
5. read the defender's artefacts: patches, advisories, other people's reports and their own
   rejected ones;
6. ran the control that could prove the finding wrong.

## Ten lessons, and where each one now lives

| # | Lesson (evidence) | Wired into |
|---|---|---|
| 1 | **Crit = composition.** Self-XSS + unkeyed cache → stored for all (Discourse). XSS + Auth0 defaults → ATO (elttam). Open redirect / DCR + OAuth → ATO (Salesforce, Uber). | `vectors.py` `CONSUMERS` and `consumers` subcommand. `mark … confirmed` prints the consumers. New rows in `/chain`. `bb-methodology` doctrine. |
| 2 | **Body, not status.** 302 carrying the admin page (ShareFile, Red Bull: EAR). 422 that serialized the private report (H1 #29). `"valid": false` beside the token. | `responses.wire_signals()`. `bbcurl` records `signals` on the audit row. `hunt-nudge` prints `SIGNAL BODY-ON-REDIRECT` / `DATA-IN-DENIAL`. |
| 3 | **Same operation, second interface.** REST vs GraphQL (GitHub), Server Actions (Next.js $15k), ActivityPub (NodeBB), mobile/partner. The most frequent root cause in the write-ups. | New vector class `sibling-interface`, seeded from manifest `function-authorization`. `hunt-differential` section. |
| 4 | **Server-side fetchers and renderers → cloud credentials.** PDF, screenshot, import, webhook test, sitemap. The payout line is whether credentials were *read* ($25k vs $2.5k for the same class). | `ssrf` mutations: redirect-loop observability, IPv4-mapped IPv6, legacy metadata, renderers. `hunt-ssrf` section. |
| 5 | **Two parsers, one string.** CDN vs origin, proxy vs app, validator vs shell/MTA. Produced every Critical in the research set. | New vector class `parser-differential`, detection-only probes. `hunt-differential` section. |
| 6 | **Build the oracle before calling a vector blind.** Boolean error, length, count, response order, redirect loop, timing pairs. | Oracle ladder appended to `sqli`/`ssti`/`rce`/`xxe`/`deserialization`. `mark dead` refuses until it is tried. |
| 7 | **Patch / advisory / prior-report bypass.** The highest-yield behaviour in the H1 set: GitLab $33.5k, PayPal fix-bypass $20k, Shopify $15k. Zero requests to find. | `bb-methodology` doctrine; `hunt-dispatch` signal row. |
| 8 | **Secrets: validate, then map scope.** The two top payouts ($50k, $40k) needed no exploitation: discovery plus careful validation, proven by a hash, not contents. | New vector class `secret-exposure`. `SIGNAL SECRET-IN-BODY` (prefix only). `hunt-source-leak` section. |
| 9 | **Client-supplied fields and filter operators.** `resId` + phone in the OTP request, array-for-string, `template:true`, `email__password=~`, OData `$filter`, Prisma `[not]`. | New vector class `filter-injection`. `business-logic` mutations. `hunt-api-misconfig` section. |
| 10 | **Severity follows data at risk.** A proven auth bypass paid $34. A hackbot with 88 High/Crit topped out at $15k, with ~80% false positives until a validator pass cut it to ~60%. | `cbh refute` on **every** finding (`bb-methodology`). The severity rule is unchanged. |

Also changed: setup-heavy vectors (multi-account, time-delayed sync, race windows) are exempt
from the five-minute rule (`bb-methodology` doctrine, item 7; `CLAUDE.md` was left untouched because it sits 3 bytes under its 60 KB budget). Three Criticals in the corpus needed 2–30 minutes of
waiting.

## What was deliberately NOT changed

- `engine/skill_signals.py` (the deny gate). New signals are advisory only, so no new
  request gets blocked.
- Severity rules, the stop gate, scope, pacing.
- Existing mutation order: entries were appended, so old ledgers' `mutations_tried` still match.
- Requests to targets: none were fired for this work. Everything comes from public pages.

## Refreshing this

Re-run the three research briefs (HackerOne disclosed, recent write-ups, research techniques)
into `corpus-YYYY-MM/`. For each new report ask: *would our tool have found it?* Is there a
skill? Is the technique in it? Would `hunt-dispatch` route there? Each "no" becomes a mutation,
a signal row or a consumer entry.

## Second pass (2026-11-02): tooling that makes the lessons run without the operator

| Tool | What it does | How it reaches the hunt |
|---|---|---|
| `engine/doctrine.py` · `cbh doctrine` | The 8-point crit/high doctrine | Appended to every skilled worker's launch text (`engine.py::_hunt_agent`, every role brief). Never sent to freeroam. `hunt-arm` order 8 tells the orchestrator to paste it into every `Agent` brief. |
| `cbh triage` refute gate | A 7/7 finding without `<finding>.refute.json` (or with only SKIPPED value controls) returns `PASS-PENDING-REFUTE`, exit 3 | One autonomous step clears it: `cbh refute`. `--no-refute` exists for drafts only. |
| `scripts/mcp-signals.py` | The same wire signals for Caido responses | PostToolUse hook on `mcp__caido__.*` (13th hook; `cbh doctor` checks it) |
| `engine/surface_census.py` · `cbh census [--seed]` | Offline: sibling interfaces (cross-kind first), server-side fetchers, secret leads (prefix only) | `--seed` writes them into the vector ledger. Runs at `/pickup` and per `hunt-arm` orders. |
| `engine/differential_probe.py` · `cbh diffprobe <url>` | Detection-only parser-differential census: 14 paced GETs through `scripts/bbcurl`, baseline + impossible-path control, LEAD only where a variant diverges from both, a random marker echo, or a changed layer | The first mutation of the `parser-differential` class. Counted as a sender by `crew-gate`, so workers fire it. |
| `cve-digest.py` `lane:` | Each CVE row marked `patch-diff` (read the fix, test the other spot and the bypass) or `edge one-shot` (one probe, move on) | `/cve` documents both lanes |
| `scripts/oob-responder.py` | Self-hosted redirect-loop responder plus outbound User-Agent log | Needs a public host (operator decision). Tested locally. |
| `engine/corpus_gap.py` · `cbh corpus-gap` | "Would the toolkit have found this report?" over `corpus.json` | Measured on 120 records. Same rule for both copies. |
| `scripts/corpus-refresh.py` | Weekly: one research worker (web-read tools only) adds new disclosed crit/high reports, then writes GAP.md | Called from `cve-boot-catchup.sh`, self-stamped every 7 days |
| `cbh report-intel docs/disclosed-reports "<observation>"` | Retrieval over every corpus, with mechanic and proof | Doctrine item 7 |

**Measured coverage (`cbh corpus-gap`, 120 reports, token-overlap rule identical for both copies):**
before this work **80.8%** of reports had their technique where the agent is routed (18
misrouted). After both passes: **99.2%** (1 misrouted). The 13 gaps that remained after the
first pass were closed with generalisable techniques: argument injection via `--`,
import/export round-trip, cookie sandwich, normalization after validation, email atom
splitting, HTTP/2 CONNECT, desync detection, DOMPurify mXSS, protocol-level SQL smuggling,
namespace squatting and consent-scope mismatch. Coverage means the technique is present in
what the agent reads. It does not mean the agent will find the bug. The live field test is
the other half.

## Live field test (2026-11-02, standoff365/yukki-lk, 37 gated GETs) and what it fixed

One worker exercised the new tools on a real programme. No new target lead (`new.ykky.ru` was
still behind the ServicePipe wall). It found seven tool defects, all fixed, each with a
regression test in `tests/test_crit_high_tooling.py::FieldTestRegressions`:
1. `bbcurl` dropped `http_code` whenever the caller passed its own `-w`, which silenced
   body-on-redirect and data-in-denial (33 of 37 rows). It now always captures `-D` and reads the
   status from the last header block.
2. `vectors.py mark` with a rejected `--mutation` label: exit 1 was already correct, but the
   message now says NOTHING WAS RECORDED.
3. `census --seed` never seeded sibling interfaces, because manifest URLs are relative. The host
   now comes from the operation's `host`.
4. `census --seed` duplicated a worked vector (`GET /x` vs `/x`). It now dedupes on class plus
   endpoint without the method.
5. A webhook receiver route counted as a fetcher. Route-only matches are now limited to
   fetch/render names.
6. `diffprobe` promoted a marker echo even when the impossible-path control echoed it too
   (Express `Cannot GET <path>`). Echo is ignored when the control echoes.
7. `skill-gate` treated quoted prose as a sender (`cbh remember --notes '... bbcurl ...'`).
   Quoted strings are now ignored unless the line executes them (`bash -c`, `eval`, `xargs`, …).

Also fixed: the new classes earned +0 payout bonus (programmes never list them), so
sibling-interface ranked 68th. `PAYOUT_ALIAS` maps them to the category they pay as, and they
now rank 1st and 2nd on new.ykky.ru.

**First autonomous weekly refresh** (`corpus-2026-11-02`): 41 new records, 78.0% coverage on
arrival. The worker declared that a 1-day window was empty and used the newest verifiable
material (the window is now ≥14 days). After closing the web-relevant gaps: **92.7%**. The
remaining gaps are two browser 0-day chains, which are outside web scope.
