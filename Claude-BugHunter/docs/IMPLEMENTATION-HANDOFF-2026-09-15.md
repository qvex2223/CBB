# Claude-BugHunter implementation handoff — 2026-09-15

## Purpose

This file records the review, implementation work completed in the current session,
validation results, known limitations, and the remaining work. It is intended to let a
future session resume without reconstructing decisions from chat history.

The working tree already contained extensive uncommitted user work before this session.
No reset, checkout, cleanup, commit, history rewrite, target request, or live-program test
was performed.

## External research that drove the design

Sources reviewed:

- Detectify, “How to hack APIs in 2026”:
  <https://labs.detectify.com/how-to/how-to-hack-apis-in-2026/>
- Current and recent `/r/bugbounty` discussions and comments from approximately
  July–September 2026, especially threads about Claude Code agents, automation,
  Burp MCP, duplicate findings, access-control testing, and over-complex PoCs.
- SecurityTalent article URL supplied by the user. The page returned an internal error,
  so its associated repository was reviewed instead:
  <https://github.com/SecurityTalent/bugskill-ai>

Main conclusions:

1. The highest-return agent capability is systematic comparison across users, roles,
   tenants, objects, methods, and API versions.
2. Generic recon and full default scanner sweeps produce crowded, duplicate-heavy output.
3. Agents perform well at endpoint mapping and response comparison, but need explicit
   state, identity, ownership, and verification models for authorization and business logic.
4. Reusable report intelligence is valuable when retrieved on demand. Loading hundreds of
   large skills into every context is wasteful.
5. A technically valid finding can still fail triage when the reproduction is long or does
   not show a final state change. Reports need a minimal human path plus raw evidence.

## Baseline discovered before implementation

- Actual inventory: **62 skills and 17 slash commands**.
- Several documents still claim 54 skills / 14 commands; the workspace CLAUDE file claims
  62 skills / 16 commands.
- The web-only edition still contains `commands/token-scan.md`, a Web3/EVM/Solana command.
- The old `/recon` command duplicates the deterministic recon engine, uses bare `curl`,
  runs broad Nuclei sweeps, and references tools that are not installed:
  `assetfinder`, `gf`, `trufflehog`, `subzy`, and SecretFinder.
- Documentation contains both Burp MCP port 9876 and the current runtime port 8181.
- Six skills exceed the 500-line guideline:
  `bb-local-toolkit`, `bb-methodology`, `bug-bounty`, `report-writing`,
  `security-arsenal`, and `web2-recon`.
- The repository was already heavily modified and contained many untracked files.

## Completed in this session

### 1. Agent success-path failure fixed

File: `engine/agent.py`

- Removed the undefined `err` variable from the successful subprocess return path.
- Non-zero subprocess exits now derive a bounded error from stderr or the exit code.
- Added a regression test that mocks a successful Claude subprocess response.

Previous behavior: a successful model response raised `NameError`, was caught as a parse
failure, and looked like an agent error.

### 2. Headless agents use the guarded request path

Files: `engine/agent.py`, `engine/engine.py`

- Removed `Bash(curl:*)` from the allowed agent tools.
- Added `Bash(bbcurl:*)`.
- Changed the hunt prompt from `curl-FIRST` to `BBCURL-FIRST`.
- Engine hunt and validation workers explicitly run with skills disabled.
- `run_agent()` accepts a project name and exports it as `CBH_PROJECT`, allowing `bbcurl`
  to locate `Targets/<project>/scope.md` and `profile.json` when the engine starts from the
  repository directory.

### 3. Shared request-policy broker added

File: `engine/request_broker.py`

The new broker centralizes:

- scope validation and default deny;
- netblock/DNS verification;
- `--resolve`/pin validation support;
- required engagement headers;
- global pacing;
- response-corpus storage;
- append-only audit records;
- explicit flags for ungated local work and authorized write probes.

Integrated consumers:

- `scripts/bbcurl`
- `engine/poc_runtime.py`
- `engine/recon.py`
- engine-created headless agents through `bbcurl`
- the target-probing part of `cbh recon`

Passive certificate-transparency lookup remains separate because it calls the recon data
source rather than the target. Direct Burp/Playwright MCP mutations are not yet forced
through this broker; see remaining work.

### 4. Recon pacing and write safety improved

Files: `engine/pacing.py`, `engine/recon.py`, `engine/engine.py`, `cbh/cli.py`

- Added parsed profile properties `max_concurrency`, `allow_bulk_tools`, and
  `allow_write_probes`.
- Katana is disabled inside an engagement unless `allow_bulk_tools: true` is explicitly set.
- If enabled, Katana derives concurrency/rate from the engagement profile rather than using
  hard-coded `-c 10 -rl 100`.
- Engine HTTP fetches use the common request broker.
- `cbh recon` target probes use the broker and profile concurrency when run inside an
  engagement.
- OpenAPI unauthenticated sweep no longer treats HTTP 422 as proof of auth bypass.
- POST/PUT/PATCH/DELETE OpenAPI probes are skipped unless the run or profile explicitly
  authorizes write probes.
- OpenAPI classification now considers schema fields and does not classify every write
  operation as SQL injection merely because it accepts a body.

Known limitation: the recon fetch wrapper currently records the true status when the normal
HTTP response path returns it. Error-body capture in the urllib fallback should receive an
additional focused test before relying on it for evidence.

### 5. Memory schema and analytics corrected

Files: `engine/memory.py`, `scripts/pattern-analytics.py`, `cbh/cli.py`

- Pattern rows now retain `result`, `locally_confirmed`, and `triage_outcome`.
- Added lifecycle outcomes: `submitted`, `accepted`, `paid`, `na`, and `downgraded` while
  retaining the existing values.
- Added normalized vulnerability-class and bounded technique identifiers.
- Legacy pattern rows with no result are interpreted as locally confirmed because the old
  file was success-only by construction.
- Target priority no longer rises simply because free-form technique strings are diverse.
- Accepted/paid outcomes receive separate weight.
- `save_profile()` still needs to use identity-value scrubbing in addition to credential-key
  redaction; this remains open.

No migration was applied to the real `hunt-memory/*.jsonl` files. New writes use the new
schema, while analytics handles old rows compatibly. A reversible migration with backups is
still recommended.

### 6. Skill routing corrected

File: `engine/skill_signals.py`

- Fixed the OAuth regex so `/token` matches.
- A URL can now emit several relevant skills instead of stopping at the first match.
- Added generic numeric/UUID path-object detection.
- Example: `/api/v1/orders/123` now routes to business logic, IDOR, and API misconfiguration
  checks rather than only one class.

Tests were updated to describe the new multi-signal contract.

### 7. Honest stop-gate exhaustion implemented

File: `engine/stop_gate.py`

- `assess()` now checks populated vector ledgers.
- Stopping is allowed when every vector has a terminal, evidenced outcome.
- An empty ledger is not exhaustion.
- A `dead` vector with zero requests and no structural explanation is not accepted as
  exhausted.

Still open: time/request budgets and a “no new response information for N probes” condition
have not yet been added to the stop decision.

### 8. Normalized API manifest implemented

File: `engine/api_manifest.py`

Offline import support was added for:

- OpenAPI/Swagger JSON;
- HAR;
- Postman collections;
- Burp XML;
- GraphQL introspection JSON;
- existing CBH manifests.

The normalized operation contains method, canonical path, host, parameters, schema fields,
declared security, sources, operation name, metadata, and risk hints. Numeric IDs, UUIDs,
and OpenAPI path variables normalize to the same operation ID, allowing traffic and specs
to merge.

Engine recon now writes `api-manifest.json` and `workflow.json` beside its existing state.
The simpler `cbh recon` manifest was raised to schema version 2.0 and includes root
operations; deeper API operations still require importing OpenAPI/HAR/Burp/GraphQL data.

### 9. Authorization matrix implemented

File: `engine/authorization_matrix.py`

Capabilities:

- builds principal/object/action plans from the normalized manifest;
- models roles and tenants;
- stores environment-variable references instead of credentials;
- refuses inline token/cookie/authorization values in a principal file;
- distinguishes owner control requests from cross-principal and cross-tenant requests;
- requires a verified state change before declaring a cross-user write violation;
- requires ownership/sensitive-data evidence before declaring a read violation;
- normalizes volatile response fields for comparison.

The module only plans and evaluates. It does not autonomously execute the matrix. Execution
should later emit `poc_runtime` specs and pass through the request broker.

### 10. Business workflow graph implemented

File: `engine/workflow_graph.py`

- Groups operations into entities.
- Derives actions from operation names, paths, and methods.
- Generates ranked replay, step-skip, cross-principal, hidden-field, value-boundary, and
  selected race-condition hypotheses.
- Produces JSON artifacts suitable for a future scheduler.

This is the first replacement for the old full `(endpoint × every vulnerability class)`
approach. The existing `vectors.seed()` still creates the old Cartesian ledger and must be
changed before the replacement is complete.

### 11. Recon snapshot diff implemented

File: `engine/recon_delta.py`

Compares two manifests and reports:

- added and removed assets;
- added and removed operations;
- newly added parameters and fields;
- changed security declaration;
- risk-ranked new/changed operations.

Automatic snapshot rotation and scheduled execution are still open.

### 12. Disclosed-report retrieval implemented

File: `engine/report_intel.py`

- Searches a local JSON report dataset offline.
- Scores title, weakness, CWE, vulnerability information, impact, program, severity, and
  bounty overlap.
- Returns at most ten compact matches; default is five.
- Does not load an entire report corpus into the agent context.

The SecurityTalent dataset was not downloaded or copied. The operator can point the command
at an existing authorized local dataset. Dataset refresh, schema adapters, and license/source
metadata still need hardening.

### 13. Triager-facing PoC minimizer implemented

File: `engine/poc_minimize.py`

- Reduces a multi-step spec to capture dependencies, explicit login/control steps, and the
  final verification step.
- Renders a short Markdown reproduction with impact, steps, expected proof, observed status,
  and a reference to the machine-readable artifact.

This is structural minimization. Network delta debugging is intentionally absent because
automatically removing and replaying state-changing steps can create unwanted repeated
effects.

### 14. CLI entry points added

File: `cbh/cli.py`

New commands:

```text
cbh api-manifest ...
cbh authz-matrix ...
cbh workflow ...
cbh recon-diff ...
cbh report-intel ...
cbh poc-minimize ...
```

These are pass-through commands to the offline engine modules. Each module also runs
directly with `python3 engine/<module>.py --help`.

## Validation completed

Latest results at the stopping point:

```text
python3 -B -m unittest discover -s tests
48 tests, all passing

python3 -B -m compileall -q engine cbh scripts
passed

python3 -B engine/recon.py
recon.py self-test: PASS

python3 -B engine/agent.py
agent.py extractor self-test: PASS

python3 -B engine/pacing.py --selftest
SELFTEST PASSED

python3 -B scripts/lint_skills.py
62 skills, 0 errors, 6 oversized-body warnings
```

No live target requests were used for validation. Tests use mocks, temporary directories,
and synthetic OpenAPI/HAR/PoC data.

## Work that remains

> **Status update — second session, 2026-09-15.** Priorities 0 and 1 are complete, as are
> most of Priority 2 and all of Priority 3. Suite: **48 -> 220 tests**, all passing;
> `lint_skills.py` 0 errors **and 0 warnings** (was 6); `gen_inventory.py --check` clean.
> Items below are marked DONE with what was actually built, or left OPEN with why.

### Priority 0 — DONE

1. **Request-broker integration tests across every transport** — DONE.
   `tests/test_request_broker.py` (22 tests): scope deny, deny-wins, default-deny with no
   scope source, local-URL passthrough, audited ungated opt-out, batch refusal, header
   injection, unset-required-header refusal, cross-process pacing, scope-checked-before-paced,
   audit row shape, response hashing + storage + dedup, error responses, store opt-out, and
   live transport checks for `bbcurl` (dry-run), `poc_runtime` (against a local server) and
   `engine/recon._get`.
2. **MCP mutation paths** — DONE. `scripts/mcp-gate.py`, a PreToolUse hook on
   `mcp__burpmcp__.*|mcp__playwright__.*` (wired in `~/.claude/settings.json`; backup
   `settings.json.bak-20260915-mcpgate`). Burp send/resend and Playwright navigate are
   scope-verified, paced against the engagement budget, and audited before they proceed;
   mandatory headers missing from a raw Burp request are refused with the exact line to add;
   a resend with no explicit host is refused as UNVERIFIED rather than waved through;
   Collaborator/OOB needs `"allow_oob": true` in `profile.json`. In-page Playwright actions
   are **not** gated and the module says so — they name no host and inherit the origin chosen
   at navigate. 16 tests in `tests/test_mcp_gate.py`.
3. **Vector-ledger replacement** — DONE. `vectors.seed_from_manifest()` derives vectors from
   operation risk hints + workflow hypotheses, each carrying the hint that justified it and a
   priority blended from it; `rank()` honours that priority. `vectors.prune()` removes only
   untouched legacy Cartesian rows (still `untried`, 0 requests, no mutation, no note) and
   backs the ledger up first. CLI: `cbh vectors seed-from-manifest` / `prune`.
4. **Engine mock end-to-end** — DONE. `tests/test_engine_end_to_end.py` walks
   recon -> manifest -> workflow -> vectors -> rank -> map -> hunt -> validate -> report plus
   resume. Manifest/workflow emission was extracted to `Engine._write_api_artifacts()` and
   now runs on the mock path too, so the chain is actually exercised.

### Priority 1 — DONE

5. `/recon` rewritten as a thin wrapper around `cbh recon` / `api-manifest` / `workflow` /
   `vectors seed-from-manifest` / `recon-diff`, with the bare-`curl`, missing-tool and
   nuclei-sweep steps removed and the reason for each removal stated.
6. `/token-scan` removed (git-tracked, recoverable). 17 -> 16 commands.
7. Counts generated, not typed: `scripts/gen_inventory.py` reads the tree and
   `--check` fails on any doc that disagrees; `docs/inventory.json` is the artifact.
   README/USAGE/INSTALL/architecture/credits/multi-harness/plugin manifests corrected.
   Attribution counts (vendored, provenance) opt out with an inline `inventory-exempt`
   marker rather than being silently rewritten; CHANGELOG is excluded because it records
   what the inventory *was*.
8. Burp MCP port 9876 -> 8181 everywhere, read from `runtime/client.mjs`.
9. `docs/architecture.md`'s "no automated exploitation tooling" replaced with what is
   actually true (no *scanner*; requests do get fired, all through the broker).
   `engine/agent.py`'s "skills auto-activate" corrected — `Skill` is not in `ALLOWED_TOOLS`,
   so headless agents hunt without skills, and the docstring now says so and why.
10. `docs/recon-manifest.md` + `recon-manifest.schema.json` at v2.0 with `operations`,
    the risk-hint table, and the round-trip into vector seeding.
11. `docs/cbh-cli.md` documents every new command. A test now runs `cbh <cmd> --help` for
    every invocation the docs show — three were written against interfaces that did not
    exist.
12. `requires-python` 3.9 -> 3.10 (the code uses `X | None`), docs matched, asserted by test.

### Priority 1 — memory and learning — DONE

13. `engine/memory_migrate.py` (`cbh memory-migrate`): dry-run by default with per-field
    counts and sha256s, `--apply` backs every file up, `--rollback <stamp>` restores,
    append-only row counts enforced, malformed lines preserved verbatim, idempotent.
    A journal row with no result is left **unannotated** rather than assumed successful.
    **Not applied to the live corpus** — that is the operator's call; the dry run reports
    295 journal + 68 pattern rows, 1070 field updates.
14. Analytics denominators come from `journal.jsonl`. The old `confirmed/len(patterns)`
    was 100% by construction; measured on a fixture it now reads 20% where it read 100%,
    and a missing journal prints a labelled warning instead of a silent fallback.
15. `save_profile()` applies `_scrub_pii` as well as `redact()` — profiles were the one
    write path still missing it, and `/pickup` reads them back every session.
16. Local confirmation and the program's verdict are separate fields
    (`locally_confirmed` / `platform_outcome`), so a technique that reproduces every time
    and is closed N/A every time is now visible instead of counted as a success.

### Priority 2 — API model — MOSTLY DONE

17. **DONE** — local `$ref` resolution (recursive, depth-capped, remote refs refused),
    nested property traversal, response schemas, and `$ref`-ed parameters/requestBodies.
    Before this, almost every real OpenAPI document yielded zero fields and therefore no
    `property-authorization` hint.
18. **DONE** — Postman collection + environment variables, with secret-shaped values
    dropped; unresolved variables park at `placeholder.invalid` instead of producing a
    hostname nobody owns.
19. **DONE** — Burp XML now imports query parameters and body field **names** (JSON, form,
    multipart, base64-encoded requests) and marks credentialed requests `secured`. Values
    are never imported: they are live session and subscriber data.
20. **OPEN** — AsyncAPI / WebSocket message import.
21. **OPEN** — protobuf descriptor / gRPC reflection import.
22. **DONE** — GraphQL introspection walks input-object members and return-type fields,
    records the resolver group, and flags `node(id:)`/relay global ids. Also fixed: every
    GraphQL operation travels as an HTTP POST, so plain queries were being tagged
    `state-change` and seeded with CSRF/replay vectors against a read.
23. **OPEN** — dedicated mobile-traffic adapter. A mobile HAR or Burp export already
    imports through the existing parsers; this item is only about a labelled adapter.
24. **DONE** — `cbh authz-matrix plan --emit-specs <dir>` writes one `poc_runtime`
    skeleton per test. Specs assert the **finding** condition, not the correct behaviour
    (a spec that PASSed on a correct deny would hand every hardened endpoint a green
    artifact, and `evidence.py`/the stop gate both read PASS as "demonstrated"); writes get
    a `verify` step that reads state back **as the owner**; DELETE verifies the object is
    gone; object ids stay `{{OBJECT_ID}}` placeholders and credentials stay `{{env:NAME}}`.
25. **DONE** — `cbh workflow --responses <engagement>` lifts object ids out of the stored
    response corpus (no new requests) and attaches them to cross-principal hypotheses,
    which then outrank the same hypothesis with no material. Only id-shaped keys with
    id-shaped values are lifted; names, emails and free text are not.

### Priority 2 — stopping, reporting, operations — DONE

26. Stop-gate budgets: `max_requests`, `max_minutes`, `no_new_information_window` in
    `profile.json`. A budget must be **spent**, not declared — requests come from
    `audit.jsonl` scoped to this hunt, the clock from when analysis mode armed, and
    stagnation from the response corpus (identical bodies across the window). `assess()`
    records which door the hunt left by (`exit_condition`). 14 tests.
27. `cbh report` embeds the minimized reproduction above the verbose artifact.
    Two bugs found and fixed doing it: `poc_minimize.required_steps()` was **dropping the
    exploit step** (verification references nothing, so dependency-only minimization kept
    login and verify and threw away the request that causes the bug), and the first
    integration used `evidence.collect()`, which rglobs the engagement and pasted *another
    finding's* reproduction under this one's title.
28. `engine/program_quality.py` (`cbh program-quality`): acceptance / duplicate / N-A /
    downgrade rates over judged submissions, median days to verdict, open submissions,
    payout per accepted. A program never submitted to reports unknown, not 0%.
29. `scripts/recon-snapshot.py` + opt-in `scripts/install-recon-snapshot.sh`: rotates
    manifests, diffs against the previous snapshot, writes only high-risk deltas to
    `recon/<target>/hunt-queue.md`, and seeds them into the vector ledger. A security
    declaration that **changed** is the top row. Scheduling the recon *run* is deliberately
    not automated — a cron job that sends requests at a live program is the operator's call.
30. `report_intel` records dataset provenance (`meta` block or `<dataset>.meta.json`);
    `--describe` prints it and `--strict` refuses a dataset that declares no source/licence.

### Priority 3 — skill size and maintenance — DONE

31. All six oversized skills split into routers plus `references/`; lint is now
    **0 errors, 0 warnings** (was 6 warnings). No content was deleted — every split was a
    move, and totals are unchanged plus the new index headers.
32. The real duplication was not payload tables: **`bb-local-toolkit` was a 97% verbatim
    copy of `bug-bounty`** — 1548 identical lines — so a skill whose description promises
    "the exact local binary path" answered a completely different question. It has been
    rewritten to do its actual job, from a live `command -v` audit of this machine,
    including what is installed-but-policy-restricted and what is absent with the
    substitute to use instead. The old body is archived at
    `references/inherited-methodology.md` rather than deleted.
    `security-arsenal`, `web2-recon`, `bb-methodology` and `report-writing` were checked and
    are **not** duplicates (4-34 shared lines, all boilerplate).
33. `tests/test_docs_consistency.py` — counts, MCP port, Python floor, manifest schema
    version, the hunt-* sub-count, `docs/inventory.json` freshness, and every `cbh` command
    the docs show.
34. Leaked file handles in `engine/engine.py`, `engine/state.py` and `engine/scope.py`
    fixed (the suite now runs clean under `-W error::ResourceWarning`); the dead
    `changed_rows` expression in the migration planner removed; bare `curl` against a target
    replaced with gated `CBH_PROJECT=<engagement> bbcurl` in 17 `hunt-*` skill examples.

### Still genuinely open

- **Items 20, 21, 23** — AsyncAPI/WebSocket import, protobuf/gRPC reflection import, and a
  labelled mobile-traffic adapter. Left rather than half-built; each needs its own format
  decisions, and a parser that silently produces nothing is the failure this session spent
  most of its time undoing.
- **The memory migration has not been applied to the live corpus.** Dry run is clean and
  rollback is tested. Run `cbh memory-migrate --apply` when you want it.
- **Commit `b0d5155` still holds the pre-scrub `audit.jsonl`** with 2 identity-shaped
  values (carried over from the previous handoff). No remote exists, so it never left the
  machine; removing it rewrites history and remains the operator's call.
- **`~/.claude/settings.json` was modified** to add the MCP gate hook. Backup:
  `settings.json.bak-20260915-mcpgate`.

