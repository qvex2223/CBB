# Caido — the proxy for the last mile

Installed 2026-10-14, replacing a Burp stack that was gone from disk (`/opt/Claude/tools/burp`
did not exist, `burpmcp` health-checked as `ECONNREFUSED 127.0.0.1:8181`, zero Burp rows in
`hunt-memory/audit.jsonl`, no `*.burp.*` evidence anywhere under `Targets/`). See
`docs/BACKLOG-2026-10-14.md` item 6 for why.

`bbcurl` remains the recon transport — it carries scope, pacing and audit by itself. Caido is for
the questions a single request cannot answer: redirect chains, cookie and session state across a
flow, replaying and mutating a captured request, and anything that has to be shown on the wire.

## What is on disk

| Thing | Path | Provenance |
|---|---|---|
| Caido server | `~/security-research/tools/caido/bin/caido-cli` (v0.58.3) | vendor tarball, SHA-512 matched `https://api.caido.io/releases/latest` |
| MCP server | `~/security-research/tools/caido/bin/caido-mcp-server` (v4.3.0) | **built here** from `c0tton-fluff/caido-mcp-server`, source in `tools/caido/src/` |
| Go toolchain (build only) | `~/security-research/tools/go` (go1.27.2) | go.dev tarball, SHA-256 verified |
| MCP wrapper | `runtime/caido-mcp.mjs` | this repo |
| Log | `~/security-research/tools/caido/logs/caido.log` | — |

The prebuilt MCP binary from the project's GitHub releases was **not** used. It was built from the
source tarball instead, after reading it: 66 registered tools, dependencies are mainstream plus
`caido-community/sdk-go`, no outbound endpoints anywhere in the tree except the doc examples, and
the OAuth token is written `0600` into a `0700` directory at `~/.caido-mcp/token.json`. Caido's own
documentation labels this server community-built and explicitly not affiliated with Caido, so that
review is the only assurance there is — repeat it on every version bump.

## Running it

Nobody has to run it by hand any more (2026-10-16). `scripts/caido-up.sh` starts it, and three
callers invoke that: `scripts/hunt-arm.py` when a hunt arms, `scripts/session-brief.py` at
`SessionStart` inside an engagement, and `cbh tools doctor --start`. It is idempotent — a bash
`/dev/tcp` probe comes first, so a second call never spawns a second instance fighting over one
project directory.

```bash
scripts/caido-up.sh            # start if needed, wait for the port, report
scripts/caido-up.sh --status   # report only, never start anything
```

Overrides: `CBH_CAIDO_PORT`, `CBH_CAIDO_HOST`, `CBH_CAIDO_BIN`, `CBH_CAIDO_WAIT`, and
`CBH_CAIDO_AUTOSTART=off` to keep the hooks from starting it at all. Log: `logs/caido.log`.
The underlying command, if you want it in the foreground:

```bash
cd ~/security-research/tools/caido
./bin/caido-cli --listen 127.0.0.1:8080 --no-open --no-sync    # proxy + UI on 8080
```

`--no-sync` is deliberate. Caido's cloud sync is for settings and workflows, but this workspace
scrubs subscriber identity out of every file it writes (`engine/responses.py::scrub_text`), and
shipping project data to a vendor cloud would walk around that for no gain. `--no-open` keeps it
from trying to launch a browser on a box with no display.

**One Caido project per engagement.** The MCP server hands an agent the whole project history, so
two programs sharing a project means one program's traffic is readable while hunting the other.
`caido_create_project` / `caido_select_project` are not gated and are cheap — use them.

## Finishing the login (operator)

`caido-mcp-server serve` refuses to start without a token, and minting one is a device flow against
**dashboard.caido.io**, which requires a Caido account:

```bash
cd ~/security-research/tools/caido
./bin/caido-mcp-server login -u http://127.0.0.1:8080
```

It prints a URL carrying a `user_code`. Opening it lands on `https://dashboard.caido.io/login`
(GitHub / Google / Microsoft, or email and password), and after signing in the consent screen has
the Allow button. The token then lands in `~/.caido-mcp/token.json` and `serve` works.

Until that is done, `node runtime/health.mjs --only=caido` reports
`MCP error -32000: Connection closed`, which is this and nothing else.

## What the gate does with it

`scripts/mcp-gate.py` treats Caido exactly like every other transport: scope checked, pacing paid,
mandatory headers enforced, one audit row per call in `hunt-memory/audit.jsonl`. The specifics,
because this server is richer than Burp's bridge:

* **Target resolution** — the explicit `host`/`port`/`tls` arguments win, because they win on the
  wire; with none of them, the raw request's own `Host` header is what gets checked. `tls` defaults
  to true, the same default the tool schema has.
* **Every request in a batch** — `caido_batch_send` carries up to 50 and `caido_race_window_send`
  up to 50; all of them are scope-checked, and the pacing budget is paid once per request before
  the first byte leaves. A batch whose wait would exceed 120s is refused, naming the batch size
  that fits, rather than a hook that sits there looking wedged.
* **Bulk needs an opt-in** — `caido_batch_send`, `caido_race_window_send` and
  `caido_automate_task_control` with `action=start|resume` all require `"allow_bulk_tools": true`
  in `Targets/<name>/profile.json`. Automate is a fuzzing engine, which is the broad automated
  scanning every project file here forbids.
* **Race bursts are marked** — `caido_race_window_send` opens raw sockets inside the MCP server, so
  Caido's own history never sees those requests. The audit row says so; it is the only record.
* **Pausing the intercept queue is refused while a proxied browser is live.** `caido_intercept_control`
  with `action=pause` holds EVERY request the proxy carries, not just the next one, so the
  engagement's Chromium — which goes through Caido by default — starts answering
  `net::ERR_TOO_MANY_RETRIES` in a few hundred milliseconds, which reads exactly like a target
  wall. The gate looks for a live browser lane (`engine/browser_state.py`: a
  `.cbh-browser.lock` with a running pid whose engagement has no `playwright-direct` marker) and
  refuses the pause, naming the lane and offering `caido_list_requests`, a tamper rule, or
  `browser_close` first. `resume`, `drop` and reading `caido_intercept_status` are never refused.
  Measured 2026-11-11: a pause mid-lane followed four failed navigations,
  and the next three were guaranteed to fail too.
* **Three tools are refused, not gated**, because their arguments do not name what they would fire:
  `caido_forward_intercept` (an intercept-queue id), `caido_run_workflow` with `type=active`
  (somebody else's workflow against a stored request), and `caido_edit_request` with no `host`
  override. Each refusal names the way through. `type=convert` workflows and the `pause`/`cancel`
  Automate actions are local or stop traffic, so they pass.
* **`caido_edit_request` may not drop a mandatory header.** It inherits the stored request's
  headers, which the hook cannot read, so the header check is limited to what `removeHeaders`
  takes away — the one case that is visible and the one that matters.

Everything else — `caido_list_*`, `caido_get_*`, diff, export, findings, scopes, projects, replay
session bookkeeping — touches local state and passes through untouched.

Escape hatch, audited, same as before: `CBH_MCP_GATE=off`.

Tests: `python3 -m unittest tests.test_mcp_gate` (44 cases, 25 of them Caido).

## Note on Caido's own scope feature

`caido_create_scope` / `caido_is_in_scope` are Caido's idea of scope, not this workspace's.
`engine/scope.py` stays authoritative — it is the one that resolves a host and checks it against a
program's netblocks. A Caido scope preset is a convenience for filtering history, never an
authorization to send.
