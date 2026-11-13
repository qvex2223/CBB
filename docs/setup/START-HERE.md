# Starting a hunt — what to do when you open a session

Written 2026-10-14, after finding that the enforcement layer this workspace documents
was not actually wired into Claude Code.

## 0. One-time, and it is not optional

`~/.claude/settings.json` had **no hooks and no env**. Everything this workspace calls
"enforced in code" is a hook, and until Claude Code is told about them none of it runs:

| Hook | What is missing without it |
|---|---|
| `PreToolUse` → `mcp-gate.py` | **Caido and Playwright requests are not scope-checked, not paced, not audited.** They talk to the network themselves; this hook is the only place that sees them. |
| `PreToolUse` → `skill-gate.py` | the matching `hunt-*` skill is advisory again |
| `PreToolUse` → `hunt-recall.py` | the endpoint's own history does not arrive before the next request |
| `PostToolUse` → `hunt-nudge.py` | no GRINDING / IDENTICAL RESPONSES / ANSWER NEVER MOVED warnings |
| `PostToolUse` → `skill-track.py` | the skill gate cannot tell which skills loaded |
| `Stop` → `hunt-stop-gate.py` | the session can quit with untried vectors in its own ledger |
| `SessionStart` → `session-brief.py` | no engagement, pacing, open-threads or scope-selftest line at startup |
| `UserPromptSubmit` → `hunt-arm.py` | **"начни хантить" arms nothing** — no skill gate, no nudge, no stop gate; only a slash command or a `hunt-*` skill would arm them, so a session told to hunt could stop after three requests |

Claude cannot write that file (editing the harness's own settings is refused by design),
so this is yours:

```bash
python3 docs/setup/apply-hooks.py            # dry run: shows what changes
python3 docs/setup/apply-hooks.py --apply    # writes it, after a timestamped backup
```

Then **restart Claude Code** — hooks load at session start. The config itself lives in
`docs/setup/hooks.json`, so it is reviewable and re-appliable after any machine move.

Already done for you: `.claude/settings.local.json` now enables `caido` and
`playwright` (the dead `burpmcp` entry was removed — the Burp stack is not on this box).

## 1. Start the proxy

```bash
~/security-research/tools/caido/bin/caido-cli --listen 127.0.0.1:8080 --no-open --no-sync
```

Not started automatically on boot. `docs/caido.md` has the rest, including the one
operator login step. Playwright needs nothing started.

## 2. Pick the program BEFORE launching Claude Code

Two things key off the engagement at launch and cannot be changed mid-session: the
pacing/scope detection used by the hooks, and Playwright's per-engagement browser
profile (session reuse). So name it in the environment:

```bash
cd ~/security-research/BugHunter      # start here: skills, commands and .mcp.json live here
export CBH_PROJECT=standoff365/flowwow       # platform/program, as the folder is named
claude
```

Starting Claude Code *inside* `Targets/<name>/` also works for the gates, but the
project-root `skills/` and `commands/` may not load from there — repo root plus
`CBH_PROJECT` is the combination that gets both.

What is ready to hunt right now (32 programs):

```bash
python3 - <<'PY'
import json
from pathlib import Path
for p in sorted(Path("Targets").rglob("profile.json")):
    if "_TEMPLATE" in str(p): continue
    d = json.loads(p.read_text())
    if d.get("scope_status") == "ready":
        print(f"{str(p.parent).replace('Targets/',''):34} pace {d.get('min_interval_seconds')}s")
PY
```

Statuses that are **not** hunting targets, and why: `vendor-env` (needs a vendor-provided lab),
`nte` (non-testable / no public surface), `pending-login` / `pending` (scope not
retrieved yet), `operator-provided` (needs data only you have).

## 3. First prompt of the session

```
/pickup standoff365/flowwow        # resumes: what was tested, open threads, untried vectors
```

Nothing logged for that target yet? Then:

```
/hunt flowwow.com
```

`/hunt` fingerprints, routes through `hunt-dispatch` to the matching `hunt-*` skills,
checks CVEs for exact versions, and runs pattern analytics for the detected stack. It
also arms analysis mode, which is what makes the skill gate and the nudge active.

Since 2026-10-15 you do not have to type a command to arm it: **"начни хантить ozon"**
(or `start hunting`, `ищи баги`, `продолжай хантить`, `пентест`) arms analysis mode
through the `UserPromptSubmit` hook and injects the standing orders for the session.
Continuous mode is the code default, so the hunt then runs until **you** end it —
`стоп охота` / `stop hunting` disarms it, and `python3 engine/stop_gate.py --continuous off`
turns the whole mode off for the workspace. A question never arms it: a prompt opening
with `как / почему / что / why / how / what` leaves the session idle.

Check the plumbing once at the start:

```bash
cbh tools doctor
```

Expect `READY caido`, `READY playwright`, and a `SESSION playwright persistent for
<program>` line. `isolated` there means `CBH_PROJECT` was not set before launch and
every login this session will be spent again next time.

## 4. The loop, and where each tool belongs

```
/recon <target>            surface: subdomains, routes, JS, manifests
cbh vectors next <host>    impact-ranked list of what has NOT been attacked yet
  ...hunt the vector with the hunt-* skill the gate names
CBH_PROJECT=<p> bbcurl ... every request: scope-checked, paced, audited, body stored
mcp__caido__*              only for the wire: redirect chains, session state, replay
/poc-run <spec>.poc.json   the PASS that makes it a finding, with a .result.json
/refute <finding>.md       fire the controls that would DISPROVE it — before the gate
cbh dedup <finding>.md     is this a duplicate of your own other finding
/validate                  the 7-Question Gate
/report                    the draft
/remember --result ...     after EVERY outcome, confirmed or rejected
```

`/remember` is the one step with no enforcement behind it, and the one that is actually
being skipped: 2 rows in `patterns.jsonl` against 3678 requests in `audit.jsonl`. Every
analytics feature in this workspace is worth exactly what gets fed to it.

Funnel, so nothing lands in the wrong tier:

* `leads/` — you think it is true, nothing fired yet
* `primitives/` — a request proved the capability, impact NOT demonstrated
* `findings/` — impact demonstrated, `.result.json` beside it

`cbh triage <finding> --demote` is the knock-back when a finding does not hold.

## 5. Ending

The Stop hook refuses to end a hunt with nothing proven and names the next move. The
honest exits: a proven Medium+ banked (continuous mode keeps going by design), a
genuinely exhausted ledger, or you saying stop. `/debrief` writes the session into
`notes.md` from artefacts rather than recollection.
