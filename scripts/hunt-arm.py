#!/usr/bin/env python3
"""
hunt-arm — UserPromptSubmit hook. Turns plain language into an armed hunt.

The push half of this workspace (skill gate, grind nudge, stop gate) only runs while
analysis mode is **armed**, and until now the only things that armed it were a slash
command or a `hunt-*` skill (`scripts/skill-track.py` -> `hunt_mode.arm`). That left a
hole exactly where the operator actually works: "начни хантить ozon" is an order to
hunt, but it loads no skill, so the session stayed *idle* — the stop gate never fired
and the session was free to quit after three requests. Measured shape of that failure
in this workspace's own corpus: 3678 audited requests against 2 rows in
`patterns.jsonl`.

So this hook reads the operator's own words:

  * hunt intent (`хантить`, `охоть`, `ищи баги`, `start hunting`, `go deep`, ...)
      -> `hunt_mode.arm()`, plus the standing orders printed to stdout, which
         Claude Code injects as context for that turn.
  * stand-down intent (`стоп охота`, `хватит хантить`, `stop hunting`, ...)
      -> `hunt_mode.disarm()`. The operator's stop is never blocked, and it has to
         be sayable in the same language the hunt was started in.

Questions are not orders: a prompt that reads as a question ("как работает хант?")
never arms the gate, because arming it means the session cannot end until a Medium+
is proven or the ledger is exhausted.

Opt out for one shell: `CBH_HUNT_ARM=off`.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "engine"))

# Intent to hunt. Russian first — that is what the operator writes.
ARM_RE = re.compile(
    r"хант|охот|охоть|"
    r"(?:ищи|ищем|найди|искать|поищи|копай|пробей|пробивай)\s+(?:баг|уязв|дыр|что)|"
    r"начин\w*\s+(?:хант|охот|иск|тест)|"
    r"продолж\w*\s+(?:хант|охот|иск|тест)|"
    r"пентест|багбаунти|баг\s*баунти|"
    r"\bhunt(?:ing)?\b|\bbug\s*bount|\bgo\s+deep\b|\bpentest\b|\brecon\b|"
    r"\bkeep\s+hunting\b|\bstart\s+(?:the\s+)?hunt\b",
    re.I)

# Intent to stop. Must name the hunt: "stop caveman" is not standing down.
DISARM_RE = re.compile(
    r"(?:стоп|останов\w*|прекрат\w*|хватит|заверш\w*|пауза)\W{0,12}"
    r"(?:хант|охот|иск\w*|тест\w*)|"
    r"(?:хант|охот)\w*\W{0,12}(?:стоп|хватит|останов\w*)|"
    r"\bstop\s+(?:the\s+)?hunt|\bstand\s+down\b|\bhalt\s+the\s+hunt\b|"
    r"\bstop\s+hunting\b",
    re.I)

QUESTION_RE = re.compile(
    r"^\s*(?:как|почему|зачем|что\b|чем\b|какой|какие|какая|где|когда|сколько|"
    r"можно\s+ли|а\s+если|объясни|расскажи|покажи|напомни|"
    r"why|how|what|which|where|when|can\s+i|do(?:es)?\s|is\s+there|explain|tell\s+me)",
    re.I)

def _client() -> str:
    """Which agent CLI drives this session — ONE implementation, engine/client.py."""
    try:
        import sys as _s
        from pathlib import Path as _P
        _s.path.insert(0, str(_P(__file__).resolve().parent.parent / "engine"))
        import client as _C  # type: ignore
        return _C.detect()
    except Exception:  # noqa: BLE001 - detection must never block a hunt
        explicit = (os.environ.get("CBH_AGENT") or "").strip().lower()
        if explicit:
            return explicit
        return "claude" if os.environ.get("CLAUDECODE") == "1" else "generic"


def _client_map() -> str:
    if _client() == "claude":
        return ""
    try:
        import sys as _s
        from pathlib import Path as _P
        _s.path.insert(0, str(_P(__file__).resolve().parent.parent / "engine"))
        from hunt_start import CLIENT_MAP  # type: ignore
        return CLIENT_MAP.format(client=_client()) + "\n\n"
    except Exception:  # noqa: BLE001
        return ""


def _spawn_line() -> str:
    """How to spawn a worker. Always the `Agent` tool under Claude Code: it is the shape
    the operator knows, each worker's transcript is openable in the UI, and `agent-gate`
    denies the background-process path for that reason (directive 2026-10-30)."""
    if _client() != "claude":
        return ("Spawn them as your own parallel subagents, all in ONE message, each with "
                "the full brief.")
    return ("Spawn them with the `Agent` tool — each one is visible and openable in the "
            "UI. Send all of them in ONE message so they run concurrently.")


def _crew_line(ev: dict) -> str:
    """How many workers THIS engagement's budget feeds — computed, not a constant.

    The old text said "Cap is 3 concurrent workers" for every programme, whether it
    publishes 30 rps or is still on the 10-second default. engine/crew.py derives it.
    """
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
        from crew import orders_line  # type: ignore
        return orders_line(start=ev.get("cwd") or "")
    except Exception:  # noqa: BLE001
        return ("Crew size: 3 concurrent workers (crew sizing unavailable; that is the "
                "measured in-process cap).")


ORDERS = """\
HUNT MODE ARMED — standing orders for this session (engine/stop_gate.py continuous mode):

Context: authorized testing of a published bug-bounty program the operator has joined;
scope and program rules are in the engagement's scope.md / CLAUDE.md and enforced by
engine/scope.py. Harness or classifier denials are respected, never routed around.

1. One engagement. `/pickup <target>` first; read its CLAUDE.md + scope.md + notes.md
   before firing anything. Never start from zero on a target that already has notes.
2. Fan out from the first minute — you ORCHESTRATE, you do not hunt alone. `/parallel`
   is the default shape of a hunt, not an option: you hold the plan, the merge and the
   ledger; the workers fire the requests. {SPAWN}
   Default crew (`"hunt_agents"` in profile.json overrides the size).
   Spawn the ROLE agents, not `general-purpose`: `subagent_type: "deep-hunter"` (one lead
   to proof or refutation), `"scout"` (15-30 hosts to ranked leads), `"refuter"` (kill a
   candidate finding before it is reported). They are generated for both clients from
   `agents/roles/` by `agents/gen_role_agents.py`, and they already carry the
   forbidden-action list, the named-victim rule and the handback-citation rule — in session
   a0053cc0 all 138 spawns were `general-purpose` and the hand-written briefs named a victim
   in 15 of 138 and the forbidden actions in 15 of 138. Your brief still names the
   engagement, the lead file, the host list and the budget. Freeroam stays a `cbh freeroam
   run` slot (no methodology, `skills_on=False`, its naive-only items are the leads
   methodology would have missed). Every slot beyond those is another `deep-hunter` on the
   next ranked vector (`cbh vectors next`); refill a slot the moment its worker hands back.
   {CREW}
   `/remember` as each result lands, never at the end of the batch.
3. Requests go through `CBH_PROJECT=<name> bbcurl` (scope + pacing + mandatory headers
   + audit). `mcp__caido__*` only for wire-level questions. Bare `curl` is a gate bypass
   and cannot back a report. Pacing is global per engagement and `flock`'d, so the crew
   queues behind one budget — never relax pacing to make a fan-out faster.
4. The hunt runs until the operator ends it. A proven Medium+ is banked, then work
   continues: write it to `findings/` with its `.result.json`,
   `/remember --result confirmed`, `/chain` it, then the next vector.
   `vectors.py rotate` -> `revisit` -> `next` -> next in-scope host -> fresh `/recon` + `/cve`.
5. Test accounts: `cbh identity new <url>` + self-register via Playwright (temp mail,
   temp SMS), without asking the operator for personal data. Blocked by CAPTCHA /
   government ID / provider down -> write it under `blocked-tests/` and continue on the
   unauthenticated surface.
6. Lanes come from `cbh leads` (open leads/primitives ranked by payout and staleness; ones
   waiting on an account are held back). Every lane ends with `cbh leads close <file> --as
   proven|refuted|exhausted|blocked|stalled`. `blocked` = the target or the programme blocks it
   (leaves the queue, waits for the operator); `stalled` = OUR tooling did not finish the lane
   (stays in the queue, flagged RETRY). Never write a dead worker or a busy browser as
   `blocked` — that emptied an engagement's queue on 2026-11-11; `cbh leads reopen <file>
   --note "why"` undoes it. Only ONE browser lane at a time per engagement (Chromium allows one
   browser per profile; the rest of the crew fires `bbcurl`).
   Every outcome gets `/remember`, including `--result rejected`. Before any report:
   `/poc-run` -> `/refute` -> `cbh dedup` -> `/validate`.
7. Severity is never inflated to clear the gate. A Low stays a Low; a confirmed
   primitive with no demonstrated impact belongs in `primitives/`, not `findings/`.
8. Every Scout/Hunter/Reviewer brief you write starts with the crit/high doctrine
   (`cbh doctrine` prints it — paste it verbatim; NEVER into a Freeroam brief).
   Every lane also starts from paid precedent: `cbh precedent --lead <file>` (155 disclosed
   reports, query derived from the file — `cbh report-intel` went unused for a whole six-day
   hunt because it needed a dataset path and an invented query). `cbh leads` already prints
   one precedent line per NEXT row; `cbh precedent --signals <captured body>` asks which
   disclosed opening a response you are holding resembles.
   Its short form: compose before closing a Low (`vectors.py consumers <class>`), read
   bodies not statuses (act on bbcurl `SIGNAL`s), same operation via a second interface,
   identities first, build the oracle before "blind", `cbh refute` every finding.
   After `/pickup`: `cbh census --project <eng> --seed` (offline) puts sibling interfaces,
   server-side fetchers and secret leads into the ledger; `cbh diffprobe <url>` (via a
   worker, ~14 paced GETs) is the parser-differential first move on any new host.
Stop the hunt by saying so ("стоп охота" / "stop hunting")."""


def caido_line() -> str:
    """Bring the proxy up before the hunt, and say what happened.

    Operator directive 2026-10-16: never print "start Caido" at the operator again.
    `caido-up.sh` is idempotent, so arming twice cannot start two instances; a
    failure is reported and does not block the hunt, because `bbcurl` is the request
    path and Caido is only the wire-level tool.
    """
    if (os.environ.get("CBH_CAIDO_AUTOSTART") or "").strip().lower() in ("0", "off", "no", "false"):
        return ""
    script = HERE / "caido-up.sh"
    if not script.is_file():
        return ""
    try:
        p = subprocess.run(["bash", str(script), "--quiet"],
                           capture_output=True, text=True, timeout=40)
    except Exception as e:  # noqa: BLE001
        return f"CAIDO: could not be started ({e}). bbcurl still works; no wire capture."
    if p.returncode == 0:
        return "CAIDO: up on 127.0.0.1:8080 (started for you — mcp__caido__* is live)."
    detail = (p.stderr or p.stdout or "").strip().splitlines()
    return ("CAIDO: DOWN — " + (detail[0] if detail else "unknown error")
            + ". Hunt through bbcurl; no redirect-chain/cookie evidence until it is up.")


def main() -> int:
    if (os.environ.get("CBH_HUNT_ARM") or "").strip().lower() in ("0", "off", "no", "false"):
        return 0
    try:
        ev = json.loads(sys.stdin.read() or "{}")
    except Exception:  # noqa: BLE001
        return 0
    prompt = (ev.get("prompt") or "")[:4000]
    session = ev.get("session_id", "")
    if not prompt.strip():
        return 0

    try:
        from hunt_mode import arm, armed, disarm  # type: ignore
    except Exception:  # noqa: BLE001
        return 0

    if DISARM_RE.search(prompt):
        try:
            disarm(session)
            print("HUNT MODE DISARMED by the operator. The stop gate stands down; "
                  "bank what is proven, then report.")
        except Exception:  # noqa: BLE001
            pass
        return 0

    if not ARM_RE.search(prompt) or QUESTION_RE.match(prompt):
        return 0
    try:
        was = armed(session, ev.get("transcript_path", "") or "")
        arm(session, "prompt: hunt intent")
        if not was:
            print(_client_map() + ORDERS.replace("{SPAWN}", _spawn_line())
                        .replace("{CREW}", _crew_line(ev)))
            line = caido_line()
            if line:
                print("")
                print(line)
    except Exception:  # noqa: BLE001
        pass
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001
        sys.exit(0)
