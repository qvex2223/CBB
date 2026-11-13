#!/usr/bin/env python3
"""
session-brief — what a SessionStart hook prints before the first prompt.

The workspace's rules live in CLAUDE.md, but "which engagement am I in, what is
the rate budget, what was left open" is state, not rules, and state read from
prose is state that goes stale. This prints it from the files themselves so the
session opens on facts instead of recollection.

Emits nothing at all outside an engagement — a session started in the workspace
root has no engagement to brief on, and noise there trains the reader to skip it.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))


def main() -> int:
    try:
        from pacing import Engagement, find_project_dir
    except Exception as e:  # noqa: BLE001 - a broken hook must not block the session
        print(f"session-brief: engine unavailable ({e})", file=sys.stderr)
        return 0

    # Workspace drift (missing hooks, stale skill copies) is printed even outside an
    # engagement: it is exactly the failure that otherwise goes unnoticed for a week.
    drift = []
    try:
        from workspace_check import brief_lines
        drift = brief_lines()
    except Exception as e:  # noqa: BLE001
        drift = [f"WORKSPACE CHECK CRASHED: {e}"]

    # The plan counter plus this box's measured consumption. The counter is in no local
    # file — only the harness has it, cached by the statusline — so the line names where
    # the real number comes from. Printed outside an engagement too: the operator asked
    # to always see it.
    limits_line = ""
    try:
        from limits import brief_line
        limits_line = brief_line()
    except Exception as e:  # noqa: BLE001
        limits_line = f"LIMITS: unavailable ({e})"

    # Errors are recorded by scripts/error-log.py into hunt-memory/errors.jsonl.
    # A log nobody opens is a log nobody reads, so the count leads the session.
    errors_line = ""
    try:
        import io
        from contextlib import redirect_stdout
        import error_log
        buf = io.StringIO()
        with redirect_stdout(buf):
            error_log.main(["--brief"])
        errors_line = buf.getvalue().strip()
    except Exception:  # noqa: BLE001 - never let the error reader break the brief
        errors_line = ""

    project = find_project_dir()
    if project is None:
        out = drift + ([limits_line] if limits_line else []) \
            + ([errors_line] if errors_line else [])
        if out:
            print("\n".join(out))
        return 0

    lines = list(drift)
    if limits_line:
        lines.append(limits_line)
    try:
        eng = Engagement.detect()
        budget = f"{eng.min_interval:.0f}s"
        hdrs = ", ".join(f"{k}: {v}" for k, v in eng.required_headers.items())
        lines.append(f"Engagement: {project.name}  ·  pacing {budget} global"
                     + (f"  ·  mandatory headers — {hdrs}" if hdrs else ""))
    except Exception as e:  # noqa: BLE001
        lines.append(f"Engagement: {project.name}  ·  profile unreadable: {e}")

    # Who sends: the orchestrator plans and merges, the workers fire (crew-gate), and a
    # worker is an `Agent` subagent rather than a background process (agent-gate), so
    # the operator can open its transcript.
    lines.append("CREW: orchestrator this session (it does not fire requests)  ·  spawn "
                 "every worker with the `Agent` tool  ·  size from `cbh crew`")

    # How many workers this engagement's budget actually feeds (engine/crew.py).
    # Printed next to CREW because the two answer different halves of one question:
    # where the workers run, and how many of them are worth starting.
    try:
        from crew import brief_line as crew_line
        cl = crew_line()
        if cl:
            lines.append(cl)
    except Exception:  # noqa: BLE001
        pass

    # Which stop gate is live decides how the session ends, so it is state the
    # session has to see at the top — not something to rediscover from the refusal.
    try:
        from stop_gate import continuous_config, max_blocks
        cont = continuous_config(project)
        if cont["on"]:
            lines.append(f"CONTINUOUS: a proven Medium+ is banked and the sweep goes on; "
                         f"only you end this hunt ({cont['source']}, "
                         f"{max_blocks(project)} pushes max). Accounts are self-service — "
                         f"blocked registration goes to blocked-tests/, not to you.")
        else:
            lines.append(f"STOP GATE: default — a proven Medium+ ends the hunt "
                         f"({cont['source']}). `stop_gate.py --continuous on` to sweep.")
    except Exception:  # noqa: BLE001
        pass

    sys.path.insert(0, str(REPO))
    try:
        from cbh.cli import (_collect_findings, _collect_hosts,
                             _collect_open_threads, _has_open_threads_section)
        hosts = _collect_hosts(project / "hosts")
        findings = _collect_findings(project / "findings")
        threads = _collect_open_threads(project / "notes.md")
        lines.append(f"{len(hosts)} host file(s) · {len(findings)} finding(s) · "
                     f"{len(threads)} open thread(s)")
        if not _has_open_threads_section(project / "notes.md"):
            lines.append("WARNING: notes.md has no '## Open threads' section — "
                         "nothing tracks where you stopped.")
        for t in threads[:5]:
            lines.append(f"  - {t[:160]}")
    except Exception as e:  # noqa: BLE001
        lines.append(f"(project state unreadable: {e})")

    # Work only the operator can finish (a passing report, an approval) is the cheapest
    # payout there is, and it sat unseen for two days on konsol (2026-10-20).
    try:
        from operator_queue import brief_line
        from paths import targets_root
        ql = brief_line(str(project.relative_to(targets_root())))
        if ql:
            lines.append(ql)
    except Exception:  # noqa: BLE001
        pass

    try:
        from yield_report import brief_line as yield_line
        yl = yield_line(project.name)
        if yl:
            lines.append(yl)
    except Exception:  # noqa: BLE001
        pass

    try:
        from chain_graph import brief_line as chain_line
        cl = chain_line(project)
        if cl:
            lines.append(cl)
    except Exception:  # noqa: BLE001
        pass

    # A scope gate that silently stopped working is worse than none, because
    # every later "IN-SCOPE" is trusted. Cheap to check once per session.
    try:
        r = subprocess.run([sys.executable, str(REPO / "engine" / "scope.py"), "--selftest"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            lines.append("WARNING: scope.py --selftest FAILED — do not trust scope "
                         "verdicts until this is fixed.")
    except Exception:  # noqa: BLE001
        pass

    # Pattern analytics for new targets or when stack detected
    try:
        # Check if this is a new target (few patterns) or has recent stack info
        from paths import memory_dir
        patterns_file = memory_dir() / "patterns.jsonl"
        if patterns_file.exists():
            import json
            pattern_count = sum(1 for _ in patterns_file.open())

            # Auto-suggest techniques if target is new or patterns are fresh
            if pattern_count < 20:  # New workspace or fresh data
                analytics_script = REPO / "scripts" / "pattern-analytics.py"
                if analytics_script.exists():
                    r = subprocess.run([sys.executable, str(analytics_script), "--format", "json"],
                                   capture_output=True, text=True, timeout=60)
                    if r.returncode == 0 and r.stdout.strip():
                        try:
                            analytics = json.loads(r.stdout)
                            top_techniques = analytics.get("patterns_analyzed", 0)
                            if top_techniques > 0:
                                lines.append(f"Pattern analytics: {top_techniques} patterns analyzed")
                                lines.append("  Use: python3 scripts/pattern-analytics.py --recommendations")
                        except (json.JSONDecodeError, KeyError):
                            pass
    except Exception:  # noqa: BLE001
        pass

    # Open the session on "here is the next untried vector", not on a blank page.
    # A session that starts without a concrete next move is a session that starts
    # by re-reading JS bundles.
    try:
        from vectors import next_vectors, stuck_report  # type: ignore
        rep = stuck_report()
        if rep:
            lines.append(f"GRINDING: {rep['requests_since_last_finding']} requests since the last "
                         f"hunt-memory write (top host {rep['top_host']}) — rotate the vector, "
                         f"and log the rejected ones with /remember.")
        vdir = REPO.parent / "hunt-memory" / "vectors"
        if vdir.exists():
            for lf in sorted(vdir.glob("*.json")):
                host = lf.stem
                nxt = next_vectors(host, 2)
                if nxt:
                    lines.append(f"Next vectors — {host}:")
                    for v in nxt:
                        lines.append(f"  - [{v['class']}] {v['endpoint']}  (skill {v['skill']})")
    except Exception:  # noqa: BLE001
        pass

    # The proxy MCP is only useful if the proxy is running, and "the MCP is broken"
    # has so far always meant "nobody started it". State it at session start, where
    # it costs one line, instead of at the moment a PoC needs a redirect chain.
    try:
        import socket
        sock = socket.socket()
        sock.settimeout(0.3)
        up = sock.connect_ex(("127.0.0.1", 8080)) == 0
        sock.close()
        if not up:
            # Being inside an engagement folder means a live program is on the other
            # end, i.e. a hunt is what this session is for — so start the proxy
            # instead of printing instructions at the operator (directive
            # 2026-10-16). Idempotent; bounded so a SessionStart hook cannot hang.
            if (os.environ.get("CBH_CAIDO_AUTOSTART") or "").strip().lower() in (
                    "0", "off", "no", "false"):
                raise RuntimeError("auto-start disabled by CBH_CAIDO_AUTOSTART")
            script = Path(__file__).resolve().parent / "caido-up.sh"
            try:
                p = subprocess.run(["bash", str(script), "--quiet"], text=True,
                                   capture_output=True, timeout=14,
                                   env={**os.environ, "CBH_CAIDO_WAIT": "10"})
                lines.append("Caido: started on 127.0.0.1:8080." if p.returncode == 0
                             else "Caido: DOWN and would not start — "
                                  f"{(p.stderr or '').strip().splitlines()[:1]}. "
                                  "bbcurl works; no wire-level evidence (see docs/caido.md)")
            except Exception as e:  # noqa: BLE001
                lines.append(f"Caido: down, auto-start failed ({e}). See docs/caido.md")
    except Exception:  # noqa: BLE001
        pass

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
