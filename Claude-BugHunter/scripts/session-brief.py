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

    project = find_project_dir()
    if project is None:
        return 0

    lines = []
    try:
        eng = Engagement.detect()
        budget = f"{eng.min_interval:.0f}s"
        hdrs = ", ".join(f"{k}: {v}" for k, v in eng.required_headers.items())
        lines.append(f"Engagement: {project.name}  ·  pacing {budget} global"
                     + (f"  ·  mandatory headers — {hdrs}" if hdrs else ""))
    except Exception as e:  # noqa: BLE001
        lines.append(f"Engagement: {project.name}  ·  profile unreadable: {e}")

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
        patterns_file = Path.cwd().parent.parent / "hunt-memory" / "patterns.jsonl"
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

    # The Burp MCP is only useful if Burp is running, and "the MCP is broken" has
    # so far always meant "nobody started it". State it at session start, where it
    # costs one line, instead of at the moment a PoC needs a redirect chain.
    try:
        import socket
        sock = socket.socket()
        sock.settimeout(0.3)
        up = sock.connect_ex(("127.0.0.1", 8181)) == 0
        sock.close()
        if not up:
            lines.append("Burp MCP: down. Start it before last-mile PoC work "
                         "(redirect chains, session state, replaying a captured request): "
                         "`Claude-BugHunter/scripts/burp-mcp.sh start`")
    except Exception:  # noqa: BLE001
        pass

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
