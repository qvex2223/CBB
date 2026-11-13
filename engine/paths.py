#!/usr/bin/env python3
"""
paths.py — where the workspace's own directories are, resolved once.

This exists because the workspace moved. The bundle used to live at
`/opt/Claude/BugHunter` with the engagements beside it at
`/opt/Claude/Targets`, and a dozen scripts hard-coded that: `/opt/Claude/Targets`
as a literal, or `parents[2] / "Targets"` which means the same thing. After the
move to `~/security-research/BugHunter` (with `Targets/` now INSIDE the
bundle) every one of those pointed at a directory that does not exist.

Nothing crashed loudly. `cve_watch.py` resolved `Targets/<name>` under a missing
root and reported "no watchlist", `cve-digest.py` fell through its candidate list,
`pattern-analytics` read an empty corpus — all of them exiting 0 or 2 with a
plausible message. That is why the cron jobs were worth nothing even when they ran:
a path that is wrong in the same way everywhere looks like an empty workspace.

So: one resolver, honest about which layout it found, used by everything that needs
a workspace directory. `$CBH_TARGETS_ROOT` and `$CBH_MEMORY_DIR` override.
"""
from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _candidates(name: str) -> list[Path]:
    return [
        REPO_ROOT / name,            # current layout: inside the bundle
        REPO_ROOT.parent / name,     # bundle and workspace side by side
        Path("/opt/Claude") / name,  # the historical /opt/Claude layout
    ]


def targets_root() -> Path:
    """The `Targets/` directory holding the engagements.

    Returns the first candidate that exists; with none of them present, returns the
    in-bundle path so a caller creating an engagement does the right thing rather
    than writing into `/opt`.
    """
    override = os.environ.get("CBH_TARGETS_ROOT")
    if override:
        return Path(override).expanduser()
    for cand in _candidates("Targets"):
        if cand.is_dir():
            return cand
    return REPO_ROOT / "Targets"


def memory_dir() -> Path:
    """`hunt-memory/` — the shared corpus. `$CBH_MEMORY_DIR` wins, as everywhere else."""
    override = os.environ.get("CBH_MEMORY_DIR")
    if override:
        return Path(override).expanduser()
    for cand in _candidates("hunt-memory"):
        if cand.is_dir():
            return cand
    return REPO_ROOT / "hunt-memory"


def template_dir() -> Path:
    return targets_root() / "_TEMPLATE"


def main() -> int:
    for label, path in (("repo", REPO_ROOT), ("targets", targets_root()),
                        ("hunt-memory", memory_dir()), ("template", template_dir())):
        print(f"{label:<12} {path}  {'ok' if path.exists() else 'MISSING'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
