#!/usr/bin/env python3
"""sync_clients.py — one source of skills, commands, roles and engagement rules,
deployed to where the client reads them.

Why this exists: the workspace context used to be forked per client. Skills lived in
`skills/` and again in `~/.claude/skills` and again in a second repo's copy;
`AGENTS.md` was generated from `CLAUDE.md` with a header that contradicted it line by
line; each engagement folder carried a generated `AGENTS.md` copy of its `CLAUDE.md`
that went stale the moment the real file was edited. One source each, now:

  skills/            → ~/.claude/skills                         (plain copies)
  commands/          → ~/.claude/commands
  agents/roles/      → .claude/agents                           (agents/gen_role_agents.py)
  AGENTS.md (root)   → hand-written doctrine, every client reads it; CLAUDE.md imports it
  Targets/*/CLAUDE.md → Targets/*/AGENTS.md as a SYMLINK, so a client looking for
                        AGENTS.md reads the engagement's real rules and can never read a
                        stale copy of them


Usage:
    python3 scripts/sync_clients.py              # deploy everything that applies
    python3 scripts/sync_clients.py --check      # exit 1 if anything is out of sync
    python3 scripts/sync_clients.py --targets    # only refresh engagement AGENTS.md links
    python3 scripts/sync_clients.py --skills     # only skills/commands copies
"""
from __future__ import annotations

import argparse
import filecmp
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOME = Path(os.path.expanduser("~"))

# (source in repo, destination) pairs. A destination whose parent does not exist is a
# client that is not installed here and is skipped, never created.
def _copy_targets() -> list[tuple[Path, Path]]:
    pairs: list[tuple[Path, Path]] = []
    for name in ("skills", "commands"):
        src = REPO / name
        if not src.is_dir():
            continue
        if (HOME / ".claude").is_dir():
            pairs.append((src, HOME / ".claude" / name))
    return pairs


def _child_diff(src_child: Path, dst_child: Path) -> list[str]:
    """Files under one skill directory (or one command file) that are missing from the
    destination or differ in content.

    Only paths that exist in the SOURCE are compared, and nothing is ever reported as
    "extra": `~/.claude/skills` is shared with Anthropic's own plugin skills, so this
    script must be blind to anything it did not put there. It adds and overwrites; it
    never deletes.
    """
    out: list[str] = []
    if src_child.is_file():
        if not dst_child.is_file() or not filecmp.cmp(src_child, dst_child, shallow=False):
            out.append(f"{dst_child.parent.name}/{src_child.name}")
        return out
    for p in sorted(src_child.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(src_child)
        target = dst_child / rel
        if not target.is_file() or not filecmp.cmp(p, target, shallow=False):
            out.append(f"{dst_child.parent.name}/{src_child.name}/{rel}")
    return out


def sync_skills(check: bool) -> list[str]:
    """Copy each skill directory / command file into every installed client's location.

    Per child, never per tree: the destination directories are shared with other
    skill sources, so a wholesale replace would delete someone else's skills.
    """
    problems: list[str] = []
    for src, dst in _copy_targets():
        changed = 0
        for src_child in sorted(src.iterdir()):
            if src_child.name.startswith("."):
                continue
            dst_child = dst / src_child.name
            diff = _child_diff(src_child, dst_child)
            if not diff:
                continue
            if check:
                problems += diff
                continue
            dst.mkdir(parents=True, exist_ok=True)
            if src_child.is_file():
                shutil.copy2(src_child, dst_child)
            else:
                shutil.copytree(src_child, dst_child, dirs_exist_ok=True)
            changed += 1
        if changed and not check:
            print(f"synced {src.relative_to(REPO)}/ → {dst} ({changed} entr(y/ies))")
    return problems


def _engagement_rule_file(folder: Path) -> Path | None:
    """The file an engagement's rules actually live in: reference.md when the folder
    keeps the full version there, else CLAUDE.md."""
    for name in ("reference.md", "CLAUDE.md"):
        if (folder / name).is_file():
            return folder / name
    return None


def sync_targets(check: bool) -> list[str]:
    """Targets/<...>/AGENTS.md → symlink to that folder's own rule file."""
    problems: list[str] = []
    root = REPO / "Targets"
    if not root.is_dir():
        return problems
    for claude_md in sorted(root.glob("**/CLAUDE.md")):
        folder = claude_md.parent
        rule = _engagement_rule_file(folder)
        if rule is None:
            continue
        link = folder / "AGENTS.md"
        want = rule.name
        if link.is_symlink() and os.readlink(link) == want:
            continue
        if check:
            kind = "regular file" if link.is_file() and not link.is_symlink() else "missing"
            problems.append(f"{link.relative_to(REPO)}: {kind}, should be a symlink → {want}")
            continue
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(want)
        print(f"linked {link.relative_to(REPO)} → {want}")
    return problems


def sync_roles(check: bool) -> list[str]:
    gen = REPO / "agents" / "gen_role_agents.py"
    if not gen.is_file():
        return []
    args = [sys.executable, str(gen)] + (["--check"] if check else [])
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        return [f"agents/gen_role_agents.py: {(r.stdout + r.stderr).strip()}"]
    if not check and r.stdout.strip():
        print(r.stdout.strip())
    return []




def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sync_clients.py",
                                 description="deploy one skill/command/role/rule source to every client")
    ap.add_argument("--check", action="store_true", help="report drift, change nothing, exit 1 if any")
    ap.add_argument("--skills", action="store_true", help="only skills/ and commands/ copies")
    ap.add_argument("--targets", action="store_true", help="only engagement AGENTS.md symlinks")
    ap.add_argument("--roles", action="store_true", help="only .claude/agents")
    a = ap.parse_args(argv)

    all_parts = not (a.skills or a.targets or a.roles)
    problems: list[str] = []
    if a.skills or all_parts:
        problems += sync_skills(a.check)
    if a.targets or all_parts:
        problems += sync_targets(a.check)
    if a.roles or all_parts:
        problems += sync_roles(a.check)

    if problems:
        head = "OUT OF SYNC" if a.check else "PROBLEMS"
        print(f"{head} ({len(problems)}):")
        for p in problems[:40]:
            print(f"  - {p}")
        if len(problems) > 40:
            print(f"  … {len(problems) - 40} more")
        return 1
    print("clients in sync" if a.check else "clients synced")
    return 0


if __name__ == "__main__":
    sys.exit(main())
