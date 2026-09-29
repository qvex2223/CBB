#!/usr/bin/env python3
"""
gen_inventory.py — the bundle's own inventory, read off the filesystem.

Every count in this repo's documentation was written by hand and then drifted:
README said 54 skills, USAGE said 54 skills / 14 commands, CLAUDE.md said 62/16,
and the tree actually held 62/17. The same happened to the Burp MCP port — docs
carried 9876 while the runtime had moved to 8181. A number nobody can regenerate
is a number that will be wrong again next month.

So: one generator, one JSON artifact, and a `--check` mode a test can call.

    python3 scripts/gen_inventory.py              # print the inventory
    python3 scripts/gen_inventory.py --write      # refresh docs/inventory.json
    python3 scripts/gen_inventory.py --check      # exit 1 if any doc disagrees
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_BURP_PORT = "8181"

# Files whose prose carries counts/ports that must match the tree.
#
# CHANGELOG.md is deliberately absent: it records what the inventory *was* at each
# release ("51 -> 71 skills"). Rewriting history to match today's tree would turn the
# one honest record of the bundle's past into another thing that has to be maintained.
CHECKED_DOCS = ("README.md", "USAGE.md", "INSTALL.md", "pyproject.toml",
                "docs/index.md", "docs/architecture.md", "docs/credits.md",
                "docs/skills.md", "docs/multi-harness.md", "docs/cbh-cli.md",
                "eval/README.md",
                ".claude-plugin/plugin.json", ".claude-plugin/marketplace.json")

# Not every count is an inventory claim: credits.md counts what was vendored from
# upstream and what was derived from disclosed reports, and those numbers are facts
# about provenance that must NOT track the tree. Such a line opts out explicitly, so
# the exemption is visible where it applies instead of hidden in this file.
EXEMPT_RE = re.compile(r"inventory-exempt", re.I)

SKILL_COUNT_RE = re.compile(r"\*{0,2}(\d+)[\s-]skills?\*{0,2}", re.I)
COMMAND_COUNT_RE = re.compile(r"\*{0,2}(\d+)\s+(?:slash\s+)?commands?\*{0,2}", re.I)
PORT_RE = re.compile(r"\b9876\b")
PYVER_RE = re.compile(r"Python\s*3\.9\+|requires-python\s*=\s*\">=3\.9\"", re.I)


def burp_port() -> str:
    """Read the port the runtime actually uses, not the one a doc remembers."""
    client = REPO / "runtime" / "client.mjs"
    if client.is_file():
        m = re.search(r"127\.0\.0\.1:(\d+)/mcp/sse", client.read_text())
        if m:
            return m.group(1)
    return DEFAULT_BURP_PORT


def inventory() -> dict:
    skills = sorted(p.name for p in (REPO / "skills").iterdir()
                    if p.is_dir() and (p / "SKILL.md").is_file())
    commands = sorted(p.stem for p in (REPO / "commands").glob("*.md"))
    engine = sorted(p.stem for p in (REPO / "engine").glob("*.py")
                    if not p.name.startswith("_"))
    return {
        "skills": len(skills), "skill_names": skills,
        "hunt_skills": sum(1 for n in skills if n.startswith("hunt-")),
        "commands": len(commands), "command_names": commands,
        "engine_modules": len(engine), "engine_module_names": engine,
        "burp_mcp_port": burp_port(),
        "manifest_schema_version": _manifest_schema_version(),
        "requires_python": _requires_python(),
    }


def _manifest_schema_version() -> str:
    src = (REPO / "engine" / "api_manifest.py").read_text()
    m = re.search(r'SCHEMA_VERSION\s*=\s*"([^"]+)"', src)
    return m.group(1) if m else "?"


def _requires_python() -> str:
    """The floor the code actually needs. `X | None` annotations are 3.10+."""
    return ">=3.10"


def check(inv: dict) -> list[str]:
    problems = []
    for rel in CHECKED_DOCS:
        path = REPO / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            where = f"{rel}:{lineno}"
            if EXEMPT_RE.search(line):
                continue
            for m in SKILL_COUNT_RE.finditer(line):
                n = int(m.group(1))
                # Sub-counts are real claims too, just about a subset — `hunt_skills` is
                # generated alongside the total so the docs can state it and still be checked.
                if n == inv["hunt_skills"]:
                    continue
                # small numbers are prose ("2-3 skills"), not inventory claims
                if n >= 20 and n != inv["skills"]:
                    problems.append(f"{where}: claims {n} skills, tree has {inv['skills']}")
            for m in COMMAND_COUNT_RE.finditer(line):
                n = int(m.group(1))
                if n >= 10 and n != inv["commands"]:
                    problems.append(f"{where}: claims {n} commands, tree has {inv['commands']}")
            if PORT_RE.search(line):
                problems.append(f"{where}: stale Burp MCP port 9876 "
                                f"(runtime uses {inv['burp_mcp_port']})")
            if PYVER_RE.search(line):
                problems.append(f"{where}: claims Python 3.9 — the code uses `X | None`, "
                                f"which needs {inv['requires_python']}")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="refresh docs/inventory.json")
    ap.add_argument("--check", action="store_true", help="exit 1 if any doc disagrees")
    args = ap.parse_args(argv)

    inv = inventory()
    if args.write:
        out = REPO / "docs" / "inventory.json"
        out.write_text(json.dumps(inv, indent=2) + "\n")
        print(f"wrote {out}")

    if args.check:
        problems = check(inv)
        for p in problems:
            print(f"STALE  {p}")
        print(f"\n{len(problems)} stale reference(s). Tree: {inv['skills']} skills, "
              f"{inv['commands']} commands, Burp MCP :{inv['burp_mcp_port']}, "
              f"manifest schema {inv['manifest_schema_version']}.")
        return 1 if problems else 0

    if not args.write:
        print(json.dumps({k: v for k, v in inv.items() if not k.endswith("_names")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
