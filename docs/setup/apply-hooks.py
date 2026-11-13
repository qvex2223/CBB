#!/usr/bin/env python3
"""Merge docs/setup/hooks.json into ~/.claude/settings.json.

The enforcement layer in this workspace is hooks: the MCP scope/pacing gate, the
skill gate, the grind nudge, the stop gate, the session brief. None of it runs until
Claude Code is told about it, and an unwired workspace looks identical to a wired one
until a request goes out ungated.

Claude cannot edit ~/.claude/settings.json itself (self-modification is refused by
design), so this is the operator's one command:

    python3 docs/setup/apply-hooks.py            # show what would change
    python3 docs/setup/apply-hooks.py --apply    # write it, after a timestamped backup

It replaces the `hooks` block wholesale and merges `env` key by key. Everything else
in the file is left untouched.
"""
from __future__ import annotations

import argparse
import datetime
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SETTINGS = Path.home() / ".claude" / "settings.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="write the change")
    ap.add_argument("--settings", default=str(SETTINGS))
    a = ap.parse_args()

    want = json.loads((HERE / "hooks.json").read_text(encoding="utf-8"))
    target = Path(a.settings).expanduser()
    current = json.loads(target.read_text(encoding="utf-8")) if target.is_file() else {}

    merged = dict(current)
    merged["env"] = dict(current.get("env") or {}, **want["env"])
    merged["hooks"] = want["hooks"]

    if merged == current:
        print(f"{target}: already wired, nothing to do.")
        return 0

    have = sorted((current.get("hooks") or {}).keys())
    print(f"{target}")
    print(f"  hooks now:   {have or 'none'}")
    print(f"  hooks after: {sorted(want['hooks'].keys())}")
    print(f"  env adds:    {', '.join(want['env'])}")
    if not a.apply:
        print("\nDry run. Re-run with --apply to write it.")
        return 0

    if target.is_file():
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = target.with_name(target.name + f".bak-{stamp}")
        shutil.copy2(target, backup)
        print(f"  backup: {backup}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    print("  written. Restart Claude Code (hooks load at session start).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
