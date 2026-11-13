#!/usr/bin/env python3
"""
error-log — the hook that makes a tool error durable.

Wired twice, deliberately:

  PostToolUseFailure   matcher .*     every tool that fails outright, any tool,
                                      main thread or subagent. Failures are rare,
                                      so a wildcard matcher costs nothing.
  PostToolUse          matcher Bash   a Bash call that SUCCEEDED as a tool call but
                                      whose command returned non-zero. That is not a
                                      tool failure and raises no PostToolUseFailure,
                                      and it is where gate refusals live (bbcurl
                                      exit 3, bbscan exit 2, a selftest exit 1).

Everything lands in `hunt-memory/errors.jsonl`. Read it with `cbh errors`.

This hook must never block or fail a tool, so it swallows every exception and
always exits 0.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))


def main() -> int:
    try:
        ev = json.loads(sys.stdin.read() or "{}")
    except Exception:  # noqa: BLE001
        return 0
    try:
        from error_log import record  # type: ignore
        record(ev)
    except Exception:  # noqa: BLE001
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
