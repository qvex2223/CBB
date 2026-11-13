#!/usr/bin/env python3
"""`cbh hunt-stop` — disarm hunt mode for this session (see engine/hunt_start.py)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hunt_start import stop_main  # noqa: E402


def main(argv=None) -> int:
    return stop_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
