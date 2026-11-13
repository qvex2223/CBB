#!/usr/bin/env python3
"""Who holds a browser lane right now, and whether it goes through Caido.

Two consumers, one source of truth:

  * `scripts/mcp-gate.py` refuses to pause Caido's intercept queue while a live
    browser is proxied through it. A paused queue HOLDS every request instead of
    forwarding it, so the browser retries until Chromium gives up with
    `net::ERR_TOO_MANY_RETRIES`. Measured 2026-11-11:
    four navigations failed, the agent read the intercept status, paused the queue
    looking for the request, and every navigation after that failed the same way in
    under half a second.
  * `engine/browser_doctor.py` prints the same state when a navigation has failed
    and the next move has to be chosen from facts rather than from retrying.

The lock file is written by `runtime/browser-lock.mjs` (`.cbh-browser.lock` inside
`Targets/<platform>/<program>/browser-profile/`): `{pid, label, started_at, profile}`.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

LOCK_NAME = ".cbh-browser.lock"
PROFILE_DIR_NAME = "browser-profile"
ENGINE_ENV = "CBH_PLAYWRIGHT_BROWSER"
ENGINES = ("chromium", "firefox", "webkit")


def engine_name(env=None) -> str:
    """Which Playwright engine this engagement's browser lane runs.

    Same knob and same default as runtime/playwright-mcp.mjs: CBH_PLAYWRIGHT_BROWSER,
    chromium unless told otherwise. An unknown value reads as the default here rather
    than exiting, because this is a reporting path; the wrapper is the one that refuses.
    """
    env = os.environ if env is None else env
    name = (env.get(ENGINE_ENV) or "").strip().lower()
    return name if name in ENGINES else "chromium"


def profile_dir_name(engine=None, env=None) -> str:
    """A Chromium user-data-dir is not a Firefox profile, so each engine gets its own.

    Mirrors runtime/playwright-mcp.mjs exactly: `browser-profile` for chromium,
    `browser-profile-<engine>` otherwise. Anything that resolves the profile dir by
    the bare constant hands the operator's login to the wrong engine's directory.
    """
    eng = (engine or engine_name(env)).lower()
    return PROFILE_DIR_NAME if eng == "chromium" else f"{PROFILE_DIR_NAME}-{eng}"


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _targets_root() -> Path:
    try:
        from paths import targets_root  # type: ignore
        return Path(targets_root())
    except Exception:  # noqa: BLE001
        return _repo_root() / "Targets"


def pid_alive(pid) -> bool:
    try:
        pid = int(pid)
    except Exception:  # noqa: BLE001
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:          # exists, owned by someone else
        return True
    except OSError:
        return False


def engagement_is_direct(project_dir: Path) -> bool:
    """True when this engagement's browser bypasses Caido (playwright-direct marker).

    `runtime/playwright-mcp.mjs` reads the same two paths: the marker is how an
    engagement whose target RSTs a MITM'd HTTP/2 connection keeps a working browser.
    """
    return ((project_dir / "playwright-direct").exists()
            or (project_dir / PROFILE_DIR_NAME / "direct").exists())


def caido_off() -> bool:
    """True when this process's environment takes the browser off Caido anyway."""
    if os.environ.get("CBH_PLAYWRIGHT_PROXY"):
        return True
    return (os.environ.get("CBH_PLAYWRIGHT_CAIDO") or "on").lower() == "off"


def live_lanes(root: Path | None = None) -> list[dict]:
    """Every engagement browser profile whose lock is held by a live process."""
    base = Path(root) / "Targets" if root else _targets_root()
    lanes: list[dict] = []
    try:
        locks = sorted(base.glob(f"**/{PROFILE_DIR_NAME}/{LOCK_NAME}"))
    except Exception:  # noqa: BLE001
        return lanes
    for lock in locks:
        try:
            holder = json.loads(lock.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if not pid_alive(holder.get("pid")):
            continue                  # stale: browser-lock.mjs breaks it on next use
        project_dir = lock.parent.parent
        lanes.append({
            "pid": holder.get("pid"),
            "label": holder.get("label") or "unlabelled lane",
            "started_at": holder.get("started_at") or "",
            "profile": str(lock.parent),
            "project_dir": str(project_dir),
            "engagement": project_dir.name,
            "via_caido": not (engagement_is_direct(project_dir) or caido_off()),
        })
    return lanes


def caido_proxied_lanes(root: Path | None = None) -> list[dict]:
    return [lane for lane in live_lanes(root) if lane["via_caido"]]


__all__ = ["LOCK_NAME", "PROFILE_DIR_NAME", "live_lanes", "caido_proxied_lanes",
           "engagement_is_direct", "caido_off", "pid_alive"]
