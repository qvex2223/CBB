#!/usr/bin/env python3
"""
pacing.py — per-engagement request pacing and mandatory headers, enforced in code.

Both of these lived as prose in `Targets/<name>/CLAUDE.md` and neither was
enforced anywhere:

  * "GLOBAL, not per-host: max 1 request every 10-15s across the whole active
    target set" — written after an estate-wide IP ban on the Allur engagement
    (2026-07-14). Nothing in the tooling slept.
  * RTEAM's "`X-Bug-Bounty: <login>` header MANDATORY on every request" — a
    program rule that a forgotten header quietly violates.

A rule that only exists in the prompt has two failure modes: it gets forgotten,
and — worse — it makes the agent reluctant to send anything at all, because
every request looks like a chance to break it. Moving the brake here means the
prompt no longer has to carry it, and the agent is free to actually fire.

The gate is an inter-process one: the last-fire timestamp lives in a file under
the hunt-memory directory and is held under `flock` across the sleep, so two
concurrent sessions/tool-calls against the same engagement queue behind each
other instead of both deciding they are within budget.

Engagement config lives in `Targets/<name>/profile.json`:

    {
      "project": "kcell",
      "min_interval_seconds": 12,
      "required_headers": {"X-Bug-Bounty": "myhandle"},
      "max_concurrency": 2,
      "note": "pacing carried over from the Allur IP-ban incident"
    }

Resolution order for "which engagement am I in": $CBH_PROJECT, else the first
ancestor directory of the cwd whose parent is named `Targets`.

Stdlib only. No network.

Usage (library):
    from pacing import Engagement
    eng = Engagement.detect()
    eng.apply_headers(spec_headers)   # raises if a required header is unset
    waited = eng.wait_turn()          # blocks until this engagement's budget allows

Usage (CLI):
    python3 engine/pacing.py --status
    python3 engine/pacing.py --selftest
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# An engagement folder with no profile.json still gets paced. Being inside
# Targets/<name>/ means there is a live program with rate limits on the other
# end; silence in the config is not permission to hammer it.
DEFAULT_MIN_INTERVAL = 10.0
PROFILE_NAME = "profile.json"


def _memory_dir() -> Path:
    """Where pacing state lives. Shares hunt-memory's resolution so a workspace
    has exactly one state root, not two."""
    try:
        from memory import resolve_dir  # noqa: PLC0415 - optional sibling module
        return resolve_dir()
    except Exception:  # noqa: BLE001 - pacing must work even if memory.py is absent
        env = os.environ.get("CBH_MEMORY_DIR")
        if env:
            return Path(env).expanduser()
        local = Path.cwd() / "hunt-memory"
        if local.is_dir():
            return local
        return Path.home() / ".cbh" / "hunt-memory"


def find_project_dir(start: Path | None = None) -> Path | None:
    """Locate the current engagement folder, or None if we are not in one.

    $CBH_PROJECT names an engagement explicitly; otherwise we walk up from the
    cwd looking for a directory sitting directly inside a `Targets` folder, so
    running from `Targets/kcell/hosts/` resolves to `Targets/kcell`.
    """
    here = (start or Path.cwd()).resolve()
    named = os.environ.get("CBH_PROJECT")
    if named:
        for parent in [here, *here.parents]:
            candidate = parent / "Targets" / named
            if candidate.is_dir():
                return candidate
        return None
    for parent in [here, *here.parents]:
        if parent.parent.name == "Targets" and parent.is_dir():
            return parent
    return None


class MissingRequiredHeader(RuntimeError):
    """A program mandates a header whose value is not configured. Refuse to fire.

    Sending the request without it would violate the program's own rules, and
    guessing the value (a handle, a tracking token) is not something the tooling
    gets to do on the researcher's behalf.
    """


class Engagement:
    """One program's pacing budget and mandatory-header set."""

    def __init__(self, project_dir: Path | None, profile: dict | None = None,
                 state_dir: Path | None = None):
        self.project_dir = project_dir
        self.name = project_dir.name if project_dir else None
        self.profile = profile if profile is not None else self._load_profile()
        self.state_dir = state_dir or (_memory_dir() / "pacing")

    # -- construction ------------------------------------------------------
    @classmethod
    def detect(cls, start: Path | None = None) -> "Engagement":
        return cls(find_project_dir(start))

    def _load_profile(self) -> dict:
        if not self.project_dir:
            return {}
        path = self.project_dir / PROFILE_NAME
        if not path.is_file():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            # A malformed profile must not silently downgrade to "no pacing" —
            # that is the exact failure the file exists to prevent.
            raise RuntimeError(f"{path}: unreadable engagement profile ({e})") from e

    # -- policy ------------------------------------------------------------
    @property
    def min_interval(self) -> float:
        if self.project_dir is None:
            return 0.0
        raw = self.profile.get("min_interval_seconds", DEFAULT_MIN_INTERVAL)
        try:
            return max(0.0, float(raw))
        except (TypeError, ValueError):
            return DEFAULT_MIN_INTERVAL

    @property
    def required_headers(self) -> dict:
        headers = self.profile.get("required_headers") or {}
        return headers if isinstance(headers, dict) else {}

    @property
    def max_concurrency(self) -> int:
        try:
            return max(1, int(self.profile.get("max_concurrency", 1)))
        except (TypeError, ValueError):
            return 1

    @property
    def allow_bulk_tools(self) -> bool:
        return self.profile.get("allow_bulk_tools") is True

    @property
    def allow_write_probes(self) -> bool:
        return self.profile.get("allow_write_probes") is True

    @property
    def allow_oob(self) -> bool:
        """Does this program permit out-of-band (Collaborator/DNS) callbacks?

        Default false: the callback resolves through a third-party server, so the
        interaction data leaves this machine. RTEAM forbids DNS exfiltration
        outright, and "the program never said no" is not authorization.
        """
        return self.profile.get("allow_oob") is True

    def apply_headers(self, headers: dict | None) -> dict:
        """Merge the program's mandatory headers into a request's headers.

        Explicit values in the spec win — the researcher overriding a header by
        hand is a deliberate act. An unset required value is fatal.
        """
        merged = dict(headers or {})
        present = {k.lower() for k in merged}
        missing = []
        for key, value in self.required_headers.items():
            if value in (None, "", "TODO"):
                missing.append(key)
                continue
            if key.lower() not in present:
                merged[key] = value
        if missing:
            raise MissingRequiredHeader(
                f"{self.name}: required header(s) {', '.join(missing)} have no value in "
                f"{PROFILE_NAME}. Set them before firing — this program rejects requests without them.")
        return merged

    # -- the gate ----------------------------------------------------------
    def _state_path(self) -> Path:
        return self.state_dir / f"{self.name}.json"

    def wait_turn(self, now=None) -> float:
        """Block until this engagement's budget allows another request.

        Returns the number of seconds actually slept. The lock is held across
        the sleep on purpose: a second process arriving mid-wait must queue
        behind this one rather than race it.
        """
        interval = self.min_interval
        if interval <= 0 or self.name is None:
            return 0.0
        self.state_dir.mkdir(parents=True, exist_ok=True)
        path = self._state_path()
        clock = now or time.time
        with open(path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                fh.seek(0)
                raw = fh.read().strip()
                last = 0.0
                count = 0
                if raw:
                    try:
                        state = json.loads(raw)
                        last = float(state.get("last_fire", 0.0))
                        count = int(state.get("count", 0))
                    except (json.JSONDecodeError, TypeError, ValueError):
                        pass  # corrupt state -> treat as first request, then rewrite it
                waited = 0.0
                gap = clock() - last
                if 0 <= gap < interval:
                    waited = interval - gap
                    time.sleep(waited)
                fh.seek(0)
                fh.truncate()
                json.dump({"project": self.name, "last_fire": clock(),
                           "count": count + 1, "min_interval_seconds": interval}, fh)
                fh.flush()
                return waited
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def status(self) -> dict:
        path = self._state_path()
        state = {}
        if path.is_file():
            try:
                state = json.loads(path.read_text(encoding="utf-8") or "{}")
            except json.JSONDecodeError:
                state = {}
        last = float(state.get("last_fire", 0.0))
        remaining = max(0.0, self.min_interval - (time.time() - last)) if last else 0.0
        return {
            "project": self.name,
            "project_dir": str(self.project_dir) if self.project_dir else None,
            "profile_found": bool(self.profile),
            "min_interval_seconds": self.min_interval,
            "required_headers": sorted(self.required_headers),
            "requests_paced": state.get("count", 0),
            "seconds_until_next": round(remaining, 1),
            "state_file": str(path),
        }


# -- selftest --------------------------------------------------------------
def _selftest() -> int:
    import tempfile

    failures = []

    def check(label, cond):
        if not cond:
            failures.append(label)
        print(f"  {'ok  ' if cond else 'FAIL'} {label}")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        proj = root / "Targets" / "acme"
        (proj / "hosts").mkdir(parents=True)
        (proj / PROFILE_NAME).write_text(json.dumps({
            "project": "acme",
            "min_interval_seconds": 0.4,
            "required_headers": {"X-Bug-Bounty": "handle"},
        }), encoding="utf-8")

        print("project resolution")
        check("resolves from a subdirectory", find_project_dir(proj / "hosts") == proj)
        check("returns None outside Targets/", find_project_dir(root) is None)

        eng = Engagement(proj, state_dir=root / "state")
        print("headers")
        check("required header injected", eng.apply_headers({})["X-Bug-Bounty"] == "handle")
        check("explicit spec value wins",
              eng.apply_headers({"X-Bug-Bounty": "other"})["X-Bug-Bounty"] == "other")
        unset = Engagement(proj, profile={"required_headers": {"X-Bug-Bounty": "TODO"}},
                           state_dir=root / "state")
        try:
            unset.apply_headers({})
            check("unset required header refuses to fire", False)
        except MissingRequiredHeader:
            check("unset required header refuses to fire", True)

        print("pacing gate")
        check("first request does not wait", eng.wait_turn() == 0.0)
        started = time.time()
        waited = eng.wait_turn()
        elapsed = time.time() - started
        check("second request is delayed", waited > 0 and elapsed >= 0.35)
        check("counter persists", eng.status()["requests_paced"] == 2)

        print("defaults")
        bare = Engagement(proj, profile={}, state_dir=root / "state")
        check("engagement without profile still paced",
              bare.min_interval == DEFAULT_MIN_INTERVAL)
        nowhere = Engagement(None, state_dir=root / "state")
        check("outside an engagement, no pacing", nowhere.min_interval == 0.0)
        check("outside an engagement, wait is a no-op", nowhere.wait_turn() == 0.0)

        print("robustness")
        (root / "state" / "acme.json").write_text("{not json", encoding="utf-8")
        check("corrupt state file does not raise", eng.wait_turn() >= 0.0)
        (proj / PROFILE_NAME).write_text("{broken", encoding="utf-8")
        try:
            Engagement(proj)
            check("malformed profile is fatal, not silently unpaced", False)
        except RuntimeError:
            check("malformed profile is fatal, not silently unpaced", True)

    print()
    if failures:
        print(f"SELFTEST FAILED — {len(failures)} check(s): {', '.join(failures)}")
        return 1
    print("SELFTEST PASSED")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="pacing.py",
        description="Per-engagement request pacing and mandatory headers.")
    ap.add_argument("--status", action="store_true",
                    help="show the detected engagement, its budget and time until the next request")
    ap.add_argument("--selftest", action="store_true", help="run the built-in checks")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()

    eng = Engagement.detect()
    st = eng.status()
    if not st["project"]:
        print("No engagement detected (not inside a Targets/<name>/ folder). Pacing disabled.")
        return 0
    print(f"engagement:        {st['project']}  ({st['project_dir']})")
    print(f"profile.json:      {'found' if st['profile_found'] else 'MISSING — using defaults'}")
    print(f"min interval:      {st['min_interval_seconds']}s (global, all hosts)")
    print(f"required headers:  {', '.join(st['required_headers']) or '(none)'}")
    print(f"requests paced:    {st['requests_paced']}")
    print(f"next request in:   {st['seconds_until_next']}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
