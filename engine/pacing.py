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
      "required_cookie": {"X_Bug_Bounty": "myhandle"},
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

# -- throttle response ------------------------------------------------------
# The flat interval above is a budget, not a brake: it does not react to the
# target saying stop. Measured on standoff365/mail_vk 2026-11-12 21:14:10-22,
# twelve consecutive `429`s came back from light.mail.ru, octavius.mail.ru and
# wallet.mail.ru, and the NEXT request left one second later in eleven of the
# twelve cases — four of them aimed at the host that had just refused. The
# engagement's own rule is "respect rate limits", and nothing enforced it.
#
# So a throttling status arms a per-host penalty that the next wait_turn()
# honours. Retry-After wins when the target states one; otherwise the penalty
# doubles per consecutive strike, because a target that says 429 three times in
# a row is not asking for a one-second pause.
THROTTLE_STATUSES = (429,)
THROTTLE_BASE_SECONDS = 60.0
THROTTLE_CAP_SECONDS = 900.0
# Clean seconds that clear the strike count. Shorter than the cap on purpose:
# one 429 an hour is noise, five in a minute is a ban forming.
THROTTLE_STRIKE_RESET = 600.0
# A penalty longer than this is refused rather than slept through. A worker turn
# that blocks for fifteen minutes is killed and loses its lane; a refusal naming
# the host and the time is something the lane can act on by moving elsewhere.
THROTTLE_MAX_SLEEP = 120.0


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
        # Resolve against the workspace's own Targets root FIRST, because cwd is
        # not a reliable anchor: a worker running from a scratchpad directory
        # (outside the workspace tree) used to resolve to None, and `bbcurl` then
        # refused every request while reporting only on stderr — which callers
        # discard. One sweep produced a full 142-row table of pure 404s that
        # looked like clean data and had fired nothing at all. Same failure class
        # as the old `/opt/Claude` hard-coding: resolves to nothing, exits clean,
        # logs success. `CBH_PROJECT` names an engagement; where the shell happens
        # to be standing must not change which one it names.
        try:
            from paths import targets_root  # noqa: PLC0415 - optional sibling module
            candidate = targets_root() / named
            if candidate.is_dir():
                return candidate
        except Exception:  # noqa: BLE001 - fall through to the cwd walk
            pass
        for parent in [here, *here.parents]:
            candidate = parent / "Targets" / named
            if candidate.is_dir():
                return candidate
        return None
    # Nested engagements (Targets/<platform>/<program>/): the nearest folder
    # under Targets/ that carries its own profile.json is the engagement, so a
    # platform hub can hold one folder per program with its own scope + pacing.
    for parent in [here, *here.parents]:
        if parent.parent.name == "Targets":
            break
        if (parent / PROFILE_NAME).is_file() and any(a.name == "Targets" for a in parent.parents):
            return parent
    for parent in [here, *here.parents]:
        if parent.parent.name == "Targets" and parent.is_dir():
            return parent
    return None


class ThrottledHost(RuntimeError):
    """The target told us to slow down and the penalty outlasts a sane sleep.

    Raised instead of blocking, so the caller can record the wall and pick a
    different host rather than holding a worker turn open until it is killed.
    """

    def __init__(self, host: str, until: float, strikes: int,
                 retry_after: float | None = None):
        self.host = host
        self.until = until
        self.strikes = strikes
        self.retry_after = retry_after
        remaining = max(0.0, until - time.time())
        source = (f"the target's own Retry-After ({retry_after:g}s)"
                  if retry_after else f"{strikes} consecutive throttling response(s)")
        super().__init__(
            f"{host}: throttled for another {remaining:.0f}s, from {source}. "
            f"Nothing was sent. Work another host, or wait it out "
            f"(`python3 engine/pacing.py --status` shows the clock).")


class MissingRequiredCookie(RuntimeError):
    """A programme mandates a cookie and `profile.json` has no value for it.

    Distinct from MissingRequiredHeader because the remedy is a different profile key and
    a different curl flag (`-b`, never `-H Cookie:`).
    """


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
    def required_cookies(self) -> dict:
        """Cookie name -> value this programme mandates on every request.

        A separate field from `required_headers`, because a cookie CANNOT be delivered as
        one. `apply_headers` merges by header name and bbcurl emits `-H "Cookie: ..."`;
        curl lets an explicit `-H Cookie:` replace the header it would have built from
        `-b`, so a mandatory cookie expressed as a header silently drops an authenticated
        lane's session jar. hh.ru is exactly this shape — its programme text asks for an
        `X_Bug_Bounty` **cookie** parameter, and `scope.md` says "(not a header!)" — and
        with nowhere to put it the identification lived in worker briefs instead: 1 of 1823
        requests went out unidentified on 2026-11-14.

            "required_cookie": {"X_Bug_Bounty": "qvex"}
        """
        cookies = self.profile.get("required_cookie") or {}
        return cookies if isinstance(cookies, dict) else {}

    def missing_cookie_values(self) -> list:
        """Required cookie names whose value is unset — same rule as a required header."""
        return [k for k, v in self.required_cookies.items() if v in (None, "", "TODO")]

    def apply_cookies(self, present: dict | None) -> dict:
        """The required pairs this request still needs, given the ones already on it.

        Returns only what is MISSING, so the caller merges rather than replaces: a lane
        carrying a session jar keeps it and gains the identification pair. An explicit
        value wins, exactly like `apply_headers` — a researcher overriding by hand is a
        deliberate act.
        """
        missing = self.missing_cookie_values()
        if missing:
            raise MissingRequiredCookie(
                f"{self.name}: required cookie(s) {', '.join(missing)} have no value in "
                f"{PROFILE_NAME}. Set them before firing — this programme rejects or blocks "
                f"requests without them.")
        have = {str(k).lower() for k in (present or {})}
        return {k: v for k, v in self.required_cookies.items() if k.lower() not in have}

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

    def wait_turn(self, now=None, requests: int = 1, hosts=()) -> float:
        """Block until this engagement's budget allows another request.

        Returns the number of seconds actually slept. The lock is held across
        the sleep on purpose: a second process arriving mid-wait must queue
        behind this one rather than race it.

        `requests` is how many requests the caller is about to fire in ONE go.
        One `bbcurl` invocation may carry many URLs, and curl then fires them
        back to back; waiting once for the batch under-paced the programme by a
        factor of N (measured 2026-11-04: a 2,420-request pass whose batches had
        to be hand-throttled with curl's own `--rate`). The budget is therefore
        advanced by the whole batch, so the next process queues behind all of it,
        and `bbcurl` injects `--rate` so the batch is spaced internally too.

        `hosts` are the hostnames this call is about to reach. Any of them
        carrying an armed throttle penalty (see `note_throttle`) is waited out
        first, or refused with `ThrottledHost` when the penalty is longer than
        `THROTTLE_MAX_SLEEP`. Passing nothing keeps the old behaviour exactly.
        """
        interval = self.min_interval
        if interval <= 0 or self.name is None:
            return 0.0
        # A throttling response from one of these hosts outranks the flat budget:
        # the target has said stop, and the budget has no opinion about that.
        # Raises ThrottledHost when the penalty is too long to sleep through.
        penalty_waited = self.throttle_wait(hosts, now=now)
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
                waited = penalty_waited
                gap = clock() - last
                if 0 <= gap < interval:
                    waited = interval - gap
                    time.sleep(waited)
                n = max(1, int(requests))
                fh.seek(0)
                fh.truncate()
                # last_fire is pushed to the END of this batch: the caller is about
                # to fire n requests spaced `interval` apart, so the next process
                # must wait past the last of them, not past the first.
                json.dump({"project": self.name, "last_fire": clock() + (n - 1) * interval,
                           "count": count + n, "min_interval_seconds": interval}, fh)
                fh.flush()
                return waited
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    # -- throttle penalties ------------------------------------------------
    def _throttle_path(self) -> Path:
        return self.state_dir / f"{self.name}.throttle.json"

    def _read_throttle(self) -> dict:
        path = self._throttle_path()
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8") or "{}")
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _retry_after_seconds(value, now: float) -> float | None:
        """Parse a Retry-After header value: delta-seconds or an HTTP-date.

        Returns None for anything unparseable, and never a negative wait — a
        date already in the past means the penalty is over, not that we owe
        negative time.
        """
        if value in (None, ""):
            return None
        raw = str(value).strip()
        try:
            return max(0.0, float(raw))
        except ValueError:
            pass
        try:
            from email.utils import parsedate_to_datetime  # noqa: PLC0415 - stdlib, parse-only
            when = parsedate_to_datetime(raw)
        except Exception:  # noqa: BLE001 - a malformed date is simply no Retry-After
            return None
        if when is None:
            return None
        try:
            return max(0.0, when.timestamp() - now)
        except (OverflowError, OSError, ValueError):
            return None

    def note_throttle(self, host: str, status, retry_after=None, now=None) -> dict | None:
        """Record a throttling response and arm this host's penalty.

        Returns the penalty record, or None when the status is not a throttle or
        we are not inside an engagement. Called after the response is read, so it
        never blocks the request that produced it — it brakes the NEXT one.
        """
        if self.name is None or not host:
            return None
        try:
            code = int(status)
        except (TypeError, ValueError):
            return None
        if code not in THROTTLE_STATUSES:
            return None
        clock = now or time.time
        ts = clock()
        stated = self._retry_after_seconds(retry_after, ts)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        path = self._throttle_path()
        with open(path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                fh.seek(0)
                raw = fh.read().strip()
                data = {}
                if raw:
                    try:
                        loaded = json.loads(raw)
                        if isinstance(loaded, dict):
                            data = loaded
                    except json.JSONDecodeError:
                        pass  # corrupt penalty file -> start this host's count over
                prev = data.get(host) if isinstance(data.get(host), dict) else {}
                last = float(prev.get("last", 0.0) or 0.0)
                strikes = int(prev.get("strikes", 0) or 0)
                if ts - last > THROTTLE_STRIKE_RESET:
                    strikes = 0
                strikes += 1
                if stated is not None:
                    penalty = min(stated, THROTTLE_CAP_SECONDS)
                else:
                    penalty = min(THROTTLE_BASE_SECONDS * (2 ** (strikes - 1)),
                                  THROTTLE_CAP_SECONDS)
                record = {"host": host, "status": code, "strikes": strikes,
                          "last": ts, "until": ts + penalty,
                          "penalty_seconds": round(penalty, 1),
                          "retry_after": stated}
                data[host] = record
                # Drop hosts whose penalty expired long ago, so the file does not
                # grow one entry per host for the life of the engagement.
                data = {h: r for h, r in data.items()
                        if isinstance(r, dict)
                        and ts - float(r.get("last", 0.0) or 0.0) <= THROTTLE_STRIKE_RESET}
                fh.seek(0)
                fh.truncate()
                json.dump(data, fh)
                fh.flush()
                return record
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def throttle_wait(self, hosts, now=None) -> float:
        """Sleep out any armed penalty on these hosts before the next request.

        Raises ThrottledHost when the remaining penalty exceeds
        THROTTLE_MAX_SLEEP: the caller is told which host, for how long and why,
        instead of having its turn consumed by a quarter-hour sleep.
        """
        if self.name is None:
            return 0.0
        wanted = [h for h in (hosts or []) if h]
        if not wanted:
            return 0.0
        data = self._read_throttle()
        if not data:
            return 0.0
        clock = now or time.time
        worst = None
        for host in wanted:
            rec = data.get(host)
            if not isinstance(rec, dict):
                continue
            remaining = float(rec.get("until", 0.0) or 0.0) - clock()
            if remaining <= 0:
                continue
            if worst is None or remaining > worst[0]:
                worst = (remaining, rec)
        if worst is None:
            return 0.0
        remaining, rec = worst
        if remaining > THROTTLE_MAX_SLEEP:
            raise ThrottledHost(str(rec.get("host") or "?"),
                                float(rec.get("until", 0.0) or 0.0),
                                int(rec.get("strikes", 0) or 0),
                                rec.get("retry_after"))
        time.sleep(remaining)
        return remaining

    def throttled_hosts(self, now=None) -> list[dict]:
        """Every host with an unexpired penalty, worst first (for --status)."""
        clock = now or time.time
        ts = clock()
        live = []
        for rec in self._read_throttle().values():
            if not isinstance(rec, dict):
                continue
            remaining = float(rec.get("until", 0.0) or 0.0) - ts
            if remaining > 0:
                live.append({**rec, "seconds_remaining": round(remaining, 1)})
        return sorted(live, key=lambda r: -r["seconds_remaining"])

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
            "required_cookies": sorted(self.required_cookies),
            "requests_paced": state.get("count", 0),
            "seconds_until_next": round(remaining, 1),
            "state_file": str(path),
            "throttled_hosts": self.throttled_hosts(),
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
        nested = root / "Targets" / "platform" / "prog"
        (nested / "hosts").mkdir(parents=True)
        (nested / PROFILE_NAME).write_text("{}", encoding="utf-8")
        check("nested program with profile.json resolves to itself",
              find_project_dir(nested / "hosts") == nested)
        check("platform hub without profile.json resolves to the hub",
              find_project_dir(root / "Targets" / "platform") == root / "Targets" / "platform")
        os.environ["CBH_PROJECT"] = "platform/prog"
        check("CBH_PROJECT=platform/prog resolves", find_project_dir(root) == nested)
        del os.environ["CBH_PROJECT"]

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

        print("throttle backoff")
        thr = Engagement(proj, profile={"min_interval_seconds": 0.01},
                         state_dir=root / "state")
        check("a 200 arms nothing", thr.note_throttle("a.example.com", 200) is None)
        check("no penalty -> no wait", thr.throttle_wait(["a.example.com"]) == 0.0)
        rec = thr.note_throttle("a.example.com", 429)
        check("a 429 arms a penalty", rec is not None and rec["strikes"] == 1)
        check("first strike is the base penalty",
              rec["penalty_seconds"] == THROTTLE_BASE_SECONDS)
        rec2 = thr.note_throttle("a.example.com", 429)
        check("consecutive strikes double the penalty",
              rec2["strikes"] == 2 and rec2["penalty_seconds"] == THROTTLE_BASE_SECONDS * 2)
        check("an unthrottled host is unaffected",
              thr.throttle_wait(["b.example.com"]) == 0.0)
        rec3 = thr.note_throttle("a.example.com", 429)
        check("the third strike doubles again, past THROTTLE_MAX_SLEEP",
              rec3["strikes"] == 3
              and rec3["penalty_seconds"] == THROTTLE_BASE_SECONDS * 4
              and rec3["penalty_seconds"] > THROTTLE_MAX_SLEEP)
        try:
            thr.throttle_wait(["a.example.com"])
            check("a long penalty refuses instead of sleeping", False)
        except ThrottledHost as e:
            check("a long penalty refuses instead of sleeping",
                  "a.example.com" in str(e) and "Nothing was sent" in str(e))
        try:
            thr.wait_turn(hosts=["a.example.com"])
            check("wait_turn refuses a throttled host", False)
        except ThrottledHost:
            check("wait_turn refuses a throttled host", True)
        check("wait_turn still fires for an unthrottled host",
              thr.wait_turn(hosts=["b.example.com"]) >= 0.0)
        check("--status names the throttled host",
              [r["host"] for r in thr.throttled_hosts()] == ["a.example.com"])

        print("throttle: Retry-After wins over the strike count")
        ra = Engagement(proj, profile={"min_interval_seconds": 0.01},
                        state_dir=root / "state2")
        short = ra.note_throttle("c.example.com", 429, retry_after="2")
        check("delta-seconds Retry-After is honoured", short["penalty_seconds"] == 2.0)
        check("a short penalty is slept, not refused",
              0.0 < ra.throttle_wait(["c.example.com"]) <= 2.0)
        check("an HTTP-date Retry-After parses",
              ra.note_throttle("d.example.com", 429,
                               retry_after="Wed, 21 Oct 2026 07:28:00 GMT") is not None)
        check("a garbage Retry-After falls back to the backoff",
              ra.note_throttle("e.example.com", 429,
                               retry_after="soon")["penalty_seconds"] == THROTTLE_BASE_SECONDS)
        check("a Retry-After over the cap is capped",
              ra.note_throttle("f.example.com", 429,
                               retry_after="99999")["penalty_seconds"] == THROTTLE_CAP_SECONDS)
        nowhere2 = Engagement(None, state_dir=root / "state2")
        check("outside an engagement nothing is armed",
              nowhere2.note_throttle("c.example.com", 429) is None)

        print("robustness")
        (root / "state" / "acme.json").write_text("{not json", encoding="utf-8")
        check("corrupt state file does not raise", eng.wait_turn() >= 0.0)
        (root / "state" / "acme.throttle.json").write_text("{not json", encoding="utf-8")
        check("corrupt penalty file does not raise",
              Engagement(proj, profile={"min_interval_seconds": 0.01},
                         state_dir=root / "state").throttle_wait(["a.example.com"]) == 0.0)
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
    print(f"required cookies:  {', '.join(st.get('required_cookies') or []) or '(none)'}")
    print(f"requests paced:    {st['requests_paced']}")
    print(f"next request in:   {st['seconds_until_next']}s")
    throttled = st.get("throttled_hosts") or []
    if throttled:
        print(f"throttled hosts:   {len(throttled)} (target said slow down)")
        for rec in throttled:
            src = (f"Retry-After {rec['retry_after']:g}s" if rec.get("retry_after")
                   else f"{rec.get('strikes')} strike(s), backoff")
            print(f"  {rec.get('host')}  {rec['seconds_remaining']:.0f}s left "
                  f"[{rec.get('status')}, {src}]")
    else:
        print("throttled hosts:   (none)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
