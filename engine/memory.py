#!/usr/bin/env python3
"""
memory.py — persistent hunt memory (journal / patterns / audit / target profiles).

`/remember`, `/pickup`, `/surface` and `/memory-gc` were all documented against a
`hunt-memory/` directory and a `tools.memory_gc` module that never existed in this
tree, so nothing was ever written and cross-target learning was a no-op. This is
the real implementation behind them.

Layout (all append-only JSONL except the per-target profiles):

  <memdir>/
    journal.jsonl        every logged finding/attempt, confirmed or not
    patterns.jsonl       techniques that actually paid — the reusable signal
    audit.jsonl          outbound requests fired by the tooling (poc_runtime)
    targets/<t>.json     per-target profile: stack, tested endpoints, findings

Directory resolution (first hit wins):
    $CBH_MEMORY_DIR
    ./hunt-memory                 (if it already exists — workspace-local)
    ~/.cbh/hunt-memory            (created on demand)

Rotation is automatic on write: a file crossing the cap becomes <file>.1, older
backups shift up to <file>.{keep}, and the oldest is dropped. Nothing here ever
deletes a live file.

Stdlib only. No network. Never stores credentials — see redact().

Usage (library):
    from memory import Memory
    m = Memory()
    m.remember({"target": "acme.com", "vuln_class": "idor",
                "endpoint": "/api/v2/users/{id}", "result": "confirmed"})
    print(m.pickup("acme.com"))
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

# Auto-technique classification integration
try:
    from technique_classifier import classify_finding
    _CLASSIFIER_AVAILABLE = True
except ImportError:
    _CLASSIFIER_AVAILABLE = False

DEFAULT_MAX_MB = 10
DEFAULT_KEEP = 3
JSONL_FILES = ("journal.jsonl", "patterns.jsonl", "audit.jsonl")
REQUIRED_FIELDS = ("target", "vuln_class", "endpoint", "result")
VALID_RESULTS = ("confirmed", "rejected", "partial", "informational", "duplicate",
                 "submitted", "accepted", "paid", "na", "downgraded")

# Two different questions live in `result`, and conflating them is how a technique
# that reproduces perfectly and gets closed N/A every single time ends up in the
# "what works" list:
#   * did it reproduce here?          -> locally_confirmed
#   * what did the program decide?    -> platform_outcome
# You do not submit what you cannot reproduce, so every platform verdict implies
# local confirmation; the reverse is not true.
LOCAL_CONFIRM_RESULTS = frozenset(
    {"confirmed", "submitted", "accepted", "paid", "na", "downgraded", "duplicate"})
PLATFORM_RESULTS = frozenset(
    {"submitted", "accepted", "paid", "na", "downgraded", "duplicate"})
# Results that belong in patterns.jsonl — the reusable "this technique worked" corpus.
PATTERN_RESULTS = ("confirmed", "accepted", "paid")

_VCLASS_ALIASES = {
    "missing-authorization": "missing_authorization",
    "missing authorization": "missing_authorization",
    "broken-access-control": "broken_access_control",
    "broken access control": "broken_access_control",
    "business logic": "business-logic",
    "race condition": "race-condition",
    "open redirect": "open-redirect",
    "info leak": "info-leak",
}


def normalize_vuln_class(value: str) -> str:
    raw = re.sub(r"\s+", " ", str(value or "unspecified").strip().lower())
    return _VCLASS_ALIASES.get(raw, raw.replace(" ", "-"))


def normalize_technique(value: str | None) -> str:
    """Turn free-form technique labels into stable, bounded identifiers."""
    raw = str(value or "generic").strip().lower()
    raw = re.sub(r"https?://\S+", "", raw)
    raw = re.sub(r"[^a-z0-9]+", "_", raw).strip("_")
    return (raw[:80].rstrip("_") or "generic")

# Keys whose values never get written to disk, at any nesting depth.
_SECRET_KEY_RE = re.compile(
    r"cookie|authorization|token|passw|secret|api[-_]?key|session|bearer|otp|credential",
    re.I)
# Bookkeeping keys that trip the regex but hold counters/timestamps, not secrets.
_SAFE_KEYS = {"sessions", "session_count", "last_session_start", "sessionless"}
_REDACTED = "[redacted]"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact(obj):
    """Strip credential-ish values before anything touches disk.

    Hunt memory is long-lived and gets grepped, copied and shared far more often
    than a session transcript does; a captured session cookie living in it forever
    is a liability, and the engagement rules say greybox creds never hit disk.
    """
    if isinstance(obj, dict):
        return {k: (_REDACTED
                    if str(k).lower() not in _SAFE_KEYS and _SECRET_KEY_RE.search(str(k))
                    else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def resolve_dir(explicit=None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("CBH_MEMORY_DIR")
    if env:
        return Path(env).expanduser()
    # Walk up from cwd so memory stays workspace-local no matter which
    # Targets/<name>/ subdirectory the session happens to be sitting in.
    here = Path.cwd().resolve()
    for d in (here, *here.parents):
        cand = d / "hunt-memory"
        if cand.is_dir():
            return cand
    # cwd is not under the workspace at all — a session sitting in / or /opt
    # walks up past it and would otherwise start a second, silent corpus in
    # ~/.cbh. Anchor on where this file lives instead: that is fixed.
    for d in Path(__file__).resolve().parents:
        cand = d / "hunt-memory"
        if cand.is_dir():
            return cand
    return Path.home() / ".cbh" / "hunt-memory"


# ------------------------------------------------------------------ rotation
def rotate(path: Path, max_mb=DEFAULT_MAX_MB, keep=DEFAULT_KEEP) -> bool:
    """Rotate `path` if it is at/over the cap. Returns True if rotation happened."""
    if not path.exists() or path.stat().st_size < max_mb * 1024 * 1024:
        return False
    oldest = path.with_suffix(path.suffix + f".{keep}")
    if oldest.exists():
        oldest.unlink()
    for i in range(keep - 1, 0, -1):
        src = path.with_suffix(path.suffix + f".{i}")
        if src.exists():
            src.rename(path.with_suffix(path.suffix + f".{i + 1}"))
    path.rename(path.with_suffix(path.suffix + ".1"))
    return True


def _backups(path: Path):
    return sorted(path.parent.glob(path.name + ".[0-9]"))


def _scrub_pii(text: str) -> str:
    """Mask identity fields (iin/msisdn/phone/passport/...) before a line hits disk.

    Shares one definition with bbcurl and poc_runtime via responses.scrub_text so the
    three writers cannot drift on what counts as PII. Best-effort by design: hunt memory
    must never be the thing that fails a hunt.
    """
    try:
        from responses import scrub_text  # noqa: PLC0415 - optional sibling module
        return scrub_text(text)
    except Exception:  # noqa: BLE001
        return text


class Memory:
    def __init__(self, directory=None, max_mb=DEFAULT_MAX_MB, keep=DEFAULT_KEEP):
        self.dir = resolve_dir(directory)
        self.targets_dir = self.dir / "targets"
        self.max_mb = max_mb
        self.keep = keep

    # -------------------------------------------------------------- internals
    def _ensure(self):
        self.targets_dir.mkdir(parents=True, exist_ok=True)

    def _append(self, filename: str, record: dict):
        self._ensure()
        path = self.dir / filename
        rotate(path, self.max_mb, self.keep)
        with path.open("a", encoding="utf-8") as fh:
            # redact() masks credential-shaped KEYS; _scrub_pii masks identity VALUES
            # wherever they sit — including inside free-text notes, which is how an IIN
            # reached journal.jsonl despite redact() being in place all along.
            fh.write(_scrub_pii(json.dumps(redact(record), ensure_ascii=False)) + "\n")
        return path

    def read(self, filename: str, target=None, limit=None):
        """Read a JSONL file (live portion only). Malformed lines are skipped."""
        path = self.dir / filename
        if not path.exists():
            return []
        out = []
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if target and rec.get("target") != target:
                    continue
                out.append(rec)
        return out[-limit:] if limit else out

    # ------------------------------------------------------- target profiles
    def profile_path(self, target: str) -> Path:
        safe = re.sub(r"[^a-z0-9._-]", "_", target.lower())
        return self.targets_dir / f"{safe}.json"

    def load_profile(self, target: str) -> dict:
        path = self.profile_path(target)
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        return {"target": target, "created": _now(), "sessions": 0,
                "tech_stack": [], "tested_endpoints": [], "findings": []}

    def save_profile(self, profile: dict):
        """Write a target profile. Both masks apply, same as every other writer.

        `redact()` alone was not enough: it matches credential-shaped KEYS, so a
        profile whose tested_endpoints list holds `/check?iin=<national id>` wrote
        the identity straight to disk. Profiles are the one write path that was
        still missing `_scrub_pii`, which is exactly where a gap hides — it is the
        file `/pickup` reads back every session.
        """
        self._ensure()
        path = self.profile_path(profile["target"])
        profile["updated"] = _now()
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(_scrub_pii(json.dumps(redact(profile), indent=2, ensure_ascii=False)),
                       encoding="utf-8")
        tmp.replace(path)
        return path

    # ---------------------------------------------------------------- writes
    def remember(self, entry: dict) -> dict:
        """Log a finding/attempt. Returns {journal, pattern, profile} paths written.

        `patterns.jsonl` only takes entries that were confirmed — that file is the
        "what actually works" corpus and stays high-signal on purpose. A payout is
        not required (plenty of programs confirm without paying, and the technique
        is still valid signal); rejected/informational entries stay in the journal.

        Auto-classifies technique if not set and classifier is available.
        """
        missing = [f for f in REQUIRED_FIELDS if not entry.get(f)]
        if missing:
            raise ValueError(f"missing required field(s): {', '.join(missing)}")
        if entry["result"] not in VALID_RESULTS:
            raise ValueError(f"result must be one of {', '.join(VALID_RESULTS)}")

        rec = dict(entry)
        rec["vuln_class"] = normalize_vuln_class(rec.get("vuln_class"))
        rec.setdefault("timestamp", _now())
        rec.setdefault("severity", None)
        rec.setdefault("payout", 0)
        rec.setdefault("tags", [])
        rec.setdefault("tech_stack", [])

        # Auto-classify technique if not set and classifier is available
        if _CLASSIFIER_AVAILABLE and (not rec.get("technique") or rec.get("technique") == "null"):
            detected = classify_finding(rec)
            if detected != "generic":
                rec["technique"] = detected
        rec["technique"] = normalize_technique(rec.get("technique"))

        # Split the two questions apart on the way in, so analytics never has to
        # guess later. An explicit value from the caller always wins: "reproduced
        # locally, program called it N/A" is a real and important state.
        if "locally_confirmed" not in rec:
            rec["locally_confirmed"] = rec["result"] in LOCAL_CONFIRM_RESULTS
        if "platform_outcome" not in rec:
            rec["platform_outcome"] = rec["result"] if rec["result"] in PLATFORM_RESULTS else None

        written = {"journal": str(self._append("journal.jsonl", rec)), "pattern": None}

        if rec["result"] in PATTERN_RESULTS:
            pattern = {k: rec.get(k) for k in
                       ("timestamp", "target", "vuln_class", "endpoint", "technique",
                        "severity", "payout", "tech_stack", "tags", "notes", "result",
                        "locally_confirmed", "platform_outcome", "platform_reason")}
            pattern["locally_confirmed"] = True
            pattern["triage_outcome"] = rec["result"] if rec["result"] in ("accepted", "paid") else None
            written["pattern"] = str(self._append("patterns.jsonl", pattern))

        profile = self.load_profile(rec["target"])
        profile["sessions"] = profile.get("sessions", 0)
        profile["last_hunt"] = rec["timestamp"]
        for ep in ([rec["endpoint"]] if isinstance(rec["endpoint"], str) else rec["endpoint"]):
            if ep not in profile["tested_endpoints"]:
                profile["tested_endpoints"].append(ep)
        for tech in rec.get("tech_stack") or []:
            if tech not in profile["tech_stack"]:
                profile["tech_stack"].append(tech)
        if rec["result"] in PATTERN_RESULTS:
            profile["findings"].append({
                "timestamp": rec["timestamp"], "vuln_class": rec["vuln_class"],
                "endpoint": rec["endpoint"], "severity": rec.get("severity"),
                "payout": rec.get("payout", 0)})
        written["profile"] = str(self.save_profile(profile))
        return written

    def start_session(self, target: str) -> dict:
        profile = self.load_profile(target)
        profile["sessions"] = profile.get("sessions", 0) + 1
        profile["last_session_start"] = _now()
        self.save_profile(profile)
        return profile

    def audit(self, record: dict):
        """Append one outbound-request record. Called by poc_runtime after each fire."""
        rec = dict(record)
        rec.setdefault("timestamp", _now())
        return self._append("audit.jsonl", rec)

    # ----------------------------------------------------------------- reads
    def pickup(self, target: str, untested=None) -> dict:
        """Assemble the resume view for a target: history, untested surface, suggestions."""
        profile = self.load_profile(target)
        journal = self.read("journal.jsonl", target=target)
        patterns = self.read("patterns.jsonl")

        tested = set(profile.get("tested_endpoints", []))
        if untested is None:
            untested = []
        untested = [u for u in untested if u not in tested]

        # Cross-target signal: techniques that were confirmed elsewhere on an
        # overlapping stack. This is the whole point of keeping memory — the same
        # framework tends to break the same way across programs.
        stack = {t.lower() for t in profile.get("tech_stack", [])}
        suggestions = []
        for p in patterns:
            if p.get("target") == target:
                continue
            overlap = stack & {t.lower() for t in (p.get("tech_stack") or [])}
            if overlap:
                suggestions.append({"from": p.get("target"), "vuln_class": p.get("vuln_class"),
                                    "technique": p.get("technique"), "payout": p.get("payout"),
                                    "shared_stack": sorted(overlap)})
        suggestions.sort(key=lambda s: (len(s["shared_stack"]), s.get("payout") or 0),
                         reverse=True)

        confirmed = [f for f in profile.get("findings", [])]
        return {
            "target": target,
            "known": profile.get("last_hunt") is not None or bool(journal),
            "sessions": profile.get("sessions", 0),
            "last_hunt": profile.get("last_hunt"),
            "tech_stack": profile.get("tech_stack", []),
            "tested_endpoints": sorted(tested),
            "untested_endpoints": untested,
            "findings": confirmed,
            "total_payout": sum(f.get("payout") or 0 for f in confirmed),
            "journal_entries": len(journal),
            "suggestions": suggestions[:10],
        }

    def seen_endpoint(self, target: str, endpoint: str) -> bool:
        """True if this endpoint was already tested on this target (duplicate guard)."""
        return endpoint in set(self.load_profile(target).get("tested_endpoints", []))

    # -------------------------------------------------------------------- gc
    def stats(self):
        rows = []
        for name in JSONL_FILES:
            path = self.dir / name
            live = path.stat().st_size if path.exists() else 0
            bks = _backups(path)
            rows.append({"file": name, "path": str(path), "live_bytes": live,
                         "backup_count": len(bks),
                         "total_bytes": live + sum(b.stat().st_size for b in bks),
                         "over_cap": live >= self.max_mb * 1024 * 1024})
        return rows

    def gc(self, do_rotate=False, purge_backups=False):
        actions = []
        for name in JSONL_FILES:
            path = self.dir / name
            if purge_backups:
                for b in _backups(path):
                    b.unlink()
                    actions.append(f"purged {b.name}")
            if do_rotate and rotate(path, self.max_mb, self.keep):
                actions.append(f"rotated {name} -> {name}.1")
        return actions


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        m = Memory(td)
        m.remember({"target": "a.example", "vuln_class": "idor", "endpoint": "/api/u/{id}",
                    "result": "confirmed", "severity": "high", "payout": 1500,
                    "technique": "numeric_id_swap_on_put", "tech_stack": ["Express", "GraphQL"],
                    "headers": {"Cookie": "session=supersecret"}})
        journal = Path(td) / "journal.jsonl"
        assert "supersecret" not in journal.read_text(), "credential leaked to disk"
        assert "[redacted]" in journal.read_text()

        # rotation: max_mb=0 means any existing file is at/over cap
        Memory(td, max_mb=0).remember({"target": "a.example", "vuln_class": "idor",
                                       "endpoint": "/api/u/{id}", "result": "partial"})
        assert (Path(td) / "journal.jsonl.1").exists(), "rotation did not fire"

        m2 = Memory(td)
        m2.remember({"target": "b.example", "vuln_class": "xss", "endpoint": "/search",
                     "result": "rejected"})
        pats = m2.read("patterns.jsonl")
        assert [p["target"] for p in pats] == ["a.example"], \
            "only confirmed findings belong in patterns.jsonl"
        prof = m2.load_profile("b.example")
        assert prof["tested_endpoints"] == ["/search"]
        prof["tech_stack"] = ["Express"]
        m2.save_profile(prof)
        pick = m2.pickup("b.example", untested=["/search", "/export"])
        assert pick["untested_endpoints"] == ["/export"], pick
        assert pick["suggestions"] and pick["suggestions"][0]["from"] == "a.example", pick
        prof = m2.load_profile("b.example")
        prof["tested_endpoints"].append("/check?iin=990101300123&msisdn=77771234567")
        m2.save_profile(prof)
        saved = m2.profile_path("b.example").read_text()
        assert "990101300123" not in saved, "identity leaked into a target profile"
        assert "77771234567" not in saved, "msisdn leaked into a target profile"

        m2.remember({"target": "d.example", "vuln_class": "idor", "endpoint": "/o/1",
                     "result": "na"})
        na = [r for r in m2.read("journal.jsonl") if r["target"] == "d.example"][0]
        assert na["locally_confirmed"] is True, "an N/A finding was still reproduced locally"
        assert na["platform_outcome"] == "na"
        assert not [p for p in m2.read("patterns.jsonl") if p["target"] == "d.example"], \
            "a platform N/A must not enter the what-works corpus"

        try:
            m2.remember({"target": "c", "vuln_class": "x", "endpoint": "/", "result": "bogus"})
        except ValueError:
            pass
        else:
            raise AssertionError("invalid result must raise")
        print("memory.py self-test: PASS")
