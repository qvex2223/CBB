#!/usr/bin/env python3
"""
state.py — persistent, resumable engagement state.

Everything the engine learns lives on disk so a long run is auditable and can be
killed/resumed without losing progress. Layout:

  <base>/<name>/
    state.json      surface items, worklist, tested set, candidate + confirmed findings, phase
    engine.log      append-only run log
    evidence/       per-finding evidence files
    report.md       generated at the end
"""
import json
import os
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat()


class Engagement:
    def __init__(self, base, name):
        self.dir = os.path.join(os.path.expanduser(base), name)
        self.name = name
        os.makedirs(os.path.join(self.dir, "evidence"), exist_ok=True)
        self.state_path = os.path.join(self.dir, "state.json")
        self.log_path = os.path.join(self.dir, "engine.log")
        self.state = self._load()

    def _load(self):
        if os.path.isfile(self.state_path):
            with open(self.state_path, encoding="utf-8") as fh:
                state = json.load(fh)
            state.setdefault("attempts", {})
            return state
        return {"name": self.name, "created": _now(), "phase": "init",
                "targets": [], "surface": [], "tested": [], "attempts": {},
                "candidates": [], "confirmed": []}

    def save(self):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.state, fh, indent=2)
        os.replace(tmp, self.state_path)

    def log(self, msg):
        line = f"{_now()}  {msg}"
        with open(self.log_path, "a") as f:
            f.write(line + "\n")
        print("  " + msg, flush=True)

    # ---- phase ----
    def set_phase(self, phase):
        self.state["phase"] = phase
        self.save()

    # ---- surface (discovered, scope-checked endpoints/params) ----
    def add_surface(self, items):
        seen = {(s["url"], s.get("param", ""), s.get("vuln_class", "")) for s in self.state["surface"]}
        added = 0
        for it in items:
            key = (it["url"], it.get("param", ""), it.get("vuln_class", ""))
            if key not in seen:
                self.state["surface"].append(it)
                seen.add(key)
                added += 1
        self.save()
        return added

    def worklist(self):
        """Ranked, not-yet-tested surface items."""
        tested = set(self.state["tested"])
        items = [s for s in self.state["surface"] if self._key(s) not in tested]
        return sorted(items, key=lambda s: -s.get("priority", 0))

    @staticmethod
    def _key(s):
        return f"{s['url']}|{s.get('param','')}|{s.get('vuln_class','')}"

    def mark_tested(self, item):
        k = self._key(item)
        if k not in self.state["tested"]:
            self.state["tested"].append(k)
            self.save()

    def mark_attempt_failed(self, item, reason):
        """A technical failure: the check was never answered, so it must NOT leave the
        worklist. The item stays retried on the next run; the error is kept for audit."""
        k = self._key(item)
        hist = self.state.setdefault("attempts", {}).setdefault(k, {"count": 0})
        hist["count"] += 1
        hist["last_error"] = str(reason)[:300]
        hist["ts"] = _now()
        self.save()

    def attempts(self, item):
        return self.state.get("attempts", {}).get(self._key(item), {"count": 0})

    # ---- findings ----
    def add_candidate(self, finding):
        finding["ts"] = _now()
        self.state["candidates"].append(finding)
        self.save()

    def confirm(self, finding, verdict):
        finding = {**finding, "verdict": verdict, "confirmed_ts": _now()}
        self.state["confirmed"].append(finding)
        self.save()

    def evidence_path(self, fname):
        return os.path.join(self.dir, "evidence", fname)

    # ---- progress ----
    def summary(self):
        attempts = self.state.get("attempts", {})
        return {"surface": len(self.state["surface"]), "tested": len(self.state["tested"]),
                "failed_attempts": sum(h.get("count", 0) for h in attempts.values()),
                "candidates": len(self.state["candidates"]), "confirmed": len(self.state["confirmed"]),
                "phase": self.state["phase"]}


def _selftest():
    import tempfile, shutil
    d = tempfile.mkdtemp()
    try:
        e = Engagement(d, "demo")
        assert e.add_surface([{"url": "http://t/a", "param": "id", "vuln_class": "idor", "priority": 5},
                              {"url": "http://t/a", "param": "id", "vuln_class": "idor"}]) == 1  # dedup
        e.add_surface([{"url": "http://t/b", "param": "q", "vuln_class": "xss", "priority": 9}])
        wl = e.worklist()
        assert wl[0]["url"] == "http://t/b"            # higher priority first
        e.mark_tested(wl[0])
        assert all(s["url"] != "http://t/b" or s.get("param") != "q" for s in e.worklist())
        e.add_candidate({"url": "http://t/a", "vuln_class": "idor", "evidence": "x"})
        e.confirm(e.state["candidates"][0], {"real": True})
        # resume: a fresh handle on the same dir sees persisted state
        e2 = Engagement(d, "demo")
        assert e2.summary() == {"surface": 2, "tested": 1, "failed_attempts": 0,
                                "candidates": 1, "confirmed": 1, "phase": "init"}
        # a failed attempt must not remove the item from the worklist
        left = next(s for s in e2.state["surface"] if s["url"] == "http://t/a")
        e2.mark_attempt_failed(left, "agent timeout")
        assert any(s["url"] == "http://t/a" for s in e2.worklist()), "failed attempt hid the item"
        assert len(e2.state["tested"]) == 1, "a failed attempt masqueraded as tested"
        assert e2.attempts(left)["count"] == 1
        print("state.py self-test: PASS")
    finally:
        shutil.rmtree(d)


if __name__ == "__main__":
    _selftest()
