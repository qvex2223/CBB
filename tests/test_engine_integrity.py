#!/usr/bin/env python3
"""Engine integrity: a technical failure is not a negative result, and an agent's
`real: true` is not proof.

Two regressions these tests pin down:
  * hunt used to mark an item tested before reading the agent's result, so a
    timeout / config error / rate-limit silently removed it from the worklist.
  * validate used to confirm on the validator's word alone; now a candidate only
    lands in `confirmed` with a passing PoC artifact to point at.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import engine as E  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.memdir = self.root / "hunt-memory"
        self.memdir.mkdir()
        self._env = dict(os.environ)
        os.environ["CBH_MEMORY_DIR"] = str(self.memdir)
        self.scope_file = self.root / "engagement.json"
        self.scope_file.write_text(json.dumps({
            "name": "integrity", "in_scope": ["localhost", "127.0.0.1"],
            "out_of_scope": [], "seeds": ["http://localhost:3002"]}))
        self.addCleanup(self._restore)

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._env)
        self.tmp.cleanup()

    def _engine(self, mocker=True):
        with contextlib.redirect_stdout(io.StringIO()):
            return E.Engine(str(self.scope_file), str(self.root / "runs"), model="mock",
                            max_hunts=5, max_turns=3, timeout=10, mock=mocker)

    def _seed(self):
        """Mock recon+rank so the state has a real surface and no network is touched."""
        eng = self._engine(mocker=True)
        with contextlib.redirect_stdout(io.StringIO()):
            eng.run(["recon", "rank"])
        return eng

    def _live(self):
        """A live-mode engine over the same engagement dir (agents will be patched)."""
        return self._engine(mocker=False)


class HuntFailureIsNotNegative(Base):
    def _hunt_with(self, reply):
        eng = self._live()
        with contextlib.redirect_stdout(io.StringIO()):
            with mock.patch.object(E.A, "run_agent", return_value=reply):
                eng.hunt()
        return eng

    def test_agent_error_leaves_the_item_in_the_worklist(self):
        self._seed()
        eng = self._hunt_with({"result": "", "error": "claude exited 1"})
        self.assertEqual(eng.eng.state["tested"], [],
                         "a crashed agent still counted as a completed check")
        self.assertTrue(eng.eng.state["attempts"], "the failure left no audit trail")
        self.assertTrue(eng.eng.worklist(), "the worklist was emptied by failures")

    def test_rate_limit_is_an_error_not_a_screened_out_item(self):
        self._seed()
        eng = self._hunt_with({"result": "usage limit reached", "error": "rate-limited"})
        self.assertEqual(eng.eng.state["tested"], [])
        self.assertTrue(all("rate-limited" in h["last_error"]
                            for h in eng.eng.state["attempts"].values()))

    def test_unparseable_agent_output_is_an_attempt_failure(self):
        self._seed()
        eng = self._hunt_with({"result": "prose without any json block", "error": None})
        self.assertEqual(eng.eng.state["tested"], [])
        self.assertTrue(eng.eng.state["attempts"])

    def test_a_later_successful_run_still_tests_the_item(self):
        self._seed()
        self._hunt_with({"result": "", "error": "timeout"})
        eng = self._live()
        ok = {"result": '```json\n{"vulnerable": false}\n```', "error": None}
        with contextlib.redirect_stdout(io.StringIO()):
            with mock.patch.object(E.A, "run_agent", return_value=ok):
                eng.hunt()
        self.assertTrue(eng.eng.state["tested"], "the retry never became a real check")
        self.assertFalse(eng.eng.worklist(), "tested items should leave the worklist")

    def test_resume_sees_the_unfinished_work(self):
        self._seed()
        self._hunt_with({"result": "", "error": "timeout"})
        resumed = self._live()  # fresh handle on the same engagement dir
        self.assertTrue(resumed.eng.worklist(),
                        "after resume the failed checks had vanished from the queue")


class ValidateNeedsProof(Base):
    def _candidates(self):
        eng = self._seed()
        d = Path(eng.eng.dir)
        # two candidates straight into state; the hunt phase is not under test here
        eng.eng.add_candidate({"url": "http://localhost:3002/api/account?id=5",
                               "param": "id", "vuln_class": "idor",
                               "severity": "medium", "evidence": "id=N returns other users PII",
                               "request": "GET /api/account?id=6"})
        eng.eng.add_candidate({"url": "http://localhost:3002/search?q=x",
                               "param": "q", "vuln_class": "idor",
                               "severity": "medium", "evidence": "other user's rows",
                               "request": "GET /search?q=6"})
        return d

    def _validate_with(self, reply):
        eng = self._live()
        with contextlib.redirect_stdout(io.StringIO()):
            with mock.patch.object(E.A, "run_agent", return_value=reply):
                eng.validate()
        return eng

    _REAL = {"result": '```json\n{"real": true, "severity": "high", "reason": "repro"}\n```',
             "error": None}

    def test_real_true_without_an_artifact_is_not_confirmed(self):
        self._candidates()
        eng = self._validate_with(self._REAL)
        state = eng.eng.state
        self.assertEqual(state["confirmed"], [],
                         "an agent's real=true confirmed a finding with zero artifacts")
        for c in state["candidates"]:
            self.assertIn("evidence_status", c)
            self.assertNotEqual(c["evidence_status"], "DEMONSTRATED")

    def test_validator_agent_crash_keeps_the_candidate_pending(self):
        self._candidates()
        eng = self._validate_with({"result": "", "error": "timeout"})
        self.assertEqual(eng.eng.state["confirmed"], [])
        # pending is derived: not confirmed -> still there for the next run
        eng2 = self._live()
        pending = [c for c in eng2.eng.state["candidates"]
                   if not any(cf.get("url") == c["url"] for cf in eng2.eng.state["confirmed"])]
        self.assertEqual(len(pending), 2)

    def test_real_true_with_a_passing_artifact_is_confirmed(self):
        d = self._candidates()
        artifact = {
            "spec_file": "idor.poc.json",
            "timestamp": "2026-09-23T00:00:00+00:00",
            "final_verdict": "PASS",
            "runs": [{"steps": [{"name": "exploit",
                                 "url": "http://localhost:3002/api/account?id=5",
                                 "result": {"status": 200}}], "result": {}}],
        }
        (d / "evidence" / "idor.result.json").write_text(json.dumps(artifact))
        eng = self._live()
        with contextlib.redirect_stdout(io.StringIO()):
            with mock.patch.object(E.A, "run_agent", return_value=self._REAL):
                eng.validate()
        confirmed = eng.eng.state["confirmed"]
        self.assertEqual([c["vuln_class"] for c in confirmed], ["idor"])
        self.assertEqual(confirmed[0]["url"], "http://localhost:3002/api/account?id=5")

    def test_a_passing_artifact_for_the_wrong_endpoint_does_not_confirm(self):
        d = self._candidates()
        artifact = {
            "final_verdict": "PASS",
            "timestamp": "2026-09-23T00:00:00+00:00",
            "runs": [{"steps": [{"url": "http://localhost:3002/other",
                                 "result": {"status": 200}}], "result": {}}],
        }
        (d / "evidence" / "other.result.json").write_text(json.dumps(artifact))
        eng = self._validate_with(self._REAL)
        self.assertEqual(eng.eng.state["confirmed"], [],
                         "an artifact for a different endpoint backed this finding")


if __name__ == "__main__":
    unittest.main()
