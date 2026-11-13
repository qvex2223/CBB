#!/usr/bin/env python3
"""Every tool error has to survive the session that hit it.

Operator instruction 2026-10-29. Before this, an error existed only in the
transcript of whoever hit it: a worker's `command not found` never reached the
orchestrator, so a merge could not tell "nothing there" from "the tool broke".
These tests pin the three things that make the log trustworthy — it records the
errors, it records them from subagents too, and it can never break a tool.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import error_log as EL  # noqa: E402


def ev(**kw):
    base = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "s"}
    base.update(kw)
    return base


class WhatCounts(unittest.TestCase):
    def test_a_clean_call_is_not_recorded(self):
        self.assertIsNone(EL.row_for(ev(tool_input={"command": "ls"},
                                        tool_response={"exit_code": 0, "stdout": "a"})))

    def test_a_nonzero_exit_is_recorded_even_though_the_tool_call_succeeded(self):
        r = EL.row_for(ev(tool_input={"command": "false"},
                          tool_response={"exit_code": 3, "stderr": "nope"}))
        self.assertIsNotNone(r)
        self.assertEqual(3, r["exit_code"])

    def test_an_outright_tool_failure_is_recorded(self):
        r = EL.row_for(ev(hook_event_name="PostToolUseFailure", tool_name="Read",
                          tool_input={"file_path": "/nope"},
                          error="File does not exist: /nope"))
        self.assertIsNotNone(r)
        self.assertEqual("missing_path", r["kind"])

    def test_exit_code_is_read_out_of_the_text_when_there_is_no_field(self):
        """The harness reports a failed Bash call as the words "Exit code 7"."""
        r = EL.row_for(ev(hook_event_name="PostToolUseFailure",
                          tool_input={"command": "bash -c 'exit 7'"},
                          error="Exit code 7"))
        self.assertEqual(7, r["exit_code"])


class Classification(unittest.TestCase):
    CASES = {
        "command_not_found": "bash: semgrep: command not found",
        "permission_denied": "Claude requested permissions to write, but you denied "
                             "[Self-Modification]",
        "gate_refusal": "bbscan: BLOCKED — 1 switch(es) reach past the operator's authorization",
        "timeout": "Command timed out after 120s",
        "network": "curl: (7) Failed to connect: ECONNREFUSED 127.0.0.1:8080",
        "traceback": "Traceback (most recent call last):\nValueError: bad",
        "missing_path": "File does not exist: /tmp/x",
    }

    def test_each_class_is_named(self):
        for want, msg in self.CASES.items():
            self.assertEqual(want, EL.classify(msg), msg)

    def test_an_unrecognised_message_with_a_bad_exit_is_a_nonzero_exit(self):
        self.assertEqual("nonzero_exit", EL.classify("something odd", 4))

    def test_a_scope_refusal_is_a_gate_refusal_not_a_network_error(self):
        self.assertEqual("gate_refusal",
                         EL.classify("bbcurl: OUT-OF-SCOPE https://www.ykky.ru/a"))


class Attribution(unittest.TestCase):
    def test_a_subagent_error_is_marked_as_one(self):
        r = EL.row_for(ev(agent_id="agent-7", tool_response={"exit_code": 1, "stderr": "x"}))
        self.assertEqual("subagent", r["actor"])
        self.assertEqual("agent-7", r["agent_id"])

    def test_the_main_thread_is_marked_main(self):
        r = EL.row_for(ev(tool_response={"exit_code": 1, "stderr": "x"}))
        self.assertEqual("main", r["actor"])


class Hygiene(unittest.TestCase):
    def test_subscriber_identity_never_reaches_the_error_log(self):
        r = EL.row_for(ev(tool_input={"command": "bbcurl 'https://h/a?iin=950101300123'"},
                          tool_response={"exit_code": 1,
                                         "stderr": "failed for contact_phone=77011234567"}))
        blob = json.dumps(r, ensure_ascii=False)
        self.assertNotIn("950101300123", blob)
        self.assertNotIn("77011234567", blob)

    def test_a_long_message_is_truncated(self):
        r = EL.row_for(ev(tool_response={"exit_code": 1, "stderr": "x" * 50_000}))
        self.assertLessEqual(len(r["message"]), EL.MSG_CHARS)


class Durability(unittest.TestCase):
    def test_rows_round_trip_through_the_file(self):
        with tempfile.TemporaryDirectory() as td:
            EL.append(EL.row_for(ev(tool_response={"exit_code": 1, "stderr": "boom"})), Path(td))
            EL.append(EL.row_for(ev(tool_name="Read", hook_event_name="PostToolUseFailure",
                                    error="File does not exist: /nope")), Path(td))
            rows = EL.load(Path(td))
            self.assertEqual(2, len(rows))
            self.assertEqual({"Bash", "Read"}, {r["tool"] for r in rows})

    def test_filters_narrow_the_read(self):
        with tempfile.TemporaryDirectory() as td:
            EL.append(EL.row_for(ev(tool_response={"exit_code": 1, "stderr": "boom"})), Path(td))
            EL.append(EL.row_for(ev(tool_name="Read", hook_event_name="PostToolUseFailure",
                                    error="bash: zzz: command not found")), Path(td))
            self.assertEqual(1, len(EL.load(Path(td), tool="Read")))
            self.assertEqual(1, len(EL.load(Path(td), kind="command_not_found")))

    def test_a_future_since_filter_returns_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            EL.append(EL.row_for(ev(tool_response={"exit_code": 1, "stderr": "boom"})), Path(td))
            future = datetime.now(timezone.utc).replace(year=2099)
            self.assertEqual([], EL.load(Path(td), since=future))

    def test_concurrent_sessions_do_not_interleave_a_row(self):
        """Several sessions share one file; a torn line would be unparseable."""
        with tempfile.TemporaryDirectory() as td:
            for i in range(40):
                EL.append(EL.row_for(ev(tool_response={"exit_code": 1,
                                                       "stderr": f"boom {i} " + "y" * 500})),
                          Path(td))
            text = EL.log_path(Path(td)).read_text(encoding="utf-8")
            for line in text.splitlines():
                json.loads(line)          # raises if a write was torn
            self.assertEqual(40, len(text.strip().splitlines()))


class Grouping(unittest.TestCase):
    def test_the_same_error_with_different_numbers_is_one_signature(self):
        rows = [EL.row_for(ev(tool_response={"exit_code": 1,
                                             "stderr": f"curl: (7) connect to 10.0.0.{i} failed"}))
                for i in range(1, 6)]
        groups = EL.digest(rows)
        self.assertEqual(1, len(groups))
        self.assertEqual(5, groups[0]["count"])

    def test_distinct_errors_stay_distinct(self):
        rows = [EL.row_for(ev(tool_response={"exit_code": 1, "stderr": "curl: (7) refused"})),
                EL.row_for(ev(tool_response={"exit_code": 1, "stderr": "bash: q: command not found"}))]
        self.assertEqual(2, len(EL.digest(rows)))


class TheHookCannotBreakAnything(unittest.TestCase):
    HOOK = REPO / "scripts" / "error-log.py"

    def _run(self, payload: str):
        return subprocess.run([sys.executable, str(self.HOOK)], input=payload,
                              capture_output=True, text=True, timeout=60,
                              env=dict(os.environ, CBH_MEMORY_DIR=self.td))

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.td = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def test_garbage_stdin_still_exits_zero(self):
        self.assertEqual(0, self._run("not json at all").returncode)

    def test_empty_stdin_still_exits_zero(self):
        self.assertEqual(0, self._run("").returncode)

    def test_a_real_payload_is_written_and_exits_zero(self):
        payload = json.dumps({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                              "tool_input": {"command": "bash -c 'exit 7'"},
                              "error": "Exit code 7"})
        self.assertEqual(0, self._run(payload).returncode)
        rows = EL.load(Path(self.td))
        self.assertEqual(1, len(rows))
        self.assertEqual(7, rows[0]["exit_code"])

    def test_the_hook_prints_nothing_on_stdout(self):
        """stdout from a PostToolUse hook lands in the transcript; stay silent."""
        out = self._run(json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                                    "tool_response": {"exit_code": 1, "stderr": "x"}}))
        self.assertEqual("", out.stdout)


class Wiring(unittest.TestCase):
    def test_doctor_counts_the_hook(self):
        import workspace_check as wc
        self.assertIn("error-log.py", wc.HOOKS)

    def test_both_events_are_wired_in_the_versioned_config(self):
        cfg = json.loads((REPO / "docs" / "setup" / "hooks.json").read_text(encoding="utf-8"))
        events = {ev_name for ev_name, groups in cfg["hooks"].items()
                  for g in groups for hk in g.get("hooks", [])
                  if "error-log.py" in hk.get("command", "")}
        self.assertIn("PostToolUseFailure", events)
        self.assertIn("PostToolUse", events)

    def test_cbh_exposes_the_reader(self):
        r = subprocess.run([sys.executable, "-m", "cbh.cli", "errors", "--since", "1s"],
                           capture_output=True, text=True, cwd=str(REPO), timeout=120)
        self.assertEqual(0, r.returncode, r.stderr)


if __name__ == "__main__":
    unittest.main()
