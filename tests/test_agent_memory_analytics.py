#!/usr/bin/env python3
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
import agent
from memory import Memory


class AgentSuccess(unittest.TestCase):
    def test_successful_process_has_no_phantom_parse_error(self):
        payload = json.dumps({"result": "ok", "num_turns": 2, "total_cost_usd": 0.1})
        proc = subprocess.CompletedProcess(["claude"], 0, payload, "")
        with mock.patch.object(agent.os.path, "exists", return_value=True), \
             mock.patch.object(agent.subprocess, "run", return_value=proc):
            got = agent.run_agent("test")
        self.assertEqual(got["result"], "ok")
        self.assertIsNone(got["error"])
        self.assertIn("Bash(bbcurl:*)", agent.ALLOWED_TOOLS)
        self.assertNotIn("Bash(curl:*)", agent.ALLOWED_TOOLS)


class MemorySchema(unittest.TestCase):
    def test_pattern_keeps_outcome_and_normalized_ids(self):
        with tempfile.TemporaryDirectory() as td:
            m = Memory(td)
            m.remember({"target": "x", "vuln_class": "Missing Authorization",
                        "endpoint": "/x", "result": "accepted",
                        "technique": "Swap user A token with user B token and compare responses"})
            row = m.read("patterns.jsonl")[0]
            self.assertEqual(row["result"], "accepted")
            self.assertEqual(row["vuln_class"], "missing_authorization")
            self.assertLessEqual(len(row["technique"]), 80)
            self.assertTrue(row["locally_confirmed"])


if __name__ == "__main__":
    unittest.main()
