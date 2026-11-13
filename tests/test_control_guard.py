import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "control-guard.py"


def run(tool, tool_input, role="worker"):
    env = dict(os.environ)
    env.pop("CBH_AGENT_ROLE", None)
    if role:
        env["CBH_AGENT_ROLE"] = role
    p = subprocess.run([sys.executable, str(SCRIPT)], input=json.dumps(
        {"tool_name": tool, "tool_input": tool_input}), capture_output=True, text=True, env=env)
    return "deny" in p.stdout


class ControlGuard(unittest.TestCase):
    def test_the_incident_is_blocked(self):
        self.assertTrue(run("Edit", {"file_path": "/x/Targets/standoff365/konsol/profile.json"}))
        self.assertTrue(run("Bash", {"command": "python3 -c \"import json;d=json.load(open('profile.json'));"
                                                "d['continuous_hunt']=False;json.dump(d,open('profile.json','w'))\""}))
        self.assertTrue(run("Bash", {"command": "python3 engine/stop_gate.py --continuous off"}))
        self.assertTrue(run("Bash", {"command": "sed -i s/true/false/ Targets/a/profile.json"}))

    def test_worker_reads_and_normal_work_pass(self):
        self.assertFalse(run("Bash", {"command": "cat Targets/a/scope.md"}))
        self.assertFalse(run("Bash", {"command": "CBH_PROJECT=a bbcurl -s https://x.example/"}))
        self.assertFalse(run("Write", {"file_path": "/x/Targets/a/recon/w1/notes.md"}))

    def test_reading_a_control_file_is_never_blocked(self):
        for c in ["grep -n In Targets/a/scope.md 2>/dev/null",
                  "cat Targets/a/scope.md > /tmp/claude-1000/s.txt",
                  "cp Targets/a/profile.json /tmp/claude-1000/p.json",
                  "cat profile.json | python3 -c \"import json,sys;json.dump(json.load(sys.stdin),open('/tmp/o','w'))\"",
                  "python3 engine/scope.py --selftest",
                  "CBH_PROJECT=a bbcurl -s https://x.example/ > /tmp/claude-1000/r.html"]:
            self.assertFalse(run("Bash", {"command": c}), c)

    def test_writes_into_control_files_are_blocked(self):
        for c in ["echo '{}' > Targets/a/profile.json",
                  "jq . x | tee Targets/a/scope.md",
                  "mv /tmp/p.json Targets/a/profile.json",
                  "python3 -c \"from pathlib import Path;Path('Targets/a/profile.json').write_text('{}')\""]:
            self.assertTrue(run("Bash", {"command": c}), c)

    def test_operator_session_is_never_touched(self):
        self.assertFalse(run("Edit", {"file_path": "/x/Targets/a/profile.json"}, role=None))


if __name__ == "__main__":
    unittest.main()
