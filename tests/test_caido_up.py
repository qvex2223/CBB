#!/usr/bin/env python3
"""caido-up: the proxy starts itself, and starting it twice is harmless.

The failure being tested against: Caido does not survive a reboot, so every session
after a restart found `ECONNREFUSED 127.0.0.1:8080` and hunted without the only tool
that can prove a redirect chain, a cookie or a session state — while the session
brief printed a start command at the operator instead of running it.

Nothing here starts a real proxy: the script is exercised against a port this test
opens itself (the "already up" path) and against a closed port with a bogus binary
(the "cannot start" path), so the suite stays offline and side-effect free.
"""
from __future__ import annotations

import socket
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "caido-up.sh"


def run(args, port, binary="/nonexistent/caido-cli", wait="1"):
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp",
           "CBH_CAIDO_PORT": str(port), "CBH_CAIDO_HOST": "127.0.0.1",
           "CBH_CAIDO_BIN": binary, "CBH_CAIDO_WAIT": wait}
    return subprocess.run(["bash", str(SCRIPT)] + args, capture_output=True,
                          text=True, env=env, timeout=60)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class CaidoUp(unittest.TestCase):
    def test_script_exists_and_is_executable(self):
        self.assertTrue(SCRIPT.is_file())
        self.assertTrue(SCRIPT.stat().st_mode & 0o111, "caido-up.sh must be executable")

    def test_already_listening_is_a_no_op(self):
        """The idempotency that lets three callers start it in the same minute."""
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            p = run([], port)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("already up", p.stdout)
        finally:
            srv.close()

    def test_status_never_starts_anything(self):
        p = run(["--status"], free_port())
        self.assertEqual(p.returncode, 1)
        self.assertIn("DOWN", p.stdout)

    def test_missing_binary_is_reported_not_crashed(self):
        p = run([], free_port())
        self.assertEqual(p.returncode, 127)
        self.assertIn("binary not found", p.stderr)
        self.assertIn("docs/caido.md", p.stderr)

    def test_quiet_stays_quiet_on_success(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            p = run(["--quiet"], port)
            self.assertEqual(p.returncode, 0)
            self.assertEqual(p.stdout.strip(), "")
        finally:
            srv.close()

    def test_unknown_argument_is_refused(self):
        p = run(["--wat"], free_port())
        self.assertEqual(p.returncode, 64)

    def test_the_callers_are_wired(self):
        """Prose cannot start a proxy — these are the call sites that do."""
        self.assertIn("caido-up.sh", (ROOT / "scripts" / "hunt-arm.py").read_text())
        self.assertIn("caido-up.sh", (ROOT / "scripts" / "session-brief.py").read_text())
        self.assertIn("caido-up.sh", (ROOT / "engine" / "tool_runtime.py").read_text())
        self.assertIn("caido-up.sh", (ROOT / "runtime" / "playwright-mcp.mjs").read_text())


if __name__ == "__main__":
    sys.exit(unittest.main())
