"""bbcurl --bb-caido: route a gated request through the Caido proxy, or refuse.

Added 2026-11-20. bbcurl never went through Caido, so proven PoCs had no Caido capture.
The flag must (1) append the proxy only AFTER the URL list is scope-checked, (2) refuse
when Caido is not listening instead of falling back to a direct connection, and (3)
refuse a --resolve pin that the proxy's own DNS lookup would not honour.
"""
import json
import os
import tempfile
import socket
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BBCURL = REPO / "scripts" / "bbcurl"
HOST = "localhost"

# A throwaway engagement in a temp Targets root, so the test names no real programme.
_TMP = tempfile.TemporaryDirectory()
ROOT = Path(_TMP.name)
PROJ = ROOT / "lab" / "caido-selftest"
PROJ.mkdir(parents=True)
(PROJ / "scope.md").write_text("# caido-selftest - scope\n\n## In scope\n- localhost\n- 127.0.0.1\n\n"
                               "## Out of scope\n- everything else\n")
(PROJ / "profile.json").write_text(json.dumps({"min_interval_seconds": 0}))


def run(args, port):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "CBH_TARGETS_ROOT": str(ROOT),
           "CBH_MEMORY_DIR": str(ROOT / "mem"),
           "CBH_PROJECT": "lab/caido-selftest", "CBH_CAIDO_PORT": str(port)}
    return subprocess.run([sys.executable, str(BBCURL), *args], capture_output=True,
                          text=True, cwd=str(PROJ), env=env, timeout=60)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _resolves_local():
    try:
        return "127.0.0.1" in {a[4][0] for a in socket.getaddrinfo(HOST, None)}
    except OSError:
        return False


@unittest.skipUnless(BBCURL.exists() and _resolves_local(),
                     "bbcurl missing or localhost does not resolve to 127.0.0.1")
class CaidoRoute(unittest.TestCase):
    URL = "https://localhost/api/v1/app/settings"

    def setUp(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]

    def tearDown(self):
        self.listener.close()

    def test_proxy_is_appended_after_the_url(self):
        url = "https://127.0.0.1/api/v1/app/settings"
        r = run(["--bb-caido", "--bb-dry-run", "-sk", url], self.port)
        self.assertIn("would run:", r.stdout, r.stderr)
        line = next(l for l in r.stdout.splitlines() if l.startswith("would run:"))
        self.assertIn(f"-x http://127.0.0.1:{self.port}", line)
        self.assertLess(line.index(url), line.index("-x http://"))

    def test_refused_when_caido_is_down(self):
        r = run(["--bb-caido", "--bb-dry-run", "-sk", self.URL], free_port())
        self.assertIn("--bb-caido REFUSED", r.stderr)
        self.assertNotIn("would run:", r.stdout)

    def test_refused_when_the_pin_would_not_hold(self):
        r = run(["--bb-caido", "--bb-dry-run", "-sk", "--resolve", "localhost:443:10.9.9.9",
                 self.URL], self.port)
        self.assertIn("the pin would not hold", r.stderr)
        self.assertNotIn("would run:", r.stdout)

    def test_without_the_flag_no_proxy_is_added(self):
        r = run(["--bb-dry-run", "-sk", "https://127.0.0.1/"], self.port)
        self.assertIn("would run:", r.stdout, r.stderr)
        self.assertNotIn("-x http://", r.stdout)


class PlaywrightBusyProfileFallsBack(unittest.TestCase):
    def test_busy_profile_does_not_kill_the_server(self):
        src = (REPO / "runtime" / "playwright-mcp.mjs").read_text()
        self.assertIn("CBH_PLAYWRIGHT_REQUIRE_PROFILE", src)
        self.assertIn("falling back to an in-memory (--isolated) profile", src)
        # `fresh` must be read before the lock, which creates the directory.
        self.assertLess(src.index("const fresh"), src.index("acquireProfileLock(profileDir"))

    def test_mcp_json_does_not_pin_an_engagement(self):
        import json
        env = json.loads((REPO / ".mcp.json").read_text())["mcpServers"]["playwright"].get("env", {})
        self.assertNotIn("CBH_PROJECT", env,
                         "a CBH_PROJECT in the shared .mcp.json binds every session's browser "
                         "to one engagement's profile; resolve it from cwd/session instead")


if __name__ == "__main__":
    unittest.main()
