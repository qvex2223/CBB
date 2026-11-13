#!/usr/bin/env python3
"""runtime/browser-lock.mjs — one holder at a time for an engagement's browser profile.

Why this exists: Chromium serialises a `--user-data-dir` behind its own SingletonLock, with
no error and no output. On 2026-11-11 two Playwright MCP servers were started against one
`Targets/<name>/browser-profile`, and 19 of 38 subagents were killed after 20-53 minutes of
waiting — every one of them a browser lane. The lock turns that silent wait into a bounded,
named refusal, so the tests below are about the refusal being bounded, actionable, and not
fooled by a dead holder.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK_MJS = ROOT / "runtime" / "browser-lock.mjs"
NODE = shutil.which("node")


def run_node(body, env=None, cwd=None):
    """Run an ESM snippet with the lock module imported as `L`. Returns parsed stdout JSON."""
    script = f"import * as L from {json.dumps(LOCK_MJS.as_uri())};\n{body}\n"
    e = dict(os.environ)
    e.pop("CBH_BROWSER_LOCK", None)
    e.pop("CBH_BROWSER_LOCK_WAIT_SECONDS", None)
    e.update(env or {})
    p = subprocess.run([NODE, "--input-type=module", "-e", script],
                       capture_output=True, text=True, timeout=90, env=e, cwd=cwd or str(ROOT))
    if p.returncode != 0:
        raise AssertionError(f"node exited {p.returncode}\nstdout: {p.stdout}\nstderr: {p.stderr}")
    out = [ln for ln in p.stdout.splitlines() if ln.startswith("{")]
    assert out, f"no JSON line on stdout\nstdout: {p.stdout}\nstderr: {p.stderr}"
    return json.loads(out[-1])


@unittest.skipUnless(NODE, "node is not installed")
class ProfileLock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.profile = str(Path(self.tmp) / "browser-profile")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def lock_file(self):
        return Path(self.profile) / ".cbh-browser.lock"

    def test_first_acquire_writes_a_lock_naming_pid_and_lane(self):
        r = run_node(f"""
const a = await L.acquireProfileLock({json.dumps(self.profile)}, {{ label: 'hunter-3' }});
console.log(JSON.stringify({{ ok: a.ok, lockPath: a.lockPath }}));
""")
        self.assertTrue(r["ok"])
        h = json.loads(self.lock_file().read_text())
        self.assertEqual("hunter-3", h["label"])
        self.assertIsInstance(h["pid"], int)
        self.assertEqual(self.profile, h["profile"])
        self.assertIn("started_at", h)

    def test_second_acquire_is_refused_and_names_the_holder(self):
        # One live process holds it; the second must not wait for the length of the first lane.
        r = run_node(f"""
const first = await L.acquireProfileLock({json.dumps(self.profile)}, {{ label: 'lane-A' }});
const second = await L.acquireProfileLock({json.dumps(self.profile)}, {{ waitMs: 0, pid: process.pid }});
console.log(JSON.stringify({{ first: first.ok, second: second.ok, holder: second.holder }}));
""")
        self.assertTrue(r["first"])
        self.assertFalse(r["second"], "a second server took a profile that was already held")
        self.assertEqual("lane-A", r["holder"]["label"])

    def test_refusal_is_bounded_by_the_wait(self):
        r = run_node(f"""
await L.acquireProfileLock({json.dumps(self.profile)}, {{}});
const t0 = Date.now();
const res = await L.acquireProfileLock({json.dumps(self.profile)}, {{ waitMs: 1200, pid: process.pid }});
console.log(JSON.stringify({{ ok: res.ok, elapsed: Date.now() - t0 }}));
""")
        self.assertFalse(r["ok"])
        self.assertLess(r["elapsed"], 20_000,
                        "the refusal has to come back inside the lane's budget, not after it")

    def test_a_dead_holder_is_broken_not_waited_on(self):
        # The crash case: a killed lane leaves its lock behind. The next lane must take it.
        Path(self.profile).mkdir(parents=True)
        self.lock_file().write_text(json.dumps(
            {"pid": 2 ** 22 - 1, "label": "killed-lane", "started_at": "2026-11-11T00:00:00Z",
             "profile": self.profile}))
        r = run_node(f"""
const a = await L.acquireProfileLock({json.dumps(self.profile)}, {{ waitMs: 0, label: 'next-lane' }});
console.log(JSON.stringify({{ ok: a.ok }}));
""")
        self.assertTrue(r["ok"], "a lock whose pid is gone stranded the profile")
        self.assertEqual("next-lane", json.loads(self.lock_file().read_text())["label"])

    def test_release_frees_the_profile_for_the_next_lane(self):
        r = run_node(f"""
const a = await L.acquireProfileLock({json.dumps(self.profile)}, {{ label: 'lane-A' }});
a.release();
const b = await L.acquireProfileLock({json.dumps(self.profile)}, {{ waitMs: 0, label: 'lane-B' }});
console.log(JSON.stringify({{ a: a.ok, b: b.ok, existsAfterRelease: b.ok }}));
""")
        self.assertTrue(r["b"], "release did not free the lock")

    def test_release_does_not_drop_a_lock_that_was_handed_on(self):
        # Stale-breaking means someone else's lock may sit at our path. Releasing must not
        # unlink the new holder's lock, or the profile ends up with two browsers again.
        r = run_node(f"""
const a = await L.acquireProfileLock({json.dumps(self.profile)}, {{ pid: 4194303, label: 'A' }});
const b = await L.acquireProfileLock({json.dumps(self.profile)}, {{ waitMs: 0, pid: process.pid, label: 'B' }});
a.release();
console.log(JSON.stringify({{ b: b.ok, holder: L.readHolder(b.lockPath) }}));
""")
        self.assertTrue(r["b"])
        self.assertIsNotNone(r["holder"], "release unlinked another lane's lock")
        self.assertEqual("B", r["holder"]["label"])

    def test_lock_can_be_switched_off(self):
        r = run_node(f"""
const a = await L.acquireProfileLock({json.dumps(self.profile)}, {{}});
const b = await L.acquireProfileLock({json.dumps(self.profile)}, {{ waitMs: 0, pid: process.pid }});
console.log(JSON.stringify({{ a: a.ok, b: b.ok, disabled: Boolean(a.disabled) }}));
""", env={"CBH_BROWSER_LOCK": "off"})
        self.assertTrue(r["a"])
        self.assertTrue(r["b"], "CBH_BROWSER_LOCK=off still refused a second server")
        self.assertTrue(r["disabled"])

    def test_wait_is_configurable_and_defaults_to_25s(self):
        d = run_node("console.log(JSON.stringify({ ms: L.lockWaitMs() }));")
        self.assertEqual(25_000, d["ms"])
        c = run_node("console.log(JSON.stringify({ ms: L.lockWaitMs() }));",
                     env={"CBH_BROWSER_LOCK_WAIT_SECONDS": "3"})
        self.assertEqual(3000, c["ms"])


@unittest.skipUnless(NODE, "node is not installed")
class BusyMessage(unittest.TestCase):
    """The refusal is the whole point: a lane that reads it must know what to do next."""

    def setUp(self):
        r = subprocess.run(
            [NODE, "--input-type=module", "-e",
             f"import * as L from {json.dumps(LOCK_MJS.as_uri())};\n"
             "console.log(L.busyMessage({ ok: false, waitedMs: 25000, holder: "
             "{ pid: 4242, label: 'xss-in-email', started_at: '2026-11-11T09:00:00Z' } },"
             " '/t/browser-profile'));"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(0, r.returncode, r.stderr)
        self.msg = r.stdout

    def test_it_names_the_holder(self):
        for part in ("4242", "xss-in-email", "2026-11-11T09:00:00Z", "/t/browser-profile"):
            self.assertIn(part, self.msg)

    def test_it_says_how_long_it_waited(self):
        self.assertIn("25 s", self.msg)

    def test_it_offers_the_three_ways_forward(self):
        self.assertIn("bbcurl", self.msg)
        self.assertIn("CBH_PLAYWRIGHT_ISOLATED=1", self.msg)

    def test_it_forbids_closing_the_lead_as_blocked(self):
        # The measured damage was not the stall, it was seven leads closed `--as blocked`.
        self.assertIn("Do NOT close the lead `--as blocked`", self.msg)
        self.assertIn("--as stalled", self.msg)


@unittest.skipUnless(NODE, "node is not installed")
class WrapperWiring(unittest.TestCase):
    def test_playwright_wrapper_takes_the_lock_before_starting_chromium(self):
        src = (ROOT / "runtime" / "playwright-mcp.mjs").read_text()
        self.assertIn("acquireProfileLock", src)
        self.assertIn("busyMessage", src)
        i_lock = src.index("acquireProfileLock(profileDir")
        i_args = src.index("'--user-data-dir'")
        self.assertLess(i_lock, i_args,
                        "the lock must be taken before --user-data-dir is handed to Chromium")


if __name__ == "__main__":
    unittest.main()
