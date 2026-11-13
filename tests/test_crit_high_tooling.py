"""Regression tests for the 2026-11-02 crit/high tooling pass.

Covers: doctrine reaching skilled workers (never freeroam), triage requiring a
`cbh refute` record before PASS, Caido wire signals, the surface census, the
differential probe's judge, the corpus gap harness, report-intel on the corpus
schema, CVE lanes, the OOB responder, and diffprobe being treated as a sender.
Source: docs/disclosed-reports/HIGH-CRIT-LESSONS-2026-11.md
"""
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The second arm. `evidence.py` now asks what the CLASS of a claim needs, and an
# ownership claim needs two identities in one artifact (engine/class_proof.py). Without
# this spec the fixture is a single authenticated request to /users/124 — exactly what the
# class gate exists to catch. It is scaffolding for the question each test below actually
# asks, so it carries the arm a real IDOR PoC would carry.
IDOR_SPEC = {"steps": [
    {"name": "owner", "method": "GET", "url": "https://api.acme.com/users/124",
     "headers": {"Authorization": "Bearer owner-token"}},
    {"name": "other-account", "method": "GET", "url": "https://api.acme.com/users/124",
     "headers": {"Authorization": "Bearer attacker-token"}}]}

sys.path.insert(0, str(ROOT / "engine"))

import corpus_gap  # noqa: E402
import differential_probe as DP  # noqa: E402
import doctrine  # noqa: E402
import evidence  # noqa: E402
import report_intel  # noqa: E402
import skill_signals  # noqa: E402
import surface_census as SC  # noqa: E402


def _load(name, path):
    import importlib.machinery
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Doctrine(unittest.TestCase):
    def test_the_skilled_agent_gets_it_and_freeroam_never_does(self):
        """Freeroam has no methodology by design; handing it the doctrine would make it
        a worse skilled worker instead of a free one. The separation is the two call
        sites in engine/engine.py, since the per-role worker script that also carried
        this split went out with the second provider (2026-11-13)."""
        src = (ROOT / "engine" / "engine.py").read_text()
        self.assertIn("self._roe() + self._doctrine()", src)
        self.assertNotIn("_doctrine", src.split("def _freeroam")[-1]
                         if "def _freeroam" in src else "")
        self.assertIn("CRIT/HIGH DOCTRINE", doctrine.text())
        # and the orchestrator is told to paste it into every skilled brief
        self.assertIn("crit/high doctrine",
                      (ROOT / "scripts" / "hunt-arm.py").read_text())

    def test_engine_hunt_agent_appends_it(self):
        src = (ROOT / "engine" / "engine.py").read_text()
        self.assertIn("self._roe() + self._doctrine()", src)

    def test_doctrine_names_the_tools_it_relies_on(self):
        t = doctrine.text()
        for needle in ("vectors.py consumers", "SIGNAL", "cbh refute", "report-intel"):
            self.assertIn(needle, t)

    def test_hunt_arm_orders_carry_it(self):
        src = (ROOT / "scripts" / "hunt-arm.py").read_text()
        self.assertIn("cbh doctrine", src)
        self.assertIn("NEVER into a Freeroam brief", src)


class TriageRequiresRefute(unittest.TestCase):
    TEXT = ("# IDOR read other user\n\nSeverity: High\nAsset: api.acme.com (in scope)\n"
            "GET https://api.acme.com/users/124\nany low-priv attacker account\n"
            "not duplicate, previously unknown\nImpact: data: leaked email of user 124\n"
            # a complete finding names the harmed party; the victim hold is tested in
            # TriageRequiresVictim below, so this fixture satisfies it.
            "**Victim:** user 124 loses their email address to any logged-in account\n")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        proj = Path(self.tmp.name) / "Targets" / "acme" / "findings"
        proj.mkdir(parents=True)
        self.f = proj / "idor.md"
        self.f.write_text(self.TEXT)
        (proj / "idor.poc.json").write_text(json.dumps(IDOR_SPEC))
        (proj / "idor.result.json").write_text(json.dumps({
            "spec_file": "idor.poc.json",
            "final_verdict": "PASS",
            "runs": [{"steps": [], "result": {"final_url": "https://api.acme.com/users/124", "status": 200}}]}))

    def triage(self, *extra):
        return subprocess.run([sys.executable, "-B", str(ROOT / "scripts" / "cbh.py"), "triage",
                               str(self.f), *extra], capture_output=True, text=True, timeout=120)

    def test_pass_without_refute_is_pending(self):
        r = self.triage()
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("PASS-PENDING-REFUTE", r.stdout)

    def test_survived_refute_passes(self):
        self.f.with_name("idor.refute.json").write_text(json.dumps({"verdict": "SURVIVED"}))
        r = self.triage()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("VERDICT: PASS", r.stdout)

    def test_incomplete_refute_is_still_pending(self):
        self.f.with_name("idor.refute.json").write_text(json.dumps({"verdict": "INCOMPLETE"}))
        self.assertEqual(self.triage().returncode, 3)

    def test_no_refute_flag_is_the_draft_escape(self):
        self.assertEqual(self.triage("--no-refute").returncode, 0)

    def test_refute_record_reader(self):
        self.assertIsNone(evidence.refute_record(self.f))
        self.f.with_name("idor.refute.json").write_text('{"verdict": "SURVIVED"}')
        self.assertEqual(evidence.refute_record(self.f)["verdict"], "SURVIVED")


class TriageRequiresVictim(unittest.TestCase):
    """2026-11-11: `victim` was in 15 of 138 worker briefs, and one engagement wrote 134
    primitives against 1 finding. A 7/7 pass with no named victim is held, not killed."""

    TEXT = TriageRequiresRefute.TEXT.replace(
        "**Victim:** user 124 loses their email address to any logged-in account\n", "")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        proj = Path(self.tmp.name) / "Targets" / "acme" / "findings"
        proj.mkdir(parents=True)
        self.f = proj / "idor.md"
        self.f.write_text(self.TEXT)
        (proj / "idor.poc.json").write_text(json.dumps(IDOR_SPEC))
        (proj / "idor.result.json").write_text(json.dumps({
            "spec_file": "idor.poc.json",
            "final_verdict": "PASS",
            "runs": [{"steps": [], "result": {"final_url": "https://api.acme.com/users/124",
                                              "status": 200}}]}))
        self.f.with_name("idor.refute.json").write_text(json.dumps({"verdict": "SURVIVED"}))

    def triage(self, env=None, *extra):
        e = dict(os.environ)
        e.update(env or {})
        return subprocess.run([sys.executable, "-B", str(ROOT / "scripts" / "cbh.py"), "triage",
                               str(self.f), *extra], capture_output=True, text=True,
                              timeout=120, env=e)

    def test_a_finding_with_no_victim_is_held(self):
        r = self.triage()
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("PASS-PENDING-VICTIM", r.stdout)

    def test_the_hold_names_the_remedy(self):
        out = self.triage().stdout
        self.assertIn("Victim:", out)
        self.assertIn("--demote", out)

    def test_a_named_victim_passes(self):
        self.f.write_text(self.TEXT + "\n**Victim:** user 124 loses their email address\n")
        r = self.triage()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("VERDICT: PASS", r.stdout)

    def test_the_kill_switch_lifts_it(self):
        r = self.triage({"CBH_VICTIM_GATE": "off"})
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_prose_about_an_attacker_is_not_a_victim_line(self):
        self.assertFalse(evidence.has_victim(
            "an attacker can read any user's email; the victim would be affected"))
        self.assertTrue(evidence.has_victim("**victim:** the buyer loses the order"))

    def test_the_verdict_itself_is_unchanged_by_a_missing_victim(self):
        # evidence.py grades proof, not framing: a PASS stays DEMONSTRATED.
        rep = evidence.check(self.f)
        self.assertEqual(rep["status"], "DEMONSTRATED")
        self.assertFalse(rep["victim"])


class CaidoSignals(unittest.TestCase):
    def run_hook(self, ev):
        return subprocess.run([sys.executable, str(ROOT / "scripts" / "mcp-signals.py")],
                              input=json.dumps(ev), capture_output=True, text=True, timeout=30)

    def test_real_caido_shape_redirect_with_body(self):
        resp = {"response": {"body": "<html>Admin</html>", "bodySize": 2233, "firstLine": "HTTP/1.0 302 Found"},
                "statusCode": 302}
        r = self.run_hook({"tool_name": "mcp__caido__caido_send_request",
                           "tool_response": [{"type": "text", "text": json.dumps(resp)}]})
        self.assertEqual(r.returncode, 2)
        self.assertIn("BODY-ON-REDIRECT", r.stderr)

    def test_quiet_on_plain_response_and_other_tools(self):
        resp = {"response": {"body": "ok", "bodySize": 2}, "statusCode": 200}
        self.assertEqual(self.run_hook({"tool_name": "mcp__caido__caido_send_request",
                                        "tool_response": resp}).returncode, 0)
        self.assertEqual(self.run_hook({"tool_name": "Bash", "tool_response": resp}).returncode, 0)

    def test_garbage_never_blocks(self):
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "mcp-signals.py")],
                           input="not json", capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0)


class Census(unittest.TestCase):
    OPS = [
        {"method": "POST", "url": "https://api.acme.com/v2/orders/{id}/refund", "path": "/v2/orders/{id}/refund",
         "host": "api.acme.com", "parameters": [], "fields": ["amount"], "risk_hints": ["state-change"]},
        {"method": "POST", "url": "https://api.acme.com/graphql", "path": "/graphql", "host": "api.acme.com",
         "operation_name": "refundOrder", "parameters": [], "fields": [], "risk_hints": ["graphql"]},
        {"method": "GET", "url": "https://m.acme.com/api/orders/{id}", "path": "/api/orders/{id}",
         "host": "m.acme.com", "parameters": [], "fields": [], "risk_hints": ["object-authorization"]},
        {"method": "POST", "url": "https://api.acme.com/v2/import", "path": "/v2/import", "host": "api.acme.com",
         "parameters": ["source_url", "return_url"], "fields": [], "risk_hints": []},
    ]

    def test_sibling_interfaces_cross_kind(self):
        sib = SC.sibling_interfaces(self.OPS)
        self.assertTrue(sib)
        top = sib[0]
        self.assertEqual(top["resource"], "order")
        self.assertTrue(top["cross_kind"])
        self.assertIn("graphql", top["interfaces"])

    def test_fetchers_take_fetch_params_not_redirect_params(self):
        f = SC.fetchers(self.OPS, [("GET", "https://api.acme.com/preview?url=x&next_url=y")])
        by = {x["endpoint"]: x for x in f}
        self.assertEqual(by["POST https://api.acme.com/v2/import"]["params"], ["source_url"])
        self.assertEqual(by["GET https://api.acme.com/preview"]["params"], ["url"])

    def test_secret_leads_from_recon_file_report_prefix_only(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "acme"
            (p / "recon").mkdir(parents=True)
            key = "AKIA" + "ABCDEFGHIJKLMNOP1234"
            (p / "recon" / "bundle.js").write_text(f'var k="{key}";')
            leads = SC.secret_leads(p, "acme", Path(d) / "mem")
            self.assertEqual(leads[0]["provider"], "AWS")
            self.assertNotIn(key, json.dumps(leads))

    def test_seed_writes_vectors(self):
        with tempfile.TemporaryDirectory() as d:
            rep = {"sibling_interfaces": SC.sibling_interfaces(self.OPS),
                   "fetchers": SC.fetchers(self.OPS, []), "secret_leads": [], "default_host": "api.acme.com"}
            added = SC.seed(rep, Path(d))
            self.assertGreaterEqual(sum(added.values()), 2)
            import vectors as V
            classes = {v["class"] for v in V.load("api.acme.com", Path(d))["vectors"]}
            self.assertTrue({"sibling-interface", "ssrf"} <= classes)


class DiffprobeJudge(unittest.TestCase):
    def r(self, name, status, sha, size, layer=None, body=b"", control=False):
        return {"name": name, "url": "u", "headers": [], "control": control, "status": status,
                "exit": 0, "bytes": size, "sha": sha, "layer": layer or {}, "_body": body}

    def test_marker_echo_and_layer_change_are_leads(self):
        res = [self.r("baseline", "200", "a", 500), self.r("baseline-repeat", "200", "a", 500),
               self.r("control-impossible-path", "404", "c", 9, control=True),
               self.r("hdr:x-forwarded-host", "302", "x", 5, {"location": "https://cbhm.invalid/"}),
               self.r("path:semicolon", "200", "s", 900, {"server": "origin"}),
               self.r("path:uppercase", "404", "c", 9)]
        rep = DP.judge(res, "cbhm")
        self.assertEqual(set(rep["leads"]), {"hdr:x-forwarded-host", "path:semicolon"})
        by = {x["name"]: x for x in rep["results"]}
        self.assertEqual(by["path:uppercase"]["verdict"], "same-as-control")
        self.assertNotIn("_body", by["baseline"])

    def test_variants_are_get_only_and_carry_a_control(self):
        v = DP.variants("https://a.b/x", "m")
        self.assertTrue(any(x.get("control") for x in v))
        self.assertFalse(any("Content-Length" in " ".join(x["headers"]) for x in v))

    def test_diffprobe_counts_as_a_sender(self):
        self.assertTrue(skill_signals.sends_request("cbh diffprobe https://a.b/x"))
        self.assertFalse(skill_signals.sends_request("cbh census --seed"))


class CorpusAndIntel(unittest.TestCase):
    def test_gap_harness_on_a_tiny_corpus(self):
        with tempfile.TemporaryDirectory() as d:
            c = Path(d) / "corpus.json"
            c.write_text(json.dumps({"meta": {"source": "t"}, "reports": [
                {"id": "a", "classes": ["auth-bypass"], "keywords": ["execution after redirect"], "lesson": "body-not-status"},
                {"id": "b", "classes": ["xss"], "keywords": ["zzqx-nonexistent-technique", "qqzz other"], "lesson": "other"}]}))
            rep = corpus_gap.run(c, ROOT)
            self.assertEqual(rep["reports"], 2)
            self.assertEqual([g["id"] for g in rep["gaps"]], ["b"])
            self.assertIn("Gaps", corpus_gap.render_md(rep))

    def test_real_corpus_is_well_formed_and_covered(self):
        c = ROOT / "docs" / "disclosed-reports" / "corpus-2026-11" / "corpus.json"
        if not c.exists():
            self.skipTest("corpus not present")
        rep = corpus_gap.run(c, ROOT)
        self.assertGreaterEqual(rep["reports"], 100)
        self.assertGreaterEqual(rep["technique_coverage_pct"], 90.0)

    def test_report_intel_reads_corpus_fields_and_string_bounties(self):
        ds = {"meta": {"source": "t"}, "reports": [
            {"id": "x", "mechanic": "execution after redirect leaks admin page", "bounty": "$2,500"}]}
        m = report_intel.search(ds, "redirect admin page")
        self.assertEqual(m[0]["id"], "x")
        self.assertEqual(m[0]["bounty"], 2500.0)
        self.assertIn("mechanic", m[0])


class CveLanes(unittest.TestCase):
    def test_lanes(self):
        d = _load("cve_digest_t", ROOT / "scripts" / "cve-digest.py")
        self.assertIn("edge one-shot", d.lane("Check Point Quantum Gateway"))
        self.assertIn("patch-diff", d.lane("Next.js"))
        self.assertEqual(d.lane("SomethingElse"), "")


class OobResponder(unittest.TestCase):
    def test_redirect_loop_lands_on_final_and_logs_ua(self):
        mod = _load("oob_t", ROOT / "scripts" / "oob-responder.py")
        import http.server
        with tempfile.TemporaryDirectory() as d:
            mod.Handler.log_path = Path(d) / "oob.jsonl"
            srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{port}/loop/mk/0",
                                             headers={"User-Agent": "curl/8.0"})
                body = urllib.request.urlopen(req, timeout=10).read().decode()
            except urllib.error.HTTPError as e:  # urllib caps redirects at 10
                body = str(e)
            finally:
                srv.shutdown()
            rows = [json.loads(l) for l in mod.Handler.log_path.read_text().splitlines()]
            self.assertGreaterEqual(len(rows), 5)
            self.assertEqual(rows[0]["user_agent"], "curl/8.0")
            self.assertIn(rows[0]["status"], (301, 302, 303, 307, 308))


if __name__ == "__main__":
    unittest.main()


class FieldTestRegressions(unittest.TestCase):
    """Defects found by the 2026-11-02 live field test on standoff365/yukki-lk."""

    def test_bbcurl_status_from_headers_when_caller_brings_w(self):
        b = _load("bbcurl_t", ROOT / "scripts" / "bbcurl")
        with tempfile.TemporaryDirectory() as d:
            h = Path(d) / "h.txt"
            h.write_text("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 301 Moved\r\nLocation: /a\r\n\r\n"
                         "HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n")
            e = {}
            b._fill_status_from_headers(e, str(h))
            self.assertEqual(e["http_code"], 302)
            self.assertEqual(e["num_redirects"], 1)
            self.assertEqual(b._own_header_path(["-D", str(h), "u"]), str(h))
            self.assertIsNone(b._own_header_path(["-D", "-", "u"]))

    def test_census_seeds_siblings_with_relative_urls_and_never_duplicates(self):
        ops = [{"method": "GET", "path": "/api/user/current", "url": "/api/user/current", "risk_hints": []},
               {"method": "POST", "path": "/api/v1/users", "url": "/api/v1/users", "risk_hints": ["state-change"]}]
        rep = {"sibling_interfaces": SC.sibling_interfaces(ops), "fetchers": [], "secret_leads": [],
               "default_host": "new.acme.test"}
        self.assertTrue(rep["sibling_interfaces"])
        with tempfile.TemporaryDirectory() as d:
            import vectors as V
            led = V.load("new.acme.test", Path(d))
            led["vectors"].append(dict(V._new_vector("ssrf", "/_next/image", origin="manual"),
                                       status="active", requests_fired=20))
            V.save(led, Path(d))
            rep["fetchers"] = [{"endpoint": "GET https://new.acme.test/_next/image", "params": ["url"], "why": ["x"]}]
            added = SC.seed(rep, Path(d))
            rows = V.load("new.acme.test", Path(d))["vectors"]
            self.assertEqual(sum(1 for v in rows if v["class"] == "ssrf"), 1, "worked vector re-added as untried")
            self.assertTrue(any(v["class"] == "sibling-interface" for v in rows))
            sib = next(v for v in rows if v["class"] == "sibling-interface")
            self.assertGreater(sib["priority"], V.CATALOG["missing_authorization"]["impact"])
            self.assertEqual(added, {"new.acme.test": 1})

    def test_webhook_receiver_route_is_not_a_fetcher(self):
        f = SC.fetchers([], [("GET", "https://cem.acme.test/webhook"), ("GET", "https://cem.acme.test/webhooks/x"),
                             ("GET", "https://a.test/render/pdf")])
        self.assertEqual([x["endpoint"] for x in f], ["GET https://a.test/render/pdf"])

    def test_diffprobe_echo_in_control_is_noise(self):
        m = "cbhq"
        def r(name, status, size, body, control=False):
            return {"name": name, "url": "u", "headers": [], "control": control, "status": status, "exit": 0,
                    "bytes": size, "sha": name, "layer": {}, "_body": body}
        res = [r("baseline", "200", 2, b"{}"), r("baseline-repeat", "200", 2, b"{}"),
               r("control-impossible-path", "404", 86, b'{"message":"Cannot GET /health/cbhq-nope"}', True),
               r("path:semicolon", "404", 81, b'{"message":"Cannot GET /health;cbhq"}')]
        rep = DP.judge(res, m)
        self.assertTrue(rep["echo_is_noise"])
        by = {x["name"]: x for x in rep["results"]}
        self.assertFalse(any("echoed" in w for w in by["path:semicolon"].get("why", [])))

    def test_quoted_prose_is_not_a_sender_but_shell_c_is(self):
        self.assertFalse(skill_signals.sends_request("cbh remember --notes 'fired bbcurl https://x/mfa'"))
        self.assertTrue(skill_signals.sends_request("bash -c 'bbcurl https://x/'"))
        self.assertTrue(skill_signals.sends_request("CBH_PROJECT=a bbcurl -s 'https://x/mfa'"))

    def test_rejected_mark_says_nothing_was_recorded(self):
        import vectors as V
        with tempfile.TemporaryDirectory() as d:
            V.save(V.seed("h", ["/a"], ["ssrf"], memdir=Path(d)), memdir=Path(d))
            with self.assertRaises(SystemExit) as cm:
                V.mark("h", "ssrf:/a", "active", mutation="free text", requests=3, memdir=Path(d))
            self.assertIn("NOTHING WAS RECORDED", str(cm.exception))
            self.assertEqual(V.load("h", Path(d))["vectors"][0]["requests_fired"], 0)

    def test_sibling_interface_has_consumers(self):
        import vectors as V
        self.assertTrue(V.consumers_for("sibling-interface"))


class BbcurlDispatch(unittest.TestCase):
    """~/.local/bin/bbcurl -> scripts/bbcurl-dispatch, which is now one implementation.

    It used to pick between two workspaces by cwd and by CBH_PROJECT. The second
    workspace went out on 2026-11-13, so the only thing left to hold is that the name
    on the operator's PATH still lands on THIS workspace's transport, from any cwd and
    with any of the old selector variables set — those must not pick anything else.
    """

    def which(self, cwd, **env):
        import os
        e = dict(os.environ, CBH_BBCURL_WHICH="1")
        for k in ("CBH_PROJECT", "CLAUDECODE", "CBH_BBCURL_IMPL"):
            e.pop(k, None)
        e.update(env)
        return subprocess.run([str(ROOT / "scripts" / "bbcurl-dispatch")], cwd=cwd, env=e,
                              capture_output=True, text=True, timeout=30).stdout.strip()

    def test_every_cwd_and_selector_lands_on_this_workspace(self):
        with tempfile.TemporaryDirectory() as d:
            claude = Path(d) / "CL"
            (claude / "Targets" / "both").mkdir(parents=True)
            (claude / "Targets" / "both" / "scope.md").write_text("x")
            roots = {"CBH_CLAUDE_ROOT": str(claude)}
            for env in ({}, {"CLAUDECODE": "1"}, {"CBH_PROJECT": "both"},
                        {"CBH_PROJECT": "unknown-to-this-workspace"},
                        {"CBH_BBCURL_IMPL": "elsewhere"}):
                for cwd in (d, str(claude)):
                    with self.subTest(env=env, cwd=cwd):
                        self.assertEqual("claude", self.which(cwd, **roots, **env))

    def test_the_wrapper_execs_this_workspaces_bbcurl(self):
        src = (ROOT / "scripts" / "bbcurl-dispatch").read_text()
        self.assertIn('exec "$CLAUDE_ROOT/scripts/bbcurl" "$@"', src)
        self.assertNotIn("ZAI_ROOT", src)

    def test_new_names_are_senders(self):
        self.assertTrue(skill_signals.sends_request("zbbcurl https://x/"))
        self.assertTrue(skill_signals.sends_request("CBH_PROJECT=a cbbcurl -s https://x/"))
