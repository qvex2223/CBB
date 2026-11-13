#!/usr/bin/env python3
"""bbscan is the only gated path to sqlmap and nmap.

Both tools build their own traffic, so bbcurl cannot cover them. Installing them
on 2026-10-29 added two transports that bypassed scope, pacing, mandatory headers
and audit; these tests pin the refusals that close that gap, because every one of
them fails open if it silently stops matching.
"""
import importlib.machinery
import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))


def _load():
    # scripts/bbscan has no .py suffix, so spec_from_file_location infers no loader.
    loader = importlib.machinery.SourceFileLoader(
        "bbscan_under_test", str(REPO / "scripts" / "bbscan"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


BB = _load()


class ArgSplit(unittest.TestCase):
    def test_bb_flags_are_stripped_from_the_tool_command_line(self):
        tool, targv, dry, approval, ungated = BB.split_args(
            ["sqlmap", "--bb-dry-run", "-u", "https://x.test/a", "--bb-approved", "approvals/a.md"])
        self.assertEqual("sqlmap", tool)
        self.assertEqual(["-u", "https://x.test/a"], targv)
        self.assertTrue(dry)
        self.assertEqual("approvals/a.md", approval)
        self.assertFalse(ungated)


class TargetExtraction(unittest.TestCase):
    def test_sqlmap_url_is_found_for_the_scope_gate(self):
        targets, errs = BB.sqlmap_targets(["-u", "https://x.test/a?id=1"])
        self.assertEqual(["https://x.test/a?id=1"], targets)
        self.assertEqual([], errs)

    def test_google_dork_is_refused_because_no_gate_can_vouch_for_its_targets(self):
        _, errs = BB.sqlmap_targets(["-g", "inurl:php?id="])
        self.assertTrue(any("google-dork" in e for e in errs))

    def test_cidr_is_expanded_so_every_address_is_scope_checked(self):
        targets, errs = BB.nmap_targets(["-p", "443", "10.1.2.0/30"])
        self.assertEqual([], errs)
        self.assertIn("10.1.2.1", targets)
        self.assertIn("10.1.2.2", targets)

    def test_a_port_list_is_never_mistaken_for_a_target(self):
        targets, _ = BB.nmap_targets(["-sV", "-p", "443,8080", "1.2.3.4"])
        self.assertEqual(["1.2.3.4"], targets)

    def test_octet_range_is_refused_not_silently_scanned(self):
        targets, errs = BB.nmap_targets(["10.1.2.1-50"])
        self.assertEqual([], targets)
        self.assertTrue(any("mapcidr" in e for e in errs))

    def test_oversized_cidr_is_refused(self):
        targets, errs = BB.nmap_targets(["10.0.0.0/8"])
        self.assertEqual([], targets)
        self.assertTrue(any("expands to" in e for e in errs))


class GatedSwitches(unittest.TestCase):
    """Narrowed 2026-10-29 on operator instruction.

    Throughput, technique, scan type and evasion are the operator's call and are
    NOT gated — the engagement's pacing budget still bounds every request. What
    stays is what a permission to test cannot cover, because the affected party is
    somebody else: another user's stored rows, a write to production, code
    execution, availability.
    """

    def _blocked(self, tool, argv, approval="", project=Path("/nonexistent")):
        return BB.check_gated(tool, argv, approval, project)

    def test_dump_reads_other_users_rows(self):
        self.assertTrue(self._blocked("sqlmap", ["--dump"]))

    def test_risk_above_one_writes_to_the_database(self):
        self.assertTrue(self._blocked("sqlmap", ["--risk=2"]))

    def test_stacked_queries_write_so_they_stay_blocked(self):
        self.assertTrue(self._blocked("sqlmap", ["--technique=S"]))

    def test_time_based_technique_is_the_operators_call(self):
        self.assertEqual([], self._blocked("sqlmap", ["--technique=T"]))

    def test_request_volume_is_the_operators_call(self):
        for a in ("--level=5", "--crawl=3", "--forms", "--tamper=space2comment"):
            self.assertEqual([], self._blocked("sqlmap", [a]), a)

    def test_reading_a_file_is_allowed_but_writing_one_is_not(self):
        self.assertEqual([], self._blocked("sqlmap", ["--file-read=/etc/hostname"]))
        self.assertTrue(self._blocked("sqlmap", ["--file-write=/tmp/x"]))

    def test_os_shell_is_command_execution(self):
        self.assertTrue(self._blocked("sqlmap", ["--os-shell"]))

    def test_boolean_technique_at_risk_one_is_the_allowed_shape(self):
        self.assertEqual([], self._blocked(
            "sqlmap", ["-u", "https://x.test/a?id=1", "--level=1", "--risk=1", "--technique=B"]))

    def test_timing_template_and_scan_type_are_the_operators_call(self):
        for a in ("-T4", "-T5", "-A", "-sU", "--min-rate=100"):
            self.assertEqual([], self._blocked("nmap", [a]), a)

    def test_detection_nse_runs_but_exploitation_does_not(self):
        self.assertEqual([], self._blocked("nmap", ["--script=vuln"]))
        for cat in ("exploit", "dos", "brute", "malware"):
            self.assertTrue(self._blocked("nmap", [f"--script={cat}"]), cat)

    def test_plain_service_scan_is_the_allowed_shape(self):
        self.assertEqual([], self._blocked("nmap", ["-sV", "-p", "443", "1.2.3.4"]))

    def test_approval_must_exist_on_disk_not_merely_be_named(self):
        self.assertTrue(self._blocked("sqlmap", ["--dump"], approval="approvals/nope.md"))

    def test_an_existing_approval_file_clears_the_gate(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td)
            (proj / "approvals").mkdir()
            (proj / "approvals" / "ok.md").write_text("programme approved on 2026-10-29",
                                                      encoding="utf-8")
            self.assertEqual([], self._blocked("sqlmap", ["--dump"],
                                               approval="approvals/ok.md", project=proj))


class BuiltProbes(unittest.TestCase):
    """nsupdate and snmp are BUILT, not forwarded.

    For both, the safeguard used to be a sentence in `permissions.autoMode.allow`
    ("Writing, deleting or altering an actual DNS record is NOT allowed by this
    entry", "never guessing a non-default secret"). A sentence is not a mechanism.
    These tests are the mechanism.
    """

    def test_the_built_nsupdate_script_has_no_update_section(self):
        plan, errs = BB.nsupdate_plan(["185.171.101.250", "--zone", "ykky.ru"])
        self.assertEqual([], errs)
        self.assertIn("prereq nxdomain", plan["script"])
        self.assertIn("send", plan["script"])
        self.assertIsNone(BB.UPDATE_VERB.search(plan["script"]))
        for verb in ("update add", "update delete", "\nadd ", "\ndelete "):
            self.assertNotIn(verb, plan["script"])

    def test_arbitrary_nsupdate_input_is_refused_not_forwarded(self):
        _, errs = BB.nsupdate_plan(
            ["185.171.101.250", "--zone", "ykky.ru", "update add evil.ykky.ru 300 A 1.2.3.4"])
        self.assertTrue(errs)
        self.assertTrue(any("builds the nsupdate script itself" in e for e in errs))

    def test_nsupdate_without_a_zone_is_refused(self):
        _, errs = BB.nsupdate_plan(["185.171.101.250"])
        self.assertTrue(any("--zone" in e for e in errs))

    def test_a_non_default_community_is_credential_guessing(self):
        _, errs = BB.snmp_plan(["185.171.101.250", "--community", "s3cret"])
        self.assertTrue(any("non-default community" in e for e in errs))

    def test_the_default_communities_are_accepted(self):
        plan, errs = BB.snmp_plan(["185.171.101.250"])
        self.assertEqual([], errs)
        self.assertEqual(["public", "private"], plan["communities"])

    def test_the_packet_is_a_valid_snmp_v2c_get(self):
        pkt = BB.snmp_packet("public", "1.3.6.1.2.1.1.1.0", 1)
        self.assertEqual(0x30, pkt[0])                      # SEQUENCE
        self.assertEqual("020101", pkt[2:5].hex())          # version 1 = v2c
        self.assertIn(b"public", pkt)
        self.assertIn(bytes.fromhex("2b06010201010100"), pkt)   # the sysDescr OID
        self.assertIn(b"\xa0", pkt)                         # GetRequest PDU tag

    def test_a_silent_socket_is_its_own_bucket_not_a_hit(self):
        """`udp-oracle-no-response-is-its-own-bucket`: a dropped packet is not a find."""
        res = BB.snmp_get("127.0.0.1", "public", timeout=0.5)
        self.assertEqual("no-response", res["state"])
        self.assertIsNone(res["value"])
        self.assertEqual(0, res["bytes"])


class PacingTranslation(unittest.TestCase):
    """The budget is useless unless it becomes the tool's own throttle."""

    def test_sqlmap_budget_becomes_delay_and_single_thread(self):
        flags = BB.pace_flags("sqlmap", ["-u", "https://x.test/a"], 0.5)
        self.assertIn("--delay=0.5", flags)
        self.assertIn("--threads=1", flags)

    def test_nmap_budget_becomes_scan_delay_and_max_rate(self):
        flags = BB.pace_flags("nmap", ["-p", "443", "1.2.3.4"], 0.5)
        self.assertIn("--scan-delay=0.5s", flags)
        self.assertTrue(any(f.startswith("--max-rate=2.000") for f in flags))
        self.assertIn("--max-parallelism", flags)

    def test_a_caller_supplied_throttle_is_not_overridden(self):
        flags = BB.pace_flags("sqlmap", ["--delay=3", "--threads=1"], 0.5)
        self.assertFalse(any(f.startswith("--delay=") for f in flags))

    def test_a_timing_template_still_gets_an_explicit_rate_cap(self):
        """-T5 is allowed, so the budget has to be enforced by an explicit flag."""
        flags = BB.pace_flags("nmap", ["-T5", "-A", "1.2.3.4"], 0.1)
        self.assertTrue(any(f.startswith("--max-rate=") for f in flags))
        self.assertIn("--scan-delay=0.1s", flags)


class SenderAndToolStand(unittest.TestCase):
    def test_all_the_names_fire_the_hooks(self):
        import skill_signals as ss
        for cmd in ("bbscan nmap -p443 1.2.3.4",
                    "bbscan snmp 1.2.3.4",
                    "sqlmap -u https://x.test/a",
                    "nmap -sV 1.2.3.4",
                    "nsupdate -v"):
            self.assertTrue(ss.sends_request(cmd), cmd)

    def test_a_word_containing_a_tool_name_is_not_a_sender(self):
        import skill_signals as ss
        self.assertFalse(ss.sends_request("echo sqlmapish"))

    def test_the_stand_declares_them_so_doctor_notices_a_disappearance(self):
        import workspace_check as wc
        for t in ("sqlmap", "nmap", "nsupdate", "bbscan"):
            self.assertIn(t, wc.TOOLS_REQUIRED)
            self.assertNotIn(t, wc.TOOLS_KNOWN_ABSENT)

    def test_a_worker_gets_bbscan_and_never_the_raw_tools(self):
        import agent
        self.assertIn("Bash(bbscan:*)", agent.ALLOWED_TOOLS)
        for bad in ("sqlmap", "nmap", "Bash(curl"):
            self.assertNotIn(bad, agent.ALLOWED_TOOLS)


class SkillsRouteThroughTheGate(unittest.TestCase):
    """A skill that prints a raw invocation is a gate nobody applies."""

    def test_no_skill_or_command_invokes_sqlmap_or_nmap_ungated(self):
        import re
        bad = []
        pat = re.compile(r"(?:^|[^\w./-])(sqlmap|nmap)\s+-", re.M)
        for md in list((REPO / "skills").rglob("*.md")) + list((REPO / "commands").rglob("*.md")):
            text = md.read_text(encoding="utf-8", errors="replace")
            for m in pat.finditer(text):
                line_start = text.rfind("\n", 0, m.start()) + 1
                line = text[line_start:text.find("\n", m.start())]
                if "bbscan" in line:
                    continue
                bad.append(f"{md.relative_to(REPO)}: {line.strip()[:90]}")
        self.assertEqual([], bad, "ungated invocations found:\n" + "\n".join(bad))


if __name__ == "__main__":
    unittest.main()
