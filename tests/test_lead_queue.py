"""cbh leads (2026-11-11): ranks open leads, holds back account-blocked ones, closes leads."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "engine"))
import lead_queue as LQ  # noqa: E402


def _eng(tmp):
    root = Path(tmp) / "Targets"
    e = root / "p" / "prog"
    (e / "leads").mkdir(parents=True)
    (e / "primitives").mkdir()
    (e / "scope.md").write_text("x")
    (e / "profile.json").write_text(json.dumps({"downrank_classes": {"info-leak": "no"}}))
    w = lambda d, n, t: (e / d / n).write_text(t)  # noqa: E731
    w("primitives", "idor-order-read.md", "# P\n\n**Status:** primitive\n**Chain:** needs `nothing` · gives `other-user-order`\n")
    w("leads", "route-existence-oracle.md", "# L\n\n**Status:** lead\n**Chain:** needs `nothing` · gives `route-oracle`\n")
    w("leads", "seller-thing.md", "# L\n\n**Status:** lead\n**Chain:** needs `seller-session` · gives `xss-on-seller`\n")
    w("leads", "done.md", "# L\n\n**Status:** REFUTED (2026-11-01)\n")
    return root, e


class LeadQueue(unittest.TestCase):
    def test_ranking_account_split_and_closed(self):
        with tempfile.TemporaryDirectory() as t:
            root, e = _eng(t)
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                q = LQ.scan(e)
            files = [r["file"] for r in q["open"]]
            self.assertEqual("primitives/idor-order-read.md", files[0])
            self.assertIn("leads/route-existence-oracle.md", files)
            self.assertIn("seller-session", q["needs_account"])
            self.assertEqual(1, q["closed"])

    def test_close_rewrites_status(self):
        with tempfile.TemporaryDirectory() as t:
            root, e = _eng(t)
            f = e / "leads" / "route-existence-oracle.md"
            self.assertEqual(0, LQ.close(str(f), "exhausted", "all arms fired"))
            txt = f.read_text()
            self.assertIn("**Status:** EXHAUSTED", txt)
            self.assertIn("Previous status: lead", txt)
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                self.assertEqual(2, LQ.scan(e)["closed"])


if __name__ == "__main__":
    unittest.main()


class StatusBannerForms(unittest.TestCase):
    """Closure banners are written five ways here; only one was ever detected (2026-11-11)."""

    def test_closed_is_recognised_in_every_house_form(self):
        from lead_queue import _is_closed, _is_blocked
        for form in (
            "**Status:** REFUTED (2026-11-01)",
            "**Status: CLOSED — verified negative**",
            "**Status** : EXHAUSTED",
            "## Status — **CLOSED 2026-10-19 by HUNTER-100 (wave 22). Verified negative.**",
            "> **Status: promoted to `primitives/x.md` and closed as a lead**",
            "**Status:** verified negative on its one ranked question",
        ):
            self.assertTrue(_is_closed(f"# T\n\n{form}\n"), form)
            self.assertFalse(_is_blocked(f"# T\n\n{form}\n"), form)

    def test_open_banners_stay_open(self):
        from lead_queue import _is_closed
        for form in (
            "**Status:** lead (hypothesis). Capability *partially* proven",
            "**Status: primitive, impact unproven (allowlist holds)**",
            # the verdict is read from the START: a sentence that merely contains "closed"
            # must not close the row
            "**Status:** lead — the consumer lane is closed at the registry level, the rest is not",
        ):
            self.assertFalse(_is_closed(f"# T\n\n{form}\n"), form)

    def test_close_then_scan_keeps_it_closed(self):
        """`cbh leads close` inserts at the FIRST status line and keeps the old one below;
        last-wins semantics would re-open what the tool just closed."""
        from lead_queue import _is_closed
        closed = ("# T\n\n**Status:** REFUTED (2026-11-11) — control was byte-identical\n\n"
                  "Previous status: lead (hypothesis)\n\n**Status:** lead\n")
        self.assertTrue(_is_closed(closed))

    def test_blocked_banner(self):
        from lead_queue import _is_blocked, _is_closed
        t = "# T\n\n**Status: BLOCKED — needs an apex-Secure cookie set**\n"
        self.assertTrue(_is_blocked(t))
        self.assertFalse(_is_closed(t))


class ClassWordAnchoring(unittest.TestCase):
    """Short class tokens must not match inside longer, unrelated words.

    Both cases below were live misclassifications on 2026-11-11: the bare `dom`
    token in the xss rule matched `Domain=ozon.ru` in a session-fixation lead's
    title and `subdomain` in two CORS primitives' titles, so all three were
    ranked at the XSS payout.
    """

    def test_domain_in_title_is_not_xss(self):
        cls = LQ._class_of(
            "club-admin-anonymous-apex-sid-mint",
            "LEAD - an unauthenticated GET mints __Secure-sid at the apex Domain=ozon.ru "
            "session-fixation-verdict-on-ozon-ru-apex-sid")
        self.assertEqual(cls, "ato")

    def test_real_dom_sink_is_still_xss(self):
        self.assertEqual(LQ._class_of("x", "LEAD - a DOM-based sink"), "xss")
        self.assertEqual(LQ._class_of("y-dom-clobbering", "LEAD - clobbering"), "xss")

    def test_credentialed_subdomain_cors_is_data_exposure(self):
        cls = LQ._class_of(
            "leasing-api-cors-wildcard-subdomain-credentialed",
            "PRIMITIVE - grants credentialed cross-origin reads to any *.ozon.ru subdomain")
        self.assertEqual(cls, "data-exposure")




class StalledVerdict(unittest.TestCase):
    """`stalled` vs `blocked` (2026-11-11).

    An orchestrator read six queued browser lanes as hangs, killed them, and closed seven
    leads `--as blocked` with the note "6 Playwright hunters hung ~20min again". `blocked`
    takes a lead out of the queue and waits for the operator, so the whole XSS-in-email class
    left the queue over a lock-contention bug of ours, and the queue read `0 workable · 21
    blocked`. `stalled` is the verdict for our own tooling failing: the lead stays workable,
    flagged RETRY.
    """

    def test_a_stalled_lead_stays_workable_and_is_flagged(self):
        with tempfile.TemporaryDirectory() as t:
            root, e = _eng(t)
            f = e / "leads" / "route-existence-oracle.md"
            self.assertEqual(0, LQ.close(str(f), "stalled", "browser profile busy"))
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                q = LQ.scan(e)
            row = next((r for r in q["open"] if r["file"].endswith("route-existence-oracle.md")), None)
            self.assertIsNotNone(row, "a stalled lead must stay in the queue, not leave it")
            self.assertTrue(row.get("stalled"))
            self.assertEqual(1, q["stalled"])
            self.assertEqual(0, q["blocked"])

    def test_stalled_is_neither_closed_nor_blocked(self):
        t = "# T\n\n**Status:** STALLED (2026-11-11) — 6 Playwright hunters hung ~20min again\n"
        self.assertFalse(LQ._is_closed(t), "stalled must not count as a closure")
        self.assertFalse(LQ._is_blocked(t), "stalled must not hold the lead back")
        self.assertTrue(LQ._is_stalled(t))

    def test_render_marks_the_row_retry(self):
        with tempfile.TemporaryDirectory() as t:
            root, e = _eng(t)
            LQ.close(str(e / "leads" / "route-existence-oracle.md"), "stalled", "worker killed")
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                out = LQ.render(LQ.scan(e), 12)
            self.assertIn("RETRY", out)
            self.assertIn("1 stalled (counted in workable)", out)
            self.assertIn("stalled", out.split("Close every lane")[1])

    def test_reopen_puts_a_mis_marked_blocked_lead_back_in_the_queue(self):
        with tempfile.TemporaryDirectory() as t:
            root, e = _eng(t)
            f = e / "leads" / "route-existence-oracle.md"
            LQ.close(str(f), "blocked", "6 Playwright hunters hung ~20min again")
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                held = LQ.scan(e)
            self.assertEqual(1, held["blocked"])
            self.assertNotIn("leads/route-existence-oracle.md", [r["file"] for r in held["open"]])

            self.assertEqual(0, LQ.main(["reopen", str(f), "--note", "our lock, not the target"]))
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                back = LQ.scan(e)
            self.assertEqual(0, back["blocked"], "the displaced BLOCKED banner still held it back")
            self.assertIn("leads/route-existence-oracle.md", [r["file"] for r in back["open"]])
            body = f.read_text()
            self.assertIn("our lock, not the target", body)
            self.assertIn("Previous status: BLOCKED", body,
                          "reopen must keep the history, not erase the mis-mark")

    def test_reopen_requires_a_reason(self):
        with tempfile.TemporaryDirectory() as t:
            _root, e = _eng(t)
            f = e / "leads" / "route-existence-oracle.md"
            with self.assertRaises(SystemExit):
                LQ.main(["reopen", str(f)])

    def test_close_accepts_stalled_from_the_cli(self):
        with tempfile.TemporaryDirectory() as t:
            _root, e = _eng(t)
            f = e / "leads" / "seller-thing.md"
            self.assertEqual(0, LQ.main(["close", str(f), "--as", "stalled",
                                         "--note", "MCP server gone"]))
            self.assertIn("**Status:** STALLED", f.read_text())


class DeclaredClass(unittest.TestCase):
    """`**Class:** <name>` on its own line beats the CLASS_WORDS guess.

    The guess reads the filename and the title, which is all most records have, but it cannot
    see what a fired control already closed: `finance-mf-ssr-render-route-url` reads as `ssrf`
    from its title and its SSRF hypothesis is refuted in its own body.
    """

    def test_a_declaration_wins_over_the_filename_guess(self):
        with tempfile.TemporaryDirectory() as t:
            root, e = _eng(t)
            f = e / "leads" / "ssrf-render-route-url.md"
            f.write_text("# L\n\n**Class:** missing_authorization\n\n**Status:** lead\n"
                         "**Chain:** needs `nothing` · gives `route-oracle`\n")
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                q = LQ.scan(e)
            row = [r for r in q["open"] if r["file"] == "leads/ssrf-render-route-url.md"]
            self.assertEqual(1, len(row), "declared lead vanished from the queue")
            self.assertEqual("missing_authorization", row[0]["class"])

    def test_without_a_declaration_the_guess_still_runs(self):
        """Positive control: the same filename, no declaration, guesses `ssrf`."""
        with tempfile.TemporaryDirectory() as t:
            root, e = _eng(t)
            f = e / "leads" / "ssrf-render-route-url.md"
            f.write_text("# L\n\n**Status:** lead\n"
                         "**Chain:** needs `nothing` · gives `route-oracle`\n")
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                q = LQ.scan(e)
            row = [r for r in q["open"] if r["file"] == "leads/ssrf-render-route-url.md"][0]
            self.assertEqual("ssrf", row["class"])

    def test_an_unknown_name_is_ignored_not_adopted(self):
        """A typo'd class would route the item nowhere, so it falls back to the guess."""
        self.assertEqual("", LQ.declared_class("**Class:** sekret-exposure"))
        self.assertEqual("secret-exposure", LQ.declared_class("**Class:** `secret-exposure`"))
        self.assertEqual("secret-exposure", LQ.declared_class("**Class:** Secret-Exposure — why"))
        self.assertEqual("", LQ.declared_class("prose mentioning **Class:** nowhere special"))

    def test_the_declaration_must_start_its_own_line(self):
        self.assertEqual("", LQ.declared_class("see the **Class:** idor note above"))
        self.assertEqual("idor", LQ.declared_class("x\n**Class:** idor\ny"))

    def test_known_classes_covers_the_corpus_and_the_skill_map(self):
        names = LQ.known_classes()
        for n in ("secret-exposure", "missing_authorization", "info-leak", "ssrf"):
            self.assertIn(n, names)

    def test_both_live_ozon_leads_declare_a_routable_class(self):
        """The two records this was built for, read from the engagement itself."""
        base = REPO / "Targets" / "standoff365" / "ozon" / "leads"
        want = {"finance-mf-ssr-render-route-url.md": "missing_authorization",
                "msg-o3-ru-mattermost-webhooks-in-public-bundle.md": "secret-exposure"}
        for name, cls in want.items():
            f = base / name
            if not f.is_file():
                self.skipTest(f"{name} not present")
            self.assertEqual(cls, LQ.declared_class(f.read_text()), name)


class HeadingVerdicts(unittest.TestCase):
    """A worker who adjudicates a record at the top writes a heading, not a status banner.

    Measured on standoff365/ozon 2026-11-12: `# LEAD — ADJUDICATED 2026-10-16 (wave17 /
    HUNTER-36). Both hypotheses in this file are DEAD.` took a deep-hunter lane of the live
    wave, with its own body saying the tier had moved to a primitive.
    """

    DATED = ["## CLOSED 2026-10-16 (wave 10, HUNTER-3) — hypothesis 3 REFUTED",
             "# LEAD — ADJUDICATED 2026-10-16 (wave17 / HUNTER-36). Both are DEAD.",
             "## KILLED — 2026-10-16, wave 14, HUNTER-20 (authenticated)",
             "> ## SUPERSEDED 2026-10-29 — see the amended reason",
             "## **REFUTED**: 2026-10-16 — 24 mutations fired"]
    # Sections, not verdicts. Each of the first two is a real heading in this engagement,
    # inside a record whose own banner says STALLED, i.e. workable.
    SECTIONS = ["## Blocked", "## Not a finding, explicitly",
                "## BLOCKED — no-card-number floor",
                "## REFUTED: the allowlist is exact-match",
                "## Closed-loop verification of the oracle",
                "## Proven capability, as fired", "## Dead ends worth recording",
                "## Deadline for the program", "## Closed questions",
                "## What is established, by a fired request"]

    def test_a_dated_verdict_heading_closes_the_row(self):
        for h in self.DATED:
            self.assertTrue(LQ._heading_verdict(h), h)

    def test_an_undated_section_heading_does_not(self):
        for h in self.SECTIONS:
            self.assertEqual("", LQ._heading_verdict(h), h)

    def test_the_status_banner_path_is_untouched(self):
        self.assertTrue(LQ._is_closed("## Status — KILLED 2026-10-16\n"))
        self.assertTrue(LQ._is_closed("**Status:** REFUTED (2026-11-01)\n"))
        self.assertFalse(LQ._is_closed("**Status:** lead — closed at the registry level\n"))

    def test_a_dated_heading_takes_the_lead_out_of_the_queue(self):
        with tempfile.TemporaryDirectory() as t:
            root, e = _eng(t)
            f = e / "leads" / "route-existence-oracle.md"
            f.write_text("# LEAD — ADJUDICATED 2026-10-16 (wave17). Both hypotheses are DEAD.\n\n"
                         "**Chain:** needs `nothing` · gives `route-oracle`\n")
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                q = LQ.scan(e)
            self.assertNotIn("leads/route-existence-oracle.md", [r["file"] for r in q["open"]])
            self.assertEqual(2, q["closed"])

    def test_a_section_heading_leaves_the_lead_workable(self):
        """Positive control for the same file, with the date removed."""
        with tempfile.TemporaryDirectory() as t:
            root, e = _eng(t)
            f = e / "leads" / "route-existence-oracle.md"
            f.write_text("# LEAD — a route-existence oracle\n\n## Blocked\n\n"
                         "## Not a finding, explicitly\n\n"
                         "**Chain:** needs `nothing` · gives `route-oracle`\n")
            with mock.patch.object(LQ, "_targets_root", lambda: root):
                q = LQ.scan(e)
            self.assertIn("leads/route-existence-oracle.md", [r["file"] for r in q["open"]])
            self.assertEqual(0, q["blocked"])

    def test_the_four_live_ozon_adjudications_are_out_of_the_queue(self):
        eng = REPO / "Targets" / "standoff365" / "ozon"
        if not eng.is_dir():
            self.skipTest("engagement not present")
        q = LQ.scan(eng)
        files = {r["file"] for v in q.values() if isinstance(v, list)
                 for r in v if isinstance(r, dict)}
        for f in ("leads/pci-finance-nativebridge-postmessage-relay.md",
                  "leads/sigma-iap-nginx-oidc-codexch.md",
                  "primitives/profit-edu-api-version-skew.park.md",
                  "primitives/webinar-chat-anon-read.park.md"):
            self.assertNotIn(f, files, f)
        # …and the two records whose SECTION headings say "Blocked" / "Not a finding" are
        # still workable, because their banners say STALLED.
        for f in ("leads/ozonid-auth-request-jwt-hs256.md",
                  "primitives/fa-gateway-route-existence-oracle.md"):
            self.assertIn(f, files, f)
