"""The skill arsenal as a graph, and the briefs built on it.

These tests exist because every defect they pin was a real wrong answer the two
modules gave on this workspace's own data, not a hypothetical:

  * a bounty field reading "$7,000 Cloudflare, $7,000 GitLab, $12,000 T-Mobile;
    74 bounties / $221k on the Akamai case; over $350k total" was parsed by
    stripping non-digits, became $700,070,001,200,074,229,850, and that one
    research write-up then topped every class-pair ranking;
  * "once the backend is confirmed relational" scored as an ESCALATION, so
    `hunt-saml` — a skill whose own doctrine sends it onward to `hunt-ato` —
    ranked as an escalation hub with three feeders;
  * `hunt-ato` names its feeders and each feeder names `hunt-ato`, so four chain
    edges existed twice and the hub count read eight instead of four;
  * `Primitive — selfreg.acme.com/api route space confirmed live` scored
    `hunt-rce` first, because `hunt-rce`'s own trigger says "a confirmed
    primitive (deserialization, LFI, SSTI, …)", and the lane was briefed with two
    Marshal-gadget chains for a route-space census;
  * a finding with no title emptied the skill ladder, and reading its first
    heading gave the draft banner, then the literal placeholder "Title", which
    then matched the precedent corpus on that word.
"""
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import autohunt  # noqa: E402
import lead_queue  # noqa: E402
import skill_graph as G  # noqa: E402
import skill_map  # noqa: E402


_WAVE_STUB = {
    "engagement": "p/t", "engagement_dir": ".", "role": "deep-hunter", "role_why": "stub",
    "slots": 1, "budget_requests_left": 10, "requests_per_lane": 10, "bar_met": False,
    "allow_stop": True, "stop_reason": "", "queue": {}, "accounts_wanted": [],
    "walled_open_items": 0, "chain_hub": "", "briefs": [],
    "client": {"client": "claude", "label": "Claude Code", "orchestrator_may_send": False},
}


class Census(unittest.TestCase):
    def setUp(self):
        self.g = G.build()

    def test_every_installed_skill_is_a_node_with_a_trigger(self):
        on_disk = {d.name for d in (REPO / "skills").iterdir() if (d / "SKILL.md").is_file()}
        self.assertEqual(set(self.g["skills"]), on_disk)
        missing = [n for n, r in self.g["skills"].items() if not r["trigger"]]
        self.assertEqual(missing, [], f"skills whose description has no TRIGGER: {missing}")

    def test_lint_is_clean(self):
        # Fails when a new skill ships without a SKIP clause (it would have no
        # edges), when skill_map names a skill that is not installed, or when the
        # corpus grows a class no skill covers.
        self.assertEqual(G.lint(self.g), [])

    def test_edges_are_deduplicated(self):
        keys = [(e["src"], e["dst"], e["kind"]) for e in self.g["edges"]]
        self.assertEqual(len(keys), len(set(keys)))

    def test_corpus_is_loaded(self):
        self.assertGreaterEqual(self.g["corpus_rows"], 100)
        self.assertGreaterEqual(len(self.g["pairs"]), 20)


class EscalationIsVerticalOnly(unittest.TestCase):
    def setUp(self):
        self.g = G.build()

    def _kind(self, src, dst):
        return [e["kind"] for e in self.g["edges"] if e["src"] == src and e["dst"] == dst]

    def test_backend_identification_is_lateral(self):
        # "hunt-sqli/hunt-nosqli once the backend is confirmed relational/NoSQL"
        # hands the surface over; it does not raise the severity.
        self.assertEqual(self._kind("hunt-ldap", "hunt-sqli"), ["owns"])
        self.assertEqual(self._kind("hunt-nosqli", "hunt-sqli"), ["owns"])
        self.assertEqual(self._kind("hunt-auth-bypass", "hunt-saml"), ["owns"])

    def test_chaining_language_is_vertical(self):
        self.assertEqual(self._kind("hunt-saml", "hunt-ato"), ["escalate"])
        self.assertEqual(self._kind("hunt-lfi", "hunt-rce"), ["escalate"])
        self.assertEqual(self._kind("hunt-subdomain", "hunt-ato"), ["escalate"])

    def test_inverted_clause_gives_the_chaining_skill_its_feeders(self):
        # hunt-ato's SKIP names the single-path skills and then says "use this
        # skill when combining 2+ of those", so the arrow runs INTO hunt-ato.
        feeders = {e["src"] for e in G.feeders("hunt-ato", self.g)}
        self.assertTrue({"hunt-mfa-bypass", "hunt-oauth", "hunt-saml", "hunt-session"} <= feeders)
        self.assertEqual(G.escalations("hunt-ato", self.g), [])

    def test_saml_is_not_an_escalation_hub(self):
        self.assertEqual([e["src"] for e in G.feeders("hunt-saml", self.g)], [])


class Money(unittest.TestCase):
    def test_several_amounts_are_not_concatenated(self):
        aggregate = ("$7,000 Cloudflare, $7,000 GitLab, $12,000 T-Mobile; "
                     "74 bounties / $221k on the Akamai case; over $350k total")
        self.assertEqual(G._money(aggregate), 350_000)
        self.assertTrue(G._is_aggregate(aggregate))

    def test_plain_and_absent_values(self):
        self.assertEqual(G._money("$12,000"), 12_000)
        self.assertEqual(G._money("~$3,000"), 3_000)
        self.assertEqual(G._money("$525 and $400"), 525)
        self.assertEqual(G._money(None), 0)
        self.assertEqual(G._money("six figures across fintech programs"), 0)
        self.assertFalse(G._is_aggregate("$12,000"))

    def test_pairs_rank_on_report_count_not_dollars(self):
        pairs = G.corpus_pairs()
        self.assertEqual(pairs, sorted(pairs, key=lambda r: (
            -r["n"], -G.SEV_RANK.get(r["top_severity"], 0), -r["bounty"], r["classes"])))
        # an aggregate row's dollars are kept out of the pair total
        for p in pairs:
            self.assertLess(p["bounty"], 10_000_000)

    def test_other_is_not_a_pair_member(self):
        for p in G.corpus_pairs():
            self.assertNotIn("other", p["classes"])


class Ladder(unittest.TestCase):
    def setUp(self):
        self.g = G.build()

    def test_url_signals_come_first_and_are_marked_gated(self):
        rows = G.ladder("https://api.x.ru/api/v2/user/orders/4821?redirect_uri=https://e", self.g,
                        top=6)
        names = [r["skill"] for r in rows]
        self.assertIn("hunt-idor", names)
        self.assertEqual(rows[0]["via"], "url-signal")
        self.assertTrue(rows[0]["gated"])

    def test_house_tier_words_do_not_score_a_skill(self):
        blob = "Primitive — `selfreg.x.ru/api` route space confirmed live, every route gated"
        names = [r["skill"] for r in G.ladder(blob, self.g, top=4)]
        self.assertNotEqual(names[:1], ["hunt-rce"])

    def test_prose_lead_with_no_url_still_ranks(self):
        rows = G.ladder("stored marker survives into the invoice PDF generator template, "
                        "rendered server-side", self.g, top=3)
        self.assertIn("hunt-ssti", [r["skill"] for r in rows])
        self.assertTrue(all(r["via"] == "trigger" for r in rows))

    def test_each_rung_carries_the_graph_layer(self):
        for r in G.ladder("https://x.ru/graphql", self.g, top=3):
            self.assertIn("defer_to", r)
            self.assertIn("escalates_to", r)


class CorpusChains(unittest.TestCase):
    def test_chains_are_whole_reports_with_evidence(self):
        for c in G.corpus_chains(top=5):
            self.assertTrue(c["id"])
            self.assertTrue(c["steps"])
            self.assertIn(c["severity"], G.SEV_RANK)

    def test_min_severity_filters(self):
        for c in G.corpus_chains(top=20, min_severity="critical"):
            self.assertEqual(c["severity"], "critical")

    def test_a_skill_finds_the_chains_of_its_classes(self):
        ids = {c["id"] for c in G.chains_for("hunt-source-leak", top=8)}
        self.assertTrue(ids, "hunt-source-leak maps to secret-exposure/info-leak and must match")


class ClassVocabulary(unittest.TestCase):
    def test_every_corpus_class_has_a_skill_map_entry(self):
        classes = {c for r in G.load_corpus() for c in (r.get("classes") or [])}
        self.assertEqual(sorted(c for c in classes if c not in skill_map.CLASS_SKILL), [])

    def test_the_queues_own_labels_resolve(self):
        # engine/lead_queue.py labels items with its own CLASS_WORDS vocabulary;
        # `data-exposure` is the one it gives the largest class on ozon and it had
        # no entry here, so those lanes got no partner pair and no chain.
        for label in ("data-exposure", "info-leak", "open-redirect", "idor"):
            self.assertTrue(skill_map.CLASS_SKILL.get(label), f"{label} maps to nothing")


class Spread(unittest.TestCase):
    # Host names in these fixtures are realistic on purpose: autohunt.HOST_RE wants
    # four characters before the TLD dot so it does not match a version string, and
    # a fixture host of "a.x.ru" matched nothing — which made the first version of
    # this test pass for the wrong reason.
    def test_no_two_lanes_share_a_host(self):
        items = [
            {"title": "LEAD — api.alpha.ru thing", "needs": ["cap-one"]},
            {"title": "LEAD — api.alpha.ru other thing", "needs": ["cap-two"]},
            {"title": "LEAD — api.beta.ru thing", "needs": ["cap-three"]},
        ]
        picked = autohunt.spread(items, 2)
        self.assertEqual([autohunt._host_of(i) for i in picked], ["api.alpha.ru", "api.beta.ru"])

    def test_no_two_lanes_wait_on_the_same_missing_capability(self):
        items = [
            {"title": "LEAD — api.alpha.ru thing", "needs": ["staff-session"]},
            {"title": "LEAD — api.beta.ru thing", "needs": ["staff-session"]},
            {"title": "LEAD — api.gamma.ru thing", "needs": ["admin-token"]},
        ]
        picked = autohunt.spread(items, 2)
        self.assertEqual([autohunt._cap_of(i) for i in picked], ["staff-session", "admin-token"])

    def test_slots_are_filled_from_the_skipped_items_rather_than_wasted(self):
        items = [{"title": "LEAD — api.alpha.ru one", "needs": ["cap"]},
                 {"title": "LEAD — api.alpha.ru two", "needs": ["cap"]}]
        self.assertEqual(len(autohunt.spread(items, 2)), 2)


class FindingTitles(unittest.TestCase):
    def test_template_headings_are_rejected_in_favour_of_the_stem(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "url-minifier-s.acme.com.md"
            f.write_text("# [ЧЕРНОВИК — перед сабмитом выполнить гейт]\n\n## Title\n\n"
                         "## Program / scope\n\nbody\n", encoding="utf-8")
            self.assertEqual(autohunt._title_of_file(str(f)), "url minifier s.acme.com")

    def test_a_real_claim_heading_is_used(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "x.md"
            f.write_text("# Reflected marker in `/pay/confirm` reaches the HTML sink unencoded\n",
                         encoding="utf-8")
            self.assertIn("Reflected marker", autohunt._title_of_file(str(f)))


class Briefs(unittest.TestCase):
    def setUp(self):
        self.g = G.build()

    def test_a_lane_with_no_scoring_title_still_gets_its_role_floor(self):
        b = autohunt.brief_for({"file": "findings/x.md", "kind": "finding", "title": "x y z",
                                "needs": [], "class": ""}, REPO, self.g, 10, "refuter")
        self.assertEqual([s["name"] for s in b["skills"]], autohunt.ROLE_SKILLS["refuter"])

    def test_the_close_line_matches_what_the_role_writes(self):
        f = {"file": "findings/x.md", "kind": "finding", "title": "t", "needs": [], "class": ""}
        self.assertIn("append the verdict",
                      autohunt.brief_for(f, REPO, self.g, 10, "refuter")["close"])
        self.assertIn("cbh leads close",
                      autohunt.brief_for(dict(f, kind="lead"), REPO, self.g, 10,
                                         "deep-hunter")["close"])
        self.assertIn("leads/<slug>.md",
                      autohunt.brief_for(f, REPO, self.g, 10, "scout")["close"])

    def test_queue_label_is_translated_into_a_corpus_class(self):
        """Translated all the way to a class the CORPUS has, not just one CLASS_SKILL has.

        This asserted `data-exposure` until 2026-11-12. That label is in `CLASS_SKILL`
        and in 0 of the 120 reports, so accepting it satisfied "a mapped class" while
        still matching no chain by class — and the skill fallback then supplied two
        off-mechanic ones. See ChainsComeFromTheClass.
        """
        b = autohunt.brief_for({"file": "p/x.md", "kind": "primitive", "class": "data-exposure",
                                "title": "`x.ru/api` route space", "needs": []},
                               REPO, self.g, 10, "deep-hunter")
        self.assertEqual(b["class"], "info-leak")
        self.assertTrue(b["partners"] or b["corpus_chains"],
                        "a mapped class must reach the corpus")
        have = {c for r in G.load_corpus() for c in (r.get("classes") or [])}
        self.assertIn(b["class"], have)

    def test_wave_without_an_engagement_reports_it_instead_of_raising(self):
        w = autohunt.wave("definitely-not-a-program-name")
        self.assertIn("error", w)


if __name__ == "__main__":
    unittest.main()


class OperatorWall(unittest.TestCase):
    """A lane must not be sent at a wall the same screen says the operator holds.

    Measured on standoff365/ozon, 2026-11-12: lane 2 of the wave was
    `primitives/selfreg-api-mux-routes-ozonid-gated.md`, needing
    `live-ozonid-session-sr-crm`, while the header three lines above it listed "a valid
    staff Ozon-ID session (employee principal)" as waiting on the operator. It passed
    `lead_queue._account_need` because that function reads ROLE words out of the slug
    and defaults to "user" when it finds none — and this engagement holds a user
    account.
    """

    ACCOUNTS = ["a valid staff Ozon-ID session (employee principal)",
                "operator-authorized-task-admin-session"]

    def test_the_measured_item_is_walled(self):
        item = {"needs": ["live-ozonid-session-sr-crm"]}
        self.assertEqual(autohunt.operator_wall(item, self.ACCOUNTS), self.ACCOUNTS[0])

    def test_a_shared_generic_word_does_not_wall(self):
        """`antibot-jar-...` shares only `session`-class filler; our own browser gets it."""
        item = {"needs": ["antibot-jar-for-the-sigma-static-fence"]}
        self.assertEqual(autohunt.operator_wall(item, self.ACCOUNTS), "")

    def test_an_item_with_no_needs_is_not_walled(self):
        self.assertEqual(autohunt.operator_wall({"needs": []}, self.ACCOUNTS), "")
        self.assertEqual(autohunt.operator_wall({}, self.ACCOUNTS), "")

    def test_no_accounts_wanted_walls_nothing(self):
        item = {"needs": ["live-ozonid-session-sr-crm"]}
        self.assertEqual(autohunt.operator_wall(item, []), "")

    def test_the_second_group_is_matched_too(self):
        item = {"needs": ["task-admin-session-for-the-facade"]}
        self.assertEqual(autohunt.operator_wall(item, self.ACCOUNTS), self.ACCOUNTS[1])

    def test_walled_items_go_last_and_rank_is_kept_inside_each_group(self):
        items = [{"file": "a", "needs": ["live-ozonid-session-sr-crm"], "title": "api.a.ru"},
                 {"file": "b", "needs": [], "title": "api.b.ru"},
                 {"file": "c", "needs": [], "title": "api.c.ru"}]
        for it in items:
            w = autohunt.operator_wall(it, self.ACCOUNTS)
            if w:
                it["operator_wall"] = w
        items.sort(key=lambda r: 1 if r.get("operator_wall") else 0)
        self.assertEqual([i["file"] for i in items], ["b", "c", "a"])


class ChainsComeFromTheClass(unittest.TestCase):
    """A chain that does not share the mechanic is scenery, and scenery reads as evidence.

    Measured 2026-11-12: `primitives/selfreg-api-mux-routes-ozonid-gated.md` (class
    `data-exposure`, a route space where every route is authz-gated) was briefed with
    `h1-47` and `h1-48` — ".env left in an application bundle" and "certificate in a git
    repo". They arrived because the lookup keyed on the loaded SKILL
    (`hunt-source-leak`), whose widest class is `secret-exposure`, and because
    `data-exposure` is in `CLASS_SKILL` but in 0 of the 120 reports.
    """

    def test_every_alias_target_is_a_class_the_corpus_actually_has(self):
        have = {c for r in G.load_corpus() for c in (r.get("classes") or []) if c}
        for label, target in skill_map.CLASS_TO_CORPUS.items():
            self.assertIn(target, have, f"{label} -> {target} is not a corpus class")

    def test_no_alias_points_at_itself(self):
        for label, target in skill_map.CLASS_TO_CORPUS.items():
            self.assertNotEqual(label, target)

    def test_the_measured_label_resolves_to_the_class_with_the_reports(self):
        self.assertEqual(skill_map.CLASS_TO_CORPUS["data-exposure"], "info-leak")
        have = [r for r in G.load_corpus() if "info-leak" in (r.get("classes") or [])]
        self.assertGreater(len(have), 10, "info-leak is the one carrying the evidence")

    def test_a_data_exposure_item_no_longer_gets_secret_exposure_chains(self):
        graph = G.build()
        item = {"file": "primitives/x.md", "kind": "primitive", "class": "data-exposure",
                "title": "Primitive — route space confirmed live, every route gated",
                "needs": [], "reward": 0, "age_days": 0}
        b = autohunt.brief_for(item, Path("."), graph, 10, "deep-hunter")
        self.assertEqual(b["class"], "info-leak")
        self.assertEqual(b["chains_via"], "class")
        for ch in b["corpus_chains"]:
            self.assertIn("info-leak", ch["classes"])

    def test_a_classless_item_says_the_chain_came_from_the_skill(self):
        graph = G.build()
        item = {"file": "leads/y.md", "kind": "lead", "class": "other",
                "title": "LEAD — a parameter reaches a server-side fetch on api.example.ru",
                "needs": [], "reward": 0, "age_days": 0}
        b = autohunt.brief_for(item, Path("."), graph, 10, "deep-hunter")
        if b["corpus_chains"]:
            self.assertEqual(b["chains_via"], "skill")
            self.assertIn("matched on the LOADED SKILL",
                          autohunt.render({**_WAVE_STUB, "briefs": [b]}))


class TruncationKeepsTheWord(unittest.TestCase):
    """`...carrying the Next-Action header, wh` — the cut took the clause that mattered."""

    LONG = ("precedent: [critical/15000.0] missing_authorization, auth-bypass, info-leak — "
            "FIRST SIGNAL: A network request from the App Router page carrying the "
            "Next-Action header, which is the Server Action entry point")

    def test_a_cut_line_ends_on_a_word_and_is_marked(self):
        out = lead_queue.cut(self.LONG, 120)
        self.assertTrue(out.endswith(" …"), out)
        self.assertNotIn("wh …", out)
        body = out[:-2].strip()
        self.assertTrue(self.LONG.startswith(body), "the kept part must be verbatim")
        self.assertIn(body.split()[-1], self.LONG.split())

    def test_a_short_line_is_returned_whole_and_unmarked(self):
        self.assertEqual(lead_queue.cut("short enough", 120), "short enough")
        self.assertNotIn("…", lead_queue.cut("short enough", 120))

    def test_a_single_long_token_still_gets_cut(self):
        out = lead_queue.cut("x" * 300, 50)
        self.assertEqual(len(out), 52)
        self.assertTrue(out.endswith(" …"))

    def test_the_title_stored_by_the_queue_is_cut_the_same_way(self):
        import inspect
        src = inspect.getsource(lead_queue.scan)
        self.assertIn('cut(title, 140)', src,
                      "a raw title[:N] slice is what cut `a client-supplied `route` in half")


class LadderVocabulary(unittest.TestCase):
    """The ladder is only as good as the words the TRIGGER table actually contains.

    Measured on the first live wave (standoff365/ozon, 2026-11-12): the lead "7
    Mattermost incoming-webhook URLs hardcoded in a public prod bundle (`msg.o3.ru`)"
    loaded `hunt-ssrf` and nothing else. It scored 1, on the single word `webhook`,
    which `hunt-ssrf`'s trigger lists as an SSRF entry point — while
    `hunt-source-leak`, whose whole subject is a secret read out of a client-reachable
    artifact, scored 0, because its trigger enumerated artifact FILENAMES and never the
    thing being hunted.

    Two fixes, and they are one decision: the trigger now carries that vocabulary, and
    term matching moved from substring-with-a-7-character-floor to word-boundary with a
    4-character floor. The floor was buying safety against `dom` matching inside
    `subdomain` by discarding the most diagnostic words in the table — `fetch`, `.env`,
    `token`, `bundle`, `cache`.
    """

    BUNDLE = ("LEAD — 7 Mattermost incoming-webhook URLs hardcoded in a public prod "
              "bundle (`msg.o3.ru`)")
    SSRF = ("LEAD — a webhook parameter makes the server fetch a user-supplied URL "
            "on api.example.ru")

    @classmethod
    def setUpClass(cls):
        cls.g = G.build()

    def _first(self, blob):
        rows = G.ladder(blob, self.g, top=4)
        self.assertTrue(rows, f"no skill at all for: {blob}")
        return rows[0]["skill"]

    def test_a_secret_in_a_public_bundle_loads_the_source_leak_skill(self):
        self.assertEqual(self._first(self.BUNDLE), "hunt-source-leak")

    def test_a_real_ssrf_webhook_still_loads_the_ssrf_skill(self):
        """The control: the shared word `webhook` must not hand SSRF to source-leak."""
        self.assertEqual(self._first(self.SSRF), "hunt-ssrf")

    def test_the_two_blobs_do_not_resolve_to_the_same_skill(self):
        self.assertNotEqual(self._first(self.BUNDLE), self._first(self.SSRF))

    def test_the_bundle_lead_wins_on_more_than_one_term(self):
        """A 1-1 tie is decided by report_count, which is how a weak hit steals a lane."""
        rows = {r["skill"]: r["score"] for r in G.ladder(self.BUNDLE, self.g, top=6)}
        self.assertGreaterEqual(rows["hunt-source-leak"], 2)
        self.assertGreater(rows["hunt-source-leak"], rows.get("hunt-ssrf", 0))

    def test_short_terms_match_on_a_word_boundary_not_inside_a_word(self):
        """`dom` inside `subdomain` is the defect the 7-character floor existed for."""
        self.assertEqual(G._term_hits("a subdomain of example.com", {"dom"}), set())
        self.assertEqual(G._term_hits("a dom clobbering sink", {"dom"}), {"dom"})
        self.assertEqual(G._term_hits("nofetching here", {"fetch"}), set())
        self.assertEqual(G._term_hits("the server will fetch it", {"fetch"}), {"fetch"})

    def test_path_and_filename_terms_still_match_inside_a_url(self):
        self.assertEqual(G._term_hits("https://t/static/app.js.map", {".js.map"}), {".js.map"})
        self.assertEqual(G._term_hits("https://t/swagger.json?x=1", {"/swagger.json"}),
                         {"/swagger.json"})

    def test_the_api_path_defect_stays_fixed(self):
        """`/api` inside `/api/v2/user/orders/4821` once put hunt-mfa-bypass on top."""
        rows = G.ladder("https://t.example.ru/api/v2/user/orders/4821", self.g, top=6)
        names = [r["skill"] for r in rows]
        self.assertIn("hunt-idor", names)
        if "hunt-mfa-bypass" in names:
            self.assertLess(names.index("hunt-idor"), names.index("hunt-mfa-bypass"))

    def test_generic_words_are_not_terms(self):
        for word in ("public", "server", "user", "client", "data", "value"):
            self.assertIn(word, G.STOP_TERMS, f"{word} carries no class information")

    def test_the_trigger_carries_the_vocabulary_the_fix_depends_on(self):
        trigger = self.g["skills"]["hunt-source-leak"]["trigger"].lower()
        for word in ("hardcoded", "credential", "bundle", "webhook"):
            self.assertIn(word, trigger)


class CatchAllNeverWins(unittest.TestCase):
    """A skill that describes the ABSENCE of a class must not outrank a real match.

    Measured on the second live wave (standoff365/ozon, 2026-11-12): lane 2 was
    `leads/finance-mf-ssr-render-route-url.md` — 262 server-side render endpoints taking
    a client-supplied `route-url` — and it loaded `hunt-misc` first, which also cost it
    its corpus chains, because the chain lookup keys on the primary rung.

    Two causes, both of them a placeholder behaving like evidence. `lead_queue` labels an
    item `other` when no CLASS_WORDS rule matched (33 of ozon's 53 open items), and
    `brief_for` appended that label to the blob the ladder scores — where it matched the
    literal word in `hunt-misc`'s TRIGGER, "a finding doesn't cleanly fit any other
    hunt-* class". The tie that followed was then decided by report_count, and `hunt-misc`
    carries the highest in the bundle (225).
    """

    @classmethod
    def setUpClass(cls):
        cls.g = G.build()

    SSR = ("LEAD — `finance.acme.com` ships 262 server-side micro-frontend render "
           "endpoints taking a client-supplied `route-url`")

    def test_the_catch_all_list_is_what_it_claims_to_be(self):
        for name in G.CATCH_ALL_SKILLS:
            if name not in self.g["skills"]:
                continue
            trigger = self.g["skills"][name]["trigger"].lower()
            self.assertTrue(
                any(w in trigger for w in ("doesn't cleanly fit", "any other hunt-",
                                           "feeling lost", "internal use only",
                                           "master orchestrator", "orchestrator only",
                                           "topic-match routing", "which bug classes",
                                           "what bug classes")),
                f"{name} is listed as a catch-all but its trigger describes a surface")

    def test_the_placeholder_class_never_reaches_the_scoring_blob(self):
        item = {"file": "leads/x.md", "kind": "lead", "class": "other", "needs": [],
                "title": self.SSR, "reward": 0, "age_days": 0}
        b = autohunt.brief_for(item, Path("."), self.g, 10, "deep-hunter")
        self.assertEqual(b["skills"][0]["name"], "hunt-ssrf")
        self.assertNotIn("hunt-misc", [s["name"] for s in b["skills"]])

    def test_a_real_class_label_still_reaches_it(self):
        """The control: suppressing `other` must not suppress a real label."""
        item = {"file": "leads/y.md", "kind": "lead", "class": "data-exposure", "needs": [],
                "title": "LEAD — an endpoint returns another tenant's order data",
                "reward": 0, "age_days": 0}
        b = autohunt.brief_for(item, Path("."), self.g, 10, "deep-hunter")
        self.assertEqual(b["class"], "info-leak")

    def test_the_catch_all_ranks_last_even_when_it_scores_higher(self):
        """`hunt-misc` has the highest report_count in the bundle; score must not save it."""
        rows = G.ladder("a finding that doesn't cleanly fit any other hunt-* class, "
                        "with a webhook that makes the server fetch a URL", self.g, top=6)
        names = [r["skill"] for r in rows]
        if "hunt-misc" in names and len(names) > 1:
            self.assertEqual(names[-1], "hunt-misc")
            self.assertGreater(len(names), 1)

    def test_a_lane_with_nothing_else_still_gets_the_catch_all(self):
        """Ranked last is not excluded: it is better than briefing a lane with nothing."""
        rows = G.ladder("doesn't cleanly fit any other hunt-* class", self.g, top=6)
        self.assertIn("hunt-misc", [r["skill"] for r in rows])


class DeclaredClassLeadsTheLadder(unittest.TestCase):
    """A class the record states for itself outranks the ladder's reading of its title.

    Measured case: `finance-mf-ssr-render-route-url`'s title is "262 endpoints taking a
    client-supplied `route-url`", so the ladder loads `hunt-ssrf` first — and that file's
    SSRF hypothesis is closed by three byte-identical controls. `**Class:**
    missing_authorization` is how that gets said, and it has to move what the lane loads.
    """

    def setUp(self):
        self.g = G.build()
        self.item = {"file": "leads/finance-mf-ssr-render-route-url.md", "kind": "lead",
                     "title": "`finance.acme.com` ships 262 server-side micro-frontend render "
                              "endpoints taking a client-supplied `route-url`",
                     "needs": [], "class": "missing_authorization"}

    def test_the_guess_alone_loads_the_refuted_reading_first(self):
        """Positive control: without the declaration the ladder leads with hunt-ssrf."""
        b = autohunt.brief_for(self.item, REPO, self.g, 10, "deep-hunter")
        self.assertEqual("hunt-ssrf", b["skills"][0]["name"])

    def test_a_declared_class_leads_and_does_not_drop_the_guess(self):
        b = autohunt.brief_for({**self.item, "class_declared": True},
                               REPO, self.g, 10, "deep-hunter")
        names = [s["name"] for s in b["skills"]]
        self.assertEqual("hunt-auth-bypass", names[0])
        self.assertEqual("class-declared", b["skills"][0]["via"])
        self.assertIn("hunt-idor", names)
        self.assertIn("hunt-ssrf", names, "the title's reading is demoted, never dropped")

    def test_no_duplicate_rung_when_both_sources_name_one_skill(self):
        item = {"file": "leads/webhooks.md", "kind": "lead",
                "title": "7 Mattermost incoming-webhook URLs hardcoded in a public prod bundle",
                "needs": [], "class": "secret-exposure", "class_declared": True}
        names = [s["name"] for s in autohunt.brief_for(item, REPO, self.g, 10,
                                                       "deep-hunter")["skills"]]
        self.assertEqual("hunt-source-leak", names[0])
        self.assertEqual(len(names), len(set(names)))

    def test_the_render_says_where_the_leading_skill_came_from(self):
        b = autohunt.brief_for({**self.item, "class_declared": True},
                               REPO, self.g, 10, "deep-hunter")
        out = autohunt.render({**_WAVE_STUB, "briefs": [b]})
        self.assertIn("declares `missing_authorization` for itself", out)

    def test_an_unmapped_declared_class_changes_nothing(self):
        """`other` maps to no skill, so a declaration of it must not empty the ladder."""
        b = autohunt.brief_for({**self.item, "class": "other", "class_declared": True},
                               REPO, self.g, 10, "deep-hunter")
        self.assertEqual("hunt-ssrf", b["skills"][0]["name"])


class TriggerGlueDoesNotRoute(unittest.TestCase):
    """`target` is in 27 of the 68 TRIGGERs, `auth` in 6, `apps` only because
    `firebase.apps` splits on the dot. Those three gave `hunt-firebase` 3 points on a
    postMessage lead and it led the 2026-11-12 wave's lane 2."""

    def setUp(self):
        self.g = G.build()

    def _top(self, blob, n=4):
        return [r["skill"] for r in G.ladder(blob, self.g, top=n)]

    POSTMESSAGE = ("LEAD — `finance.acme.com/apps/auth/verify-person-update` posts an auth "
                   "token to `window.parent` with target origin `*`, and the surface has "
                   "no framing protection")

    def test_a_stack_skill_no_longer_scores_on_path_segments(self):
        top = self._top(self.POSTMESSAGE)
        for wrong in ("hunt-firebase", "hunt-supabase", "hunt-rce"):
            self.assertNotIn(wrong, top)

    def test_the_glue_words_carry_no_score_at_all(self):
        for glue in ("target", "auth", "apps", "covers", "live", "finding"):
            self.assertEqual([], self._top(glue), glue)

    def test_the_stack_skills_still_win_on_their_own_fingerprints(self):
        """Positive control: every skill de-noised above still routes its real surface."""
        for blob, want in (
            ("bundle initializes firebaseConfig with apiKey and authDomain, "
             "firestore.googleapis.com requests", "hunt-firebase"),
            ("client bundle contains a Supabase anon key, requests hit "
             "ref.supabase.co/rest/v1/", "hunt-supabase"),
            ("x-powered-by Next.js, middleware auth bypass via _next/static path",
             "hunt-nextjs"),
            ("APP_DEBUG stack trace leaks the env, laravel_session cookie, Blade error page",
             "hunt-laravel"),
        ):
            self.assertEqual(want, self._top(blob)[0], blob[:40])

    def test_a_declared_class_promotes_a_skill_the_ladder_already_named(self):
        """`hunt-cors`/`hunt-dom` both scored on `origin`, so neither was missing from the
        ladder — they were behind `hunt-source-leak`. The declaration decides the order."""
        item = {"file": "leads/pm.md", "kind": "lead", "title": self.POSTMESSAGE,
                "needs": [], "class": "postmessage", "class_declared": True}
        b = autohunt.brief_for(item, REPO, self.g, 10, "deep-hunter")
        self.assertEqual(["hunt-dom", "hunt-cors"], [s["name"] for s in b["skills"]][:2])
        self.assertEqual(["class-declared"] * 2, [s["via"] for s in b["skills"]][:2])
        self.assertEqual("cors", b["class"], "postmessage must alias onto a corpus class")
        self.assertTrue(b["corpus_chains"])

    def test_no_rung_is_duplicated_by_the_promotion(self):
        item = {"file": "leads/pm.md", "kind": "lead", "title": self.POSTMESSAGE,
                "needs": [], "class": "postmessage", "class_declared": True}
        names = [s["name"] for s in autohunt.brief_for(item, REPO, self.g, 10,
                                                       "deep-hunter")["skills"]]
        self.assertEqual(len(names), len(set(names)))


class EgressWallAndRefuterFloor(unittest.TestCase):
    """Two things the 2026-11-12 wave printed wrong after the class work landed."""

    def setUp(self):
        self.g = G.build()

    MATTERMOST_NEED = ("POST /hooks/{token} from an egress that clears the .o3.ru edge "
                       "challenge (and, per the wave-16 browser data point, possibly an "
                       "allowlisted network)")

    def test_an_egress_need_is_a_network_wall(self):
        self.assertTrue(autohunt.network_wall({"needs": [self.MATTERMOST_NEED]}))
        for need in ("a corporate network position", "an IP allowlist entry",
                     "a residential proxy in RU", "access from inside the perimeter"):
            self.assertTrue(autohunt.network_wall({"needs": [need]}), need)

    def test_an_account_or_capability_need_is_not(self):
        """Positive control: the walls are different and the remedies are different."""
        for need in ("a valid staff Ozon-ID session (employee principal)",
                     "antibot-jar-for-the-sigma-static-fence",
                     "json-error-content-type-moved-off-application-json",
                     "a decision on sending a url-valued argument to a token minter"):
            self.assertEqual("", autohunt.network_wall({"needs": [need]}), need)

    def test_the_egress_walled_item_ranks_below_an_account_walled_one(self):
        items = [{"file": "a.md", "needs": [self.MATTERMOST_NEED], "title": "a"},
                 {"file": "b.md", "needs": ["live-ozonid-session-sr-crm"], "title": "b"},
                 {"file": "c.md", "needs": ["nothing"], "title": "c"}]
        for it in items:
            w = autohunt.operator_wall(it, ["a valid staff Ozon-ID session (employee)"])
            if w:
                it["operator_wall"] = w
            n = autohunt.network_wall(it)
            if n:
                it["network_wall"] = n
        items.sort(key=lambda r: (1 if r.get("operator_wall") else 0)
                   + (2 if r.get("network_wall") else 0))
        self.assertEqual(["c.md", "b.md", "a.md"], [i["file"] for i in items])

    def test_the_brief_says_nothing_supplies_it_and_how_to_close(self):
        b = autohunt.brief_for({"file": "leads/x.md", "kind": "lead", "title": "x y z",
                                "needs": [self.MATTERMOST_NEED], "class": "secret-exposure",
                                "network_wall": self.MATTERMOST_NEED},
                               REPO, self.g, 10, "deep-hunter")
        out = autohunt.render({**_WAVE_STUB, "briefs": [b]})
        self.assertIn("network position, not a capability", out)
        self.assertIn("--as blocked", out)

    def test_a_finding_is_named_by_its_claim_not_its_filename(self):
        f = REPO / "Targets" / "standoff365" / "ozon" / "findings" / "url-minifier-s.acme.com.md"
        if not f.is_file():
            self.skipTest("finding not present")
        title = autohunt._title_of_file(str(f))
        self.assertNotEqual("url minifier s.acme.com", title)
        self.assertIn("s.acme.com", title)
        self.assertGreater(len(title), 40)

    def test_a_placeholder_title_body_is_not_a_claim(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "some-finding-slug.md"
            p.write_text("# [ЧЕРНОВИК]\n\n## Title\n<одно предложение: что именно сломано>\n")
            self.assertEqual("some finding slug", autohunt._title_of_file(str(p)))

    def test_the_refuter_loads_its_own_tooling_first(self):
        """The claim line scores `hunt-csrf` on `post` and `hunt-llm-ai` on `document`;
        neither is what kills or proves a claim."""
        item = {"file": "findings/url-minifier.md", "kind": "finding", "class": "",
                "needs": [], "title": "Анонимное создание коротких ссылок (POST "
                                      "/api/v1/document-manager/url-minifier/create)"}
        b = autohunt.brief_for(item, REPO, self.g, 10, "refuter")
        self.assertEqual(autohunt.ROLE_SKILLS["refuter"],
                         [s["name"] for s in b["skills"]][:2])
        self.assertEqual([], b["corpus_chains"],
                         "a refuter follows the claim, not a corpus mechanic")
