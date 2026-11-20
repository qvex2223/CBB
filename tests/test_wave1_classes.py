"""Wave 1 registrations (2026-11-17): a SKILL.md edit alone runs nothing.

Lanes come from `cbh leads` and `cbh vectors next`, and `cbh vectors next` reads a per-host
ledger seeded from `engine/vectors.py`. A class or mutation absent from that module's tables is
never seeded, never ranked, never offered and never fired, and the skill describing it sits on
disk unread. These tests are the registration half of each wave-1 item: the matrix entry exists,
the ladder offers it exactly once, and it does NOT leak into a class it does not belong to.

Each item also states its own negative control, because a membership test with no negative
control passes on a table that contains everything.
"""
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "engine"))
import lead_queue as LQ  # noqa: E402
import vectors as V  # noqa: E402

SKILLS = REPO / "skills"


def _mut(cls, needle):
    return [m for m in V.CLASS_MUTATIONS.get(cls, []) if needle in m]


class Item2NestedReference(unittest.TestCase):
    """CVE-2026-126338: the direct read 404s while a nested reference copies the object in."""

    NEEDLE = "nested reference on an id you ALREADY hold"

    def test_registered_as_a_mutation_on_idor(self):
        self.assertEqual(1, len(_mut("idor", self.NEEDLE)),
                         "exactly one matrix entry, or `untried_mutations` double-counts it")

    def test_not_a_class_of_its_own(self):
        """A class would double every host's ledger; this is a mutation."""
        for name in ("nested-reference", "nested_reference"):
            self.assertNotIn(name, V.CATALOG)

    def test_the_ladder_offers_it_and_then_stops(self):
        vec = {"class": "idor", "endpoint": "/api/x", "mutations_tried": []}
        offered = V.untried_mutations(vec)
        self.assertIn(_mut("idor", self.NEEDLE)[0], offered)
        vec["mutations_tried"] = list(V.mutations_for("idor"))
        self.assertEqual([], V.untried_mutations(vec),
                         "a fully-tried vector must offer nothing")

    def test_negative_control_other_classes_do_not_carry_it(self):
        for cls in ("xss", "sqli", "ssrf", "cache-poison", "open-redirect"):
            self.assertEqual([], _mut(cls, self.NEEDLE),
                             f"the idor mutation leaked into {cls}")

    def test_the_entry_states_the_oracle_and_forbids_a_sweep(self):
        """The 500 branch and the no-enumeration rule are the whole value of the entry."""
        entry = _mut("idor", self.NEEDLE)[0]
        self.assertIn("500", entry)
        self.assertIn("404", entry)
        self.assertIn("ALREADY hold", entry)

    def test_the_skill_carries_the_section_and_a_skip_clause(self):
        body = (SKILLS / "hunt-idor" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("A 404 Does Not Close The Lead", body)
        self.assertIn("CVE-2026-126338", body)
        self.assertIn("DO NOT ENUMERATE", body)
        self.assertIn("**SKIP**", body)

    def test_api_security_records_that_a_404_is_not_a_closed_cell(self):
        body = (SKILLS / "api-security" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Nested references defeat a 404", body)
        self.assertIn("**SKIP**", body)


class Item4RedirectParam(unittest.TestCase):
    """CVE-2026-123009: the server put the parameter in its own redirect, then trusted it."""

    CLS = "redirect-param"

    def test_registered_in_all_three_places(self):
        self.assertIn(self.CLS, V.CATALOG)
        self.assertIn(self.CLS, LQ.known_classes())
        import skill_map
        self.assertIn(self.CLS, skill_map.CLASS_SKILL)

    def test_a_declaration_is_not_silently_dropped(self):
        self.assertEqual(self.CLS, LQ.declared_class(f"# x\n\n**Class:** `{self.CLS}`\n"))

    def test_an_unambiguous_inference_token_ranks_it_as_an_authorization_bug(self):
        self.assertEqual("idor", LQ._class_of("from_base_branch-unvalidated",
                                              "the server put it in its own Location"))
        self.assertEqual("idor", LQ._class_of("server-set-param-trusted", "only in Location"))

    def test_the_bare_phrase_redirect_param_is_NOT_an_inference_token(self):
        """Regression: it collided with a real chain slug and re-priced an open redirect.

        Measured on the 2026-11-17 replay. `vozi-qr-widget-bakes-visitor-query-into-displayed-qr`
        carries `**Chain:** ... gives \\`onelink-redirect-param-in-official-ozon-qr\\``, and the
        bare token moved it from the open-redirect band to the idor band and into the top-3 lane
        list, displacing a real lead. A chain slug may use those two words for the ordinary
        thing, so inference must not key on them; an item that IS this class declares it.
        """
        self.assertEqual("open-redirect", LQ._class_of(
            "vozi-qr-widget-bakes-visitor-query-into-displayed-qr",
            "QR widget bakes the visitor query string into the rendered QR "
            "onelink-redirect-param-in-official-ozon-qr"))
        for rx, _cls in LQ.CLASS_WORDS:
            self.assertNotIn("redirect-param", rx,
                             "the ambiguous token is back in the inference table")

    def test_negative_control_a_plain_open_redirect_is_untouched(self):
        """The new regex must not swallow ordinary open-redirect leads.

        Only cases that actually contain the token `redirect` test this: those are the ones the
        new rule could steal, because it is matched BEFORE `open-redirect|redirect`.
        """
        for name, title in (("open-redirect-on-next", "redirect to off-origin host"),
                            ("redirect-to-evil", "redirect parameter unvalidated"),
                            ("oauth-redirect-uri-lax", "redirect_uri accepts a sibling")):
            self.assertNotEqual("idor", LQ._class_of(name, title),
                                f"{name} was stolen by the redirect-param rule")

    def test_a_lead_naming_no_class_word_still_falls_through_to_other(self):
        """Pre-existing gap, asserted so it is not mistaken for this wave's doing.

        `logout-returnto` / "returnTo off-origin" contains no CLASS_WORDS token at all, so it
        ranks at DEFAULT_REWARD as `other` — it did before this wave and it does after. It is one
        instance of the 774 open `other` items `cbh adoption` counts, which is a ranking problem
        of its own and NOT in this plan's scope.
        """
        self.assertEqual("other", LQ._class_of("logout-returnto", "returnTo off-origin"))

    def test_it_is_not_seeded_from_a_manifest_hint(self):
        """A manifest records no redirect, so a risk hint would propose it everywhere."""
        for classes in V.HINT_CLASSES.values():
            self.assertNotIn(self.CLS, classes)

    def test_the_mutation_ladder_states_the_400_trap(self):
        entry = [m for m in V.CLASS_MUTATIONS[self.CLS] if "400" in m]
        self.assertEqual(1, len(entry))
        self.assertIn("CVE-2026-123009", entry[0])

    def test_consumers_include_the_post_revocation_read(self):
        self.assertTrue(any("revocation" in c for c in V.consumers_for(self.CLS)))

    def test_the_skills_carry_it(self):
        idor = (SKILLS / "hunt-idor" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Parameters The Server Put There Itself", idor)
        self.assertIn("from_base_branch", idor)
        self.assertIn("A 400 is not a failure", idor)
        recon = (SKILLS / "api-recon" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("own redirects", recon)
        self.assertIn("costs no requests", recon)


class Item5OwnershipTransfer(unittest.TestCase):
    """CVE-2026-118535: trust keyed on a permanent id survives the change of owner."""

    NEEDLE = "SECOND identity"

    def test_registered_as_an_idor_mutation(self):
        self.assertEqual(1, len(_mut("idor", self.NEEDLE)))

    def test_negative_control_not_on_other_classes(self):
        for cls in ("xss", "sqli", "cache-poison", "token-purpose", "redirect-param"):
            self.assertEqual([], _mut(cls, self.NEEDLE))

    def test_the_entry_names_what_to_enumerate_after_the_transfer(self):
        entry = _mut("idor", self.NEEDLE)[0]
        for token in ("secrets", "tokens", "webhooks", "permanent id"):
            self.assertIn(token, entry)

    def test_the_skills_carry_it(self):
        api = (SKILLS / "api-security" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("survives a transfer of ownership", api)
        self.assertIn("CVE-2026-118535", api)
        self.assertIn("REGISTER FIRST", api)
        inv = (SKILLS / "hunt-invariants" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("revocation is total", inv)


class Item6TokenPurpose(unittest.TestCase):
    """CVE-2026-114607: one store, two flows, no column saying which minted the row."""

    CLS = "token-purpose"

    def test_registered_in_all_three_places(self):
        self.assertIn(self.CLS, V.CATALOG)
        self.assertIn(self.CLS, LQ.known_classes())
        import skill_map
        self.assertIn(self.CLS, skill_map.CLASS_SKILL)

    def test_a_declaration_is_not_silently_dropped(self):
        self.assertEqual(self.CLS, LQ.declared_class(f"# x\n\n**Class:** `{self.CLS}`\n"))

    def test_it_ranks_at_the_ato_band(self):
        self.assertEqual("ato", LQ._class_of("magic-link-accepts-oauth-state",
                                             "state record redeemed by the magic-link verifier"))

    def test_negative_control_invite_token_is_not_a_trigger_word(self):
        """`invite-token` was dropped from the regex on purpose: it collides with invite leads."""
        self.assertNotEqual(self.CLS, LQ._class_of("invite-token-not-bound", "invite token reuse"))

    def test_it_rides_only_the_oauth_hint(self):
        self.assertIn(self.CLS, V.HINT_CLASSES["oauth"])
        for hint, classes in V.HINT_CLASSES.items():
            if hint != "oauth":
                self.assertNotIn(self.CLS, classes, f"{self.CLS} leaked onto the {hint} hint")

    def test_the_ladder_puts_the_census_before_the_payload(self):
        first = V.CLASS_MUTATIONS[self.CLS][0]
        self.assertIn("census first", first)

    def test_the_ladder_states_the_additionalData_detail(self):
        """Top-level in the body does not work — the public PoC fails for that reason."""
        self.assertTrue(any("additionalData" in m or "top level" in m
                            for m in V.CLASS_MUTATIONS[self.CLS]))

    def test_consumers_name_the_session_read_as_the_impact(self):
        self.assertTrue(any("/me" in c or "ATO" in c for c in V.consumers_for(self.CLS)))

    def test_the_skills_carry_it(self):
        oauth = (SKILLS / "hunt-oauth" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Token Purpose Confusion", oauth)
        self.assertIn("CVE-2026-114607", oauth)
        self.assertIn("additionalData", oauth)
        self.assertIn("Do not port their detection heuristic", oauth)
        self.assertIn("token-purpose", (SKILLS / "hunt-session" / "SKILL.md").read_text("utf-8"))
        ato = (SKILLS / "hunt-ato" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("token purpose confusion", ato)
        self.assertIn("pre-registration", ato)


class Item7CacheIdentity(unittest.TestCase):
    """Next.js Cache Components: identity, not key — and the race arm is excluded."""

    def test_both_deterministic_arms_are_registered(self):
        self.assertEqual(1, len(_mut("cache-poison", "cache IDENTITY")))
        self.assertEqual(1, len(_mut("cache-poison", "nested cached function")))

    def test_each_arm_cites_its_cve(self):
        self.assertIn("CVE-2026-119349", _mut("cache-poison", "cache IDENTITY")[0])
        self.assertIn("CVE-2026-119351", _mut("cache-poison", "nested cached function")[0])

    def test_the_cold_fill_race_is_absent_from_the_matrix(self):
        """It needs concurrent requests: blast radius on other users and on availability."""
        for m in V.CLASS_MUTATIONS["cache-poison"]:
            self.assertNotIn("CVE-2026-119790", m)
            self.assertNotIn("cold cache fill", m)

    def test_no_new_class_was_created_for_it(self):
        for name in ("cache-identity", "use-cache", "cache_identity"):
            self.assertNotIn(name, V.CATALOG)

    def test_the_skills_carry_it_and_say_which_arm_is_excluded(self):
        nx = (SKILLS / "hunt-nextjs" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("identity confusion, not key confusion", nx)
        self.assertIn("CVE-2026-119790", nx)
        self.assertIn("**Park:** availability", nx)
        self.assertIn("16.4.5", nx)
        cp = (SKILLS / "hunt-cache-poison" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Cache key vs cache identity", cp)


class Item3CveVersionRange(unittest.TestCase):
    """A version range is a vendor hint, not an oracle."""

    def test_the_new_status_exists(self):
        src = (REPO / "scripts" / "cve-digest.py").read_text(encoding="utf-8")
        self.assertIn('"below-range-unverified"', src)

    def test_the_old_example_no_longer_closes_a_below_range_row_as_checked(self):
        md = (REPO / "commands" / "cve.md").read_text(encoding="utf-8")
        self.assertNotIn('--status checked   --note "Tomcat 9.0.85, not in affected range"', md)
        self.assertIn("below-range-unverified", md)

    def test_the_rule_carries_the_evidence_and_its_caveats(self):
        md = (REPO / "commands" / "cve.md").read_text(encoding="utf-8")
        self.assertIn("149 vulnerable prior releases", md)
        self.assertIn("58.3%", md)
        self.assertIn("37.9%", md)   # the attack-vector-shift caveat
        self.assertIn("15.0%", md)   # the no-reference-PoC caveat


class DeclaringTheClassMustNotDemoteTheLead(unittest.TestCase):
    """A routable class with no reward band ranks at DEFAULT_REWARD.

    So declaring the truth would push the lead DOWN the queue — the opposite of the point.
    Found 2026-11-17 while adding these two classes: both were routable through
    `skill_map.CLASS_SKILL` and absent from `DEFAULT_WEIGHTS`.
    """

    def test_both_new_classes_have_a_band(self):
        for cls in ("redirect-param", "token-purpose"):
            self.assertIn(cls, LQ.DEFAULT_WEIGHTS, f"declaring `{cls}` would demote the lead")

    def test_the_band_is_at_least_the_default(self):
        for cls in ("redirect-param", "token-purpose"):
            self.assertGreater(LQ.DEFAULT_WEIGHTS[cls], LQ.DEFAULT_REWARD)

    def test_token_purpose_is_priced_as_an_account_takeover(self):
        self.assertEqual(LQ.DEFAULT_WEIGHTS["ato"], LQ.DEFAULT_WEIGHTS["token-purpose"])

    def test_redirect_param_is_priced_as_an_authorization_bug(self):
        self.assertEqual(LQ.DEFAULT_WEIGHTS["idor"], LQ.DEFAULT_WEIGHTS["redirect-param"])

    def test_every_routable_class_this_wave_added_is_in_both_tables(self):
        """The general form of the bug, so the next class cannot repeat it."""
        for cls in ("redirect-param", "token-purpose"):
            self.assertIn(cls, LQ.known_classes())
            self.assertIn(cls, LQ.DEFAULT_WEIGHTS)


class TheQueueActuallyOffersThem(unittest.TestCase):
    """Check C.2 of the plan: the class reaches `cbh vectors next`, not just a table.

    `vectors.seed` RETURNS the ledger and does not save it — the caller does. A first version
    of this test forgot that, read an empty ledger back and looked exactly like a registration
    failure.
    """

    def _ledger(self, endpoints):
        import tempfile
        d = Path(tempfile.mkdtemp())
        V.save(V.seed("t.example", endpoints, memdir=d), memdir=d)
        return d

    def test_token_purpose_is_offered_and_ranks_near_the_top(self):
        d = self._ledger(["/api/auth/sign-in/social"])
        offered = [v["class"] for v in V.next_vectors("t.example", count=10, memdir=d)]
        self.assertIn("token-purpose", offered)
        self.assertLess(offered.index("token-purpose"), 6,
                        "impact 92 must rank it with the account-takeover classes")

    def test_redirect_param_is_offered(self):
        d = self._ledger(["/_new/main/"])
        offered = [v["class"] for v in V.next_vectors("t.example", count=40, memdir=d)]
        self.assertIn("redirect-param", offered)

    def test_the_first_token_purpose_mutation_is_the_census(self):
        d = self._ledger(["/api/auth/sign-in/social"])
        vec = next(v for v in V.next_vectors("t.example", count=10, memdir=d)
                   if v["class"] == "token-purpose")
        self.assertIn("census first", V.next_mutation(vec))

    def test_the_first_redirect_param_mutation_is_the_corpus_diff(self):
        """It must cost no requests to start: the first move is reading the corpus."""
        d = self._ledger(["/_new/main/"])
        vec = next(v for v in V.next_vectors("t.example", count=40, memdir=d)
                   if v["class"] == "redirect-param")
        self.assertIn("corpus diff", V.next_mutation(vec))


class TheLadderNamesTheSkill(unittest.TestCase):
    """A skill the ladder never names is a skill no lane loads.

    `cbh autohunt` puts `cbh skill-graph --ladder` in every brief, and `skill-gate` demands the
    skills it marks. Measured 2026-11-17 by a Grok verification run: the ladder for
    `/api/auth/magic-link/verify?token=abc` did not rank `hunt-oauth` at all — it appeared only
    in a `defer:` column — because `?token=` is a query parameter and misses the
    `/(oauth|authorize|token)\b` path signal, while `/verify` and `/auth` route to
    hunt-mfa-bypass and hunt-auth-bypass. The write-up existed and nothing would have opened it.
    """

    def _classes_for(self, url):
        import skill_signals as SS
        return {cls for rx, cls, _skill, _gated in SS.PATH_SIGNALS
                if __import__("re").search(rx, url)}

    def _skills_for(self, url):
        import skill_signals as SS
        return {skill for rx, _cls, skill, _gated in SS.PATH_SIGNALS
                if __import__("re").search(rx, url)}

    def test_a_magic_link_verify_url_routes_to_hunt_oauth(self):
        url = "/api/auth/magic-link/verify?token=abc"
        self.assertIn("hunt-oauth", self._skills_for(url))
        self.assertIn("token-purpose", self._classes_for(url))

    def test_a_social_sign_in_url_routes_to_hunt_oauth(self):
        for url in ("/api/auth/sign-in/social", "/api/auth/signin/oauth"):
            self.assertIn("hunt-oauth", self._skills_for(url))

    def test_the_mfa_surface_is_not_stolen(self):
        """Bare `/verify` and `/otp` stay with hunt-mfa-bypass: the new tokens are narrow."""
        for url in ("/account/verify?code=1", "/api/otp/resend", "/2fa/verify"):
            self.assertNotIn("token-purpose", self._classes_for(url),
                             f"{url} was pulled onto the token-purpose signal")
            self.assertIn("hunt-mfa-bypass", self._skills_for(url))

    def test_an_ordinary_login_url_gains_nothing(self):
        self.assertNotIn("token-purpose", self._classes_for("/api/login"))
        self.assertNotIn("hunt-oauth", self._skills_for("/api/login"))


class RoutabilityOfEveryWave1Class(unittest.TestCase):
    """Any class these items register must be routable, or `**Class:**` is silently dropped.

    `lead_queue.declared_class` returns "" for a name outside `known_classes()`, which is the
    union of `CLASS_WORDS`, `skill_map.CLASS_SKILL` and `CLASS_TO_CORPUS`. Two classes already
    in the ledgers fail this today (`business_logic`, `open_redirect`); nothing this wave adds
    may join them.
    """

    WAVE1_CLASSES = ("redirect-param", "token-purpose")

    def test_every_class_this_wave_registers_is_routable(self):
        known = LQ.known_classes()
        for cls in self.WAVE1_CLASSES:
            self.assertIn(cls, known, f"`**Class:** {cls}` would be silently dropped")
            self.assertIn(cls, V.CATALOG, f"{cls} is not seeded or ranked")

    def test_the_known_bad_pair_is_still_detected_as_unroutable(self):
        """A guard on the guard: if these ever become routable, the check above went blind."""
        known = LQ.known_classes()
        self.assertNotIn("business_logic", known)
        self.assertNotIn("open_redirect", known)


if __name__ == "__main__":
    unittest.main()
