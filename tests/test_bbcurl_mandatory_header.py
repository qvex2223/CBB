"""A mandatory header must not be dropped because its name appears in some other argument.

`bbcurl` skips injecting a programme's required header when the caller already set it by
hand. The original check was `" ".join(argv).lower()` against `"<name>:"`, which matched the
name **anywhere on the command line** — including inside the value of an unrelated argument.

That failed open on a live engagement. The Юкки programme asks researchers to put
`X-BugBounty: <user>` in the User-Agent, so every request of the shape
`bbcurl -A 'Mozilla/5.0 ... X-BugBounty: qvex' <url>` looked to the old check like the header
had been set deliberately, and the standalone header the engagement also requires was silently
left off. Silently is the problem: `MissingRequiredHeader` exists precisely so a request cannot
go out without the programme's marker, and this path bypassed it with no warning.

These tests pin the behaviour of the header-name parser itself, which is the part that got it
wrong, rather than the subprocess assembly around it.
"""
import importlib.util
import pathlib
import unittest

BBCURL = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "bbcurl"


def _load():
    spec = importlib.util.spec_from_loader("bbcurl_under_test",
                                           importlib.machinery.SourceFileLoader(
                                               "bbcurl_under_test", str(BBCURL)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


import importlib.machinery  # noqa: E402  (needed by _load above)


class ExplicitHeaderNames(unittest.TestCase):
    def setUp(self):
        self.names = _load()._explicit_header_names

    # --- the regression itself -------------------------------------------------
    def test_name_inside_a_user_agent_is_not_an_explicit_header(self):
        argv = ["-sk", "-A", "Mozilla/5.0 (X11; Linux x86_64) Chrome/155.0.0.0 X-BugBounty: qvex",
                "https://185.171.101.250/"]
        self.assertEqual(self.names(argv), set(),
                         "a header name in a -A value must not count as the caller setting it")

    def test_name_inside_a_post_body_is_not_an_explicit_header(self):
        argv = ["-X", "POST", "-d", "note=X-BugBounty: qvex", "https://example.test/"]
        self.assertEqual(self.names(argv), set())

    def test_name_inside_the_url_is_not_an_explicit_header(self):
        argv = ["https://example.test/?h=X-BugBounty:qvex"]
        self.assertEqual(self.names(argv), set())

    # --- the forms that genuinely do mean "I set this myself" ------------------
    def test_separate_dash_h(self):
        self.assertEqual(self.names(["-H", "X-BugBounty: mine", "https://example.test/"]),
                         {"x-bugbounty"})

    def test_glued_dash_h(self):
        self.assertEqual(self.names(["-HX-BugBounty:mine", "https://example.test/"]),
                         {"x-bugbounty"})

    def test_long_form_equals(self):
        self.assertEqual(self.names(["--header=X-BugBounty: mine", "https://example.test/"]),
                         {"x-bugbounty"})

    def test_long_form_separate(self):
        self.assertEqual(self.names(["--header", "X-BugBounty: mine", "https://example.test/"]),
                         {"x-bugbounty"})

    def test_curl_removal_syntax_also_claims_the_name(self):
        # `-H 'name;'` tells curl to REMOVE that header. The caller has still taken
        # charge of the name, so bbcurl must not quietly add it back.
        self.assertEqual(self.names(["-H", "X-BugBounty;", "https://example.test/"]),
                         {"x-bugbounty"})

    def test_case_is_normalised(self):
        self.assertEqual(self.names(["-H", "x-BUGBOUNTY: mine", "https://example.test/"]),
                         {"x-bugbounty"})

    def test_several_headers_are_all_collected(self):
        argv = ["-H", "X-BugBounty: mine", "-H", "Accept: application/json",
                "-A", "UA with X-Other: decoy", "https://example.test/"]
        self.assertEqual(self.names(argv), {"x-bugbounty", "accept"})

    # --- shapes that must not crash or produce junk ---------------------------
    def test_dash_h_with_no_value_is_ignored(self):
        self.assertEqual(self.names(["-H"]), set())

    def test_value_with_no_separator_is_ignored(self):
        self.assertEqual(self.names(["-H", "NotAHeaderLine", "https://example.test/"]), set())

    def test_leading_colon_is_not_a_name(self):
        self.assertEqual(self.names(["-H", ":novalue", "https://example.test/"]), set())


if __name__ == "__main__":
    unittest.main()


class ExtractUrlsOnlyFindsDestinations(unittest.TestCase):
    """An option VALUE that looks like a URL is not a destination to scope-check.

    `extract_urls` feeds the scope gate. It used to treat the value of any option it
    did not know about as a URL, which produced false OUT-OF-SCOPE refusals on the
    exact tests that matter for one of this programme's own payable classes:
    `--request-target http://172.17.201.1/` is the absolute-URI **request line** used
    to test a host for being an open relay, while the TCP destination is still the
    in-scope address in the URL argument. The gate refused to send it.

    Same shape as the earlier `--resolve` false block. These tests pin both halves:
    content and local-file values are ignored, and anything that is genuinely a
    destination is still collected.
    """

    def setUp(self):
        self.urls = _load().extract_urls

    # --- the regression: content and file values must NOT be scope-checked -----
    def test_request_target_absolute_uri_is_content(self):
        argv = ["-sk", "--request-target", "http://172.17.201.1/", "https://185.171.101.250/"]
        self.assertEqual(self.urls(argv), ["https://185.171.101.250/"])

    def test_body_containing_a_url_is_content(self):
        for opt in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
                    "--data-urlencode", "--json"):
            with self.subTest(opt=opt):
                argv = ["-X", "POST", opt, "u=http://169.254.169.254/latest/meta-data/",
                        "https://185.171.101.250/"]
                self.assertEqual(self.urls(argv), ["https://185.171.101.250/"])

    def test_form_value_is_content(self):
        for opt in ("-F", "--form", "--form-string"):
            with self.subTest(opt=opt):
                argv = [opt, "cb=http://10.1.50.45/", "https://185.171.101.250/"]
                self.assertEqual(self.urls(argv), ["https://185.171.101.250/"])

    def test_referer_and_user_agent_are_content(self):
        argv = ["-e", "http://evil.example/", "-A", "UA http://evil.example/",
                "https://185.171.101.250/"]
        self.assertEqual(self.urls(argv), ["https://185.171.101.250/"])

    def test_local_file_options_are_not_destinations(self):
        for opt in ("-o", "--output", "-D", "--dump-header", "-c", "--cookie-jar",
                    "-T", "--upload-file", "--trace", "--cacert", "-E", "--cert",
                    "--hsts", "--alt-svc", "-K", "--config"):
            with self.subTest(opt=opt):
                argv = [opt, "https://not-a-destination.example/x", "https://185.171.101.250/"]
                self.assertEqual(self.urls(argv), ["https://185.171.101.250/"])

    # --- the other half: real destinations are still collected ----------------
    def test_the_url_argument_is_still_collected(self):
        self.assertEqual(self.urls(["-sk", "https://185.171.101.250/"]),
                         ["https://185.171.101.250/"])

    def test_long_form_url_option_is_still_a_destination(self):
        self.assertEqual(self.urls(["--url", "https://ykky.ru/"]), ["https://ykky.ru/"])

    def test_several_url_arguments_are_all_collected(self):
        argv = ["-sk", "https://185.171.101.250/", "https://185.171.101.188/"]
        self.assertEqual(self.urls(argv),
                         ["https://185.171.101.250/", "https://185.171.101.188/"])

    def test_a_proxy_is_still_treated_as_a_destination(self):
        # -x/--proxy is deliberately NOT in the content list: curl connects to it,
        # so it must stay subject to the scope gate.
        self.assertIn("http://192.0.2.1:8080/", self.urls(
            ["-x", "http://192.0.2.1:8080/", "https://185.171.101.250/"]))

    def test_content_option_does_not_swallow_the_following_url(self):
        # The value is skipped, not the argument after it.
        argv = ["--request-target", "http://172.17.201.1/", "-sk", "https://185.171.101.250/"]
        self.assertEqual(self.urls(argv), ["https://185.171.101.250/"])
