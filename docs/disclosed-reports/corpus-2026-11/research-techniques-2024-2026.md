RESEARCH REPORT — high-impact web techniques + methods, 2024–2026. Read-only, publication pages only. No request sent to any target.

Format per item: URL · date · author | technique (class) | SIGNAL | MIN TEST | IMPACT/proof | DIFFERENTIAL?

=== A. REQUEST-BOUNDARY / PROXY-BACKEND DISAGREEMENT (highest paid class in the corpus) ===

1. HTTP/1.1 Must Die: the desync endgame
https://portswigger.net/research/http1-must-die · 2025-08-06 (upd 2025-10-17) · James Kettle (w/ Wannes Verwimp, sw33tLie, bsysop, Medusa)
Technique: V-H / H-V header-masking discrepancies; 0.CL desync made exploitable via "early-response gadget"; double-desync 0.CL→CL.0; `Expect: 100-continue` desyncs (4 variants incl. obfuscated `Expect: y 100-continue`). Class: request smuggling / desync.
SIGNAL: masked header yields a response differing from normal/absent/arbitrary-masked (`Host : foo`, leading space, `Xost`); Server banner tells which layer answered (`awselb/2.0` vs `Microsoft-HTTPAPI/2.0`); "Mystery 400"; second header block leaking stripped front-end headers (`X-Nf-*`, `X-Bb-*`); 504 deadlock on HEAD; server not treating `\n\n` as end-of-headers.
MIN TEST: discrepancy probe only (HTTP Request Smuggler v3.0 permutations; Turbo Intruder `0cl-find-offset`), benign controllable response (`Location: /Logon?ReturnUrl=%2fwrtz`) — detect, don't weaponize.
IMPACT: Cloudflare internal desync affecting >24,000,000 sites ($7k); GitLab response-queue poisoning retrieved another user's report video after 27,000 requests ($7k); Akamai CL.0-via-obfuscated-Expect served attacker content on auth.lastpass.com → 74 bounties / $221k, CVE-2025-32094; T-Mobile staging 0.CL ($12k). >$350k total.
DIFFERENTIAL: yes, core — front-end vs back-end message-length interpretation (CL / TE / implicit-0 / H2), amplified by H2→H1 downgrade.

2. Can AI do novel security research? Meet the HTTP Terminator
https://portswigger.net/research/can-ai-do-novel-security-research · 2026-08-05 (upd 2026-10-06) · James Kettle
Technique: autonomous 4-phase research loop (ideation → evaluation → weaponization → cascade) inventing desync vectors; "micro-inspiration" = 138 RFCs split to ~15,000 fragments → ~30,000 unique vectors; protocol-ruler (header size-limit measurement detects front-end rewriting/expansion); dangling-byte RQP (send smuggled request one byte short → removes the stacked-response race). Class: methodology / desync.
SIGNAL (the oracle worth copying): request-contamination detection — baseline request with stable response + candidate trigger on a separate connection; ANY change to the baseline response = hit, no assumption about what a poisoned response looks like; second phase classifies (CL.0 etc.) by eliciting a third distinct response.
MIN TEST: scan 30,000 sites, <1 req/s per domain, 2000 threads, anomaly layer; deterministic locked judging code (zero false positives).
IMPACT: ~700 vulnerable targets (banks, gov, airport staff panel w/ flight+luggage data via F5 Big-IP); `multipart/byteranges` Content-Type as CL.0 trigger hit >200 sites; dual-matching Content-Length → stolen long-lived bank API key (Citrix NetScaler) + SSO compromise; 0-day CVE-2026-63078 (Apache Traffic Server); new class "Shared-Parser Confusion" (servers reusing response-parsing code on requests).
DIFFERENTIAL: yes. Key agent lesson: judgement in code, not in the model; fresh context per stage; human in the cascade loop.

3. Unveiling TE.0 HTTP Request Smuggling
https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/ · 2024-07-17 · Paolo Arnolfo (sw33tLie), Guillermo Gregorio (bsysop), @_medusa_1_
Technique: front-end honours `Transfer-Encoding: chunked`, back-end treats body as 0 (TE.0). Class: smuggling.
SIGNAL: Google Cloud hosting, `Via: 1.1 google`; GCP LB defaulting to HTTP/1.1 upstream; IAP error "Invalid IAP credentials: empty token". Worked ONLY with `OPTIONS /` (failed GET/POST).
MIN TEST: OPTIONS + TE: chunked + keep-alive, no CL, hex chunk size `50`, two blank lines after terminating `0`, tooling CL auto-insertion off; smuggled line points at own collaborator.
IMPACT: thousands of GCP sites; bank main API → mass 0-click ATO (live users redirected, session tokens leaked); IAP zero-trust bypass. $8,500.
DIFFERENTIAL: yes (CL.0 inverted).

4. Playing with HTTP/2 CONNECT
https://blog.flomb.net/posts/http2connect/ · 2025-09-15 · fl0mb
Technique: HTTP/2 per-stream CONNECT tunnels → multiplexed internal port scan over one TLS conn. Class: SSRF / proxy misconfig.
SIGNAL: ALPN `h2`/h2c; `:status 200` HEADERS = tunnel accepted; 503 / proxy error DATA / `RST_STREAM` (`CONNECT_ERROR` Envoy, `NO_ERROR` Apache) = refused.
MIN TEST: preface + empty SETTINGS + one HPACK HEADERS `:method CONNECT`, `:authority host:port`; read status only, send no DATA.
IMPACT: lab-proven tunneling + scanning (Envoy `allow_connect: true`, Apache mod_proxy_connect); no real-world target reported. Tool: github.com/fl0mb/HTTP2-CONNECT-Tunnel.
DIFFERENTIAL: multi-component config, not a parser diff.

=== B. URL/PATH NORMALIZATION + CACHE KEY DISAGREEMENT ===

5. Confusion Attacks: Hidden Semantic Ambiguity in Apache HTTP Server
https://blog.orange.tw/posts/2024-08-confusion-attacks-en/ · 2024-08-09 · Orange Tsai (BH USA 2024). 3 classes, 9 CVEs, 20 techniques.
Technique: modules disagree on shared `request_rec` — filename confusion (mod_rewrite truncates at `%3F`, after regex match), DocumentRoot confusion (path tried with and without docroot), handler confusion (`r->content_type` used as handler). Class: component confusion → ACL bypass, source disclosure, RCE.
SIGNAL: `Server: Apache` < 2.4.60 (esp. Debian/Ubuntu); RewriteRule substitution starting with a backreference (`/$1.html`); single file protected by `<Files>` while PHP-FPM via `SetHandler proxy:`; PHP via `AddType` not `AddHandler`; live `/cgi-bin/` ScriptAlias; ModSecurity in front; 400 page whose body contains raw `<?php`; `AllowEncodedSlashes On`.
MIN TEST: `/admin.php%3Fooo.php` vs 401/403 on `/admin.php`; `/user/orange%2Fsecret.yml%3F`; `/html/usr/lib/cgi-bin/download.cgi%3F` (benign /usr/share doc file); CRLF handler test `%0d%0aLocation:/ooo%0d%0aContent-Type:server-status%0d%0a%0d%0a`.
IMPACT: auth/IP-restriction bypass; arbitrary file read (Redmine `secret_key.txt` → Rails deserialization RCE); PHP/CGI source disclosure; SSRF + unix socket; PHP-FPM+pearcmd RCE. CVE-2024-38472/38473/38474/38475/38476/38477, CVE-2023-38709.
DIFFERENTIAL: yes in every class (mod_rewrite URL-view vs filesystem; `<Files>` vs PHP-FPM `?`-truncation; content_type vs handler; ModSecurity error path vs httpd).

6. Gotta cache 'em all: bending the rules of web cache exploitation
https://portswigger.net/research/gotta-cache-em-all · 2024-08-08 · Martin Doyhenard (DEF CON 32)
Technique: origin-only path delimiters (`;` Spring, `.` Rails, `%00` OpenLiteSpeed, `%0a` nginx) + normalization gaps → web cache deception AND arbitrary cache poisoning via key normalization ("Cache-What-Where"). Class: cache.
SIGNAL: `X-Cache: hit`, response-time delta, `Cache-Control: public` vs `no-store`; CloudFront/Azure/Imperva normalize before cache rules, Cloudflare/GCP/Fastly do not; IIS treats encoded backslash as slash, no tested CDN does.
MIN TEST: baseline non-cacheable R0 → `/homeabcd` (differs) → `/home$abcd` (matches R0 ⇒ `$` is origin delimiter); `GET /home/index?cacheBuster` vs `/aaa/../home/index?cacheBuster`; Intruder over all ASCII raw+encoded. Cache-buster = the safety mechanism.
IMPACT: token/API-key theft → ATO, defacement, malicious JS on popular keys. No named target/bounty.
DIFFERENTIAL: yes — CDN parser vs origin parser.

7. ChatGPT Account Takeover — Wildcard Web Cache Deception
https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html · 2024-02-04 · Harel (nokline / h4r3l)
Technique: cache rule keyed on path prefix (`/share/*`) + CDN not decoding `%2F..%2F` while origin does → cache a sensitive endpoint under a cached wildcard. Class: WCD via inconsistent decoding.
SIGNAL: shared-link path with no static extension; `Cf-Cache-Status: HIT`; nonexistent path under `/share/` also cached.
MIN TEST: `GET /share/random-nonexistent` → check HIT; then `/share/%2F..%2Fapi/auth/session?cachebuster=<unique>` against own session (unique buster = no other user's entry touched).
IMPACT: victim's `/api/auth/session` token cached and retrieved by attacker → full ATO (chats, billing). $6,500.
DIFFERENTIAL: yes — CDN vs web server URL parsing.

8. Nginx/Apache path confusion → PAN-OS auth bypass (CVE-2025-0108), Assetnote/Searchlight. Listed on https://slcyber.io/assetnote-security-research-center/ (direct post URL not resolved in this pass — 404 on guessed slug; cite the index). Same class as #5/#6: front-end nginx vs Apache vs PHP path view → pre-auth access to management endpoints. Flagged as a lead, not verified in detail here.

=== C. OTHER PARSER DIFFERENTIALS (cookie, email, charset, unicode) ===

9. Stealing HttpOnly cookies with the cookie sandwich technique
https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique · 2025-01-22 (upd 2025-06-30) · Zakhar Fedotkin
Technique: JS sets `$Version=1` + `param1="start` + `param2=end"`; server switches to RFC2109/quoted-string parsing and swallows the cookies in between — including HttpOnly — into one reflected value. Class: cookie parser differential → HttpOnly bypass.
SIGNAL: any endpoint reflecting a cookie value into body or `Set-Cookie` (analytics/visitor-ID endpoints are the archetype); Tomcat 8.5/9.0/10.0 (RFC2109 by default); Flask returns `\073` for the swallowed `;`.
MIN TEST: own dummy cookies only, `$Version` first (longer Path, e.g. `Path=/json`), check whether the reflected value swallows the intervening pairs instead of returning `start`.
IMPACT: chained WAF-bypassing reflected XSS + credentialed-CORS Tomcat subdomain reflector → read HttpOnly `PHPSESSID`.
DIFFERENTIAL: yes — browser RFC6265 vs server legacy parser.

10. Splitting the email atom: exploiting parsers to bypass access controls
https://portswigger.net/research/splitting-the-email-atom · 2024-08-07 (upd 2025-06-27) · Gareth Heyes (BH + DEF CON)
Technique: encoded-word (`=?utf-8?q?..?=`), UUCP `!` / `%`-hack source routes, malformed punycode (`xn--0117` → `@`), unicode overflow (mod-256, PHP `chr()`) → validator and mailer disagree on the destination domain. Class: parser discrepancy → access control bypass.
SIGNAL: domain-restricted registration/verification; `RCPT TO` in Collaborator SMTP showing the DECODED form; Ruby Mail gem / PHP IDN stacks; Sendmail 8.15.2 vs Postfix 3.6.4 behave differently.
MIN TEST: register/change email to `=?utf-8?q?=61=62=63?=<collab-id>@<own-collab-domain>` and read the SMTP envelope. Method: "Probe, Observe, Encode and Exploit" (Hackvertor tags, Turbo Intruder script, punycode fuzzer).
IMPACT: GitHub verified addresses at microsoft.com/mozilla.com/github.com (→ Cloudflare Zero Trust domain-rule bypass); Zendesk + GitLab domain-restriction bypass; Joomla punycode `<style>` injection → CSS-import CSRF-token leak → RCE (CVE-2024-21725).
DIFFERENTIAL: yes — app validator vs library vs MTA (and IdP vs relying party).

11. WorstFit: Unveiling Hidden Transformers in Windows ANSI
https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/ · 2025-01-10 (BH EU 2024) · Orange Tsai + splitline
Technique: Windows Best-Fit conversion UTF-16→ANSI happens AFTER escaping/validation, re-introducing `" \ / -`. Class: charset/representation differential → argument injection, path traversal, RCE.
SIGNAL: Windows host + ACP (`...\Nls\CodePage /v ACP`); narrow APIs (`GetCommandLineA`, `getenv`, `FindFirstFileA`, plain `int main()`); app spawning CLI tools (wget/tar/openssl/java/curl) from PHP `escapeshellarg`, Python `list2cmdline`, Node; CGI passing `QUERY_STRING`/`PATH_INFO`; Python <3.6.
MIN TEST: fullwidth `＂` U+FF02 (→ `"` on 125x/874), `＼` U+FF3C, `¥` on cp932, `／` U+FF0F traversal, soft hyphen `%AD` → `-` (cp932/936/950); file-existence oracle `/index.php/..¥..¥windows/win.ini/` vs `..¥..¥NONEXIST/` ("No input file specified" = exists).
IMPACT: CVE-2024-4577 (PHP-CGI RCE), elFinder via tar `--use-compress-program`, openssl `-engine` remote DLL, RStudio CVE-2024-45720, Perforce CVE-2024-8067, Excel CVE-2024-49026 → NTLM relay → RCE; Cuckoo traversal → Flask PIN → RCE.
DIFFERENTIAL: yes — escaping layer sees Unicode, consuming component sees Best-Fit bytes.

12. Abusing Windows, .NET quirks and Unicode Normalization to exploit DNN (CVE-2025-52488)
https://slcyber.io/research-center/abusing-windows-net-quirks-and-unicode-normalization-to-exploit-dnn-dotnetnuke/ · 2025-07 · Searchlight Cyber / Assetnote research team
Technique: `%EF%BC%8E` (U+FF0E) / `%EF%BC%BC` (U+FF3C) normalized to `.` and `\` AFTER security checks → filename becomes UNC path; `File.Exists` on a UNC path leaks NTLM. Class: unicode normalization + Windows path semantics → pre-auth credential disclosure.
SIGNAL: DNN 6.0.0–<10.0.1, `FileUploader.ashx`; generally: any .NET app doing `Path.Combine`/`File.Exists` on user-supplied names.
MIN TEST: POST crafted filename with fullwidth chars, observe inbound SMB to own Responder-style listener (OOB — check program policy first).
IMPACT: pre-auth NTLM hash disclosure, CVSS 8.6, GHSA-mgfv-2362-jq96. Article has a "hunting variants" section.
DIFFERENTIAL: yes — validation on pre-normalized string, consumption post-normalization.

13. Lost in Translation: Exploiting Unicode Normalization — Ryan Barnett & Isabella Barnett, https://www.youtube.com/watch?v=ETB2w-f3pM4 (#4 of 2025). Broad normalization exploit corpus from WAF-vendor telemetry; shipped ActiveScan++ updates. Same signal/test shape as #11/#12.

14. Parser Differentials: When Interpretation Becomes a Vulnerability — @joernchen, https://www.youtube.com/watch?v=Dq_KVLXzxH8 (#10 of 2025). Cross-language/framework case studies; panel called it "an excellent starting point" for research ideas — i.e. the class itself as a hunting lens.

=== D. INJECTION CLASSES WITH NEW ORACLES ===

15. Successful Errors: New Code Injection and SSTI Techniques (#1 of 2025)
https://github.com/vladko312/Research_Successful_Errors · 2026-01-03 (OFFZONE talk 2025) · Vladislav Korchagin
Technique: Error-Based SSTI (force an error whose message echoes attacker data/command output) + Boolean Error-Based Blind (error raised only when a condition is false → no time delays). Class: SSTI / code injection.
SIGNAL (language-agnostic detection, the agent-ready part): `(1/0).zxy.zxy` errors in any supported language and the error text identifies it; blind pairs `(3*4/2)` vs `3*)2(/4` and `((7*8)/(2*4))` vs `7)(*)8)(2/(*4` — a response difference proves evaluation without running any command. Polyglot `${{<%[%'"}}%\.`.
MIN TEST: the arithmetic pairs above; keep true/false payloads minimally different to exclude WAF/proxy noise; baseline comparison over status, length, word/line counts, headers, cookies, redirects, final URL, Content-Type, Server, stable within 5%, discard first request.
Per-language error sinks: Python `getattr("", OUTPUT)` / `{% include OUTPUT %}`; PHP `call_user_func(OUTPUT)`; SpEL `Integer.valueOf(OUTPUT)`; OGNL `OUTPUT/0`; Freemarker `?new()`; Ruby `File.read(OUTPUT)`; Node `require(OUTPUT)`; Elixir `[1,2][OUTPUT]`. Prefix output with `Y:/A:/` so it can never accidentally resolve and suppress the error.
IMPACT: output recovery on previously blind sinks — expr-eval (CVE-2025-13204), JSONPath Plus (CVE-2025-1302), Twig sandbox CVE-2022-23614, Dust.JS. Toolkit: SSTImap ≥1.3.0.
DIFFERENTIAL: no — single-component, but needs a deliberately constructed oracle.

16. ORM Leaking: More Than You Joined For (#2 of 2025)
https://www.elttam.com/blog/leaking-more-than-you-joined-for/ · 2025-12-18 · Alex Brown (elttam)
Technique: user-controlled filter field/operator reaches the ORM → boolean/error/timing oracle over fields that are never meant to be searchable (password, salt, token). Class: mass data extraction via search/filter.
SIGNAL: filter params naming field AND operator (`q=email=~elttam.com`), keys containing `__` (Django/Beego relational traversal `created_by__user__username__contains`), list/search endpoints accepting arbitrary field names, OData `/$metadata` + `$filter`/`$expand`, endpoints accepting a nested object where a string is expected (`resetToken[not]=E` via `express.urlencoded({extended:true})`, `j:`-prefixed JSON cookies).
MIN TEST: filter on a harmless field → add unexpected field/operator or send object-for-string → observe change in result count/length/error/timing. Collation matters (MySQL/MariaDB/SQLite/MSSQL case-insensitive by default).
IMPACT: Harbor password hashes + salts (CVE-2025-30086, two patch bypasses: `email__password__startswith`, then `=~` fuzzy syntax appending `__icontains`); Prisma reset-token bypass → ATO; Directus CVE-2025-64748; EF dynamic-LINQ and OData full token leak. Tools: `plormber` (timing), elttam semgrep-rules.
DIFFERENTIAL: exploitation is oracle/differential; discovery hybrid (Sourcegraph regex found the Harbor sink, Beego `parseExprs` source gave the bypasses).

17. SQL Injection Isn't Dead: Smuggling Queries at the Protocol Level (#2 of 2024)
https://media.defcon.org/DEF%20CON%2032/DEF%20CON%2032%20presentations/DEF%20CON%2032%20-%20Paul%20Gerste%20-%20SQL%20Injection%20Isn%27t%20Dead%20Smuggling%20Queries%20at%20the%20Protocol%20Level.pdf · DEF CON 32, 2024-08-10 · Paul Gerste (Sonar)
Technique: DB wire protocols are TLV; integer truncation of a size field lets a whole statement be smuggled past prepared statements. Class: protocol-level SQLi.
SIGNAL: driver/version — pgx v5.5.3 (CVE-2024-27304), sqlx (RUSTSEC-2024-0363); MongoDB discussed too; app paths accepting very large parameter values.
MIN TEST: dependency/version fingerprint + local reproduction (PoC github.com/roaris/CVE-2024-27304-PoC). Live exploitation needs multiple ~2GB queries and knowledge of the surrounding query — practically hard, so treat as version-driven, not probe-driven.
IMPACT: arbitrary statement injection, bypassing parameterization.
DIFFERENTIAL: yes conceptually (desync applied to binary protocols — explicitly cites Kettle).

=== E. CLIENT-SIDE / BROWSER-TRUST CLASSES ===

18. Exploring the DOMPurify library: Bypasses and Fixes
https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes · 2024-11-17 · Mizu (@kevin_mizu)
Technique: mXSS via node flattening at >512 depth, namespace/integration-point confusion (svg/math `<style>`, `mi`, `mtext`, `desc`, `foreignObject`), nested `<caption>` stack popping, `<button>`/`<image>` "elevator", second-order DOM clobbering of `__depth`, triple-parsing. Class: sanitizer bypass → XSS.
SIGNAL: DOMPurify ≤3.1.2 (default config suffices, SVG/MathML allowed by default); output re-parsed after sanitize (`innerHTML` re-assignment, double `sanitize()` as in older Mermaid, server-side pre-parse); Chromium/Safari victim (most variants not Firefox).
MIN TEST: fingerprint version, then in an isolated copy check whether sanitized output changes structurally after one extra `DOMParser` round-trip with a harmless marker; PoCs use `alert(1)` only.
IMPACT: full XSS in default config, surviving sanitize-twice patterns. Post-3.1.3 security rests "heavily on a single regular expression".
DIFFERENTIAL: same parser disagreeing with itself across serialize/re-parse; cross-library depth limits (libxml2 255) matter when content is pre-parsed server-side.

19. DoubleClickjacking
https://evil.blog/2024/12/doubleclickjacking-what.html (redirect from paulosyibelo.com) · 2024-12 · Paulos Yibelo
Technique: `window.open` decoy; `window.opener.location` navigates the parent tab to a sensitive page; decoy closes on `mousedown` so the second click lands on the real button. Class: UI redress, no framing.
SIGNAL: sensitive action reachable by top-level navigation with attacker-chosen params (OAuth authorize, account settings); single-click confirm with a predictable button position; buttons live immediately on load (no gesture gating).
MIN TEST: own account + own OAuth client; set target URL + button top/left/width/height; double-click and see whether the action fires. Fix validation: buttons must stay disabled until mousemove/Tab.
IMPACT: ATO demoed on Salesforce and Slack; claimed on "almost every site that supports OAuth", crypto wallets, extensions.
BYPASSES: X-Frame-Options, CSP frame-ancestors, SameSite Lax/Strict — all irrelevant because the target loads top-level in the victim's session.
DIFFERENTIAL: no — browser-behaviour primitive.

20. Exploiting Client-Side Path Traversal (CSPT2CSRF)
https://blog.doyensec.com/2024/07/02/cspt2csrf.html · 2024-07-02 · Maxence Schmitt (Doyensec). Whitepaper: https://www.doyensec.com/resources/Doyensec_CSPT2CSRF_Whitepaper.pdf · follow-ups: https://blog.doyensec.com/2025/01/09/cspt-file-upload.html (2025-01-09, upload-restriction bypass: `%PDF` header within first 1024 bytes still parses as JSON for mmmagic; WebP/JSON polyglots) · https://blog.doyensec.com/2025/03/27/cspt-resources.html (2025-03-27)
Technique: front-end puts user input into an API request PATH; `../` reroutes the app's own authenticated request → CSRF that survives SameSite. Class: client-side path traversal.
SIGNAL: user-controlled value (fragment, query, path param, stored data) appearing as a path SEGMENT in front-end API URLs; sinks keep original method/headers/body — describe every finding as a source–sink pair; GET sink + file upload/download gadget hosting crafted JSON = chain into a state-changing POST.
MIN TEST: insert traversal into a candidate source, watch in proxy whether the outgoing API path changes (Burp extension github.com/doyensec/CSPTBurpExtension, Bambda filter, semgrep rules, Eval Villain).
IMPACT: Mattermost, Rocket.Chat and others; JSONP→XSS and CSPT→XSS variants collected in the resources post.
DIFFERENTIAL: no, but it is a source→sink dataflow view of the client bundle — not a payload checklist.

21. Hijacking OAuth flows via Cookie Tossing
https://labs.snyk.io/resources/hijacking-oauth-flows-via-cookie-tossing/ · 2024-11-26 · Elliot Ward (Snyk Labs; builds on Thomas Houhou)
Technique: subdomain sets `Domain=.target` session cookie scoped to a narrow Path (`/api/authorize`, `/auth/<idp>/callback`) → path precedence makes those endpoints run under the ATTACKER's session while everything else looks normal → victim's OAuth link lands on attacker's account. Class: cookie scope/precedence abuse → ATO.
SIGNAL: subdomains hosting user content or any subdomain XSS (self-XSS is enough); cookie-based session WITHOUT `__Host-` prefix; state-changing JSON endpoints relying on CORS preflight with no CSRF token; multi-step connect/payment flows. SameSite is irrelevant (subdomain is same-site).
MIN TEST: two own accounts + own subdomain; set parent-domain cookie with narrow Path; verify that endpoint acts under the planted session while other pages keep the real one.
IMPACT: Gitpod CVE-2024-21583 — victim's Bitbucket/GitHub linked to attacker's account → repo access, source edit, commits.
DIFFERENTIAL: multi-component chain (6–7 preconditions), not a parser diff.

22. OAuth Non-Happy Path to ATO
https://blog.voorivex.team/oauth-non-happy-path-to-ato · 2024-11-22 · Omid Rezaei (Voorivex)
Technique: force the callback's error branch (`response_type=id_token`) → app redirects to whatever `Referer` holds; 3xx chains preserve URL fragment and the original `window.open` opener as Referer → token/code leaks to attacker origin. `response_type=code,id_token` (Google accepts comma-separated) returns the usable code too; `prompt=none` removes the account picker so no interaction breaks the chain. Class: OAuth flow abuse.
SIGNAL: callback error handling that redirects based on Referer; behaviour change when callback params are stripped; token appearing in fragment after changing `response_type`; providers accepting multi-value `response_type` / `prompt=none`; no interactive final step.
MIN TEST: own account — strip/alter callback params and record redirect target; swap `response_type`; open flow via `window.open` from own page and read the Referer the callback sees.
IMPACT: full ATO via stolen `code`+`state`; ~$3,000 (CVSS reduced to ~7.7 because not all users link Google).
DIFFERENTIAL: yes, multi-component — provider + app fallback + browser fragment/Referer semantics.

23. XS-leaks pair (2025 top-10): XSS-Leak: Leaking Cross-Origin Redirects — Salvatore Abello, https://blog.babelo.xyz/posts/cross-site-subdomain-leak/ (#8): Chrome connection-pool prioritisation as an oracle to leak redirect hostnames cross-domain. Cross-Site ETag Length Leak — Takeshi Kaneko, https://blog.arkark.dev/2025/12/26/etag-length-leak (#6, 2025-12-26): chains edge cases to leak cross-origin response SIZE; panel rated it more versatile and harder to patch than the redirect leak. SIGNAL for both: cross-origin responses whose size/host differs by auth state. Low direct bounty value, high value as oracles.

=== F. FRAMEWORK-SOURCE-DERIVED, MASS-APPLICABLE (best agent fit) ===

24. Next.js, cache, and chains: the stale elixir (#7 of 2025)
https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir · 2025-01 · Rachid Allam (zhero)
Technique: external `x-now-route-matches` makes Next.js treat an SSR response as SSG → framework's OWN cache stores it (no CDN needed) with `s-maxage=1, stale-while-revalidate`; combine with a data request (`__nextDataReq`, `/_next/data/{buildID}/page.json`, `x-nextjs-data`) → JSON cached under the HTML URL. CVE-2024-46982 (+ CVE-2025-32421 race bypass). Class: internal cache poisoning.
SIGNAL: Next.js 13.5.1–14.2.9, pages router, non-dynamic SSR routes, NOT on Vercel; buildId visible in `__NEXT_DATA__`; the tell: Cache-Control flips from `private, no-cache, no-store, max-age=0, must-revalidate` to `s-maxage=1, stale-while-revalidate` when the header is added.
MIN TEST: unimportant endpoint only — cache busters barely work because the poisoned cache is internal; for the external-cache variant drop `Accept-Encoding` if it is in the cache key (browsers always send it, so real users are unaffected). Get program permission.
IMPACT: DoS (SSR page replaced by JSON), stored XSS from any reflected request value (UA, locale, cookie, Host), cache deception of victim PII. High/Critical, six figures across fintech/crypto/e-commerce.
DIFFERENTIAL: source-derived (conditionals in `server/base-server.ts`), not a two-component diff.

25. Next.js and the corrupt middleware (CVE-2025-29927)
https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware · 2025-03 · Rachid Allam (zhero) + Yasser Allam (inzo_)
Technique: `x-middleware-subrequest` recursion guard, sent externally, skips middleware entirely. Payload by version: `pages/_middleware` (<12.2); `middleware` / `src/middleware` (12.2+); name repeated ≥5× colon-separated (13.2+). All versions from 11.1.4 to the patches (15.2.3 / 14.2.25 / 13.5.9 / 12.3.5). Class: authorization bypass, CVSS 9.1.
SIGNAL: self-hosted Next.js (Vercel/Netlify protected); middleware-gated path with `x-middleware-rewrite` / `-next` / `-redirect` response header or a Location containing `unauthorized`, status ≠ 200; CSP/cookies set by middleware.
MIN TEST: request the gated path with and without the header, compare — redirect/rewrite disappears, CSP header vanishes. Avoid CDN-fronted paths (a 404 can get cached — CPDoS).
IMPACT: authz bypass (15.1.7), CSP bypass (15.0.3), cache-poisoning DoS.
DIFFERENTIAL: discovery needed framework source (`next-server.ts`, `sandbox/context.ts`); exploitation needs none — header value is guessable.

26. ProjectDiscovery: CVE-2025-29927 technical analysis + nuclei detection
https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass · 2025-03-23 · Prince Chaddha
Methodology (the reusable part): 3-request flow — (1) fingerprint `_next/static` in body or "Next.js" in headers, regex-extract internal `href` paths from the page; (2) baseline: keep only paths showing middleware involvement (`x-middleware-rewrite`/`-next`/`-redirect`, Location contains `unauthorized`) AND status ≠ 200; (3) exploit: resend with both 5× payloads, require transition blocked→200. Explicitly: version detection is a HINT, active before/after verification is PROOF; template shipped ~24h after disclosure. Caveat noted: status-200-only is a weak signal; body/length comparison would be stronger.

27. High-fidelity detection for RSC/Next.js RCE (CVE-2025-55182, CVE-2025-66478)
https://www.slcyber.io/research/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478 · 2025-12-04 · Adam Kues (Searchlight/Assetnote)
Technique: pre-auth RCE in React Server Components, default config, no prerequisites. Many public PoCs misdiagnose it.
SIGNAL / MIN TEST (the model answer for safe confirmation): `POST /` with `Next-Action: x` + router/request-id headers, multipart field `"1"` = `{}` and field `"0"` = `["$1:a:a"]`. Vulnerable ⇒ HTTP 500 whose body contains `E{"digest"`. Mechanism: `getOutlinedModel` splits on `:` and walks `{}.a.a` → throws; patched versions require object + `hasOwnProperty`, so no 500. Caveat stated by the author: a digest error without THIS payload does not count; probe can over-flag outside the affected version range; WAFs often block the full RCE payload but not this probe.
IMPACT: pre-auth RCE; scanner github.com/assetnote/react2shell-scanner.
DIFFERENTIAL: no — a patch-behaviour oracle derived from source.

28. How an obscure PHP footgun led to RCE in Craft CMS (CVE-2024-56145)
https://www.assetnote.io/resources/research/how-an-obscure-php-footgun-led-to-rce-in-craft-cms · 2024-12 · Assetnote
Technique: `register_argc_argv=On` (PHP default, and on in Craft's official Docker image) makes PHP build argv FROM THE QUERY STRING (space-separated) → CLI argument injection → Twig template load via FTP wrapper → pre-auth RCE. Class: config footgun → RCE.
SIGNAL: Craft CMS, default PHP ini, query string treated as argv. CISA KEV 2025-06-02; nuclei template exists.
DIFFERENTIAL: no — one-shot version/config fingerprint.

29. SOAPwn: Pwning .NET Framework Apps Through HTTP Client Proxies And WSDL (#5 of 2025)
https://watchtowr.com/wp-content/uploads/SOAPwnwatchtowr_soappwn-research-whitepaper_10-12-2025.pdf · 2025-12-10 · Piotr Bazydło. Grows a Microsoft-wontfix `HttpWebClientProtocol` flaw into an RCE sink across multiple .NET products. Class: sink-centric framework research — "find one unfixed primitive, then enumerate its importers across products".

=== G. RECON/METHODOLOGY PIECES WITH CRITICAL OUTCOMES ===

30. Novel SSRF Technique Involving HTTP Redirect Loops (#3 of 2025)
https://slcyber.io/research-center/novel-ssrf-technique-involving-http-redirect-loops/ · 2025-06-23 · Shubham Shah (Searchlight Cyber)
Technique: blind SSRF made visible — own server returns an incrementing status (301+n up to 310) bouncing to itself, then a 302 to the real target; the app's own redirect-error path (fires above ~5 redirects, below libcurl's 30) dumps every collected response including the final 200 body. Class: SSRF escalation.
SIGNAL: SSRF follows redirects; error text CHANGES with redirect count (JSON parse error at low counts, `NetworkException` past the max); full response leaks for some status codes (500) but not 200.
MIN TEST: own Flask redirect-loop server ending at a harmless page; if the chain + final body appear, it is susceptible. Only then aim at internal endpoints, with authorization.
IMPACT: AWS metadata credentials retrieved; author reports reuse "in several situations".
DIFFERENTIAL: yes — gap between libcurl's redirect handling and the app's own lower limit; found black-box before the binary finished loading in Ghidra.

31. Listen to the whispers: web timing attacks that actually work
https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work · 2024-08-07 (upd 2024-11-18) · James Kettle
Technique: single-packet attack + dual-packet sync (TCP_NODELAY off, send all but last byte/frame, ~100ms wait, sacrificial PING) → compare RESPONSE ORDER, not absolute time. Class: timing oracle for otherwise blind bugs.
SIGNAL: which of a pair returns first; DNS cache warming; 64-octet DNS label makes resolution be skipped (faster); exceptions short-circuit slow paths ("timing attacks are exceptionally good at detecting exceptions"); keyed vs unkeyed param 310ms vs 22ms; WAF delay stacking on repeated params. Smallest exploited gap 200μs (was 30,000μs).
MIN TEST (probe pairs): `'` vs `''`; `%23` vs `%21` (server-side param pollution); invalid vs valid JSON escape; random header vs `True-Client-IP: <own domain>`; duplicate Host; `aaa{62}` vs `aaa{63}` label. 30 measurements per input, compare bottom quartiles; report at ≥80% consistent ordering over up to 50 pairs. Tools: Param Miner scans "Detect/Exploit scoped SSRF", "Guess headers", Turbo Intruder, h2spacex, nowafpls.
IMPACT (30,000-site bed): 375 IP-spoofing-vulnerable domains; blind SQLi; blind JSON injection; hundreds of reverse proxies exposing tens of thousands of internal routes; firewall bypass to internal SonarQube; staging + US government admin console; 403→access.
DIFFERENTIAL: yes on both axes — every probe is control-vs-test, and the findings live between components (front-end/back-end, WAF, DNS, cache, logging). Kettle's caution: timing proves "something" happened, not WHAT — pair it with "bug doppelgangers" (a non-blind version of the same class).

32. Hacking Subaru: STARLINK admin panel
https://samcurry.net/hacking-subaru · 2025-01-23 (found 2024-11-20) · Sam Curry + Shubham Shah
Method, step by step (fully repeatable): consumer app authorization was solid → pivot to EMPLOYEE/admin tooling; `my.subaru.com` CNAME → `mys.prod.subarucs.com` (new apex) → subdomain enum → `portal.prod.subarucs.com`; login page loads `/assets/_js/` → ffuf → `login.js` → endpoint `/forgotPassword/resetPassword.json` takes email+new password, NO token; `/adminProfile/getSecurityQuestion.json` = account-existence oracle; employee names from LinkedIn + `<initial><lastname>@subaru.com`; 4th guess valid; custom 2FA was a UI modal only — delete the line, backend still serves.
SIGNAL set: unfamiliar apex revealed by CNAME chains; brute-forceable JS directories; reset endpoint with no token param; valid/invalid email response delta; MFA enforced only client-side.
IMPACT: unrestricted access to all vehicles + customer accounts in US/CA/JP; PII, vehicle PIN, ~1 year of location history (~1,600 points); added self as authorized user and unlocked a consenting friend's car. Fixed in ~24h.
DIFFERENTIAL: no — pure trust-boundary/recon work. Author's own takeaway: the techniques are not new; employee/dealer systems have broad default access.

Also from the 2025 list, lower hunter value but worth knowing: World Poker Tour back-office takeover (Curry+Shah, https://samcurry.net/, 2025-10-12); Hacking Millions of Modems (Curry, 2024-06-03, started from blind XXE); Searchlight's AEM pre-auth chain (https://slcyber.io/research-center/finding-critical-bugs-in-adobe-experience-manager/, 2025-10-14, Kues+Pindur) and Oracle Identity Manager pre-auth RCE (CVE-2025-61757).

NOT FOUND, to avoid a false claim: no new 2024–2026 Frans Rosén / Detectify Labs technique publication surfaced — his Dirty Dancing (2022) is cited as the ancestor of #22 but he published no new piece in this window as far as these searches show. Orange Tsai 2025/2026 publications beyond WorstFit were not located in this pass. PAN-OS CVE-2025-0108 post URL unresolved (index page only).

================ SYNTHESIS ================

(1) METHODOLOGICAL PATTERNS BEHIND HIGH-IMPACT RESEARCH

P1. Two components, one string, two meanings. Dominant pattern — it produced every Critical in the corpus: CL/TE/0/H2 length views (#1,#3), mod_rewrite URL-view vs filesystem (#5), CDN vs origin path decoding (#6,#7), browser RFC6265 vs server RFC2109 cookies (#9), app validator vs MTA (#10), Unicode vs Best-Fit ANSI (#11), pre- vs post-normalization filenames (#12), libcurl's redirect limit vs the app's own (#30). Operational form: identify two parsers on the path, then find a byte sequence they disagree about. Kettle's own framing: HTTP/1.1's root flaw is weak message boundaries (#1); Orange's: the server "cannot distinguish its semantics" (#5).

P2. The oracle is the research product, not the payload. Winning pieces invent a way to SEE: request contamination on a separate connection (#2), response ORDER instead of time (#31), status-incrementing redirect loop (#30), error message carrying command output (#15), boolean error instead of sleep (#15), result-count/length/timing per filter field (#16), connection-pool priority (#23), ETag length (#23), `E{"digest"` 500 (#27), "No input file specified" file-existence oracle (#11), security-question endpoint as account-existence oracle (#32). Rule: if nothing is visible, build the oracle first; do not mark the vector dead.

P3. Detection separated from exploitation, deliberately. #1 scans for discrepancies rather than firing fragile multi-step exploits (WAFs now block classic probes). #27 ships a probe that errors on vulnerable and stays silent on patched, carrying no RCE payload (and passes WAFs that block the real one). #26: version detection is a hint, before/after transition is proof. This is also what makes it safe and reportable.

P4. Fingerprint → one-shot differential test → mass apply. #3 (bbscope → cleaned scope → subdomain enum → one OPTIONS payload across everything), #31 (30,000 sites), #2 (30,000 sites, <1 req/s per domain, deterministic judge, zero FPs), #26/#27 (template/scanner in ~24h–days after disclosure). High-impact research is a cheap test multiplied by surface, not a deep manual dig on one host.

P5. Read the framework's source, attack everybody who runs it. #24,#25 (Next.js internals → six figures across programs), #16 (Beego `parseExprs` gave two patch bypasses), #29 (one wontfix .NET primitive → importers across products), #28 (one PHP ini default). The bug is in the dependency; the hunt is "who deploys it, in which version, self-hosted".

P6. Non-happy paths and internal-only mechanisms. Error branches (#22), recursion guards exposed externally (#25,#24 `x-now-route-matches`), front-end-stripped internal headers leaking back (#1 `X-Nf-*`), legacy modes still reachable (#9 `$Version`, #10 UUCP/percent hack, #5 1996 handler code). Anything labelled "internal", "legacy" or "error path" is under-tested by definition.

P7. Chain small, individually unreportable facts. #21 (7 preconditions), #22 (response_type + fragment-over-3xx + opener Referer + prompt=none), #9 (WAF-bypass XSS + Tomcat reflector + CORS), #6 "Cache-What-Where" (self-XSS or X-Forwarded-Host redirect becomes critical once the cache key is controllable), #20 (GET CSPT + upload gadget → state-changing POST). Corollary: a self-XSS, an open redirect on a subdomain, a reflected cookie — each is a component, not a Low to be closed.

P8. Pivot off the consumer surface. #32: customer app authorization solid ⇒ go to employee/admin/dealer systems reached via CNAME chains and JS-directory fuzzing; client-side-only MFA; token-less reset. Still the fastest path to Critical with zero novel technique.

(2) WHAT TO TURN INTO REPEATABLE AGENT STEPS (signal → test → proof)

Each one below is deterministic, non-destructive, and ends in a comparison that can be stored as a result artifact.

S1. Two-parser census per host. Record, from banners and behaviour, the chain (CDN/WAF/front-end/app server/framework/language/OS). Trigger: ≥2 distinct parsers present ⇒ queue S2/S3/S4. Signals already in the corpus: `Via: 1.1 google` (#3), `awselb/2.0` vs `Microsoft-HTTPAPI/2.0` divergence under masked headers (#1), `Cf-Cache-Status` (#7), `Server: Apache <2.4.60` (#5), `__NEXT_DATA__` buildId (#24).

S2. Header-masking differential (desync pre-check, no smuggling). For each of {`Host`, ` Host`, `Host `, `Xost`, `Host :`}: compare status+length+body-hash+Server. Any divergence from both the normal and the absent case ⇒ V-H/H-V candidate ⇒ hand to HTTP Request Smuggler/Terminator-style scanning, never a hand-rolled exploit (#1,#2). Also: `Expect: 100-continue` and `Expect: y 100-continue` → look for a second header block, hidden banners, 504-on-HEAD (#1).

S3. Delimiter + normalization map, cache-busted. Baseline non-cacheable R0; `/<path><X><rand>` for all ASCII raw and `%`-encoded; `X` where response == R0 ⇒ origin delimiter. Then `/a/../home?buster` vs `/home?buster` and `/home/..%2fX` ⇒ who normalizes. Then WCD attempt only on own session with a unique cache buster (#6,#7). Proof artifact: the delimiter table + a HIT on an own-session URL.

S4. Cache-key probe before anything reflectable. Keyed vs unkeyed param timing (310ms vs 22ms, #31); `Accept-Encoding` presence (#24). Required precondition before sending any reflectable value at a cacheable response.

S5. Framework-version → patch-behaviour oracle, not version alone. Maintain the pattern: baseline (prove the guard is active) → probe (one header/body variant) → require a TRANSITION. Instances to ship: `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` on a path that currently rewrites/redirects, require blocked→200 plus body/length change (#25,#26); `x-now-route-matches` on a non-dynamic SSR route, require Cache-Control flip to `s-maxage=1, stale-while-revalidate` (#24); RSC probe `["$1:a:a"]` + `{}` with `Next-Action: x`, require 500 + `E{"digest"` (#27).

S6. Blind-injection oracle ladder, before declaring "no injection". Order: polyglot `${{<%[%'"}}%\.` → `(1/0).zxy.zxy` → arithmetic pairs `(3*4/2)` vs `3*)2(/4` and `((7*8)/(2*4))` vs `7)(*)8)(2/(*4` → language-specific error sink with `Y:/A:/` prefix → boolean error `1/(cond)` (#15). Baseline comparison fields and the 5% stability rule come straight from the research and map onto an existing per-field response-diff capability. Same ladder shape for #16: harmless filter → unexpected field → operator → object-for-string, oracle = count/length/error/timing.

S7. Timing pair as a standing fallback. Single-packet pairs: `'`/`''`, `%23`/`%21`, bad/good JSON escape, `True-Client-IP: <own-domain>` vs random header, duplicate Host, `aaa{62}`/`aaa{63}` (#31). 30 samples, bottom-quartile compare, ≥80% ordering consistency to report. Converts "no visible reaction" into a ranked lead instead of a dead vector.

S8. Scoped-SSRF escalation kit. Own-infrastructure redirect-loop responder with incrementing statuses 301→310 then 302 to a harmless page; record whether the app prints the chain and the final body; only then, with authorization, aim internal (#30). Also HTTP/2 CONNECT probe (status 200 vs RST_STREAM) where a proxy is in scope (#4).

S9. Client-bundle source→sink pass as a first-class step. Enumerate user-controlled values reaching API request PATH segments (CSPT sources: fragment, query, path, stored) and record each as source–sink pair with its method/header/body constraints; check for an upload/download JSON gadget to chain GET→POST (#20). Cookie layer: inventory session cookies lacking `__Host-`, list subdomains hosting user content, test path-precedence planting with own accounts (#21).

S10. Email/identity parser probe on every registration/verification flow. One encoded-word address at own OOB domain; read the envelope; also punycode and `!`/`%` route forms (#10). Fingerprints a whole access-control class in one request.

S11. Employee-surface pivot, automated. CNAME-chain expansion of every in-scope apex → subdomain enum on NEW apexes → fetch login JS → ffuf the JS directory → extract endpoints → flag reset endpoints without a token param, existence oracles, and MFA enforced only in the UI (#32).

S12. Discipline rules borrowed from #2 (directly applicable to an agent toolkit): judging code must be deterministic and locked, not model opinion; every stage gets fresh context + a validation gate; make the oracle assumption-free (any change to a stable baseline) so unknown classes are caught; ask after each hit "how do I detect this elsewhere" and "what else does this cause" (the cascade) — that is exactly the chain step.

(3) WHAT A CHECKLIST-DRIVEN AGENT MISSES (each tied to a source)

M1. It tests one component at a time. Every item in section A/B/C is invisible to a per-endpoint payload list because the bug exists only in the DISAGREEMENT (#1,#5,#6,#9,#10,#11,#30). No payload library contains "compare `Host :` against `Host`".
M2. It accepts "no visible output" as negative. #15 exists because blind SSTI was being abandoned; #31 because blind SQLi/SSRF/param-pollution had no channel; #30 because the SSRF printed nothing. A checklist has payloads, not oracles.
M3. It reads status codes instead of transitions. #26 explicitly warns version-present ≠ exploitable and 200-only ≠ bypass; #27 insists a digest error without the exact payload does not count; #1 downgrades a redirect-followed PASS. Proof is baseline→probe delta plus a mechanism, not a code.
M4. It never looks at the error/legacy/internal path. `$Version` (#9), `Expect` obfuscation (#1), recursion-guard headers (#24,#25), OAuth error branch (#22), 1996 handler fallback (#5), RFC2047 encoded-word (#10).
M5. It closes Lows that are chain components. Self-XSS (#21), subdomain XSS (#21), open redirect / X-Forwarded-Host (#6 Cache-What-Where), reflected cookie on analytics (#9), GET-only CSPT (#20), framable page (#19 needs no framing at all). A checklist has no notion of "capability that another finding consumes".
M6. It assumes the defence it can see is the defence that applies. SameSite is void from a subdomain (#21) and in top-level navigation (#19); HttpOnly is void against a legacy cookie parser (#9); CSP frame-ancestors/XFO are void without framing (#19); prepared statements are void at the protocol level (#17); sanitize-twice is worse, not better (#18); WAFs block the exploit but not the detector (#1,#27).
M7. It attacks the app, not the dependency. #24,#25,#27,#28,#29 are all "read the framework, then enumerate deployments". A per-target checklist has no step that says "fingerprint exact version, read that version's source, derive a patch-behaviour probe".
M8. It stops at the consumer surface. #32: the customer API was properly authorized; the Critical was two CNAMEs and one JS file away on an employee portal.
M9. It mistakes a random body difference for a finding, and a stable status for safety. #15's 5%-stability baseline over status/length/words/lines/headers/cookies/redirect/final-URL/Content-Type/Server and #2's deterministic locked judge are the counter-measures; #31 warns timing proves "something", not what — pair with a non-blind doppelganger of the same class.
M10. It does not build infrastructure. Several Criticals required the hunter to STAND UP A SERVER whose behaviour is the test: incrementing-redirect responder (#30), encoded-word/Collaborator SMTP receive (#10), decoy double-click page (#19), subdomain cookie-planting page (#21), own OAuth client (#19,#22), UNC/SMB listener (#12, policy permitting). An agent with only a request tool cannot reach those classes.

Sources (all read this session):
https://portswigger.net/research/top-10-web-hacking-techniques-of-2024 · https://portswigger.net/research/top-10-web-hacking-techniques-of-2025 · https://portswigger.net/research/http1-must-die · https://portswigger.net/research/can-ai-do-novel-security-research · https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work · https://portswigger.net/research/gotta-cache-em-all · https://portswigger.net/research/splitting-the-email-atom · https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique · https://blog.orange.tw/posts/2024-08-confusion-attacks-en/ · https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/ · https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/ · https://blog.flomb.net/posts/http2connect/ · https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html · https://www.elttam.com/blog/leaking-more-than-you-joined-for/ · https://github.com/vladko312/Research_Successful_Errors · https://slcyber.io/research-center/novel-ssrf-technique-involving-http-redirect-loops/ · https://www.slcyber.io/research/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478 · https://slcyber.io/research-center/abusing-windows-net-quirks-and-unicode-normalization-to-exploit-dnn-dotnetnuke/ · https://slcyber.io/assetnote-security-research-center/ · https://www.assetnote.io/resources/research/how-an-obscure-php-footgun-led-to-rce-in-craft-cms · https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir · https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware · https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass · https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes · https://evil.blog/2024/12/doubleclickjacking-what.html · https://blog.voorivex.team/oauth-non-happy-path-to-ato · https://labs.snyk.io/resources/hijacking-oauth-flows-via-cookie-tossing/ · https://blog.doyensec.com/2024/07/02/cspt2csrf.html · https://blog.doyensec.com/2025/01/09/cspt-file-upload.html · https://blog.doyensec.com/2025/03/27/cspt-resources.html · https://samcurry.net/hacking-subaru · https://media.defcon.org/DEF%20CON%2032/DEF%20CON%2032%20presentations/DEF%20CON%2032%20-%20Paul%20Gerste%20-%20SQL%20Injection%20Isn%27t%20Dead%20Smuggling%20Queries%20at%20the%20Protocol%20Level.pdf · https://blog.babelo.xyz/posts/cross-site-subdomain-leak/ · https://blog.arkark.dev/2025/12/26/etag-length-leak · https://watchtowr.com/wp-content/uploads/SOAPwnwatchtowr_soappwn-research-whitepaper_10-12-2025.pdf · https://www.youtube.com/watch?v=ETB2w-f3pM4 · https://www.youtube.com/watch?v=Dq_KVLXzxH8