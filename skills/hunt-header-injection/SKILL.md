---
name: hunt-header-injection
description: "TRIGGER — a response header's value visibly moves with request input (query/body/cookie echoed into `Set-Cookie`/`Location`/`Content-Type`/`Content-Disposition`/`Link`/custom `X-*`), or a request header (Referer, X-Forwarded-*) is re-emitted into a response/log/email. Covers CRLF response splitting, Host/X-Forwarded-Host confusion, cookie/Set-Cookie manipulation, forwarding-header spoofing, and content-type/encoding confusion as one unified normalization-failure class. SKIP — hunt-host-header once the specific chain is Host-header→SSRF/password-reset/OAuth (deeper on that one path); hunt-cache-poison once impact is specifically a poisoned CDN cache rather than the header-injection entry point; hunt-http-smuggling for the CL/TE request-framing-desync primitive specifically; hunt-csrf/hunt-cors for header-adjacent bugs with no injection component."
sources: "ported from usestrix/strix (Apache-2.0), strix/skills/vulnerabilities/header_injection.md — adapted for Claude-BugHunter"
report_count: 0
---

# HUNT-HEADER-INJECTION — HTTP Header Injection

Header injection turns user input into protocol-level control: response
splitting, cache poisoning, session fixation, authentication bypass, and
request smuggling all trace back to a server-controlled header value that
wasn't normalized. The bug usually lives in a middle layer — a framework that
copies a request value into a response header, a proxy that trusts a
forwarded header, a cache keyed on something the attacker influences. Treat
any user-controlled value that reaches a header as exploitation-equivalent
until proven otherwise. This skill is the unified entry point; once a specific
chain is confirmed (Host→SSRF, CL/TE smuggling, CDN cache poisoning), the
dedicated skill for that chain takes over the deep-dive.

## Attack Surface

**Input shapes that reach headers**
- Query/body/path values echoed into `Set-Cookie`, `Location`, `Content-Type`,
  `Content-Disposition`, `Link`, custom `X-*`
- Request headers re-emitted into responses (Referer, User-Agent,
  X-Forwarded-*, custom correlation IDs)
- Webhook/callback flows where the server builds an outbound request from a
  user-supplied URL (Host, Referer)
- Outbound email headers (To/From/Subject) populated from user input

**Code patterns that enable injection**
- Direct concatenation of user input into a header value without CR/LF stripping
- Frameworks that accept header values as raw strings and serialize verbatim
- Proxy chains trusting `X-Forwarded-*`/`Forwarded`/`X-Real-IP` set by an
  upstream anyone can spoof
- `X-HTTP-Method-Override` and similar method-shaping headers respected past
  the auth layer

**Transport/parser layers** — HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3 each parse
framing differently; CDN/reverse-proxy → application server is where the two
sides may disagree; chunked-encoding and multipart boundaries are their own
parser-confusion surface.

## High-Value Targets

- Password-reset / account-recovery flows (Host header determines the link sent)
- OAuth/SSO redirect endpoints (`Location`, `redirect_uri` echoes)
- Auth gateways trusting `X-Forwarded-For`/`X-Real-IP` for IP allowlists or rate limits
- CDN/WAF caches (poisoning a public cache with a per-user response)
- Multi-tenant routing keyed on Host or `X-Tenant-Id`
- File-download endpoints (`Content-Disposition` filename from user input)
- Outbound notification/email systems where user input lands in a message header

## Reconnaissance

**Header inventory** — flip query/body/cookie values and diff `Set-Cookie`,
`Location`, `Content-Type`, `Content-Disposition`, `ETag`, `Vary`, custom
`X-*` in the response. For each varying header, identify the source field
(user-controlled vs. server-derived). Look for request headers reflected back
(Referer in error pages, User-Agent in a debug/correlation header,
X-Forwarded-Host echoed into a link).

**CR/LF and whitespace variants**
```
%0a               bare LF
%0d               bare CR
%0d%0a            CRLF
%250d%250a        double-encoded (WAFs that decode only once)
%c0%8d %c0%8a     overlong UTF-8 of CR/LF — invalid per spec, some parsers accept it
%e2%80%a8         U+2028 line separator — sometimes folded to LF downstream
%e2%80%a9         U+2029 paragraph separator
%09               tab — RFC 7230 allows tabs in field values; sneaks past \s+ filters
%00               null byte — truncates the header value in some parsers
```

**Parser/server fingerprinting** — `Server`, `Via`, `X-Powered-By`,
`X-AspNet-Version`, `X-Served-By`, `CF-Ray`, `X-Amzn-RequestId` reveal the
stack; `Vary`, `Age`, `X-Cache`, `CF-Cache-Status` reveal the caching layer and
key composition. Replay the same payload over HTTP/1.1 vs HTTP/2 vs chunked
and diff status/headers/body length. Send both `Host` and `X-Forwarded-Host`
with different values and observe which one wins in redirects/links/logs.

## Key Vulnerabilities

### CRLF Response Splitting and Smuggling

Inject `\r\n\r\n` to terminate the current response and prepend a second
attacker-controlled response; a cache or downstream proxy may key on the first
response and serve the second to other users.
```
GET /redirect?to=foo%0d%0aSet-Cookie:%20admin=1%0d%0a%0d%0a<html>poisoned</html> HTTP/1.1
```
Request smuggling is the same primitive at the request layer: inject a header
that makes the proxy and backend disagree on message framing — conflicting
`Content-Length`/`Transfer-Encoding`, or two `Content-Length` headers with
different values. The backend reads one request, the frontend a different
one; the leftover bytes become a smuggled request prepended to the next
victim's connection. Go deep on this specific primitive in `hunt-http-smuggling`.

### Cache Poisoning

- **Unkeyed input → keyed response** — input that influences the body but not
  the cache key (an `X-Forwarded-Host` echoed in a link, an unkeyed query
  param reflected in HTML)
- **`Vary` manipulation** — inject `Vary` to over-fragment (DoS-flavored) or
  under-fragment (cross-user serving) the cache
- **`X-Forwarded-Proto`/`X-Forwarded-Host` poisoning** — backend builds
  canonical URLs from these; CDN caches the response with attacker-controlled links
- **`Cache-Control` injection** — flip `private`↔`public`; inject
  `max-age=999999` for persistence, or `max-age=0`/`no-cache` to flush (`Age`
  is generated by the cache itself, not a control — don't bother with it)
- **Web cache deception** — trick the cache into storing an authenticated
  response at a public-looking URL by appending a cacheable extension
  (`/account/profile.css`)

Full chain-to-cache-poisoning deep-dive lives in `hunt-cache-poison`.

### Host Header Confusion

Backends often trust `Host` (or `X-Forwarded-Host`) when constructing absolute
URLs — password-reset emails, OAuth `redirect_uri`, canonical link tags. A
forged Host produces a reset link pointing at attacker infrastructure while
still carrying the victim's real reset token.
```
POST /password-reset HTTP/1.1
Host: attacker.tld
```
Also test: `Host` vs `X-Forwarded-Host` precedence, IPv6 bracketing (`Host:
[::1]:80`), trailing dot (`Host: example.com.`), port confusion (`Host:
example.com:@attacker.tld`). Full Host→SSRF/ATO chain deep-dive lives in
`hunt-host-header`.

### Cookie / Set-Cookie Manipulation

- Inject `Domain=.example.com` or `Path=/` to widen an attacker-set cookie's scope
- Inject `SameSite=None; Secure` to allow cross-site inclusion
- Inject `Max-Age=999999999` for persistence, or `Max-Age=-1` to nuke the
  victim's session
- Inject a cookie sharing a name with a real session cookie — precedence rules
  can let a same-domain attacker shadow it (cookie tossing)
- Reflected cookie XSS — if the cookie value is later rendered unescaped in
  HTML, the injection point is the header but the sink is the page

### Proxy and Forwarding Header Spoofing

The `X-Forwarded-*` family is informational — no protocol guarantee about who
set it. Any application trusting it past the boundary it controls is exploitable.
```
X-Forwarded-For: 127.0.0.1          # bypass IP allowlists / rate limits
X-Forwarded-Proto: https            # satisfy "HTTPS-only" checks over plain HTTP
X-Forwarded-Host: attacker.tld      # Host-confusion variants
X-Real-IP / Client-IP / True-Client-IP / CF-Connecting-IP / Forwarded (RFC 7239)
X-Original-URL / X-Rewrite-URL      # IIS/ASP.NET — server-side rewrite after auth check
```
Spray all header-name variants — different frameworks trust different ones.

### Content-Type / Encoding Confusion

- Inject `Content-Type: text/html` into an endpoint that returned JSON;
  browsers may sniff and render → XSS
- `charset=utf-7` in `Content-Type` for legacy UTF-7-encoded XSS
- `Content-Disposition: inline` to switch a download into in-page rendering
- `Content-Encoding: gzip` without actually compressing — decode-fail paths
  sometimes leak raw response bytes
- Absence of `X-Content-Type-Options: nosniff` is what *enables* the sniffing
  attacks above — a hardening control, not itself an attack surface; if it's
  set inconsistently across endpoints, target the ones missing it

### XSS via Response Headers

- `Location: javascript:alert(1)` / `Location: data:text/html,<script>...`
  when the redirect target is reflected unescaped (most modern browsers block
  navigation, but legacy clients and some Electron-style hosts don't)
- `Refresh: 0; url=javascript:alert(1)` — legacy `Refresh` header, JS-free
  meta-refresh equivalent
- Reflected request-header XSS — `Referer` echoed into an error page,
  `User-Agent` echoed into a debug header, combined with a CRLF injection
  into a body-injection sink

### Open Redirect via Headers

`Location` is the obvious one; also `Refresh: 0; url=https://attacker.tld`
(bypasses `Location`-only filters), `Link: <https://attacker.tld>;
rel="canonical"` (consumed by SEO tooling/some clients), and
`X-Accel-Redirect: /internal/file` (Nginx — if user input reaches this,
internal-only files become accessible). Full open-redirect deep-dive lives in
`hunt-open-redirect`.

### HTTP/2 Pseudo-Header and Frame Confusion

- HTTP/2 splits headers into pseudo-headers (`:method`, `:path`, `:authority`,
  `:scheme`) and regular fields; servers downgrading to HTTP/1.1 sometimes
  mishandle pseudo-header values, enabling smuggling across the H2→H1 boundary
- HTTP/2 lowercases header names; a case-sensitive upstream H1 filter may miss
  a lowercase variant the H2 backend then accepts
- HEADERS/CONTINUATION frame splitting — payload spans frames, intermediaries
  differ on whether they reassemble before applying filters

## Bypass Techniques

**Encoding** — URL-encode (`%0d%0a`) and double-encode (`%250d%250a`) for
WAFs that decode the wrong number of times; mix encodings within one payload
(`%0d%0A`, `%0D\n`, alternating case); Unicode line/paragraph separators
sometimes fold to LF.

**Header normalization edges** — leading/trailing whitespace and tabs in
header names/values; obs-fold continuation lines (RFC 7230, formally
obsolete, some parsers still accept); duplicate headers — spec says join with
`,`, but servers pick first/last/differ from the proxy in front of them.

**Method and method-override** — `X-HTTP-Method-Override`
(`X-Method-Override`, `X-HTTP-Method`) to reach a state-changing handler when
the framework consults the override before applying method-based
authorization. Effective from server-side/non-browser clients (curl,
internal tooling, server-to-server proxies) — from a browser the header is
non-safelisted and triggers a CORS preflight, so it isn't a standalone CSRF primitive.

**Header name games** — case mangling for exact-casing filters; null-byte
truncation in the header name (`X-Forwarded-For\x00Evil`) on parsers that stop at NUL.

## Testing Methodology

1. **Inventory varying headers** — enumerate every response header whose
   value moves with input
2. **Probe CR/LF normalization** — inject `%0d%0a` (and encoding variants)
   into each varying header source; observe whether the second line lands as
   a real header
3. **Test Host/X-Forwarded-Host** — submit a password-reset or any
   link-generating flow with an attacker-controlled Host; confirm the link in
   the response or follow-up email
4. **Probe forwarding headers** — spoof `X-Forwarded-For`, `X-Real-IP`,
   `True-Client-IP`, `CF-Connecting-IP` against IP-restricted endpoints
   (admin, rate-limited)
5. **Test cache key/response split** — find inputs that change the body but
   not the cache key; confirm a second request from a different session sees
   the poisoned response
6. **Test method override** — `X-HTTP-Method-Override` paired with
   state-changing endpoints reachable via POST or GET
7. **Test request smuggling pairs** — conflicting `Content-Length`/
   `Transfer-Encoding`, two `Content-Length` headers, malformed chunked
   encoding, against any frontend→backend pair
8. **Cross-protocol** — replay payloads over HTTP/1.1 and HTTP/2; diff behavior

## Validation

1. Show two distinct users/sessions receiving content keyed on an
   attacker-supplied header — proves cache poisoning
2. Capture a password-reset/OAuth link pointing at attacker-controlled host —
   proves Host injection
3. Demonstrate the same endpoint returning different auth decisions with and
   without a forged forwarding header
4. Response splitting: show a downstream cache/proxy serving the injected
   second response to an unrelated request
5. Request smuggling: show one victim request seeing data from a different
   request appended (not just timing or single-shot anomaly)
6. Every finding needs a durable artifact (cached response, sent email, log
   entry, session change) — a transient anomaly is not validation

## False Positives

- Header varies by input but is correctly keyed in the cache (intentional
  personalization, `Vary` set correctly)
- `X-Forwarded-*` reflected back but only used for logging — not a security
  boundary, may not be exploitable
- Browsers blocking `Location: javascript:`/`data:` — the protocol allows it
  but most modern browsers refuse to navigate
- CRLF appears in response headers but is stripped by an outer proxy before
  reaching any client or cache
- Smuggling indicators that turn out to be normal pipelining/keep-alive behavior

## Impact

Cross-user cache poisoning (defacement, XSS, ATO via cached auth response);
ATO via Host-confused password-reset/OAuth flows; auth bypass on endpoints
trusting forwarding headers; session fixation and cookie tossing; open
redirect for phishing/OAuth `redirect_uri` abuse; request smuggling — one
victim's request reads another victim's response, including auth
headers/cookies; WAF/detection bypass via header-name and encoding tricks.

## Pro Tips

1. Fastest win is usually Host/`X-Forwarded-Host` in a password-reset or
   OAuth flow — try it first, costs one request
2. For cache poisoning, find the *unkeyed* input first (influences body, not
   cache key); the rest follows
3. `X-HTTP-Method-Override` is high-yield against backends routing on it
   before method-based auth — most useful from server-side/non-browser callers
4. Smuggling lives at the boundary — identify the proxy→backend pair (CDN→
   origin, ingress→service) and target the framing disagreement
5. `X-Original-URL`/`X-Rewrite-URL` against IIS/ASP.NET admin endpoints is
   still a high-yield bypass
6. Before claiming a CRLF win, verify the second line landed as a **real**
   header in the cache or downstream consumer — many servers strip CRLF silently
7. Outbound email flows are a separate but related surface — user input
   flowing into SMTP headers (To, Cc, Subject, Reply-To) is its own injection
   class with the same root cause

## Related Skills & Chains

- **`hunt-host-header`** — Take the Host-confusion finding here further into
  the specific SSRF/password-reset/OAuth-poisoning chain.
- **`hunt-cache-poison`** — Take the unkeyed-input finding here further into a
  full CDN cache-poisoning PoC with a second, independent client confirming
  the poisoned response is served.
- **`hunt-http-smuggling`** — Take the CL/TE framing-disagreement finding here
  into a full request-smuggling PoC against the specific proxy→backend pair.
- **`hunt-open-redirect`** — Take the `Location`/`Refresh`/`Link` header
  redirect finding here further, especially when it lands on an OAuth
  `redirect_uri`.
- **`hunt-xss`** — Chain a header-reflected value that later renders unescaped
  in HTML (reflected cookie XSS, Content-Type sniffing) into a full XSS PoC there.
- **`triage-validation`** — CRLF appearing in a raw response but stripped
  before reaching any real consumer is not a finding; confirm the second line
  survives to an actual cache/client.
