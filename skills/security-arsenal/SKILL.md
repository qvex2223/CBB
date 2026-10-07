---
name: security-arsenal
description: "TRIGGER — need a specific payload/bypass string (XSS/SSRF/SQLi/XXE/NoSQLi/command-injection/SSTI/IDOR/path-traversal/smuggling/WebSocket/MFA), a gf pattern name, or a check against the always-rejected list before spending time on a lead. SKIP — the matching hunt-* skill for the surrounding methodology/detection context; this skill is payload/reference lookup only, not the hunting approach itself."
---

# SECURITY ARSENAL

Payloads, bypass tables, wordlists, and submission rules.

---


## Payload references — open the one you need

This skill is the index. Payload tables are long and class-specific, so they live beside
it; reading all five costs context that could hold probe results.

| File | Classes |
|---|---|
| `references/injection-payloads.md` | XSS · SQLi · NoSQLi · XXE · command injection · SSTI · path traversal |
| `references/auth-payloads.md` | IDOR · auth bypass · MFA/2FA bypass · SAML |
| `references/protocol-payloads.md` | SSRF · HTTP request smuggling · WebSocket |
| `references/submission-rules.md` | never-submit list · conditionally-valid-with-chain list |
| `references/wordlists-and-patterns.md` | wordlists on this box · `gf` pattern names |

**Read `references/submission-rules.md` before writing any report.** The never-submit list
is the cheapest way to avoid burning a validity ratio, and it is shorter than the reports
it prevents.

Payloads are not a methodology. Once a class is confirmed, load its `hunt-*` skill: that
is where the bypass ladder and the chain templates live, and it is the file that gets
maintained.

## Related Skills & Chains

- **`hunt-xss`** / **`hunt-ssrf`** / **`hunt-sqli`** / **`hunt-ssti`** / **`hunt-idor`** — When a hunter is actively testing a parameter and needs payloads. Workflow primitive: this skill is the payload library those hunt-* skills reach for; the hunt-* skill identifies the sink, this skill provides the syntax.
- **`triage-validation`** — When deciding if a finding is reportable at all. Workflow primitive: the "Always Rejected" and "Conditionally Valid — Requires Chain" tables in both skills must agree; `triage-validation` runs the 7-Question Gate, this skill provides the chain-required mapping used by Q7.
- **`web2-recon`** — When the URL set has been classified by `gf` patterns. Workflow primitive: `gf xss/ssrf/sqli` outputs from recon → look up the corresponding payload section here; `gf` pattern names index directly into this skill's payload sections.
- **`evidence-hygiene`** — When a payload produces output worth screenshotting. Workflow primitive: after a payload demonstrates impact (cookie theft, data exfil), hand off to `evidence-hygiene` for redaction before the screenshot becomes evidence.
- **`bb-methodology`** — When Phase 3 (Discovery) routes by input type. Workflow primitive: Phase 3's decision flow ("ID param → IDOR checklist", "URL input → SSRF checklist") names which section of this arsenal to load.

---

## Operator Notes (Claude-BugHunter)

> Engagement-derived + 2026-specific additions to the vendored foundation.
> Wisdom from real authorized engagements + Phase 2 verification across
> this repo's 31+ skill-area live tests. The upstream payload library
> covers the WHAT; this layer covers the WHEN-IT-WORKS-vs-WHEN-IT-DOESN'T.

### Payload freshness — what's gone stale by 2026

The classic CL.TE / TE.CL HTTP smuggling payloads no longer work against Nginx ≥ 1.21, Caddy 2.x, Envoy ≥ 1.20 (verified in Phase 2H). They DO still work against HAProxy ≤ 2.4, older F5 BIG-IP, Citrix ADC, AWS ALB-specific configs, and Apache Traffic Server. Fingerprint the front-end first — `curl -sI` → `Server:` header + `Via:` chain + TLS JA3 — before burning hours on payloads that the parser already rejects at the front door.

Same story for XXE classic — Python lxml ≥ 5.x silently drops SYSTEM entities by default (Phase 2G finding). The payloads remain valid against: Java SAX, PHP DOMDocument with LIBXML_NOENT, .NET XmlDocument with XmlResolver still wired, older lxml (< 5.0), Ruby Nokogiri with DTDLOAD, and a long tail of embedded XML processors (SOAP libraries, SAML implementations, Office document parsers). The payload library still ships these — the operator decision is whether the target's parser is in the still-vulnerable set.

Other stale-by-default-but-not-everywhere payloads as of 2026: `javascript:` URLs in `<a href>` (Chrome blocks unless explicit user gesture; works in embedded WebViews, Electron, older Edge); `data:text/html` for top-level navigation (modern browsers strip in nav contexts); CRLF injection in `Location:` (most reverse proxies normalize). Always test in the actual target environment, not in a generic browser.

### WAF evaluation order matters

When multiple bypass payloads exist for the same WAF, the order to try is:

1. **Encoding tricks** — case variation (`SeLeCt`), URL-encode once, URL-encode twice, Unicode escape (`<`), HTML-entity (`&#x3c;`), UTF-8 overlong sequences.
2. **Parser quirks** — XML namespace, JSON `\u` escapes mid-keyword, `Content-Type: application/json` vs `application/x-www-form-urlencoded` parser-confusion, multipart boundary tricks.
3. **Protocol-level** — HTTP/2 vs HTTP/1.1 (some WAFs only inspect one), Host header injection, `X-Original-URL`, `X-Forwarded-*` smuggling.
4. **WAF rule-specific bypasses** — Cloudflare, AWS WAF, Akamai, Imperva, F5 ASM each have known signature gaps; load the vendor-specific payload subsection.

Most engagements end at step 2 — modern WAFs trip on the parser-quirk class because the WAF and the origin app disagree on what's a "valid" request.

### OOB-Or-It-Didn't-Happen Gate applies everywhere

Every blind primitive (blind SQLi, blind XSS, blind SSRF, blind RCE, blind XXE) needs OOB confirmation. Without it, you can't tell the bug from a parser-error log. Phase 2D's hardened lab proved the gate kills FPs that look identical to real bugs at the surface — error messages with `you have an error in your SQL syntax` text in a 500 page can be parser logs from a different request entirely, hit a Burp Collaborator domain (or interactsh) and confirm callback before filing.

OOB callback infrastructure ranking by 2026: (1) Burp Collaborator (Pro license; cleanest), (2) interactsh-client (open source; comparable), (3) DNSLog.cn (free but logged by third party — never use for paid engagements), (4) self-hosted catch-all DNS + HTTP listener (most reliable for long-running engagements).

### Marker discipline

Generic words appear naturally in target content. A search for `javascript` hitting "JavaScript Tutorial" is not reflection — it's keyword overlap. Use unique random strings:

```
m=$(head -c 12 /dev/urandom | base64 | tr -d '+/=' | head -c 12)
# now m is like "K7gXq2pNRm1z" — search for THIS in the response
curl "https://target/search?q=${m}" | grep -c "$m"
```

If the marker appears in the response, you have reflection. If it appears unescaped in HTML context, you have XSS potential. If it appears in a Location header, redirect. If it appears in a SQL error, injection. The marker is the single source of truth — generic keywords lie.

### Statistical Sampling for noisy oracles

Single-trial timing differentials are noise. Require n≥10 interleaved trials, Welch's t-statistic > 3, or equivalent confidence-interval separation. Phase 2D verified this against a deliberately-noisy timing oracle: single trial showed 129ms delta (which would have been filed); n=10 showed mean 78ms vs 191ms with t=5.26 (real, well-supported).

Skeleton for timing-side-channel validation:

```python
import statistics
def welch_t(a, b):
    ma, mb = statistics.mean(a), statistics.mean(b)
    va, vb = statistics.variance(a), statistics.variance(b)
    return (ma - mb) / ((va/len(a) + vb/len(b)) ** 0.5)
# interleave control + test trials, n=10 each, t > 3 = signal
```

Same rule applies to blind boolean oracles where the diff is response-length or status-code under jitter — sample, don't assume.
