---
name: hunt-dispatch
description: "TRIGGER — internal use only: invoked right after `/hunt` receives a box answer (blackbox|greybox), to fingerprint the target and load the matching framework/stack skill set. SKIP — not for direct user invocation; if unsure what to test, use bb-methodology instead."
---

# hunt-dispatch

skill-set loader for `/hunt`. one concept (which skills to load), one place. web app pentest (WAPT) only.

invocation contract:

```
hunt-dispatch box=blackbox
hunt-dispatch box=greybox
```

## step 1 — fingerprint

fingerprint **every** live host, not just the apex. for multi-host / wildcard
targets the stack-skill routing must be driven by all banners, not one host's.

use `-L` (follow redirects) — CDN and framework signals routinely sit behind a
30x, so a no-redirect `curl -sI` silently misses those matches. pull both headers
and the landing-page HTML (`__NEXT_DATA__`, `VIEWSTATE`, `laravel_session`,
`Ignition`, framework markers live in the body, not headers).

```bash
HOSTS="$TARGET"
if [ -f "recon/$TARGET/live-hosts.txt" ]; then
  HOSTS=$(cat "recon/$TARGET/live-hosts.txt")
fi
for H in $HOSTS; do
  echo "=== $H ==="
  # -L follow redirects, -D - dump headers, -o body; cap body to keep context small
  curl -sSL -m 12 -D - -o /tmp/fp_body "https://$H" 2>/dev/null | tr -d '\r'
  # surface body-only stack markers
  grep -aoE '__NEXT_DATA__|/_next/|VIEWSTATE|rO0[AB]|laravel_session|Ignition|Telescope|Whitelabel|/actuator|application/grpc|socket\.io|swagger|\.js\.map' \
    /tmp/fp_body | sort -u
done
rm -f /tmp/fp_body
```

if `live-hosts.txt` is absent, the loop still runs once against `$TARGET`. record
which signal came from which host — a stack skill matched on host B does not imply
host A runs that stack.

**version banner → CVE check, before generic hunting.** if the fingerprint returns
an exact product **version** (not just the framework family) — SharePoint build
number, WordPress/plugin version in `generator` meta, a Laravel/Spring/ColdFusion
version string, `X-AspNet-Version`, a `Server:`/`X-Powered-By:` version — treat that
as a criticality signal, not just a routing signal. Run `/intel` (or an inline
NVD + `docs/cve-coverage.md` grep) for `"<product> <version>"` immediately, before
falling through to the generic class hunt-\* set. Reason: most in-scope KEV entries
for this bundle's stack (SharePoint deserialization, WordPress core SQLi, Adobe
ColdFusion path traversal, Oracle WebLogic/E-Business Suite) are exact-version
n-days, not generic-class bugs — a version match here is higher-signal than
anything the generic `hunt-*` set will independently rediscover. Note the result
(CVE ID + patched-or-not) in the taxonomy print's `stack:` line; if a matching
unpatched CVE exists, that's the hunt priority over the generic set for that host.

look for the following signals → stack/class skill mapping:

```
MongoDB | mongoose | CouchDB | Redis        →  hunt-nosqli
?page= | ?file= | ?path= | php wrapper       →  hunt-lfi
rO0A | VIEWSTATE | rememberMe cookie         →  hunt-deserialization
Access-Control-Allow-Origin header           →  hunt-cors
/forgot-password | /reset | X-Forwarded     →  hunt-host-header
?redirect= | ?next= | ?return= | ?url=      →  hunt-open-redirect
OTP | /verify | /2fa | no-rate-limit         →  hunt-brute-force
Set-Cookie session | PHPSESSID               →  hunt-session
Active Directory | LDAP | OpenLDAP | ADFS   →  hunt-ldap
__NEXT_DATA__ | /_next/ | buildId            →  hunt-nextjs
X-Powered-By: Express | Node.js | .js stack  →  hunt-nodejs
postMessage | dangerouslySetInnerHTML         →  hunt-dom
WebSocket | ws:// | socket.io                →  hunt-websocket
gRPC | :50051 | application/grpc             →  hunt-grpc
laravel_session | Ignition | Telescope        →  hunt-laravel
X-Application-Context | Whitelabel | /actuator → hunt-springboot
ASP.NET | __VIEWSTATE | X-AspNet-Version     →  hunt-aspnet
SPRequestGuid | /_layouts/15/ | /_vti_bin/   →  hunt-sharepoint
WWW-Authenticate: NTLM | Negotiate            →  hunt-ntlm-info
.js.map | swagger.json | /.env               →  hunt-source-leak
HSTS missing | SPF | DMARC | AXFR            →  hunt-tls-network
firebaseio.com | firestore.googleapis.com    →  hunt-firebase
| firebase.apps / firebaseConfig in bundle
supabase.co | apikey: header + anon/service  →  hunt-supabase
  role JWT claim
*.auth0.com authorize redirect | auth0-js /  →  hunt-auth0
  auth0-spa-js in bundle
Via: kong | X-Consumer-* | server: envoy   →  hunt-trusted-header-auth
  | X-Auth-Request-* | X-Amzn-Oidc-* |
  X-Goog-Authenticated-User-Email |
  CF-Access-Authenticated-User-Email |
  X-MSISDN / X-Subscriber-Id
```

**stronger than any banner for `hunt-trusted-header-auth`:** an endpoint that
returns *account-specific data with no cookie and no `Authorization` header*.
Something identified that request. Route it to `hunt-trusted-header-auth`
regardless of what the fingerprint banners said — an anonymous-but-personalised
response is the highest-signal observation in the whole fingerprint step.

response header value visibly moves with a request-controlled input (query/
body/cookie echoed into `Set-Cookie`/`Location`/`Content-Type`/
`Content-Disposition`/custom `X-*`) → `hunt-header-injection` (unified entry
point; it hands off to `hunt-host-header`/`hunt-cache-poison`/
`hunt-http-smuggling`/`hunt-open-redirect` once the specific chain is confirmed).

`--source-code <path>` supplied to `/hunt` → always load `hunt-source-aware-sast`
in addition to the fingerprint-matched set above (static triage baseline is
the default whenever a repo is available, not conditional on other signals).

### conflict resolution & load budget

real targets almost always return multiple signals at once — e.g. a single host
can show `__NEXT_DATA__` (Next.js front end) + `laravel_session` (backend) +
`Access-Control-Allow-Origin` (class signal) simultaneously. loading every match
blindly can pull 20-plus skills and blow the context window, drowning the
high-signal skill in noise. apply this precedence and cap:

**priority order (load highest tiers first, stop at the cap):**

```
tier 1  app framework / stack    hunt-nextjs, hunt-nodejs, hunt-laravel,
        hunt-springboot, hunt-aspnet, hunt-sharepoint, hunt-firebase,
        hunt-supabase, hunt-auth0
tier 2  protocol / class signals hunt-nosqli, hunt-lfi, hunt-deserialization,
        hunt-cors, hunt-host-header, hunt-open-redirect, hunt-grpc,
        hunt-websocket, hunt-dom, hunt-source-leak, hunt-tls-network,
        hunt-ldap, hunt-brute-force, hunt-session, hunt-ntlm-info,
        hunt-header-injection, hunt-trusted-header-auth
```

`hunt-source-aware-sast` is not fingerprint-triggered and sits outside the
8-cap — it loads whenever `/hunt` runs with `--source-code`, independent of
which stack/class skills the live fingerprint matches.

**load budget: cap stack-skill loads at 8.** if more than 8 match, keep the
highest-tier 8 and drop the rest; print the dropped ones under `deferred:` in the
taxonomy block so they can be loaded on demand later.

**de-dup rules (avoid loading two skills for the same evidence):**

- CDN banner alone (Cloudflare/Akamai/Fastly) is **not** a stack match — it
  fingerprints the edge, not the app. do not load a skill for it; note it for
  `hunt-cache-poison` / `hunt-http-smuggling`, which the mode set already carries.
- a framework marker (`__NEXT_DATA__`, `laravel_session`) and a generic class
  signal (`?redirect=`, `Access-Control-Allow-Origin`) on the same host → load the
  framework skill (tier 1) and keep the class skill **only if budget remains**;
  the WAPT mode set already loads the common class skills unconditionally.

## step 2 — load skill set

invoke each skill in order via the Skill tool.

always-on:

```
bb-methodology
security-arsenal
triage-validation
```

full hunt-* set (all OWASP-relevant):

```
hunt-xss             hunt-sqli            hunt-ssrf            hunt-idor
hunt-csrf            hunt-xxe             hunt-rce             hunt-graphql
hunt-oauth           hunt-saml            hunt-mfa-bypass      hunt-auth-bypass
hunt-ato             hunt-file-upload     hunt-business-logic  hunt-race-condition
hunt-llm-ai          hunt-api-misconfig   hunt-ssti            hunt-cache-poison
hunt-http-smuggling  hunt-subdomain       hunt-misc
hunt-aspnet          hunt-sharepoint      hunt-ntlm-info
hunt-lfi             hunt-nosqli          hunt-deserialization
hunt-cors            hunt-host-header     hunt-open-redirect
hunt-brute-force     hunt-session         hunt-ldap
hunt-nextjs          hunt-nodejs          hunt-dom
hunt-websocket       hunt-grpc            hunt-laravel
hunt-springboot      hunt-source-leak     hunt-tls-network
hunt-firebase        hunt-supabase        hunt-auth0
hunt-header-injection    hunt-trusted-header-auth
```

`hunt-source-aware-sast` loads additionally whenever `--source-code` is supplied.

report format: `report-writing` (`bugcrowd-reporting` if the target is on bugcrowd).

box=greybox: creds already captured by `/hunt`, available in session memory.

**do not fan out across the authenticated hunt-\* set until the creds are
validated.** `/hunt` only prompts for and stores creds (commands/hunt.md) — it
does not confirm they work. firing every authenticated test with dead, MFA-gated,
or wrong-role creds wastes the whole run and produces false "no auth surface"
conclusions. run a single low-cost auth preflight first:

```bash
# session-cookie creds: one authenticated GET against an identity echo endpoint
curl -sS -m 12 -b "$SESSION_COOKIE" "https://$TARGET/api/me" -w '\n%{http_code}\n'
#   200 + your username/email  → live session, role visible in body
#   401/403                    → dead or insufficient — STOP, re-auth

# bearer/JWT creds: same probe with Authorization
curl -sS -m 12 -H "Authorization: Bearer $TOKEN" \
  "https://$TARGET/api/me" -w '\n%{http_code}\n'

# raw user/pass: drive the real login flow once, capture Set-Cookie, then echo
#   watch for an MFA / step-up challenge in the response — if present, the creds
#   alone do not yield an authenticated session (see memory: operator-capability)
```

confirm three things from the preflight, and record them for the hunt-\* skills:

1. **live** — auth probe returns 200, not 401/403.
2. **role/privilege** — the `/api/me` (or equivalent) body shows the expected
   role/tenant/scopes. IDOR and authz tests need a known baseline identity; a
   silently-admin or silently-readonly cred skews every authz finding.
3. **not MFA-gated** — login did not stop at a 2fa/step-up challenge. if it did,
   you hold creds but **not** a session — default to least capability and confirm
   with the operator before claiming authenticated reach.

if the preflight fails, do **not** silently continue as blackbox — surface
"greybox creds did not validate (HTTP {code} / MFA challenge)" so the operator
can re-supply. only after a clean preflight: apply the validated session to every
authenticated test.

## step 3 — taxonomy print (once, at session start)

emit a deterministic block. plain text, lowercase, colon-delimited, no decoration.

```
loaded for wapt ({blackbox|greybox}): {N} skills
  inj:        hunt-xss, hunt-sqli, hunt-ssrf, hunt-rce, hunt-xxe, hunt-ssti, hunt-file-upload
  authz:      hunt-idor, hunt-auth-bypass, hunt-ato
  auth:       hunt-oauth, hunt-saml, hunt-mfa-bypass
  api:        hunt-graphql, hunt-api-misconfig
  logic:      hunt-business-logic, hunt-race-condition
  infra:      hunt-http-smuggling, hunt-cache-poison, hunt-tls-network
  recon:      hunt-subdomain, hunt-source-leak
  ai:         hunt-llm-ai
  stack:      {fingerprint-matched skills (<=8, tier order), or "none detected"}
  deferred:   {stack skills past the 8-cap, or omit line if none}
  headers:    hunt-header-injection, hunt-trusted-header-auth
  source:     hunt-source-aware-sast (only if --source-code supplied, else omit line)
  misc:       hunt-misc, hunt-csrf
  reporting:  bb-methodology, security-arsenal, triage-validation
```

## step 4 — return control to /hunt

after taxonomy print, hand control back to `/hunt` for step 3 (sibling delegation) and step 4 (active testing). do not run probes here — this skill only loads context.

## privacy

never echo back, log, or persist:
- SOW / scope-of-work / engagement-letter content
- grey box credentials (kept in session memory by `/hunt`, never written to disk)
- client identifiers in user-level memory

---

## Related Skills & Chains

- **`bb-methodology`** — When mode confirmation completes. Workflow primitive: `bb-methodology` confirms the hunting phase; the answer feeds directly into this skill's `box=blackbox` / `box=greybox` invocation.
- **`hunt-nextjs`** / **`hunt-nodejs`** / **`hunt-laravel`** / **`hunt-springboot`** / **`hunt-aspnet`** / **`hunt-sharepoint`** / **`hunt-firebase`** / **`hunt-supabase`** / **`hunt-auth0`** — When fingerprint signals match. Workflow primitive: step 1's curl fingerprint scan against `recon/<target>/live-hosts.txt` maps banner / body signals to one or more of these stack skills.
- **`hunt-source-aware-sast`** — When `/hunt` is invoked with `--source-code`. Workflow primitive: loads unconditionally alongside the fingerprint-matched set, independent of the 8-skill cap.
- **`hunt-xss`** / **`hunt-sqli`** / **`hunt-ssrf`** / **all other hunt-* skills`** — When the mode-specific skill set is being printed. Workflow primitive: this skill is the loader; it names the hunt-* skills but does not run probes — actual hunting happens after step 4 returns control to `/hunt`.
- **`report-writing`** / **`bugcrowd-reporting`** — When the taxonomy print specifies the report format. Workflow primitive: `mode=wapt` ends with `report-writing` as the deliverable format, or `bugcrowd-reporting` if the target is on Bugcrowd.
