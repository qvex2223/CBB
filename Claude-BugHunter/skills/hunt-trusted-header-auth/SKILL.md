---
name: hunt-trusted-header-auth
description: "TRIGGER — the app decides WHO you are from a request header instead of from a session/token: `X-User-Id`, `X-Remote-User`, `X-Authenticated-User`, `X-Consumer-*` (Kong), `X-Auth-Request-Email` (oauth2-proxy), `X-Amzn-Oidc-Identity` (ALB), `X-Goog-Authenticated-User-Email` (IAP), `CF-Access-Authenticated-User-Email`, `X-Forwarded-Client-Cert` (mTLS/Envoy), or a carrier/subscriber header (`X-MSISDN`, `X-Subscriber-Id`, `X-Up-Calling-Line-Id`). Also fires when an API returns your own account data with NO cookie/Authorization at all — something else identified you. SKIP — hunt-header-injection when the header value is reflected/injected into a RESPONSE header (CRLF, cache key) rather than trusted as identity; hunt-idor when identity is established correctly and only the object reference is unchecked; hunt-api-misconfig for JWT-internal flaws (alg=none, kid traversal) where the token itself is the identity carrier."
sources: github, hackerone_public, portswigger_research, cloud_provider_docs
report_count: 9
---

# hunt-trusted-header-auth

Identity delegated to a **request header**. The reverse proxy / API gateway / edge
authenticates the user and injects `X-User-Id: 4711` for the backend. The backend
trusts it absolutely. If the edge does not **strip the inbound copy** of that header,
anyone can set it and become anyone.

This is not a misconfiguration finding. Where it lands it is an unauthenticated
authorization bypass, and it usually reaches PII directly.

---

## Crown Jewel Targets

- **Anything behind an API gateway** — Kong (`X-Consumer-ID`, `X-Consumer-Username`,
  `X-Consumer-Custom-ID`), Envoy/Istio (`x-forwarded-client-cert`), Apigee, Tyk.
  The gateway's whole job is injecting identity headers; the strip list is the only
  thing standing between the internet and impersonation.
- **Identity-aware proxies** — oauth2-proxy (`X-Auth-Request-User`, `-Email`,
  `-Groups`), AWS ALB OIDC (`X-Amzn-Oidc-Identity`, `X-Amzn-Oidc-Data`), Google IAP
  (`X-Goog-Authenticated-User-Email`), Cloudflare Access
  (`CF-Access-Authenticated-User-Email`, `Cf-Access-Jwt-Assertion`).
- **Carrier / telco subscriber APIs** — header enrichment injects the subscriber's
  line identity (`X-MSISDN`, `X-Subscriber-Id`, `X-Up-Calling-Line-Id`,
  `X-Nokia-MSISDN`, `X-Network-Info`) on the mobile-data path. These APIs are built
  assuming *the request came over our radio network*. Reached over the public
  internet, that assumption is just a header. Very high value: the identity is a
  phone number, so the impersonation space is enumerable.
- **Internal admin/ops surfaces fronted by SSO** — Grafana (`X-WEBAUTH-USER`),
  Kibana, Jupyter, Airflow, Prometheus behind an auth proxy. Grafana's
  `auth.proxy` mode is a documented footgun when the instance is directly reachable.
- **Multi-tenant SaaS** — `X-Tenant-Id`, `X-Org-Id`, `X-Account-Id`, `X-Realm`
  routing headers. Swapping the tenant is a cross-tenant breach, not an IDOR.
- **Anything with a mobile app** — mobile clients get custom identity headers far
  more often than web clients, and the mobile API host is often a different, less
  scrutinised origin.

**Asset priority:** hosts that answer with *your own data* while you send no cookie
and no `Authorization`. Something identified you. Find out what.

---

## Attack Surface Signals

**The tell that beats every other signal:** an endpoint returns
account-specific data on a request carrying **no session cookie and no
Authorization header**. Note it and dig — anonymous-but-personalised is the
fingerprint of this class.

**Header names to probe** (send them; watch for a response *change*):

```
X-User-Id            X-User            X-User-Email        X-Username
X-Remote-User        X-Remote-Email    X-Remote-Groups     X-WEBAUTH-USER
X-Authenticated-User X-Auth-User       X-Auth-Request-User X-Auth-Request-Email
X-Forwarded-User     X-Forwarded-Email X-Forwarded-Preferred-Username
X-Consumer-ID        X-Consumer-Username  X-Consumer-Custom-ID  X-Credential-Identifier
X-Amzn-Oidc-Identity X-Amzn-Oidc-Data  X-Goog-Authenticated-User-Email
CF-Access-Authenticated-User-Email      Cf-Access-Jwt-Assertion
X-Tenant-Id          X-Org-Id          X-Account-Id        X-Realm
X-Roles              X-Scope           X-Permissions       X-Is-Admin
X-SSL-Client-Verify  X-SSL-Client-S-DN X-Client-Cert       X-Forwarded-Client-Cert
X-MSISDN             X-Subscriber-Id   X-Up-Calling-Line-Id  X-Nokia-MSISDN
X-Internal           X-Internal-Request  X-Debug           X-Env
```

**Where the header names leak** (don't guess blind — harvest first):

- JS bundles and source maps: `grep -aoE '[Xx]-[A-Za-z0-9-]{2,30}' bundle.js | sort -u`
  then keep the ones that look like identity, not tracing.
- `Access-Control-Allow-Headers` on a preflight — the server *lists the custom headers
  it accepts*. This is the single highest-yield discovery source and it is free:
  ```bash
  curl -sSI -X OPTIONS "https://$H/api/v1/profile" \
    -H 'Origin: https://example.org' \
    -H 'Access-Control-Request-Method: GET' \
    -H 'Access-Control-Request-Headers: x-user-id' | grep -i '^access-control'
  ```
- Swagger/OpenAPI specs: header parameters marked `in: header`, `required: true`.
- Error bodies: `"missing required header: X-Subscriber-Id"` names the header for you.
- Gateway fingerprints in responses: `Via: kong/*`, `X-Kong-Upstream-Latency`,
  `server: envoy`, `X-Envoy-Upstream-Service-Time`, `X-Amz-Cf-Id` + ALB cookies.

---

## How to hunt

**1. Baseline.** Request the endpoint clean. Record status, length, body identity
fields. Everything downstream is a diff against this.

**2. Add the header with YOUR OWN identity.** Your own user id, your own email,
your own subscriber number. Nothing else. If the response changes — different
length, your data now present, a `401` becoming `200` — the header is trusted.
That is the finding. You have proven the trust boundary without ever touching
another person's data.

**3. Prove impersonation safely.** Escalate to a *second account you own*, or an
identifier you are authorised to use. If neither exists, a **non-existent**
identifier is still decisive: a distinct "user not found" for `X-User-Id: 999999999`
versus your own data for your real id proves the header selects the identity.

> Do NOT enumerate live third-party identities. On a subscriber-header API that
> means real phone numbers and real people's data — a scope violation in every
> program, and the difference between a paid Critical and a banned account. Prove
> the mechanism, stop, report. See `evidence-hygiene` before capturing anything.

**4. Beat the edge's strip list.** When the header is stripped at the edge, the
backend still trusts it — you just need a spelling the stripper misses and the
backend normalises:

```
X-User-Id        vs  X_User_Id          underscore form (nginx drops underscored
                                        headers by default; some backends map them)
X-User-Id        vs  X-User-ID          casing, if the strip list is case-sensitive
one header       vs  sent twice         duplicate: which copy wins, first or last?
                                        edge appends its own -> backend may read [0]
X-User-Id        vs  X-Original-User-Id / X-Forwarded-User / vendor prefix variants
direct to origin vs  through the CDN    origin IP found via DNS history or a
                                        certificate-transparency SAN entry
```

Duplicate-header behaviour is the highest-yield of these: the edge *appends* its
authenticated value, so if the backend reads the **first** occurrence it reads yours.

**5. Check the mobile/API host separately.** The web origin stripping the header
says nothing about `api.` or the host the mobile app talks to. Same backend, no edge.

**6. Then check what the identity unlocks.** Read is the floor. Try the write and
state-changing endpoints under the same header before scoring severity.

---

## Chains

- **+ permissive CORS** (`Access-Control-Allow-Origin` reflected with
  `Allow-Credentials: true`, or a header-identified API needing no credentials at
  all) → any website silently reads victim data cross-origin. Header-trusted
  identity plus reflected origin turns a server-side bypass into a drive-by mass
  leak. Always run the preflight probe from step 2 of Attack Surface Signals.
- **+ enumerable identifier** (sequential user id, phone number, tenant slug) →
  the impact statement is "any subscriber's data", not "a user's data". Do not
  demonstrate at scale; argue it from the identifier space.
- **+ password reset / profile write** → account takeover. `hunt-ato`.
- **+ `X-Roles` / `X-Is-Admin`** → vertical escalation on top of the horizontal one.
- **`X-Original-URL` / `X-Rewrite-URL`** accepted → path-level auth bypass to the
  admin routes the edge ACL protects. `hunt-auth-bypass`.

---

## Severity framing (this class gets under-scored constantly)

Report it as **broken authentication / improper authorization**, never as "insecure
header handling" or "security misconfiguration" — the second framing lands in the
program's unpaid-misconfig bucket. The report needs, in order: the header is
client-settable; it selects the identity; unauthenticated (or cross-account) data
comes back; the identifier space is enumerable. Missing security headers are noise;
a header that *is* the authentication is a critical control failure.

If the header only changes logging, tracing, locale, or a feature flag, it is not
this class. Kill it before writing.

---

## Anti-patterns to grep for (greybox / `--source-code`)

```javascript
// Express: identity read straight off the request
const userId = req.headers['x-user-id'];          // never re-verified
const user   = await User.findById(userId);

// nginx passes it through, and the location block never resets it:
//   proxy_set_header X-User-Id $upstream_user;   <- set for the good path
//   (no `proxy_set_header X-User-Id "";` on the paths that skip auth)
```

```python
# Django/Flask: WSGI turns X-Remote-User into HTTP_X_REMOTE_USER
user = request.META.get("HTTP_X_REMOTE_USER")     # trusted with no proxy allowlist
```

Look for: any read of a header into an identity/authorization variable with no
corresponding "and the request came from our proxy" check (source IP allowlist,
shared secret header, mTLS). The absence of that second check *is* the bug.

---

## Related Skills & Chains

- **`hunt-idor`** — Once the header selects identity, every object-reference test
  reruns under the impersonated identity. Chain primitive: `X-User-Id` accepted +
  `/api/v1/orders` scoped to that header = full cross-account read without ever
  holding a credential.
- **`hunt-cors`** — Run the preflight probe both to *discover* accepted custom
  headers and to check whether the identified endpoint is also cross-origin
  readable. Chain primitive: trusted identity header + reflected `Origin` +
  `Allow-Credentials` = drive-by mass data leak.
- **`hunt-auth-bypass`** — The sibling class for skipping the auth check entirely
  (legacy endpoint, unvalidated `aud`) rather than forging the identity it produced.
- **`hunt-header-injection`** — Adjacent but distinct: there the header value lands
  in a *response*; here it is consumed as *identity*. Same probe surface, so sweep
  both when a custom header is in play.
- **`hunt-api-misconfig`** — When the identity carrier is a JWT in the header rather
  than a bare value, the attack moves into token-internal flaws (alg=none, kid
  traversal, audience confusion) — that skill owns those.
- **`triage-validation`** — Run the 7-Question Gate before reporting. Q1 is the
  killer here: prove the header is *client-settable end-to-end from the internet*,
  not just accepted by an origin you reached directly through a hole in the edge.
- **`evidence-hygiene`** — Screenshots of this class contain identifiers and PII by
  construction. Redact before capture, not after.
