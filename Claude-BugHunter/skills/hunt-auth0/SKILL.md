---
name: hunt-auth0
description: "TRIGGER — login redirects to `https://<tenant>.<region>.auth0.com/authorize`, client bundle references `auth0-js`/`@auth0/auth0-spa-js`/`auth0-react`, or `/.well-known/openid-configuration` resolves on an `auth0.com` domain. Covers Auth0 tenant misconfiguration (Rules/Actions claim injection, callback-URL wildcards, MFA gaps, Organizations cross-tenant leaks) and how downstream APIs validate Auth0-issued tokens (audience/scope confusion). SKIP — hunt-oauth for the generic OAuth/OIDC flow class (redirect_uri, state, PKCE) shared by any provider; hunt-saml if the same tenant also exposes a SAML connection/ACS endpoint; hunt-mfa-bypass once the finding is purely the MFA-step gap with no Auth0-tenant-config component."
sources: "ported from usestrix/strix (Apache-2.0), strix/skills/technologies/auth0.md — adapted for Claude-BugHunter"
report_count: 0
---

# HUNT-AUTH0 — Auth0 Tenant Security Testing

Auth0 misconfigurations enable account takeover, cross-tenant data access, and
privilege escalation through Rules/Actions, loose Application settings, weak
API authorization, and token-acceptance bugs in the applications consuming
Auth0-issued tokens. Test **both** the Auth0 tenant configuration itself and
how the downstream API validates the tokens it receives — a perfectly
configured Universal Login still fails if the API accepts any valid token
regardless of `aud`/`scope`.

## Attack Surface

**Auth0 components**
- Applications: SPA, Regular Web, Native, Machine-to-Machine (M2M)
- APIs (Resource Servers): identifiers, scopes, RBAC, permissions
- Connections: database, social, enterprise (SAML/OIDC)
- Rules (legacy) and Actions (post-login, pre-user-registration, credentials exchange)
- Organizations (multi-tenant B2B), roles, permissions
- Universal Login, custom domains, custom database scripts

**Token types**
- ID Token (OIDC), Access Token (JWT or opaque), Refresh Token
- Management API tokens, client-credentials tokens (M2M)
- PAR, PKCE flows for public clients

**Management** — Auth0 Management API (`/api/v2/`), tenant settings, attack
protection, MFA policies, anomaly detection, log streaming, hooks, custom prompts.

## Reconnaissance

**Tenant discovery** (from app config, JS bundles, mobile apps)
```
domain: tenant.us.auth0.com / tenant.eu.auth0.com / login.customdomain.com
client_id, audience, scope values in authorize URLs
```

**OIDC discovery**
```bash
curl -s "https://$TENANT.auth0.com/.well-known/openid-configuration"
curl -s "https://$TENANT.auth0.com/.well-known/jwks.json"
```

**Authenticated userinfo** (requires a bearer access token — unauthenticated
requests return 401, so a 401 here is not a finding)
```bash
curl -s "https://$TENANT.auth0.com/userinfo" -H "Authorization: Bearer $ACCESS_TOKEN"
```

**Application fingerprint**
- Login redirects to `https://$TENANT.auth0.com/authorize?client_id=...`
- `auth0-js`, `@auth0/auth0-spa-js`, `auth0-react` in frontend bundles
- The `audience` parameter in token requests names the target API

**Management API exposure** — grep for leaked M2M credentials with
`read:users`/`update:users`/`create:users` scopes; check whether the
Management API is called directly from browser JS (CORS misconfiguration).

## Key Vulnerabilities

### Application Configuration

**Callback URL / origin misconfigurations**
- Wildcard or overly broad Allowed Callback URLs: `https://app.com/*`,
  `http://localhost:*`
- Allowed Logout URLs, Web Origins, CORS origins too permissive
- Native app custom-scheme hijacking (`com.app://callback`)

**Token settings**
- ID Token used as an API access token (audience/scope confusion)
- Refresh-token rotation disabled, or TTL too long
- Signing algorithm downgrade if the downstream service doesn't enforce RS256

### API Authorization (Resource Server)

**Missing scope/RBAC enforcement**
- API accepts any valid access token without checking the required
  `scope`/`permissions` claim
- RBAC is enabled in Auth0 but the API never calls `/userinfo` or validates the
  `permissions` array
- Wrong `audience` accepted — a token issued for App A works against App B's API

```bash
# Token minted for audience A, replayed against API B
curl -s "https://$API_B_HOST/protected" -H "Authorization: Bearer $TOKEN_FOR_AUDIENCE_A"
```

### Rules and Actions Abuse

**Post-login Rule/Action injection**
```javascript
// If a user can set app_metadata via signup/API, this Rule pattern is a
// direct privilege-escalation path:
user.app_metadata.role = 'admin'
```
- `context.authorization` manipulation inside Actions
- Secrets hardcoded in Rule code, exposed via tenant-admin access or a
  Management API leak

**Signup / registration Actions**
- `pre-user-registration` not blocking disposable emails or client-controlled
  role self-assignment
- Social-connection account linking without verified email → account takeover
  (link attacker's social IdP to a victim's unverified-email account)

### Organizations (B2B Multi-Tenancy)

- Missing `org_id` validation in the API — a user from Org A reaches Org B data
- Invitation flows accepting attacker-controlled email domains
- Organization membership not re-checked after a role change (stale
  membership honored past revocation)

### MFA Bypass

- MFA not enforced on the Management API or on high-risk applications
- Remember-browser cookie bypasses step-up for sensitive actions
- MFA challenge only enforced on Universal Login, but the API also accepts
  password-grant tokens issued without MFA
- Brute-forceable recovery codes or enrollment endpoints

### Account Takeover Vectors

- Password-reset link not invalidated after use; predictable reset tokens
- Email verification not required before a sensitive action
- Password change without re-authentication or MFA step-up
- Linking an attacker's social IdP to a victim account sharing the same
  (unverified) email

### Management API

- M2M application with excessive scopes: `delete:users`, `update:users_app_metadata`
- Management API token embedded in frontend JS or a mobile app
- No rate limiting on `/api/v2/users` enumeration

### Custom Database Scripts

- Custom login script with SQL injection in the username lookup
- `get_user` script returning excessive profile fields
- Hardcoded credentials or weak hashing inside the script

## Advanced Techniques

**Cross-application token confusion**
- Same `client_secret` reused across dev/prod environments
- Multiple APIs sharing signing keys without `aud` validation

**Resource Owner Password Grant** (legacy, if enabled) — direct
username/password to the token endpoint, bypassing Universal Login's MFA entirely.

**Impersonation/Delegation** — `act_as` or delegation features misconfigured
(legacy, only on older tenants).

## Testing Methodology

1. **Extract tenant config** — domain, `client_id`, `audience`, scopes from the app
2. **Callback/origin matrix** — fuzz Allowed Callback URLs and Web Origins
3. **Token validation** — swap audiences, strip scopes, use expired tokens,
   wrong signing keys
4. **Org boundary** — two org users accessing each other's org-scoped resources
5. **MFA policy** — sensitive actions without step-up; API paths bypassing MFA
6. **Management API** — hunt for leaked M2M creds; test scope boundaries
7. **Rules/Actions** — trace claim injection from `user_metadata`/`app_metadata`

## Validation

1. Demonstrate account takeover or cross-org access via token/callback/metadata abuse
2. Show the API accepting a token missing the required scope/permission/audience
3. MFA-bypass PoC on a protected application flow
4. Document the root-cause Auth0 setting (Rule, Application config, API RBAC)
5. Provide the full authorize → callback → API-request chain with evidence

## False Positives

- Callback-URL validation rejects every fuzz attempt consistently
- API validates `aud`, `iss`, and `scope`/`permissions` on every request
- MFA enforced via an Action on every login for sensitive applications
- `app_metadata` writable only by an admin through the Management API, never
  through user signup
- Organizations feature correctly binds `org_id` in the token and the API
  enforces it

## Impact

- Full account takeover across Auth0-connected applications
- Cross-tenant data breach in B2B Organizations deployments
- Privilege escalation via metadata/claim injection in Rules
- Mass user enumeration/modification via Management API abuse

## Pro Tips

1. Always capture the full `authorize` URL — `audience` and `scope` reveal
   which API is the real target
2. Decode the access-token JWT — check `permissions`, `scope`, `org_id`, and
   any `https://.../roles` custom-namespace claims
3. Test dev/staging tenants separately — they often have weaker callback rules
4. Management API M2M creds leaked in CI logs are high-value — search GitHub,
   buckets, build artifacts
5. Pair with `hunt-oauth` for flow-level bugs (redirect_uri, state, PKCE) and
   `hunt-api-misconfig` for the token-layer JWT class

## Related Skills & Chains

- **`hunt-oauth`** — Generic OAuth/OIDC flow bugs (loose `redirect_uri`,
  missing `state`, downgraded PKCE) apply on top of Auth0's implementation;
  chain a leaky `redirect_uri` here into the Universal Login flow for token theft.
- **`hunt-saml`** — When the same tenant also runs an enterprise SAML
  connection, XSW/signature-stripping attacks live there — log the Auth0 tenant
  context here and the assertion-internals attack in `hunt-saml`.
- **`hunt-mfa-bypass`** — Auth0's remember-browser cookie and password-grant
  paths are Auth0-specific instances of the general MFA-step-skip pattern;
  cross-reference for the generic bypass catalogue.
- **`hunt-ato`** — Chain a Rules/Actions claim-injection or account-linking bug
  here into a demonstrated full takeover; log the multi-primitive chain there.
- **`triage-validation`** — A Management API call returning 403 with a
  descriptive error is not itself proof of a scope gap; confirm the actual
  privileged action succeeds before claiming escalation.
