---
name: hunt-firebase
description: "TRIGGER — target's client bundle initializes `firebase.apps`/`firebaseConfig` (apiKey, authDomain, projectId), or requests hit `firestore.googleapis.com`, `<project>.firebaseio.com`, or `storage.googleapis.com/storage/v1/b/`. Covers Firestore/Realtime Database security-rule bypass, Cloud Storage exposure, Cloud Functions trusting client input over `context.auth`, and ID-token/App-Check confusion. SKIP — hunt-supabase/hunt-auth0 for other BaaS/IdP stacks; hunt-api-misconfig once the bug is a generic JWT/mass-assignment issue with no Firebase-rules component."
sources: "ported from usestrix/strix (Apache-2.0), strix/skills/technologies/firebase_firestore.md — adapted for Claude-BugHunter"
report_count: 0
---

# HUNT-FIREBASE — Firebase / Firestore Security Testing

Firebase apps push authorization into declarative **security rules** instead of
server code — Firestore, Realtime Database, and Cloud Storage each have their
own rules engine, and rules are not filters: a client query must itself include
the constraints that make the rule true for every returned document. Most
Firebase bugs are a rules gap (over-broad `allow read/write`), a Cloud Function
trusting the client-supplied `uid`/`orgId` instead of `context.auth`, or a
token-verification shortcut (wrong `aud`/`iss`, App Check mistaken for
authorization).

## Attack Surface

**Data Stores**
- Firestore (documents/collections, rules, REST + SDK)
- Realtime Database (JSON tree, rules)
- Cloud Storage (rules, signed URLs)

**Authentication**
- Auth ID tokens, custom claims, anonymous/sign-in providers
- App Check attestation (and its limits — it is not authorization)

**Server-Side**
- Cloud Functions (`onCall` gets `context.auth` automatically; `onRequest` must
  verify ID tokens itself)
- Admin SDK — bypasses rules entirely, so ownership/tenant checks must live in code

**Infrastructure**
- Hosting rewrites, CDN/caching, CORS

## Architecture / Endpoints

```
Firestore REST : https://firestore.googleapis.com/v1/projects/<project>/databases/(default)/documents/<path>
Realtime DB    : https://<project>.firebaseio.com/.json
Storage REST   : https://storage.googleapis.com/storage/v1/b/<bucket>
```

- Google-signed ID tokens: `iss` = `accounts.google.com` or
  `securetoken.google.com/<project>`, audience = `<project>`/`<app-id>`,
  identity in `sub`/`uid`.
- Rules engines are **separate** per store — a tight Firestore rule says
  nothing about the Realtime Database or Storage rules on the same project.
- Functions using the **Admin SDK bypass rules** — every ownership/tenant check
  must be explicit in code, not assumed from rules.

## High-Value Targets

- Firestore collections with sensitive data (users, orders, payments)
- Realtime Database root and high-level nodes
- Cloud Storage buckets with private files
- Cloud Functions — especially triggers that grant roles or issue signed URLs
- Admin/staff routes and privilege-granting endpoints
- Export/report functions that generate signed outputs

## Reconnaissance

**Extract project config from client bundle**
```javascript
// grep JS bundles for the initializeApp() call
firebase.apps[0].options
// apiKey, authDomain, projectId, appId, storageBucket, messagingSenderId
```

**Obtain principals** — capture ID tokens for each and build a matrix:
unauthenticated, anonymous (if enabled), user A, user B, staff/admin (if available).

## Key Vulnerabilities

### Firestore Rules

**Common gaps**
```
allow read: if request.auth != null   // any authenticated user reads ALL data
allow write: if request.auth != null  // mass write access
```
- Missing per-field validation — lets a write add `isAdmin`/`role`/`tenantId` fields
- Trusting client-supplied `ownerId`/`orgId` instead of
  `resource.data.ownerId == request.auth.uid`
- Over-broad `list` rules on root collections (per-doc checks exist, but `list`
  still leaks the collection)

**Secure pattern for comparison**
```javascript
request.resource.data.keys().hasOnly(['field1', 'field2', 'field3'])
resource.data.ownerId == request.auth.uid &&
request.resource.data.ownerId == request.auth.uid
exists(/databases/(default)/documents/orgs/$(org)/members/$(request.auth.uid))
```

**Tests**
```bash
# Compare row/doc counts and IDs for user A vs user B on the identical query
curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/$COLLECTION" \
  -H "Authorization: Bearer $TOKEN_A" | jq '.documents | length'
curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/$COLLECTION" \
  -H "Authorization: Bearer $TOKEN_B" | jq '.documents | length'

# Cross-tenant read without org filter, and write-path with a foreign ownerId
# (use REST directly — the SDK enforces client-side constraints the REST API doesn't)
```

- Explore `collectionGroup` queries — they can bypass per-collection rules if
  the rule author only thought about single-collection access.
- Use `startAt`/`endAt`/`in`/`array-contains` to probe rule edges and
  pagination cursors that a naive rule didn't anticipate.

### Realtime Database

Misconfigured rules frequently expose the **entire JSON tree** from the root:
```bash
curl -s "https://$PROJECT.firebaseio.com/.json"
curl -s "https://$PROJECT.firebaseio.com/.json?auth=$TOKEN"
```
Confirm rules use `auth.uid` and granular path checks — `.read/.write: true` or
bare `auth != null` at a high-level node is the smoking gun. Attempt to write
privilege-bearing nodes (roles, org membership) once read access is confirmed.

### Cloud Storage

```bash
# Public read on a bucket that shouldn't be
curl -s "https://storage.googleapis.com/storage/v1/b/$BUCKET/o?prefix=" # list objects
curl -s "https://storage.googleapis.com/$BUCKET/$OBJECT_PATH"          # direct GET

# Signed URL reuse — capture one, replay across accounts/paths, try case/encoding variants
```
- Verify `Content-Type`/`Content-Disposition: attachment` on downloads —
  missing `X-Content-Type-Options: nosniff` + an uploadable HTML/SVG is a
  same-origin stored-XSS path via the storage bucket.

### Cloud Functions

`onCall` gets `context.auth` for free; `onRequest` must verify the ID token
manually — this is where most Firebase Functions bugs live.

**Common gaps**
- Trusting client `uid`/`orgId` from the request body instead of `context.auth`
- Missing `aud`/`iss` verification when the function hand-parses a JWT
- Over-broad CORS allowing credentialed cross-origin requests
- `onCreate`/`onWrite` triggers granting roles based on client-controlled
  document content

**Tests**
```bash
# Call the same logical action via both onCall and onRequest with varied tokens
# — expect identical authorization decisions from both
curl -s -X POST "https://$REGION-$PROJECT.cloudfunctions.net/$FUNCTION" \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" \
  -d '{"data":{"targetUserId":"<victim-uid>"}}'

# Create a crafted document to see if it triggers a privilege-granting function
```

### Auth & Token Issues

**Verification requirements**: issuer, audience (project), signature (Google
JWKS), expiration — and App Check binding when the app relies on it.

**Pitfalls**
- Accepting any JWT with a valid signature but the wrong `aud`/project
- Trusting `uid` from the request body instead of `context.auth.uid`
- Mixing session cookies and ID tokens without verifying both paths equivalently
- Custom claims copied into a document, then trusted by app code reading the doc

```bash
# Replay a token across environments/projects — expect strict aud/iss rejection
# Call a Function with and without Authorization — verify identical checks, not
# "assume unauthenticated is denied because the docs say so"
```

### App Check Is Not Authorization

App Check proves "a genuine app instance is calling," not "this caller is
allowed to do this." REST calls straight to `*.googleapis.com` with a valid ID
token succeed **regardless of App Check** — compare SDK-path vs direct-REST-path
behavior with/without the App Check header to confirm no elevated
authorization is actually gated on it.

### Tenant Isolation

Multi-tenant Firebase apps model tenants as `orgs/<orgId>/...` collections.
Tenant must be bound from **server context** (a membership document or custom
claim), never from the client payload.

```bash
# Vary org header/subdomain/query while keeping the token fixed
# — server must deny cross-tenant access regardless of what the client claims
```

## Bypass Techniques

- **Content-type switching** — JSON vs form vs multipart to hit an alternate
  code path in `onRequest`
- **Parameter/field pollution** — duplicate JSON keys (last-one-wins in many
  parsers); sneak a privilege field past a naive allowlist
- **Caching/CDN** — Hosting rewrites that key responses without Authorization
  or tenant headers
- **Race windows** — write then read before a background enforcement function
  (e.g. a Cloud Function that re-derives permissions async) completes

## Blind Enumeration

- Firestore: error shape, document count, `ETag`/length infer existence
  without direct read access
- Storage: length/timing differences on signed-URL attempts leak validity
- Functions: constant-time vs variable-latency responses reveal authorization
  branches even when the body is identical

## Testing Methodology

1. **Extract config** from the client bundle
2. **Obtain principals** — tokens for unauth, anonymous, user A/B, admin
3. **Build the matrix** — Resource × Action × Principal across
   Firestore/Realtime/Storage/Functions
4. **SDK vs REST** — exercise every action via both; the SDK often adds
   client-side constraints the REST API doesn't enforce
5. **Seed IDs** from list/query paths
6. **Cross-principal** — swap document paths, tenants, and user IDs across principals

## Validation

- Owner vs non-owner Firestore/Realtime queries showing unauthorized access or
  metadata leak, with the exact request + role context documented
- Cloud Storage read/write beyond intended scope (public object, signed-URL
  reuse, list exposure)
- A Function accepting a forged/foreign identity (wrong `aud`/`iss`) or
  trusting a client-supplied `uid`/`orgId`
- Minimal reproducible requests, tokens/roles used, and the observed delta
  between principals

## Related Skills & Chains

- **`hunt-idor`** — Firestore/Realtime rules that check `request.auth != null`
  without an ownership constraint are IDOR at the rules-engine layer instead of
  the route layer; the exploitation and reporting shape is identical.
- **`hunt-api-misconfig`** — Cloud Function ID-token verification gaps (missing
  `aud`/`iss` check, `alg` confusion) are the same JWT-attack class covered
  there, just surfacing through a Function instead of a REST middleware.
- **`hunt-cors`** — Over-broad CORS on `onRequest` Functions is the CORS class,
  log the Firebase-specific chain (credentialed cross-origin call reaching an
  Admin-SDK-backed Function) here.
- **`triage-validation`** — A 200 response with an empty Firestore document
  array is not a finding; confirm actual data returned before claiming access.
