---
name: hunt-supabase
description: "TRIGGER — target's requests hit `<ref>.supabase.co/rest/v1/`, `/rest/v1/rpc/`, `/storage/v1`, `/graphql/v1`, `/auth/v1`, or `wss://<ref>.supabase.co/realtime/v1`; client bundle contains a Supabase `anon` key. Covers Row Level Security (RLS) gaps, unsafe `SECURITY DEFINER` RPCs, leaked `service_role` keys, lax Storage policies, and Edge Functions trusting headers without binding to issuer/audience/tenant. SKIP — hunt-firebase/hunt-auth0 for other BaaS/IdP stacks; hunt-graphql for the general GraphQL class once the bug isn't RLS-specific (pg_graphql inherits RLS, so most Supabase GraphQL bugs ARE RLS bugs — check here first)."
sources: "ported from usestrix/strix (Apache-2.0), strix/skills/technologies/supabase.md — adapted for Claude-BugHunter"
report_count: 0
---

# HUNT-SUPABASE — Supabase Security Testing

Supabase exposes Postgres directly through PostgREST, a GraphQL layer, realtime
subscriptions, storage, and Edge Functions — all gated by **Row Level Security
(RLS)** policies on the underlying tables. The `anon` and `authenticated` Postgres
roles are meant to hit these policies; the `service_role` key **bypasses RLS
entirely** and must never reach a client. Most Supabase bugs are an RLS policy
that only covers `SELECT` and forgets `UPDATE`/`DELETE`/`INSERT`, a
`SECURITY DEFINER` RPC that doesn't re-check ownership inside the function
body, or a leaked `service_role` key sitting in a JS bundle or Edge Function
response.

## Attack Surface

**Data Access**
- PostgREST: table CRUD, filters, embeds/relations, RPC (remote functions)
- GraphQL: `pg_graphql` over the Postgres schema — inherits RLS
- Realtime: replication subscriptions, broadcast/presence channels

**Storage** — buckets, objects, signed URLs, public/private policies

**Authentication** — Auth (GoTrue): JWTs, cookie/session, magic links, OAuth flows

**Server-Side** — Edge Functions (Deno) calling Supabase with secrets

## Architecture / Endpoints

```
REST      : https://<ref>.supabase.co/rest/v1/<table>
RPC       : https://<ref>.supabase.co/rest/v1/rpc/<fn>
Storage   : https://<ref>.supabase.co/storage/v1
GraphQL   : https://<ref>.supabase.co/graphql/v1
Realtime  : wss://<ref>.supabase.co/realtime/v1
Auth      : https://<ref>.supabase.co/auth/v1
Functions : https://<ref>.functions.supabase.co/
```

**Headers**
- `apikey: <anon-or-service>` — identifies the project (not the user)
- `Authorization: Bearer <JWT>` — binds the user context (`auth.uid()`)

**Roles** — `anon`, `authenticated` are standard; `service_role` bypasses RLS
and must never be client-exposed.

**Key principle**: `auth.uid()` returns the current user's UUID from the JWT.
Every policy must derive identity from the JWT, never from a client-supplied
column value.

## High-Value Targets

- Tables with sensitive data (users, orders, payments, PII)
- RPC functions, especially `SECURITY DEFINER`
- Storage buckets with private files
- Edge Functions with `service_role` access
- Export/report endpoints generating signed outputs
- Admin/staff routes and privilege-granting endpoints

## Reconnaissance

```
/rest/v1/<table>
/rest/v1/rpc/<fn>
/storage/v1/object/public/<bucket>/
/storage/v1/object/list/<bucket>?prefix=
/graphql/v1
/auth/v1
```

Obtain principals: unauthenticated (anon key only), user A, user B,
admin/staff if available. **Grep client bundles and Edge Function error
responses for a leaked `service_role` key** — this is the single highest-value
find on any Supabase target, since it bypasses every RLS policy in the project.

## Key Vulnerabilities

### Row Level Security (RLS)

RLS must be enabled on every non-public table; absence, or a "permit-all"
policy, means bulk exposure.

**Common gaps**
- Policy checks `auth.uid()` for `SELECT` but forgets `UPDATE`/`DELETE`/`INSERT`
- Missing tenant constraint (`org_id`/`tenant_id`) — cross-tenant access
- Policy relies on a client-provided column (`user_id` in the request body)
  instead of the JWT
- Complex joins where the policy applies after the filter, enabling inference
  via row counts

**Tests**
```bash
# Compare row counts for two users on the identical query
curl -s "https://$REF.supabase.co/rest/v1/$TABLE?select=*" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $TOKEN_A" \
  -H "Prefer: count=exact" -I | grep -i content-range

# Cross-tenant probe — no org filter, or an OR that includes a null/foreign org
curl -s "https://$REF.supabase.co/rest/v1/$TABLE?org_id=eq.$OTHER_ORG" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $TOKEN_B"
curl -s "https://$REF.supabase.co/rest/v1/$TABLE?or=(org_id.eq.other,org_id.is.null)" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $TOKEN_B"

# Write-path — PATCH/DELETE/POST against a foreign row ID or owner_id
curl -s -X PATCH "https://$REF.supabase.co/rest/v1/$TABLE?id=eq.$FOREIGN_ID" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" -d '{"field":"pwned"}'
```

### PostgREST & REST

- Filters: `eq`, `neq`, `lt`, `gt`, `ilike`, `or`, `is`, `in`
- Embedded relations: `select=*,profile(*)` — exploits overfetch if the nested
  resolver skips its own per-row check
- Generous `LIKE`/`ILIKE` filters combined with missing RLS → mass disclosure
  via wildcard queries
- `Prefer: return=representation` echoes writes back; `Prefer: count=exact`
  leaks exact row counts even through a 200-with-empty-body response
- `Accept-Profile`/`Content-Profile` select the Postgres schema — try non-`public`
  schemas the UI doesn't expose

**IDOR patterns**
```
/rest/v1/<table>?select=*&id=eq.<other_id>
/rest/v1/<table>?select=*&slug=eq.<other_slug>
/rest/v1/<table>?select=*&email=eq.<other_email>
```

**Mass assignment** — if the write path is a raw `PATCH` (not routed through an
RPC), verify which columns are actually restricted at the database-permission
level, not just hidden from the UI.

### RPC Functions

RPC maps directly to a SQL function. `SECURITY DEFINER` runs with the
function-owner's privileges and **bypasses RLS unless the function body
explicitly re-checks ownership**; `SECURITY INVOKER` respects the caller.

**Anti-patterns**
- `SECURITY DEFINER` + missing owner check inside the function body →
  vertical/horizontal bypass
- `search_path` left to `public` — the function resolves an unsafe/shadowed object
- Function trusts a client-supplied `user_id`/`tenant_id` argument rather than
  calling `auth.uid()` internally

```bash
# Call as a different user, passing a foreign ID as an argument
curl -s -X POST "https://$REF.supabase.co/rest/v1/rpc/$FN" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" -d '{"user_id":"<foreign-uuid>"}'

# Same call with the anon key only, no bearer token at all
```

### Storage

```bash
# Public bucket with sensitive data
curl -s "https://$REF.supabase.co/storage/v1/object/public/$BUCKET/$PATH"

# List prefixes without auth
curl -s "https://$REF.supabase.co/storage/v1/object/list/$BUCKET?prefix="

# Signed-URL reuse across tenants/paths — capture one, replay against a
# different object path or after the intended TTL
```

- Upload HTML/SVG and check whether it's served with `X-Content-Type-Options:
  nosniff` and `Content-Disposition: attachment` — a bare `text/html` response
  from user-controlled storage content is stored XSS on the storage subdomain.
- Path confusion: mixed case, URL-encoding, `..` segments rejected client-side
  but accepted by the API directly.

### Realtime

`wss://<ref>.supabase.co/realtime/v1` — channel names derived from
table/schema/filters can leak other users' updates when RLS or channel guards
are weak; broadcast/presence channels sometimes allow cross-room join/publish
without auth.

**Tests** — subscribe to `postgres_changes` on a protected table and confirm
visibility matches RLS exactly; attempt joining another user's channel
(`room:<user_id>`, `org:<org_id>`).

### GraphQL (`pg_graphql`)

`/graphql/v1` sits over the same Postgres schema and **inherits RLS** — but
nested-relation resolvers sometimes skip the per-row ownership check that the
top-level query enforces (the same "authorized at the root, not at every
edge" pattern as generic GraphQL). Compare REST vs GraphQL responses for the
identical principal and query shape — protections drift between the two paths.

### Auth & Tokens (GoTrue)

Claims: `sub` = uid, `role`, `aud` = `authenticated`.

**Pitfalls**
- Tokens stored in `localStorage` → XSS exfiltration
- Treating `apikey` as identity — it's project-scoped, not user identity
- `service_role` key exposed in a client bundle or an Edge Function error/response
- Refresh-token mismanagement leading to sessions that outlive the intended TTL

```bash
# Replay a token across services / check audience-pinning
# Try a downgraded token (expired, wrong audience) against a custom endpoint
```

### Edge Functions

Deno-based, often initialized with `service_role` — every ownership/tenant
check must be explicit in the function code, since the client the function is
calling with has zero RLS restriction.

**Risks**
- Trusting `Authorization`/`apikey` headers without verifying the JWT against
  issuer/audience
- CORS: wildcard origin with credentials; reflected `Authorization` in responses
- SSRF via `fetch()` inside the function; secrets leaking via error traces/logs

```bash
# Call with and without Authorization — compare behavior
# Try foreign resource IDs in the payload — server must re-derive user/tenant
# from the JWT, not trust the payload
```

### Tenant Isolation

Every query must join/filter by `tenant_id`/`org_id` derived from the JWT, not
client input. Vary subdomain/header/path tenant selectors while holding the
JWT's tenant constant — server must deny cross-tenant access regardless.

## Bypass Techniques

- Content-type switching: `application/json` ↔ `application/x-www-form-urlencoded`
  ↔ `multipart/form-data`
- Parameter pollution: duplicate keys in JSON/query — PostgREST parser may
  choose last/first inconsistently with your assumption
- REST vs GraphQL parity probing — fetch via whichever path enforces less
- Race windows: parallel writes to beat a post-insert ownership-assignment step

## Blind Enumeration

- `Prefer: count=exact` + `ETag`/length diffs infer unauthorized row existence
- `If-None-Match` conditional requests detect object existence
- Storage signed URLs: timing/length deltas map valid vs invalid tokens

## Testing Methodology

1. **Inventory surfaces** — REST, Storage, GraphQL, Realtime, Auth, Functions
2. **Obtain principals** — anon, user A/B, admin; check for a leaked `service_role`
3. **Build the matrix** — Resource × Action × Principal
4. **REST vs GraphQL** — test both for parity gaps
5. **Seed IDs** from list/search endpoints
6. **Cross-principal** — swap IDs, tenants, transports across principals

## Validation

- Owner vs non-owner REST/GraphQL requests showing unauthorized access
  (content or metadata), request + role context documented
- A mis-scoped RPC or Storage signed URL usable by another user/tenant
- Realtime or GraphQL exposure matching a missing policy check
- A leaked `service_role` key with a confirmed RLS-bypassing call as proof

## Related Skills & Chains

- **`hunt-idor`** — RLS policies scoped to `SELECT` only are IDOR at the
  database layer; the write-path variant (`UPDATE`/`DELETE` missing the same
  policy) is the highest-value chain from a read-only RLS gap.
- **`hunt-graphql`** — `pg_graphql` nested-relation overfetch is the standard
  GraphQL authorization-at-the-edge gap; log Supabase-specific findings here,
  cross-reference the general technique there.
- **`hunt-api-misconfig`** — A leaked `service_role` JWT is functionally a
  hardcoded master-key/JWT-confusion finding; report the leak location
  (bundle, Edge Function error) alongside the RLS-bypass proof.
- **`triage-validation`** — A 200 with an empty PostgREST array (RLS silently
  filtered to zero rows) is not a finding; confirm actual foreign data returned.
