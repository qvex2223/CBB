---
name: api-security
description: "TRIGGER — an API surface is already mapped (by api-recon, a swagger/openapi doc or a JS bundle) and you are attacking it as a whole: which of REST / GraphQL / WebSocket / SOAP enforces the check, BOLA/BFLA across roles, excessive data exposure, rate-limit trust confusion, JWT and OAuth weaknesses. SKIP — api-recon while the surface is still being mapped; hunt-idor for one named object reference; hunt-graphql for GraphQL-internal abuse; hunt-api-misconfig for JWT-internal flaws, mass assignment and verb tampering; hunt-trusted-header-auth when identity comes from a request header."
sources: artex
---

# API Security Testing (REST, GraphQL, WebSocket, SOAP)

## In this workspace

Ported from ARTEX. Same method, this workspace's plumbing:

- Requests go through `CBH_PROJECT=<platform>/<program> bbcurl`; wire-level questions through
  Caido; the final proof lands in a `poc_runtime` spec (`/poc-run`), then `/refute`, `cbh dedup`,
  `/validate`.
- "A second account or role proves the boundary is real" is the workspace rule too: identities
  first (owner + member + outsider + a second tenant) before the first payload, and **own accounts
  only**. No account for a role → `cbh identity new <url>` + self-registration. A registration
  wall is ONE vector, not a park and not an ask (`cbh autonomy`): note it in `blocked-tests/`
  without a `**Park:**` line — so it stays a workable lane — and keep going on what you have.
- Same operation, second interface, is the highest-yield move here: REST vs GraphQL vs a Next.js
  Server Action vs the mobile/partner API vs export/import. The check usually lives on only one of
  them; prove it by reading the state back (`cbh doctrine`, rule 3).
- Capability proven but no demonstrated consequence → `primitives/`, not `findings/`.


This is the hunting counterpart of api-recon. api-recon maps the API surface and stops; this skill attacks the mapped surface under an authorized engagement. The standing finding quality gates and the adversarial gate in your system prompt apply throughout, and an access-control finding only exists once a second account or role has proven the boundary is real.

Attribution: adapted from the `api-security` playbook of [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) (MIT License).

## Boundaries

- Rate-limit and load tests only within the engagement's written impact budget. Most bounty programs forbid denial of service outright; volume that degrades the service for other users is out of bounds. Race-condition tests use a handful of concurrent requests, never load tools.
- Do not exfiltrate real user data to prove a BOLA. One record you are authorized to touch, or your own second account, is sufficient evidence.
- Destructive payloads (deletion, mass assignment on write endpoints) only against accounts and resources created for the test.
- Every confirmed finding needs a replayable artifact: the exact request, the exact response, and the authorization context that produced it.

## Phase checklists

### Phase 1: discovery (handoff from api-recon)

- Spec sources: `/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql`, JS bundles, robots.txt.
- Undocumented path brute force: ffuf or kiterunner with API wordlists.
- GraphQL introspection, three tiers: the full introspection query; a trimmed query if the full one is blocked; minimal `__schema { types { name } }` as the last probe.

### Phase 2: authentication

JWT (jwt_tool or manual):

- [ ] `alg: none`: header rewritten, signature stripped.
- [ ] key confusion: RS256 public key accepted as an HS256 secret.
- [ ] weak HMAC secret: dictionary attack (`jwt_tool -C -d wordlist.txt`).
- [ ] expired or tampered claims: `exp`, `iat`, `sub`, `role`.
- [ ] `kid` injection: path traversal inside the key id.

OAuth 2.0:

- [ ] `redirect_uri` manipulation leading to authorization-code theft.
- [ ] missing `state` (CSRF on the authorization flow).
- [ ] token leakage via `Referer` or platform logs.
- [ ] missing PKCE on public clients.

GraphQL auth:

- [ ] mutation reachable through GET (CSRF).
- [ ] batched queries bypassing per-operation authorization.

### Phase 3: authorization (BOLA / IDOR / BFLA)

BOLA, object level:

- [ ] enumerate numeric ids: `/user/1` to `/user/2`.
- [ ] enumerate UUIDs harvested from other responses.
- [ ] substitute usernames or emails in paths and bodies.
- [ ] two-session replay: user A's session requesting user B's objects (Burp Autorize or a manual response diff).

BFLA, function level:

- [ ] standard user calling admin endpoints.
- [ ] HTTP method swap: GET to PUT, PATCH, DELETE.
- [ ] version downgrade: `/v2/admin` to `/v1/admin`.
- [ ] batch-operation injection: append an admin id to the bulk body.

### Phase 4: GraphQL-specific

- [ ] introspection exposing schema details it should hide.
- [ ] alias overload (dozens of aliases in one query) and batched queries as compute amplification, within the impact budget.
- [ ] field-suggestion error messages leaking schema names.
- [ ] GraphiQL or a playground exposed unauthenticated.
- [ ] deep nesting as a resource-exhaustion vector, within the impact budget.
- [ ] trace or debug mode returning metadata.

### Phase 5: REST input validation

- [ ] HTTP method swap on every endpoint.
- [ ] Content-Type tampering: JSON to XML to multipart (XXE where XML is accepted).
- [ ] NoSQL operator injection: `{"username": {"$gt": ""}}`.
- [ ] SSRF through URL-taking parameters (webhooks, avatar imports, fetchers).
- [ ] HTTP parameter pollution: `?role=user&role=admin`.
- [ ] mass assignment: `is_admin: true` added to request bodies.

### Phase 6: business logic and differential testing

- [ ] diff v1 against v2 of the same API: status-code changes, removed fields, latency regressions.
- [ ] role matrix: admin, user, readonly through the same workflow.
- [ ] coupon, credit, and price manipulation on test accounts.
- [ ] TOCTOU races with a few concurrent requests.

### Phase 7: WebSocket

- [ ] endpoint discovery (upgrade handshakes).
- [ ] message injection, prototype pollution through frames.
- [ ] oversized-message handling.
- [ ] type confusion in frame payloads.
- [ ] cross-site WebSocket hijacking (CSWH).

### Phase 8: rate-limit trust confusion

- [ ] header spoofing: `X-Forwarded-For`, `X-Real-IP`, reported as a trust-boundary finding, never scaled into volume.
- [ ] path variants: `/api/`, `/api`, `/Api/`, `/API/` bypassing a path-keyed limiter.
- [ ] the finding is the bypass mechanism itself; do not demonstrate it under load.

### Phase 9: data exposure

- [ ] response fields beyond what the UI renders (diff the API response against the page).
- [ ] pagination enumeration: `?page=1&limit=10000`.
- [ ] error messages leaking stack traces, internal paths, or SQL.
- [ ] GraphQL nested traversal reaching unauthorized data.
- [ ] spec files exposing internal endpoints.

### Phase 10: regression handoff

- [ ] persist every confirmed finding as a replayable request (curl command or HAR artifact) so retests and the reporter can re-verify.
- [ ] mark which findings are safe to re-run and which are one-shot (nonce or state dependent).

## Tools

| Tool | Use | Notes |
|---|---|---|
| curl + jq | request replay and diffing | always available |
| jwt_tool | JWT attack automation | pip-installable; verify before use |
| ffuf, kiterunner | endpoint brute force | verify container availability |
| Burp Autorize, AuthMatrix | two-session authorization diffing | only where a Burp instance exists |

The upstream playbook also names Vespasian, Entropy, Escape DAST, FireTail, and api.sh; treat those as references until verified in this environment, and prefer the manual checklists over unverified tooling.

## Completion self-check

- [ ] every executed phase produced artifacts (requests, responses, diffs) in the work dir.
- [ ] each access-control finding was confirmed with a second session or role.
- [ ] nothing in the report relies on a tool or output you did not actually run.

## Nested references defeat a 404

When a BOLA probe answers `404`, do not close it. Census every request field that names
another object — `reply`, `parent_id`, `source_id`, `template_id`, `copy_from`,
`import_from` — and check whether the handler scopes that lookup by the reference's own
key instead of by your tenant. If it does, the server fetches the foreign object for you
and copies it into one you own, while the direct route still answers `404`. The oracle on
an id you already hold: `200` = hit, `500` = the object exists but your inner key is wrong,
`404` = no such id. Never sweep the id space for it — see `hunt-idor` for why that is
unaimable and bans the source IP.

**SKIP** — `hunt-idor` owns the full write-up of this class; this entry exists so a BOLA
matrix does not record a `404` as a closed cell.

---

## Trust that survives a transfer of ownership

Authorization is usually tested against the grants an identity holds now. Test the other
direction: what still trusts an object after the object changed hands. Trust recorded against a
**permanent id** — a repo id, a project id, a connected-source id — is not revoked when ownership
moves, so the new owner inherits whatever that id was trusted for.

**Worked example — CVE-2026-118535 (Gitea, High 7.3, `>= 1.27.0`, fixed 28.4.0).**
`ActionScopedWorkflowSource` stores the consuming scope's `OwnerID` and the source's stable
`SourceRepoID`. Owner-level enrollment resolves only repositories the owner holds *now*, but
dispatch loads the source by id without re-checking its new owner. Transfer changes the source's
owner and leaves the trust row intact; the new owner edits the workflow and it runs with the
consumer's plaintext secrets and a write-scoped token for repositories the attacker gets `404`
for. The advisory's own argument that this is a missed lifecycle check rather than intended
behaviour: deletion *does* remove those rows, and transfer already removes the repo from the old
owner's `AllowedCrossRepoIDs`.

**How to test it on your own accounts.** Two identities you hold. Create the object under A,
enroll it wherever it can be trusted (CI source, webhook, allowlist, shared secret scope),
transfer it to B, then from B change what the object does and see what still runs. A lane needing
the second identity is marked `REGISTER FIRST`, not held back.

**Where else the shape appears:** transferring a project between workspaces, moving a repository
between orgs, re-parenting a team, changing the owner of an API client or service account.

**SKIP** — `hunt-invariants` states the invariant this breaks; `hunt-idor` carries it as a
mutation on the object-ownership ladder.

