# Recon → Hunt Manifest

`manifest.json` is the data contract between the **recon** phase
(`web2-recon` · `hunt-subdomain` · `cbh recon` · `engine/recon.py`) and the **hunt** phase
(`hunt` · `cbh surface` · `cbh vectors seed-from-manifest` · `/hunt`).
One file, written to `recon/<target>/manifest.json`, that the hunt side ingests so recon
output flows straight into the engagement instead of being re-typed.

JSON Schema: [`recon-manifest.schema.json`](recon-manifest.schema.json).

## Producers — who writes it

The manifest is a **shared container**; each producer fills the parts it discovers:

| Producer | Fills |
|---|---|
| `cbh recon <target>` | `target`, `generated_at`, `counts`, `assets`, `ranked_surface`, `operations` (root only) |
| `cbh api-manifest <inputs>` | `operations` — from OpenAPI/Swagger, HAR, Postman, Burp XML, GraphQL introspection |
| `engine/engine.py` recon phase | writes `api-manifest.json` + `workflow.json` beside the run state |
| `hunt-source-leak` skill — secret scanning | appends `secrets[]` |
| `web2-recon` skill — service/tech probes | fills `identity_fabric{}` |

A producer that doesn't discover a section leaves it empty (`[]` / `{}`) — never absent.

## Consumers — who reads it

| Consumer | Uses |
|---|---|
| `cbh surface <target>` | prints the ranked **P1 / P2 / Kill** surface from `ranked_surface` |
| `hunt <target> [manifest.json]` | seeds `scope.md` (live hosts) + `notes.md` (ranked surface) |
| `cbh workflow <manifest>` | derives business-state hypotheses from `operations` |
| `cbh vectors seed-from-manifest` | turns `operations` + hypotheses into an attack-vector ledger |
| `cbh recon-diff <old> <new>` | reports added/removed operations, new params, changed security |
| `/hunt`, `/surface` slash commands | same data, LLM-driven |

`hunt` resolves the manifest from: 2nd arg → `$HUNT_MANIFEST` → `./recon/<target>/manifest.json`.

## Schema (v2.0)

Version 2.0 adds one field — `operations` — and changes nothing else, so a 1.0 consumer
reads a 2.0 manifest unchanged. The addition matters because `assets`/`ranked_surface`
describe *hosts and URLs*, and the thing worth attacking is an **operation**: a method,
a canonical path, the parameters and schema fields it accepts, and whether it declares
authentication. That is the unit `cbh vectors seed-from-manifest` seeds from, which is
what replaced seeding every vulnerability class against every endpoint.

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | `"2.0"` (`"1.0"` still accepted — `operations` absent) |
| `target` | string | root domain |
| `generated_at` | string | UTC ISO-8601 |
| `producers` | string[] | e.g. `["cbh-recon/2.1.0"]` |
| `counts` | object | `{subdomains, resolved, live}` |
| `assets` | object[] | `{host, ips[], url, status, server, title, tech[], source}` (`url`/`status` null for DNS-only) |
| `ranked_surface` | object[] | `{url, host, bug_classes[], priority, rationale}` · priority ∈ `P1`/`P2`/`KILL` |
| `secrets` | object[] | `{pattern, severity, category, source}` — from `secret_scan.py` |
| `identity_fabric` | object | `{idp, tenant, domains[], ...}` — from identity-fabric probes |
| `operations` | object[] | **v2.0** · normalized API operations — see below |

### `operations[]` (v2.0)

| Field | Type | Notes |
|---|---|---|
| `id` | string | `op_<sha256[:12]>` of `METHOD host canonical-path` — stable across sources |
| `method` | string | uppercase |
| `path` | string | canonical: `/v1/orders/42`, `/v1/orders/{orderId}` and a UUID path all normalize to `/v1/orders/{id}`, so a spec and captured traffic merge into one row |
| `host`, `url` | string | as observed |
| `operation_name` | string | `operationId` / Postman name / GraphQL field, when the source has one |
| `parameters` | string[] | query/path/header parameter names |
| `fields` | string[] | request & response schema field names |
| `secured` | bool\|null | declared auth requirement; `null` when the source does not say — **not** the same as `false` |
| `risk_hints` | string[] | why this operation is worth attacking (see below) |
| `source` | string | `openapi` · `har` · `postman` · `burp` · `graphql` · `crawl` |

**`risk_hints`** are derived from the operation's own shape, and they are what picks the
vector classes downstream — not a guess about the endpoint:

| Hint | Derived from | Seeds |
|---|---|---|
| `object-authorization` | a path variable, or an id-shaped field | `idor` |
| `state-change` | POST/PUT/PATCH/DELETE | `csrf` |
| `property-authorization` | a sensitive schema field (`role`, `owner_id`, `price`, `status`, …) | `api-misconfig` (mass assignment) |
| `function-authorization` | `admin`/`internal`/`worker`/`permission` in the path or fields | `auth-bypass`, `missing_authorization` |
| `business-flow` | `price`, `amount`, `balance`, `coupon`, `order`, `invoice`, `payment` | `business-logic` |
| `oauth` | `/authorize`, `/token`, `oidc` | `auth-bypass`, `open-redirect` |
| `graphql` | a GraphQL endpoint | `graphql` |
| `declared-public` | the source declares no auth | `missing_authorization` |

## Example

```json
{
  "schema_version": "1.0",
  "target": "acme.com",
  "generated_at": "2026-06-25T12:00:00+00:00",
  "producers": ["cbh-recon/2.1.0"],
  "counts": { "subdomains": 47, "resolved": 31, "live": 12 },
  "assets": [
    { "host": "api.acme.com", "ips": ["1.2.3.4"], "url": "https://api.acme.com",
      "status": 200, "server": "nginx", "title": "API", "tech": [], "source": "crtsh+httpx" }
  ],
  "ranked_surface": [
    { "url": "https://api.acme.com", "host": "api.acme.com",
      "bug_classes": ["hunt-api-misconfig", "hunt-idor"], "priority": "P1",
      "rationale": "high-value surface (api/auth/admin/non-prod)" }
  ],
  "secrets": [],
  "identity_fabric": {},
  "operations": [
    { "id": "op_3f2a91c4b7de", "method": "POST",
      "url": "https://api.acme.com/v1/orders/{id}/refund",
      "host": "api.acme.com", "path": "/v1/orders/{id}/refund",
      "operation_name": "refundOrder",
      "parameters": ["id"], "fields": ["amount", "status"],
      "secured": null,
      "risk_hints": ["object-authorization", "state-change",
                     "property-authorization", "business-flow"],
      "source": "openapi", "metadata": {} }
  ]
}
```

## Round-trip

```bash
cbh recon acme.com                 # → recon/acme.com/manifest.json   (producer)
cbh surface acme.com               # ranked P1/P2/Kill                 (consumer)
hunt acme.com recon/acme.com/manifest.json   # seeds scope.md + notes.md (consumer)
```

Deeper API surface than the root hosts needs an offline description or captured traffic —
`cbh recon` cannot invent operations it never saw:

```bash
cbh api-manifest openapi.json traffic.har --out manifest.json   # normalize + merge
cbh workflow manifest.json --out workflow.json                  # business hypotheses
cbh vectors seed-from-manifest api.acme.com \
    --manifest manifest.json --workflow workflow.json           # ledger, ranked by risk
cbh vectors next api.acme.com                                   # what to attack first
```
