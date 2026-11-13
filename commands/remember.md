---
name: remember
description: Log current finding or successful pattern to hunt memory. Auto-fills from /validate output if available. Usage: /remember
---

# /remember

Save a finding or successful pattern to persistent hunt memory.

## What This Does

1. Auto-populates fields from session context (target, endpoint, vuln_class, technique)
2. **Auto-classifies technique** if not set using 50+ pattern mappings (2026-08-13)
3. If `/validate` was run in this session, pre-fills from validation output
4. Prompts you to confirm or edit before saving
5. Writes to `journal.jsonl` (always) + `patterns.jsonl` (if confirmed)
6. Updates the target profile's `tested_endpoints` and `findings`

## Usage

```
/remember                    # after finding something
/remember --from-validate    # explicitly pull from last /validate
```

## Deterministic backing

The write itself is `cbh remember` (implemented in `engine/memory.py`), so the
record that lands on disk is schema-checked, not LLM-formatted:

```bash
cbh remember --target target.com --vuln-class idor \
  --endpoint '/api/v2/users/{id}/orders' --result confirmed \
  --severity high --payout 1500 \
  --technique numeric_id_swap_with_put_method \
  --tech 'Next.js,GraphQL,PostgreSQL' --tags 'authz,api'
```

`--result` must be one of `confirmed|rejected|partial|informational|duplicate`;
`target`, `vuln-class`, `endpoint` and `result` are required. Credential-shaped
keys (cookie/authorization/token/password/secret/session/otp/…) are redacted before
anything is written — hunt memory is long-lived and gets grepped and copied, so it
never holds a session.

Memory lives in `$CBH_MEMORY_DIR`, else `./hunt-memory` if that directory exists,
else `~/.cbh/hunt-memory`.

## Interactive Flow

```
REMEMBER — Log finding to hunt memory

Target:     target.com (auto-detected)
Endpoint:   /api/v2/users/{id}/orders (from session)
Vuln Class: idor (from session)
Technique:  numeric_id_swap_with_put_method

Result:     [confirmed / rejected / partial / informational]?
Severity:   [critical / high / medium / low]?
Payout:     $___?
Notes:      ___?
Tags:       [comma-separated]?

Save to hunt memory? [y/n]
```

## Minimum Required Fields

- target
- vuln_class
- endpoint
- result

## What Gets Written

| Field | journal.jsonl | patterns.jsonl | target profile |
|---|---|---|---|
| Finding details | Always | If `result=confirmed` | findings[] updated |
| Tested endpoint | — | — | tested_endpoints[] updated |
| Tech stack | — | From target profile | — |

## Why This Matters

- Next time you hunt a target with similar tech stack, your successful patterns are suggested first
- `/pickup target.com` shows which endpoints you've tested and which remain
- Cross-target learning: patterns from target A inform hunting on target B
