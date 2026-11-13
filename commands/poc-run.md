---
name: poc-run
description: Deterministic backing is `python3 engine/poc_runtime.py <spec.json>` — fires one HTTP request from a JSON PoC spec, scope-gated (deny-wins/default-deny via engine/scope.py), evaluates it against an `expect` block in code, writes a `.result.json` artifact. Use before /validate to attach a real captured request/response instead of a remembered one. Usage: /poc-run <spec.json>
---

# /poc-run

Fire a candidate PoC exactly once and capture the real request/response —
the artifact `/validate`'s Q1/Q6 want, instead of a paraphrased memory of an
earlier curl run. See the `poc-runtime` skill for the full workflow and
design rationale.

## What This Does

1. Loads a PoC spec JSON (method/url/headers/body + an `expect` block).
2. Checks the target against the engagement's scope — refuses to fire if
   out of scope, or if no scope source is given at all (deny-by-default).
3. Sends the request exactly once (or up to `--repeat`, hard-capped at 5 —
   this validates, it does not load-test or brute-force).
4. Records the full redirect chain, final URL, and every `Set-Cookie`, then
   evaluates the response against `expect` in code: status, `body_contains`,
   `body_not_contains`, `header_contains`.
5. Writes `<spec-stem>.result.json` with the captured request/response and a
   PASS / FAIL / ERROR / INCONCLUSIVE verdict.

## Usage

```
/poc-run Targets/acme/findings/idor-users.poc.json
```

Under the hood:

```bash
python3 engine/poc_runtime.py Targets/acme/findings/idor-users.poc.json \
  --md Targets/acme/scope.md
```

Do not start the spec from a blank file when the request already flew:

```bash
cbh spec <url-substring> --steps --out Targets/acme/findings/idor-users.poc.json
```

rebuilds it from the response corpus — method, headers, body, and an `expect`
block taken from the bytes the server actually returned. Auth headers were
redacted at capture time and come back as placeholders to fill in by hand; the
second step is a `REPLACE ME` verify step, because a chain that never checks the
state changed is a single request wearing a chain's clothes.

## Spec format

```json
{
  "note": "IDOR — victim id 124 while authenticated as own id 123",
  "method": "GET",
  "url": "https://api.acme.com/v1/users/124",
  "headers": {"Cookie": "session=<own-account-session>"},
  "body": null,
  "expect": {
    "status": 200,
    "body_contains": ["\"id\":124"],
    "body_not_contains": ["\"id\":123"],
    "header_contains": {"content-type": "application/json"}
  },
  "repeat": 1
}
```

## Rules

- **Scope gate is mandatory.** No `--md`/`--scope-file`/`--in-scope` given →
  the tool refuses to fire unless `--no-scope-check` is passed explicitly
  (localhost/lab targets only). Same deny-wins/default-deny logic as `/scope`.
- **This is a validator, not a scanner.** One request by default; `--repeat`
  exists for legitimate race-condition/flake checks and hard-caps at 5. It
  does not replace the pacing rules in `Targets/<name>/CLAUDE.md`.
- **The human still picks the request.** This tool doesn't generate payloads
  or decide what to test — it removes the "did I remember the response
  right" step between a manual PoC and the report.
- Redact the `.result.json` per `evidence-hygiene` before it goes near an
  attachment — cookies/tokens/PII are captured verbatim in the raw response.

## Related

- `/validate` — run after a PASS, quoting the `.result.json` for Q1/Q6.
- `/scope` — same underlying scope engine; run standalone first if unsure.
