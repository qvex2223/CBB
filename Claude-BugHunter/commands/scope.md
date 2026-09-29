---
name: scope
description: Mandatory pre-flight scope check — verify an asset is in scope BEFORE any HTTP touch. Deterministic (deny-wins, default-deny) via engine/scope.py against the engagement's scope.md, including the DNS-resolution gate for netblock-scoped programs (--resolve) and netblock-ownership lookup (--whois). Blocks out-of-scope testing. Usage: /scope <asset> [<asset> ...]
---

# /scope

The mandatory pre-flight gate. Verify a host or URL is in scope **before** any
active testing. Scope is enforced in **code** (`engine/scope.py`), not by LLM
judgment — deny wins, default deny.

## What This Does

1. Loads in-scope / out-of-scope patterns from the engagement's `scope.md`
   (the `hunt` scaffold creates it) or from inline patterns.
2. Checks each asset deterministically with `engine/scope.py`:
   - apex `acme.com` → the apex **and** any subdomain
   - `*.acme.com` → any subdomain (NOT the bare apex)
   - `api.acme.com` → that exact host
   - `10.0.0.0/8` → any IP in the CIDR
   - `re:^lab[0-9]+\.acme\.io$` → explicit regex (prefix `re:`)
3. With `--resolve`, resolves each host (DNS only — the target is never touched)
   and requires the resulting IP to fall inside the program's in-scope netblocks.
4. Prints `IN-SCOPE` / `OUT-OF-SCOPE <reason>` / `UNVERIFIED <reason>` and exits
   non-zero if any asset is out of scope — so it can gate automation.

## Usage

```
/scope api.acme.com
/scope api.acme.com staging.acme.io admin.acme.com
```

Under the hood, run the deterministic checker directly:

```bash
# Against the engagement scope.md (preferred — fill scope.md from the program page first)
python3 engine/scope.py api.acme.com --md ~/Targets/acme/scope.md

# Netblock-scoped program: name match is NOT scope — check where it resolves
python3 engine/scope.py api.acme.com --md ~/Targets/acme/scope.md --resolve

# Plus netblock ownership, for programs that gate on "is this really their infra"
python3 engine/scope.py api.acme.com --md ~/Targets/acme/scope.md --resolve --whois

# Or with inline patterns (repeat --in-scope / --out-of-scope per pattern)
python3 engine/scope.py api.acme.com evil.com \
  --in-scope acme.com --in-scope '*.acme.io' --out-of-scope admin.acme.com
```

`--strict` also exits non-zero on `UNVERIFIED`; `--json` emits machine-readable output.

## The DNS-resolution gate — `--resolve`

Many programs scope by **where a host resolves**, not by its DNS name: *"only
subdomains that resolve inside the IP ranges below"*. A `*.acme.com` subdomain
pointing at a third-party VAS provider, white-label partner, or someone else's
datacenter is **out of scope even though the name matches** — and a report on it
gets closed as out-of-scope no matter how good the bug is.

Name-only matching cannot see that. `--resolve` can:

```
OUT-OF-SCOPE  partner.acme.com  (partner.acme.com matches an in-scope name rule
              but resolves to 203.0.113.9 — OUTSIDE every in-scope netblock.
              Name match alone is not scope.)
```

Scope files declare netblocks as ordinary in-scope bullets. CIDR (`10.0.0.0/24`),
single addresses, and range shorthand (`195.47.255.208–255`, any dash character)
are all recognised and populate the IP gate automatically.

When netblocks are declared and you run **without** `--resolve`, the verdict is
`UNVERIFIED`, not `IN-SCOPE` — the check is deliberately unable to approve a host
it has not placed.

## `--whois` — host ownership

Some programs publish no netblocks and instead judge ownership by hand
("does this host genuinely belong to us?"). `--whois` resolves and then looks up
the netblock owner (local `whois` binary, else RDAP over HTTPS) so a name-matching
host sitting on a third party's infrastructure is visible before you test it:

```
UNVERIFIED    partner.acme.com  (… no in-scope netblocks published …)
                 owner 203.0.113.9: netname=DC-SOMEHOST-NET, org=Some Hosting
                                    Customers net, country=XX, asn=AS64500
```

An org/country that isn't the program's is the signal to stop and ask, not to test.
Note this queries a registry (whois server or `rdap.org`), so it only runs when
explicitly requested.

## Rules

- **Run this before any HTTP touch.** An `OUT-OF-SCOPE` result is a hard stop —
  do not probe the asset.
- **`UNVERIFIED` is not approval.** It means code could not place the host. Resolve
  it (`--resolve`), check ownership (`--whois`), or ask the program — do not treat
  it as a soft yes.
- If `scope.md` is still the empty template (`(paste ... here)` placeholders),
  fill it from the program page first; an empty in-scope list = default-deny =
  everything rejected, which is the safe default.
- Deny wins: if an asset matches both an in-scope and an out-of-scope rule, it is
  out of scope. Out-of-scope netblocks deny on the resolved IP too.
- `engine/poc_runtime.py` enforces the same resolution gate before firing any PoC
  whenever the engagement's scope declares netblocks.
