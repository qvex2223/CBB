#!/usr/bin/env python3
"""
vectors.py — the anti-dead-end engine.

The workspace already enforces its brakes in code (scope.py, pacing.py) while the
"keep going, rotate the vector, do not close a host on a hunch" half lives only as
prose in CLAUDE.md. Prose loses to prose: an agent that is told ten times to be
careful and once to be aggressive resolves every ambiguous moment into "analyze
more". So the push half gets code too.

Three things live here:

  * a per-target **vector ledger** — every attack vector on a target with a status,
    the number of requests actually fired at it, and the mutations already burned.
    `next` always has an answer, so "I am stuck" stops being a terminal state.
  * a **mutation matrix** — given a vector class and what was already tried, the
    next concrete thing to send. This is what "смени вектор" means operationally.
  * a **stuck detector** — reads hunt-memory/audit.jsonl and notices when many
    requests went out with nothing logged, i.e. grinding instead of rotating.

A vector cannot be marked `dead` without fired requests backing it (audit.jsonl is
the witness). That is the rule the workspace's own data says was never followed:
threads closed as "good hygiene" with zero requests behind them.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from memory import resolve_dir  # type: ignore
except Exception:  # noqa: BLE001 - keep usable standalone
    def resolve_dir(explicit=None) -> Path:  # type: ignore
        env = os.environ.get("CBH_MEMORY_DIR")
        if env:
            return Path(env)
        return Path(__file__).resolve().parent.parent.parent / "hunt-memory"


STATUSES = ("untried", "active", "dead", "confirmed", "blocked")

# ---------------------------------------------------------------------------
# vector catalog — what is always worth trying, ranked by what it pays if true.
# impact is the ranking key for `next`; it is deliberately impact-first, not
# ease-first (the same rule CLAUDE.md states in prose).
# ---------------------------------------------------------------------------
CATALOG: Dict[str, Dict] = {
    "missing_authorization": {"impact": 95, "skill": "hunt-auth-bypass",
                              "hint": "strip Authorization/Cookie entirely on every state-changing route"},
    "idor":                  {"impact": 90, "skill": "hunt-idor",
                              "hint": "swap the object id across two identities, then repeat on PUT/DELETE"},
    # CVE-2026-123009: the server's OWN redirect carried `?from_base_branch=<branch>`, read
    # back with no binding and no validator, and the write check then resolved against the
    # attacker-owned repo the request targeted. Deliberately NOT in HINT_CLASSES: a manifest
    # records no redirect, so seeding it from a risk hint would propose it everywhere. It
    # reaches a ledger through the Cartesian seeder and through a lane that observed the
    # signal.
    # CVE-2026-114607: OAuth `state` records and magic-link tokens shared one `verification`
    # store, indexed by token, with no column recording which flow created the row — so a
    # record minted by one flow was accepted by the other flow's verifier and minted a session
    # for an account the attacker does not own. Impact 92: it is an account takeover with no
    # victim interaction.
    "token-purpose":         {"impact": 92, "skill": "hunt-oauth",
                              "hint": "feed a record minted by one auth flow to the verifier of "
                                      "another (state -> magic-link, invite/reset -> the other "
                                      "verifier); one store, two purposes, no type column"},
    "redirect-param":        {"impact": 82, "skill": "hunt-idor",
                              "hint": "census parameters that appear ONLY in a Location header, "
                                      "then re-send them on the route the redirect pointed at; "
                                      "a 400 may already have performed the write"},
    "business-logic":        {"impact": 88, "skill": "hunt-business-logic",
                              "hint": "negative/zero/overflow amounts, replay, step-skip, state-machine reorder"},
    "rce":                   {"impact": 98, "skill": "hunt-rce", "hint": "benign markers only (id, sleep)"},
    "ssrf":                  {"impact": 85, "skill": "hunt-ssrf",
                              "hint": "internal ranges, redirect-follow, DNS-only variant before giving up"},
    "sqli":                  {"impact": 85, "skill": "hunt-sqli",
                              "hint": "boolean diff first, then timing; escalate to "
                                      "`bbscan sqlmap --level=1 --risk=1 --technique=B` only "
                                      "AFTER the pair diffed by hand"},
    "auth-bypass":           {"impact": 84, "skill": "hunt-auth-bypass",
                              "hint": "forced browse, role swap, expired/none-alg token, sibling controller"},
    "race-condition":        {"impact": 78, "skill": "hunt-race-condition",
                              "hint": "single-packet attack on coupon/credit/limit endpoints"},
    "graphql":               {"impact": 75, "skill": "hunt-graphql",
                              "hint": "introspection, then node(id) IDOR, then unauth mutations"},
    "file-upload":           {"impact": 74, "skill": "hunt-file-upload", "hint": "svg, html, double extension"},
    "deserialization":       {"impact": 74, "skill": "hunt-deserialization", "hint": "magic bytes in any b64 blob"},
    "ssti":                  {"impact": 72, "skill": "hunt-ssti", "hint": "{{7*7}} / ${7*7} in every reflected field"},
    "xxe":                   {"impact": 70, "skill": "hunt-xxe", "hint": "any endpoint that accepts XML or SVG/DOCX"},
    "api-misconfig":         {"impact": 68, "skill": "hunt-api-misconfig",
                              "hint": "old API versions, debug routes, swagger/openapi, actuator"},
    "xss":                   {"impact": 60, "skill": "hunt-xss", "hint": "marker first, payload second"},
    "cors":                  {"impact": 55, "skill": "hunt-cors", "hint": "null origin + credentials"},
    "host-header":           {"impact": 55, "skill": "hunt-host-header", "hint": "password-reset poisoning"},
    "cache-poison":          {"impact": 65, "skill": "hunt-cache-poison",
                              "hint": "unkeyed input: headers, then the COOKIE class (split_*/ab_*/exp_*) "
                                      "that no header wordlist finds; prove the query string is keyed "
                                      "before sending anything reflectable"},
    "csrf":                  {"impact": 50, "skill": "hunt-csrf", "hint": "state-changing POST without token/SameSite"},
    "open-redirect":         {"impact": 40, "skill": "hunt-open-redirect", "hint": "only matters chained into OAuth"},
    "info-leak":             {"impact": 40, "skill": "hunt-source-leak", "hint": "sourcemaps, .git, backups, env"},
    # --- added 2026-11-02 from the disclosed crit/high corpus
    #     (docs/disclosed-reports/HIGH-CRIT-LESSONS-2026-11.md) ---
    "sibling-interface":     {"impact": 88, "skill": "hunt-differential",
                              "hint": "the same privileged operation via its OTHER interface: REST vs "
                                      "GraphQL, Next.js Server Action, mobile/partner API, ActivityPub, "
                                      "export/import — the check usually lives on only one of them"},
    "secret-exposure":       {"impact": 86, "skill": "hunt-source-leak",
                              "hint": "credential in bundle/sourcemap/app/response -> validate with one "
                                      "read-only call (keyhacks.md) -> map scope; the validation IS the finding"},
    "filter-injection":      {"impact": 82, "skill": "hunt-api-misconfig",
                              "hint": "user-controlled filter FIELD or OPERATOR (field__op=, $filter gt/lt, "
                                      "where[x][not]=) on a list endpoint -> char-by-char read of a hash/token"},
    "parser-differential":   {"impact": 80, "skill": "hunt-differential",
                              "hint": "two components read one string differently (CDN vs origin, proxy vs "
                                      "app, validator vs shell/MTA): census the chain, then detection-only "
                                      "probes; never weaponize a desync without approval"},
}

# ---------------------------------------------------------------------------
# mutation matrix — ordered. index N is "what to try after N-1 failed".
# generic moves apply to every class and run out last.
# ---------------------------------------------------------------------------
GENERIC_MUTATIONS: List[str] = [
    "method swap: GET->POST->PUT->PATCH->DELETE on the same path (frameworks often authz only one verb)",
    "API version swap: /v2/ -> /v1/ -> /v3/ -> /internal/ -> /beta/ (the fix rarely lands on the old route)",
    "auth removal: send with no Cookie, no Authorization, no CSRF token — separately, not all at once",
    "auth downgrade: expired token, other-account token, empty token, alg=none, token from a sibling tenant",
    "content-type swap: application/json -> x-www-form-urlencoded -> multipart -> text/plain (parser differs)",
    "parameter pollution: repeat the param, array form param[]=, JSON body vs query vs header placement",
    "path normalization: //path, /./path, /path/, %2e%2e%2f, ;/ , unicode dot, trailing %00",
    "header override: X-Original-URL, X-Rewrite-URL, X-Forwarded-For, X-Forwarded-Host, X-Real-IP",
    "case + encoding: uppercase path segment, double-URL-encode the payload, unicode homoglyph",
    "sibling enumeration: every other route in the same controller/prefix, not just this one",
    "mobile / partner surface: same API under /mobile, /app, /partner, different Host or User-Agent",
    "response-shape probing: identical request, wrong id type (string vs int vs uuid) — error text leaks logic",
]

CLASS_MUTATIONS: Dict[str, List[str]] = {
    "idor": [
        "increment/decrement the id; then a UUID from another object you legitimately own",
        "same id on PUT/DELETE after GET was refused",
        "id moved from path to body to query to header (X-User-Id)",
        "batch/bulk endpoint that takes an id array — authz is often per-request, not per-item",
        "GraphQL node(id:) / REST expand=, include=, fields= parameters reaching the same object",
    ],
    "missing_authorization": [
        "drop every credential header on the state-changing route itself",
        "call the internal/worker/external API prefix directly (…/external/, …/internal/, …/worker/)",
        "OPTIONS then the real verb — CORS preflight sometimes reveals allowed unauth verbs",
        "sibling methods of the same worker/controller — guess by naming convention, then confirm by 404-vs-405",
    ],
    "business-logic": [
        "negative, zero, and fractional amounts",
        "replay the same signed request twice (idempotency key reuse)",
        "skip a step: call step 3 with only step 1 completed",
        "swap the currency/plan/tariff id for a cheaper one mid-flow",
        "race the state transition (two requests, one packet)",
    ],
    "ssrf": [
        "127.0.0.1 / localhost / 0.0.0.0 / [::1] / 169.254.169.254",
        "decimal, octal, and hex IP encodings of the same host",
        "attacker host that 302-redirects to the internal target",
        "DNS-only callback to prove blind SSRF before hunting a reachable service",
        "protocol swap: file://, gopher://, dict://, http over a non-80 port",
    ],
    "sqli": [
        "boolean pair: ' AND '1'='1  vs  ' AND '1'='2 — diff the bodies, not the status",
        "the same payload in ORDER BY / LIMIT / column-name position (not just WHERE)",
        "JSON body field instead of query param",
        "second-order: inject on write, observe on the read endpoint",
        "the pair diffed? escalate: `CBH_PROJECT=<eng> bbscan sqlmap -u '<url>' --level=1 "
        "--risk=1 --technique=B --flush-session` (bbscan = scope + pacing + mandatory header "
        "+ audit; raw sqlmap has none). Enumeration and --risk>1 need written approval",
    ],
    "auth-bypass": [
        "forced browse to the post-auth route directly",
        "role field in JWT/body/header flipped to admin",
        "the sibling endpoints in the same controller — the fix is usually per-route",
        "old API version of the same route",
    ],
    "graphql": [
        "introspection; if disabled, field suggestion via typo'd field names",
        "aliases to bypass per-field rate limits",
        "mutations without auth",
        "node(id:) / relay global ids as an IDOR primitive",
    ],
    "xss": [
        "unencoded marker check first (z1z<svg) before any payload",
        "attribute context, JS-string context, and href/src context separately",
        "the value on the *response* of a different endpoint that renders the same field",
        "consumer: what turns script execution into ATO here — OAuth implicit/prompt=none token "
        "theft, identity-link/email-change API, a token-returning endpoint on a sibling host",
        "self-XSS/cookie-driven reflection + a cache NOT keyed on that input = stored XSS for everyone "
        "(prove keying with two request-ids first, own session only)",
        "non-HTML sink: the same value rendered by a server-side PDF/screenshot/email renderer (-> SSRF/SSTI)",
    ],
    # --- added 2026-11-02 from the disclosed crit/high corpus ---
    "sibling-interface": [
        "list every interface that reaches the same object: REST, GraphQL, Server Actions "
        "(Next-Action header, 40-42 hex ids in the bundle), mobile API, export/import, websocket",
        "fire the privileged operation through each interface with the LOW-priv identity; "
        "read the state back, do not trust the 200",
        "client-side-only role guard: call the admin API the UI hides with a normal session",
        "secondary protocol (federation/ActivityPub/webhook/SOAP) for the same data: does it carry "
        "the read-permission check the primary route has?",
        "GET vs POST of the same handler: signature/CSRF/auth check inside an `if method == POST`",
    ],
    "secret-exposure": [
        "extract: jsluice / gitleaks over bundles, .map sourcesContent, mobile app strings, env-like files",
        "validate with ONE read-only identity call per keyhacks.md (whoami/user/account endpoint)",
        "map blast radius read-only: scopes/permissions listing, orgs, buckets — never write, never read "
        "customer data; prove with a hash or a count, not contents",
        "signed cookie/session that carries its own key (itsdangerous, JWT HS256 weak secret) -> forge "
        "a session for your OWN second account only",
    ],
    "filter-injection": [
        "harmless filter first, then an unexpected field name (password, reset_token, secret) — does "
        "the count/length/order change?",
        "operator injection: field__startswith= / __regex= (Django), $filter gt/lt (OData), "
        "[not]/[contains] (Prisma/qs), {\"$ne\":null} (Mongo)",
        "relation traversal in the field path: owner__password, user.resetToken",
        "oracle = result count / response length / error / timing; prove on your OWN account's "
        "field before any other row",
    ],
    "parser-differential": [
        "run `cbh diffprobe <url>` first (detection-only, ~14 paced GETs through bbcurl): header "
        "masking + path normalization + layer census, LEADs only where a variant diverges from both "
        "baseline and impossible-path control",
        "census the chain from banners: CDN/WAF -> proxy -> app server -> framework (Server, Via, "
        "Cf-Cache-Status, X-Cache, x-powered-by)",
        "header masking: Host vs ' Host' vs 'Host ' vs 'Xost' vs 'Host :' — compare status+length+Server",
        "delimiter/normalization map with a cache buster: /path<X>rand for ; . %00 %23 %3f, then "
        "/a/../x vs /x and /x/..%2fy",
        "cache key probe before anything reflectable (keyed vs unkeyed param, Accept-Encoding)",
        "framework internal headers sent from outside: x-middleware-subrequest, x-now-route-matches, "
        "X-Original-URL — require a TRANSITION (blocked->200, cache-control flip), not a status",
    ],
}

# Oracle ladder for blind classes — appended so a blind vector cannot be killed
# (mark dead refuses while mutations remain) before an oracle was tried.
_ORACLE_LADDER = [
    "build an oracle before calling it blind: boolean error (1/(cond)) vs sleep; response length; "
    "result count; response ORDER in a single-packet pair; error text carrying output",
    "timing pair as fallback: 30 single-packet pairs, compare the bottom quartile; >=80% consistent "
    "ordering = a lead, then pair it with a non-blind variant of the same class",
]
for _c in ("sqli", "ssti", "rce", "xxe", "deserialization"):
    CLASS_MUTATIONS.setdefault(_c, [])
    CLASS_MUTATIONS[_c] = CLASS_MUTATIONS[_c] + _ORACLE_LADDER

CLASS_MUTATIONS["ssrf"] = CLASS_MUTATIONS["ssrf"] + [
    "make a blind SSRF observable: own redirect-loop responder (301->302->...->310) — does the app "
    "print the chain / final body / status?",
    "IPv4-mapped IPv6 [::ffff:a9fe:a9fe], legacy metadata paths (/v1beta1, /latest/meta-data without "
    "token), ECS 169.254.170.2 — the payout line in the corpus is whether credentials were READ",
    "server-side renderers as the fetcher: HTML/iframe into a PDF/screenshot/email renderer, "
    "sitemap/import/webhook-test/avatar-by-URL features",
]
CLASS_MUTATIONS["auth-bypass"] = CLASS_MUTATIONS["auth-bypass"] + [
    "execution-after-redirect: every 3xx on a protected route — read the body without -L; "
    "a page or data inside the redirect is the bypass",
    "the same operation through a sibling interface (GraphQL/Server Action/mobile) — see class "
    "sibling-interface",
    "trusted-header identity: X-Real-IP/X-Forwarded-For/claim values folded into an allow decision",
]
CLASS_MUTATIONS["idor"] = CLASS_MUTATIONS["idor"] + [
    "two identities + a tenant set up BEFORE the first payload (owner, member, outsider); "
    "ids taken from public share URLs / denial bodies / exports into destructive verbs",
    # CVE-2026-126338: the direct read answers 404 while a nested reference makes the server
    # copy the foreign object into one you own. A mutation on `idor`, not a class of its own,
    # so it cannot double a host's ledger. NEVER a sweep: in the disclosed case the reference
    # ids are one instance-wide sequence that does not reveal its tenant, so enumeration is
    # unaimable and bans the source IP.
    "nested reference on an id you ALREADY hold (reply/parent/source_id/template_id/copy_from): "
    "the server copies the foreign object into yours while the direct route still 404s — "
    "200 hit / 500 object exists but inner key wrong / 404 no such id",
    # CVE-2026-118535: trust stored against a permanent object id and not revoked when the
    # object changed owner. Needs a second identity we hold, so the lane is marked
    # REGISTER FIRST rather than held back.
    "transfer an object we own (repo/project/workspace/team) to our SECOND identity, then "
    "enumerate what still trusts it: secrets, tokens, webhooks, scoped sources, allowlists — "
    "trust stored against a permanent id survives the change of owner",
]
CLASS_MUTATIONS["business-logic"] = CLASS_MUTATIONS["business-logic"] + [
    "client-supplied fields that should be server-side: price/resident/role/template/destination "
    "phone in the request body; array instead of string (user[email][]=a&user[email][]=b)",
    "replay the request the UI gated (verification step) directly; is the OTP/request id bound "
    "to the resource it verifies?",
]
CLASS_MUTATIONS["rce"] = CLASS_MUTATIONS["rce"] + [
    "argument injection: a value starting with `--` into a CLI argv (git/curl/tar/convert) when the "
    "end-of-options separator is missing — `--output=` file write, then a known target file",
]
CLASS_MUTATIONS["business-logic"] = CLASS_MUTATIONS["business-logic"] + [
    "import/export round-trip: export your own object, add admin-only booleans (template, role, "
    "custom_attributes) or framework setters (remote_<field>_url), re-import",
]
CLASS_MUTATIONS.setdefault("token-purpose", [])
CLASS_MUTATIONS["token-purpose"] = CLASS_MUTATIONS["token-purpose"] + [
    "census first: does the app run TWO token flows (OAuth state + magic-link / invite / "
    "password-reset / device-code)? one store with no type column is the whole bug",
    "a `state` record submitted to the magic-link verifier — put the victim address in the "
    "field that verifier reads, not at the top level of the body (CVE-2026-114607)",
    "a magic-link / invite / reset token submitted to the OAuth state consumer",
    "same token twice across the two verifiers: does either consume it, or do both accept it?",
]
CLASS_MUTATIONS.setdefault("redirect-param", [])
CLASS_MUTATIONS["redirect-param"] = CLASS_MUTATIONS["redirect-param"] + [
    "corpus diff: every parameter present in a Location value and absent from the request that "
    "produced it, re-sent on the route the redirect pointed at",
    "the same parameter after the grant on the SOURCE object is revoked — the check may resolve "
    "against the destination you own",
    "read the object back after a 4xx: in CVE-2026-123009 the push ran before the stale-commit "
    "check, so a 400 had already created and populated the branch",
]
CLASS_MUTATIONS.setdefault("open-redirect", [])
CLASS_MUTATIONS["open-redirect"] = CLASS_MUTATIONS["open-redirect"] + [
    "consumer: chain into an OAuth redirect_uri / Dynamic Client Registration / logout returnTo "
    "to carry a code or token off-origin — alone it pays ~0",
]
CLASS_MUTATIONS.setdefault("cache-poison", [])
CLASS_MUTATIONS["cache-poison"] = CLASS_MUTATIONS["cache-poison"] + [
    "composition: a self-XSS / X-Forwarded-Host redirect / reflected cookie becomes critical "
    "once the cache key is controllable — prove keying with two request-ids, own session",
    # Next.js Cache Components, Nov 2026. DETERMINISTIC arms only: the cold-fill race
    # (CVE-2026-119790) needs concurrent requests, which is blast radius on other users and
    # availability, so it is deliberately absent from the matrix.
    "cache IDENTITY, not cache key: two calls whose arguments differ only in a way the identity "
    "hash flattens (binary/Buffer args, Date, a class instance) — CVE-2026-119349",
    "nested cached function: does the OUTER entry get stored before the INNER one's root "
    "parameters (tenant/locale/user) are recorded? CVE-2026-119351 — vary the inner scope with "
    "the outer arguments held still",
]
CLASS_MUTATIONS.setdefault("file-upload", [])
CLASS_MUTATIONS["file-upload"] = CLASS_MUTATIONS["file-upload"] + [
    "write-time check vs read-time behaviour: response-content-type override on S3/MinIO, "
    "image check without extension check (polyglot), archive entry filenames kept on extract",
]

# ---------------------------------------------------------------------------
# consumers — "what turns this primitive into impact?". Disclosed crit/high
# reports are compositions; the Low gets closed as hygiene because nobody asked
# who consumes it. `mark ... confirmed` prints these; `consumers <class>` too.
# ---------------------------------------------------------------------------
CONSUMERS: Dict[str, List[str]] = {
    "xss": ["OAuth implicit / prompt=none token theft -> ATO", "identity-link or email-change API -> ATO",
            "unkeyed cache -> stored for all visitors", "CSP gap via allowlisted JSONP/modulepreload gadget"],
    "open-redirect": ["OAuth redirect_uri / DCR -> code or token theft", "CSPT 307/308 gadget -> cross-origin fetch",
                      "logout returnTo chain"],
    "cspt": ["upload/download JSON gadget -> state-changing POST", "third-party 307/308 redirector -> exfil"],
    "ssrf": ["cloud metadata credentials (read them, minimally)", "internal admin/Vault/actuator",
             "redirect-loop to make blind SSRF readable"],
    "info-leak": ["credential -> validate + map scope (secret-exposure)", "internal id -> IDOR on destructive verb",
                  "version -> patch-diff probe"],
    "secret-exposure": ["validated scope -> org/repo/bucket read (prove by hash/count)",
                        "signing key -> forged session for own 2nd account"],
    "cors": ["credentialed read of an endpoint carrying tokens/PII"],
    "host-header": ["password-reset link poisoning -> ATO", "cache poisoning of canonical/redirect"],
    "file-upload": ["served from app origin as HTML -> stored XSS", "server-side parser (ExifTool/XML/archive) -> RCE/XXE"],
    "idor": ["PUT/DELETE on the same id", "id from public share URL / denial body into destructive call"],
    "token-purpose": ["a session for an account we do not own -> ATO (read /me back to prove it)",
                      "a fresh emailVerified account created for an address we do not control",
                      "the second factor skipped, because the other flow never asked for one"],
    "redirect-param": ["read of an object the caller cannot reach on its own route",
                       "write on that object (the push/copy the parameter drives)",
                       "access that survived a revocation — re-test after the grant is removed"],
    "auth-bypass": ["admin function -> data of all users", "sibling interface without the check"],
    "csrf": ["email/password/2FA change -> ATO"],
    "cache-poison": ["stored XSS for all", "token/session in a cached response"],
    "filter-injection": ["reset token char-by-char -> ATO on own 2nd account", "password hash read -> severity by data"],
    "parser-differential": ["auth proxy bypass", "cache poisoning", "request smuggling (detection only)"],
    "sibling-interface": ["privileged write on the unguarded interface -> state change read back",
                          "data read across tenants via the second interface", "role/plan change -> ATO or free tier"],
}


def consumers_for(vclass: str) -> List[str]:
    return CONSUMERS.get(vclass, [])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _vec_dir(memdir: Optional[Path] = None) -> Path:
    d = (memdir or resolve_dir()) / "vectors"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path(target: str, memdir: Optional[Path] = None) -> Path:
    safe = target.replace("/", "_").replace(":", "_")
    return _vec_dir(memdir) / f"{safe}.json"


def load(target: str, memdir: Optional[Path] = None) -> Dict:
    p = _path(target, memdir)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except json.JSONDecodeError:
            pass
    return {"target": target, "created": _now(), "vectors": []}


def save(ledger: Dict, memdir: Optional[Path] = None) -> Path:
    p = _path(ledger["target"], memdir)
    ledger["updated"] = _now()
    p.write_text(json.dumps(ledger, indent=2, ensure_ascii=False))
    return p


def vector_id(vclass: str, endpoint: str) -> str:
    return f"{vclass}:{endpoint}"


def _new_vector(vclass: str, endpoint: str, *, origin: str, reason: str = "",
                priority: Optional[int] = None, operation_id: str = "") -> Dict:
    return {
        "id": vector_id(vclass, endpoint), "class": vclass, "endpoint": endpoint,
        "status": "untried", "requests_fired": 0, "mutations_tried": [], "notes": "",
        "origin": origin, "reason": reason, "operation_id": operation_id,
        "priority": priority if priority is not None else CATALOG.get(vclass, {}).get("impact", 30),
        "created": _now(), "updated": _now(),
    }


def seed(target: str, endpoints: List[str], classes: Optional[List[str]] = None,
         memdir: Optional[Path] = None) -> Dict:
    """Fill the ledger with every (class, endpoint) pair worth trying.

    This is the blunt Cartesian seeder: it knows nothing about the endpoint, so it
    proposes every class for every path. Rows it creates are tagged
    `origin="cartesian"` so `prune` can drop the untouched ones once a real API
    manifest exists. Prefer `seed_from_manifest()` whenever a manifest is available.
    """
    ledger = load(target, memdir)
    known = {v["id"] for v in ledger["vectors"]}
    classes = classes or list(CATALOG)
    for ep in endpoints:
        for c in classes:
            vid = vector_id(c, ep)
            if vid in known:
                continue
            known.add(vid)
            ledger["vectors"].append(_new_vector(c, ep, origin="cartesian"))
    return ledger


# ---------------------------------------------------------------------------
# manifest-driven seeding — the replacement for the Cartesian product.
#
# `(every endpoint x every class)` produces a ledger nobody can finish and whose
# ranking is pure catalog impact, so `next` recommends RCE on a static asset. The
# normalized API manifest already carries risk hints derived from the operation's
# own shape (path variables, write methods, sensitive schema fields, declared
# security), and the workflow graph already carries ranked business hypotheses.
# Seeding from those yields vectors that have a *reason*, and the reason is what
# `next` should be ranking on.
# ---------------------------------------------------------------------------
HINT_CLASSES: Dict[str, List[str]] = {
    "object-authorization":   ["idor"],
    "function-authorization": ["auth-bypass", "missing_authorization", "sibling-interface"],
    "property-authorization": ["api-misconfig"],
    "business-flow":          ["business-logic"],
    "state-change":           ["csrf"],
    "declared-public":        ["missing_authorization"],
    # `token-purpose` rides the oauth hint deliberately and nothing broader: the bug needs a
    # second token flow to exist, and an oauth-hinted operation is where one is.
    "oauth":                  ["auth-bypass", "open-redirect", "token-purpose"],
    "graphql":                ["graphql"],
}

# workflow hypothesis kind -> the vector class that owns it
HYPOTHESIS_CLASSES: Dict[str, str] = {
    "replay":          "business-logic",
    "step-skip":       "business-logic",
    "value-boundary":  "business-logic",
    "cross-principal": "idor",
    "hidden-field":    "api-misconfig",
    "race":            "race-condition",
}


def endpoint_of(op: Dict) -> str:
    """Ledger endpoint key for an operation: method + canonical path."""
    return f"{op.get('method', 'GET')} {op.get('path', '/')}".strip()


def classes_for_operation(op: Dict) -> List[Dict]:
    """Which vector classes this one operation actually justifies, and why."""
    hints = list(op.get("risk_hints") or [])
    out: Dict[str, str] = {}
    for hint in hints:
        for vclass in HINT_CLASSES.get(hint, []):
            out.setdefault(vclass, hint)
    # An unauthenticated-looking write is the classic missing-authorization case
    # even when no other hint fired.
    if op.get("method") in ("POST", "PUT", "PATCH", "DELETE") and op.get("secured") is not True:
        out.setdefault("missing_authorization", "unsecured-write")
    # Reflected/echoed input surfaces: any operation that takes parameters can carry
    # an injection, but only those two classes — not the whole catalog.
    if op.get("parameters") or op.get("fields"):
        out.setdefault("sqli", "accepts-input")
        out.setdefault("xss", "accepts-input")
    if not out:
        out["info-leak"] = "no-risk-hint"
    return [{"class": c, "reason": r} for c, r in out.items()]


def seed_from_manifest(target: str, manifest: Dict, workflow: Optional[Dict] = None,
                       memdir: Optional[Path] = None, hosts: Optional[List[str]] = None) -> Dict:
    """Derive vectors from operation risk hints + workflow hypotheses.

    Only relevant classes are created, each carrying the hint that justified it and
    a priority that blends catalog impact with the operation's own risk. Existing
    vectors are never duplicated or downgraded.
    """
    ledger = load(target, memdir)
    by_id = {v["id"]: v for v in ledger["vectors"]}
    hosts = {h.lower() for h in (hosts or [])}
    ops = manifest.get("operations") or []
    added = 0
    for op in ops:
        if hosts and (op.get("host") or "").lower() not in hosts:
            continue
        ep = endpoint_of(op)
        risk_bonus = min(len(op.get("risk_hints") or []) * 3, 12)
        for item in classes_for_operation(op):
            vclass, reason = item["class"], item["reason"]
            vid = vector_id(vclass, ep)
            existing = by_id.get(vid)
            priority = CATALOG.get(vclass, {}).get("impact", 30) + risk_bonus
            if existing:
                # keep whatever progress exists; upgrade provenance and priority only
                existing["origin"] = "manifest"
                existing["reason"] = existing.get("reason") or reason
                existing["operation_id"] = existing.get("operation_id") or op.get("id", "")
                existing["priority"] = max(existing.get("priority") or 0, priority)
                continue
            vec = _new_vector(vclass, ep, origin="manifest", reason=reason,
                              priority=priority, operation_id=op.get("id", ""))
            ledger["vectors"].append(vec)
            by_id[vid] = vec
            added += 1

    op_paths = {op.get("id"): endpoint_of(op) for op in ops}
    for hyp in (workflow or {}).get("hypotheses") or []:
        vclass = HYPOTHESIS_CLASSES.get(hyp.get("kind", ""))
        ep = op_paths.get(hyp.get("operation_id"))
        if not vclass or not ep:
            continue
        vid = vector_id(vclass, ep)
        reason = f"workflow:{hyp['kind']}"
        existing = by_id.get(vid)
        if existing:
            existing["priority"] = max(existing.get("priority") or 0, int(hyp.get("priority", 0)))
            notes = existing.get("notes", "")
            if hyp.get("test") and hyp["test"] not in notes:
                existing["notes"] = (notes + f"\n[{reason}] {hyp['test']}").strip()
            continue
        vec = _new_vector(vclass, ep, origin="manifest", reason=reason,
                          priority=int(hyp.get("priority", 0)),
                          operation_id=hyp.get("operation_id", ""))
        vec["notes"] = f"[{reason}] {hyp.get('test', '')}".strip()
        ledger["vectors"].append(vec)
        by_id[vid] = vec
        added += 1

    ledger["seeded_from_manifest"] = _now()
    ledger["last_seed_added"] = added
    return ledger


def prunable(ledger: Dict) -> List[Dict]:
    """Legacy Cartesian rows that were never touched — safe to drop, and only those.

    A row is prunable only if nothing was ever invested in it: still `untried`, zero
    requests fired, no mutation burned, no note written, and not manifest-derived.
    Everything else is somebody's work and stays.
    """
    return [v for v in ledger.get("vectors", [])
            if v.get("origin", "cartesian") != "manifest"
            and v.get("status") == "untried"
            and not v.get("requests_fired")
            and not v.get("mutations_tried")
            and not (v.get("notes") or "").strip()]


def prune(target: str, apply: bool = False, memdir: Optional[Path] = None) -> Dict:
    """Dry-run by default. Writes a timestamped backup before it removes anything."""
    ledger = load(target, memdir)
    doomed = prunable(ledger)
    report = {"target": target, "total": len(ledger.get("vectors", [])),
              "prunable": len(doomed), "kept": len(ledger.get("vectors", [])) - len(doomed),
              "applied": False, "backup": None,
              "sample": [v["id"] for v in doomed[:10]]}
    if not apply or not doomed:
        return report
    path = _path(target, memdir)
    if path.exists():
        backup = path.with_suffix(f".json.bak-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}")
        backup.write_text(path.read_text())
        report["backup"] = str(backup)
    doomed_ids = {v["id"] for v in doomed}
    ledger["vectors"] = [v for v in ledger["vectors"] if v["id"] not in doomed_ids]
    save(ledger, memdir)
    report["applied"] = True
    return report


def mutations_for(vclass: str) -> List[str]:
    return CLASS_MUTATIONS.get(vclass, []) + GENERIC_MUTATIONS


def next_mutation(vec: Dict) -> Optional[str]:
    tried = set(vec.get("mutations_tried", []))
    for m in mutations_for(vec["class"]):
        if m not in tried:
            return m
    return None


def untried_mutations(vec: Dict) -> List[str]:
    """The matrix entries this vector has not burned yet.

    The count MUST be derived from the matrix, not from len(mutations_tried):
    the two disagreed, so a vector with twelve unrecognised labels recorded
    reported "0 mutations still untried" while next_mutation() still handed
    back the first entry — a refusal message that contradicted itself.
    """
    tried = set(vec.get("mutations_tried", []))
    return [m for m in mutations_for(vec["class"]) if m not in tried]


def resolve_mutation(vclass: str, label: str) -> Optional[str]:
    """Map whatever the caller typed onto the canonical matrix string.

    `mark --mutation` used to record the raw label, but next_mutation()
    compares against the exact matrix text, so a shorthand ("method swap",
    "3") registered nothing: the vector looked untouched no matter how many
    mutations had really been burned. Accepted forms, in order:
      * the exact matrix string;
      * a 1-based index into mutations_for(vclass);
      * a case-insensitive prefix or substring that matches exactly one entry.
    Returns None when the label matches nothing, or is ambiguous between two
    entries — the caller refuses rather than recording a guess.
    """
    matrix = mutations_for(vclass)
    if not label:
        return None
    label = label.strip()
    if label in matrix:
        return label
    if label.isdigit():
        i = int(label)
        if 1 <= i <= len(matrix):
            return matrix[i - 1]
        return None
    low = label.lower()
    hits = [m for m in matrix if m.lower().startswith(low)]
    if len(hits) != 1:
        hits = [m for m in matrix if low in m.lower()]
    return hits[0] if len(hits) == 1 else None


def reward_profile(project_dir: Optional[Path] = None) -> Dict:
    """The engagement's payout model, as the programme wrote it (profile.json).

    `reward_by_class`  {class: max payout} — ranks a class by what this programme pays.
    `downrank_classes` classes the programme excludes unless impact is demonstrated
                       (open redirect, version disclosure, ...). Accepted either as
                       {class: reason} or as a bare list of class names, which is how
                       the workspace CLAUDE.md documents it and how every real
                       profile.json writes it; a list is normalised to a dict here so
                       callers downstream can always `.get()` a reason.
    Empty when the engagement has not filled them in: ranking then falls back to
    catalog impact alone, exactly as before 2026-10-20.
    """
    try:
        if project_dir is None:
            from pacing import find_project_dir
            project_dir = find_project_dir()
        if project_dir is None:
            return {}
        prof = json.loads((Path(project_dir) / "profile.json").read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    return {"reward_by_class": prof.get("reward_by_class") or {},
            "downrank_classes": _as_downrank_map(prof.get("downrank_classes"))}


DOWNRANK_DEFAULT_REASON = "excluded by the programme unless impact is demonstrated"


def _as_downrank_map(value) -> Dict[str, str]:
    """Accept both profile.json shapes for `downrank_classes` and return a dict.

    A bare list is the documented and actually-used shape. Before this normalisation
    `next_vectors()` called `.get()` on it and raised AttributeError, which took out
    `cbh vectors next` and the hunt-nudge rotation hints for every engagement whose
    profile used the list form -- i.e. all of them.
    """
    if isinstance(value, dict):
        return {str(k): (v if isinstance(v, str) else DOWNRANK_DEFAULT_REASON)
                for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return {str(c): DOWNRANK_DEFAULT_REASON for c in value}
    return {}


REWARD_BONUS_MAX = 25      # a class at the programme's top payout gets +25
DOWNRANK_PENALTY = 15      # tried later, never dropped: excluded-without-impact classes are chain material


# Classes added 2026-11-02 are mechanisms, not payout categories: a programme's
# reward_by_class never names them, so without this they earned +0 against +25 for
# the category they actually pay as (field test: sibling-interface ranked 68th).
PAYOUT_ALIAS: Dict[str, List[str]] = {
    "sibling-interface": ["auth-bypass", "idor", "missing_authorization"],
    "secret-exposure": ["info-leak", "ato"],
    "filter-injection": ["idor", "ato", "info-leak"],
    "parser-differential": ["auth-bypass", "cache-poison"],
}


def payout_adjustment(vclass: str, profile: Optional[Dict]) -> int:
    if not profile:
        return 0
    adj = 0
    by = profile.get("reward_by_class") or {}
    if by:
        top = max(by.values()) or 1
        if vclass in by:
            adj += round(REWARD_BONUS_MAX * by[vclass] / top)
        else:
            alias = [by[a] for a in PAYOUT_ALIAS.get(vclass, []) if a in by]
            if alias:
                adj += round(REWARD_BONUS_MAX * max(alias) / top)
    if vclass in (profile.get("downrank_classes") or {}):
        adj -= DOWNRANK_PENALTY
    return adj


def rank(vectors: List[Dict], profile: Optional[Dict] = None) -> List[Dict]:
    def key(v):
        # A manifest-seeded vector carries the priority its own operation earned
        # (risk hints, workflow hypothesis). Fall back to raw catalog impact only
        # for rows nobody derived from evidence.
        impact = v.get("priority") or CATALOG.get(v["class"], {}).get("impact", 30)
        # untried before active; a vector with fired requests behind it ranks below
        # a fresh one of the same impact, so breadth happens before grinding.
        status_bonus = {"untried": 20, "active": 10}.get(v["status"], -100)
        return -(impact + status_bonus + payout_adjustment(v["class"], profile)
                 - min(v.get("requests_fired", 0), 15))
    return sorted(vectors, key=key)


def next_vectors(target: str, count: int = 5, memdir: Optional[Path] = None) -> List[Dict]:
    ledger = load(target, memdir)
    live = [v for v in ledger["vectors"] if v["status"] in ("untried", "active")]
    profile = reward_profile()
    out = []
    for v in rank(live, profile)[:count]:
        item = dict(v)
        item["payout"] = (profile.get("reward_by_class") or {}).get(v["class"])
        item["downrank"] = (profile.get("downrank_classes") or {}).get(v["class"])
        item["skill"] = CATALOG.get(v["class"], {}).get("skill", "bb-methodology")
        item["hint"] = CATALOG.get(v["class"], {}).get("hint", "")
        item["next_mutation"] = next_mutation(v)
        out.append(item)
    return out


def mark(target: str, vid: str, status: str, mutation: Optional[str] = None,
         note: str = "", requests: int = 0, force: bool = False,
         memdir: Optional[Path] = None) -> Dict:
    """Update a vector. Marking `dead` without fired requests is refused."""
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    ledger = load(target, memdir)
    for v in ledger["vectors"]:
        if v["id"] != vid:
            continue
        v["requests_fired"] = v.get("requests_fired", 0) + max(requests, 0)
        if mutation:
            canonical = resolve_mutation(v["class"], mutation)
            if canonical is None:
                matrix = mutations_for(v["class"])
                listing = "\n".join(f"  {i}. {m}" for i, m in enumerate(matrix, 1))
                raise SystemExit(
                    f"NOTHING WAS RECORDED (status, --requests and --note are not written either; exit 1). "
                    f"unrecognised mutation label {mutation!r} for class {v['class']!r}. "
                    "Recording it verbatim would mark nothing — the guard compares against the "
                    "matrix text — so the vector would still look untouched.\n"
                    f"Pass the exact string, its 1-based number, or an unambiguous prefix:\n{listing}")
            if canonical not in v.setdefault("mutations_tried", []):
                v["mutations_tried"].append(canonical)
        if status == "dead" and not force:
            fired = v["requests_fired"]
            remaining = untried_mutations(v)
            if fired == 0:
                raise SystemExit(
                    f"refusing to kill {vid}: 0 requests fired at it. "
                    "A vector closed on analysis is an open thread, not a dead one. "
                    "Fire something, or use --force with a reason in --note.")
            if remaining:
                raise SystemExit(
                    f"refusing to kill {vid}: {len(remaining)} "
                    f"mutations still untried. Next one: {remaining[0]}\n"
                    "Use --force only if the whole class is structurally impossible here.")
        v["status"] = status
        if note:
            v["notes"] = (v.get("notes", "") + f"\n[{_now()}] {note}").strip()
        v["updated"] = _now()
        save(ledger, memdir)
        return v
    raise SystemExit(f"no such vector: {vid}")


# ---------------------------------------------------------------------------
# stuck detection — grinding one host with nothing logged is the observable
# symptom of "he hits a wall and keeps hitting it".
# ---------------------------------------------------------------------------
def _tail_jsonl(path: Path, limit: int) -> List[Dict]:
    if not path.exists():
        return []
    rows: List[Dict] = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows[-limit:]


def _host_of(url: str) -> str:
    s = url.split("://", 1)[-1]
    return s.split("/", 1)[0]


def stuck_report(threshold: int = 15, memdir: Optional[Path] = None) -> Optional[Dict]:
    """Requests fired since the last hunt-memory write, grouped by host."""
    mem = memdir or resolve_dir()
    audit = _tail_jsonl(mem / "audit.jsonl", 400)
    journal = _tail_jsonl(mem / "journal.jsonl", 50)
    if not audit:
        return None
    last_write = journal[-1].get("timestamp", "") if journal else ""
    since = [r for r in audit if r.get("timestamp", "") > last_write]
    if len(since) < threshold:
        return None
    hosts: Dict[str, int] = {}
    for r in since:
        for u in r.get("urls", []) or []:
            h = _host_of(u)
            hosts[h] = hosts.get(h, 0) + 1
    top = sorted(hosts.items(), key=lambda kv: -kv[1])
    out = {
        "requests_since_last_finding": len(since),
        "engagement": since[-1].get("engagement", ""),
        "hosts": top[:5],
        "top_host": top[0][0] if top else "",
    }
    # How many of those requests actually got a *different* answer? A burst of 30
    # that produced 2 distinct bodies is not 30 probes, and the operator deserves to
    # be told which of the two situations they are in.
    try:
        import responses  # type: ignore
        with_bodies = [r for r in since if r.get("body_sha256")]
        if with_bodies:
            out.update({k: v for k, v in responses.identical_run(with_bodies).items()
                        if k in ("distinct", "identical_ratio")})
            out["responses_recorded"] = len(with_bodies)
    except Exception:  # noqa: BLE001
        pass
    return out


def revisit(target: str, memdir: Optional[Path] = None) -> List[Dict]:
    """Past non-confirmed findings + the mutation that was never tried on them.

    'Пройтись по прошлым находкам другими методами' — a rejected/partial entry is
    a vector with one burned mutation, not a closed door.
    """
    mem = memdir or resolve_dir()
    rows = _tail_jsonl(mem / "journal.jsonl", 500)
    ledger = load(target, memdir)
    by_id = {v["id"]: v for v in ledger["vectors"]}
    out = []
    for r in rows:
        if target and r.get("target") != target:
            continue
        if r.get("result") == "confirmed":
            continue
        vclass = r.get("vuln_class") or "info-leak"
        ep = r.get("endpoint", "")
        vid = vector_id(vclass, ep)
        vec = by_id.get(vid, {"class": vclass, "endpoint": ep, "mutations_tried": []})
        out.append({
            "endpoint": ep,
            "vuln_class": vclass,
            "result": r.get("result"),
            "when": r.get("timestamp", "")[:10],
            "skill": CATALOG.get(vclass, {}).get("skill", "bb-methodology"),
            "untried_mutation": next_mutation(vec),
            "mutations_left": len(mutations_for(vclass)) - len(vec.get("mutations_tried", [])),
        })
    return out


def _print_next(items: List[Dict]) -> None:
    if not items:
        print("ledger empty — seed it:  cbh vectors seed <target> --endpoints a,b,c")
        return
    for i, v in enumerate(items, 1):
        print(f"{i}. [{v['class']}] {v['endpoint']}")
        print(f"   skill: {v['skill']}  ·  status: {v['status']}  ·  fired: {v['requests_fired']}")
        if v.get("payout"):
            print(f"   programme pays up to: {v['payout']:,}".replace(",", " "))
        if v.get("downrank"):
            print(f"   DOWNRANKED by programme: {v['downrank']}")
        if v.get("hint"):
            print(f"   hint: {v['hint']}")
        if v.get("next_mutation"):
            print(f"   next move: {v['next_mutation']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vectors", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("seed", help="create the vector ledger for a target")
    p.add_argument("target")
    p.add_argument("--endpoints", required=True, help="comma-separated")
    p.add_argument("--classes", help="comma-separated; default = whole catalog")

    p = sub.add_parser("seed-from-manifest",
                       help="derive only relevant vectors from an API manifest (+workflow)")
    p.add_argument("target")
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--workflow", type=Path, help="workflow.json from engine/workflow_graph.py")
    p.add_argument("--hosts", default="", help="comma-separated; limit to these manifest hosts")

    p = sub.add_parser("prune", help="drop untouched legacy Cartesian rows (dry-run by default)")
    p.add_argument("target")
    p.add_argument("--apply", action="store_true", help="actually write (backs up first)")

    p = sub.add_parser("next", help="what to attack next (impact-ranked, never empty)")
    p.add_argument("target")
    p.add_argument("-n", "--count", type=int, default=5)

    p = sub.add_parser("mark", help="update a vector's status")
    p.add_argument("target")
    p.add_argument("id")
    p.add_argument("status", choices=STATUSES)
    p.add_argument("--mutation", help="the mutation just burned")
    p.add_argument("--note", default="")
    p.add_argument("--requests", type=int, default=0)
    p.add_argument("--force", action="store_true")

    p = sub.add_parser("rotate", help="next mutation for a class you are stuck on")
    p.add_argument("vclass")
    p.add_argument("--tried", default="", help="comma-separated indices already burned")

    p = sub.add_parser("revisit", help="old non-confirmed findings + an untried method for each")
    p.add_argument("target")

    p = sub.add_parser("stuck", help="are we grinding? reads audit.jsonl vs journal.jsonl")
    p.add_argument("--threshold", type=int, default=15)

    sub.add_parser("list-classes", help="the catalog with impact ranking")

    p = sub.add_parser("consumers", help="what turns a primitive of this class into impact")
    p.add_argument("vclass")

    args = ap.parse_args(argv)

    if args.cmd == "seed":
        eps = [e.strip() for e in args.endpoints.split(",") if e.strip()]
        cls = [c.strip() for c in args.classes.split(",")] if args.classes else None
        ledger = seed(args.target, eps, cls)
        save(ledger)
        print(f"seeded {len(ledger['vectors'])} vectors for {args.target} -> {_path(args.target)}")
    elif args.cmd == "seed-from-manifest":
        manifest = json.loads(args.manifest.read_text())
        workflow = json.loads(args.workflow.read_text()) if args.workflow else None
        hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
        ledger = seed_from_manifest(args.target, manifest, workflow, hosts=hosts)
        save(ledger)
        print(f"{args.target}: +{ledger['last_seed_added']} vectors from "
              f"{len(manifest.get('operations') or [])} operations "
              f"({len(ledger['vectors'])} total) -> {_path(args.target)}")
    elif args.cmd == "prune":
        rep = prune(args.target, args.apply)
        verb = "pruned" if rep["applied"] else "would prune"
        print(f"{rep['target']}: {verb} {rep['prunable']} of {rep['total']} vectors "
              f"({rep['kept']} kept)")
        for vid in rep["sample"]:
            print(f"  - {vid}")
        if rep["backup"]:
            print(f"backup: {rep['backup']}")
        elif not rep["applied"] and rep["prunable"]:
            print("re-run with --apply to write (a timestamped backup is made first)")
    elif args.cmd == "next":
        _print_next(next_vectors(args.target, args.count))
    elif args.cmd == "mark":
        v = mark(args.target, args.id, args.status, args.mutation, args.note,
                 args.requests, args.force)
        print(f"{v['id']} -> {v['status']} (fired {v['requests_fired']})")
        if v["status"] == "confirmed" and consumers_for(v["class"]):
            print("BEFORE YOU CLOSE IT — who consumes this primitive? (disclosed crit/high are "
                  "compositions; a Low closed alone is the toolkit's commonest miss)")
            for c in consumers_for(v["class"]):
                print(f"  -> {c}")
            print("  run /chain on it; add a `**Chain:** needs `x` · gives `y`` line to the write-up")
    elif args.cmd == "rotate":
        muts = mutations_for(args.vclass)
        tried = {int(i) for i in args.tried.split(",") if i.strip().isdigit()}
        for i, m in enumerate(muts):
            flag = "x" if i in tried else " "
            print(f"[{flag}] {i}. {m}")
    elif args.cmd == "revisit":
        rows = revisit(args.target)
        if not rows:
            print("nothing to revisit — no non-confirmed entries for this target")
        for r in rows:
            print(f"- {r['when']} [{r['vuln_class']}] {r['endpoint']}  ({r['result']})")
            print(f"    skill: {r['skill']}  ·  {r['mutations_left']} methods untried")
            if r["untried_mutation"]:
                print(f"    try:   {r['untried_mutation']}")
    elif args.cmd == "stuck":
        rep = stuck_report(args.threshold)
        if not rep:
            print("not stuck")
            return 0
        print(f"STUCK: {rep['requests_since_last_finding']} requests since the last hunt-memory write")
        for h, n in rep["hosts"]:
            print(f"  {n:4d}  {h}")
        return 1
    elif args.cmd == "consumers":
        cons = consumers_for(args.vclass)
        if not cons:
            print(f"no consumer table for {args.vclass!r} — ask /chain")
        for c in cons:
            print(f"-> {c}")
    elif args.cmd == "list-classes":
        for c, meta in sorted(CATALOG.items(), key=lambda kv: -kv[1]["impact"]):
            print(f"{meta['impact']:3d}  {c:24s} {meta['skill']:22s} {meta['hint']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
