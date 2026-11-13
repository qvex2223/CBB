---
name: hunt-source-leak
description: "TRIGGER — start of every recon session, before deep manual testing: check for `.js.map`, `/swagger.json`/`/openapi.json`, `.env`/`.git`, webpack chunks, `robots.txt`/`security.txt`, `asset-manifest.json`. Also whenever a secret is `hardcoded` in a client-reachable artifact — an API key, access token, `credential`, connection string or `webhook` URL read out of a public JS `bundle`, chunk or config. SKIP — web2-recon for the broader subdomain/URL-discovery pipeline this feeds into; hunt-api-misconfig once a leaked route/secret is being exploited rather than just discovered."
sources: hackerone_public, offensive_research
report_count: 31
---

# HUNT-SOURCE-LEAK — Source Code & Build Artifact Leakage

## Crown Jewel Targets

Source map exposing TypeScript source = see all API routes, auth logic, secrets. Swagger/OpenAPI JSON = complete API surface map.

**Highest-value findings:**
- **`.js.map` source maps** — reconstruct full TypeScript/ES6 source code → find hardcoded API keys, internal endpoints, auth logic bypasses
- **`swagger.json` / `openapi.json`** — complete REST API specification with all endpoints, parameters, auth schemes, and internal route names
- **`.env` / `.env.production`** — APP_KEY, DB_PASSWORD, API_KEY, SECRET_KEY in plaintext
- **`.git/` exposure** — `git clone` the entire source history → all past hardcoded secrets
- **`asset-manifest.json` / `_next/static/`** — all JS bundle paths → systematic source map discovery
- **`build-info` / `info.json`** — git commit hash, build timestamp, dependency versions → CVE targeting

---

## Phase 1 — Quick Wins (Run First)

```bash
# These 10 requests take <30 seconds and often yield Critical findings
for PATH in \
  "/.env" \
  "/.env.production" \
  "/.env.local" \
  "/.git/HEAD" \
  "/swagger.json" \
  "/api/swagger.json" \
  "/v1/swagger.json" \
  "/openapi.json" \
  "/api/openapi.json" \
  "/api-docs"; do
  STATUS=$(curl -s -o /tmp/sl_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] HIT: https://$TARGET$PATH"
    head -5 /tmp/sl_test
    echo "---"
  fi
done
```

---

## Phase 2 — Source Map Discovery

```bash
# Step 1: Get asset manifest to find all JS bundle paths
curl -s "https://$TARGET/asset-manifest.json" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/static/js/main.*.js" 2>/dev/null | head -3

# Next.js
BUILD_ID=$(curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
curl -s "https://$TARGET/_next/static/$BUILD_ID/_buildManifest.js" | head -5

# Step 2: For each JS bundle, check for source map reference at end of file
for JS_URL in $(curl -s https://$TARGET/ | grep -oP 'src="[^"]*\.js"' | sed 's/src="//;s/"//'); do
  LAST_LINE=$(curl -s "https://$TARGET$JS_URL" | tail -1)
  echo "$LAST_LINE" | grep -q "sourceMappingURL" && echo "[+] Source map: $JS_URL"
done

# Step 3: Download and reconstruct source from .map files
JS_URL="https://$TARGET/static/js/main.abc123.js"
MAP_URL="${JS_URL}.map"
curl -s "$MAP_URL" | python3 -c "
import sys, json, os
data = json.load(sys.stdin)
sources = data.get('sources', [])
contents = data.get('sourcesContent', [])
for i, (src, content) in enumerate(zip(sources, contents)):
    if content:
        path = '/tmp/sourcemap_extract/' + src.replace('../','').replace('./',''). replace('webpack://','')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)
        print(f'[+] Extracted: {src}')
"

# Step 4: Grep extracted source for secrets
grep -r "API_KEY\|SECRET\|PASSWORD\|TOKEN\|PRIVATE" /tmp/sourcemap_extract/ 2>/dev/null
grep -r "process\.env\." /tmp/sourcemap_extract/ 2>/dev/null | grep -v "NEXT_PUBLIC_" | head -20
grep -r "http://internal\|localhost\|127\.0\.0\.1\|10\.\|172\.\|192\.168" /tmp/sourcemap_extract/ 2>/dev/null | head -20
```

---

## Phase 3 — Swagger / OpenAPI Discovery

```bash
# Common paths
SWAGGER_PATHS=(
  "/swagger.json" "/swagger.yaml" "/swagger/"
  "/api/swagger.json" "/api/swagger.yaml"
  "/v1/swagger.json" "/v2/swagger.json" "/v3/swagger.json"
  "/openapi.json" "/openapi.yaml"
  "/api/openapi.json" "/api-docs" "/api-docs.json"
  "/api/v1/swagger.json" "/api/v2/swagger.json"
  "/rest/swagger.json" "/rest/api-docs"
  "/.well-known/openapi.json"
  "/graphql/schema.json"
)

for PATH in "${SWAGGER_PATHS[@]}"; do
  STATUS=$(curl -s -o /tmp/swagger_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found: https://$TARGET$PATH"
    # Extract all API paths from swagger
    python3 -c "
import sys, json
try:
    d = json.load(open('/tmp/swagger_test'))
    paths = list(d.get('paths', {}).keys())
    print(f'Endpoints: {len(paths)}')
    print('\n'.join(sorted(paths)))
except: pass
" | head -50
  fi
done
```

---

## Phase 4 — .git Exposure

```bash
# Check if .git directory is accessible
curl -s "https://$TARGET/.git/HEAD" | grep -q "ref:" && echo "[+] .git exposed!"

# If exposed, reconstruct repo
# Tool: git-dumper
pip3 install git-dumper
git-dumper "https://$TARGET/.git/" /tmp/dumped-repo/

# Grep for secrets in all git history
cd /tmp/dumped-repo && \
  git log --all --oneline 2>/dev/null | head -20
  git grep -i "password\|secret\|api_key\|token" $(git rev-list --all) 2>/dev/null | head -30

# trufflehog on git history
trufflehog git file:///tmp/dumped-repo/ 2>/dev/null | head -50
```

---

## Phase 5 — Forgotten Files & Debug Endpoints

```bash
# Build artifacts and debug files
DEBUG_PATHS=(
  "/build-info.json" "/build/build-info.json"
  "/info" "/actuator/info" "/api/info"
  "/version" "/api/version" "/_version"
  "/health" "/status" "/ping"
  "/robots.txt" "/security.txt" "/.well-known/security.txt"
  "/sitemap.xml" "/manifest.json" "/browserconfig.xml"
  "/crossdomain.xml" "/clientaccesspolicy.xml"
  "/phpinfo.php" "/info.php" "/test.php"
  "/server-status" "/server-info" "/.htaccess"
  "/web.config" "/applicationHost.config"
  "/WEB-INF/web.xml" "/META-INF/MANIFEST.MF"
  "/package.json" "/composer.json" "/Gemfile"
  "/Dockerfile" "/docker-compose.yml" "/.dockerenv"
)

for PATH in "${DEBUG_PATHS[@]}"; do
  STATUS=$(curl -s -o /tmp/debug_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found: https://$TARGET$PATH ($STATUS, $(wc -c < /tmp/debug_test) bytes)"
    head -3 /tmp/debug_test
    echo "---"
  fi
done
```

---

## Phase 6 — .DS_Store File Listing

```bash
# .DS_Store files on macOS-deployed web servers reveal directory structure
curl -s "https://$TARGET/.DS_Store" | xxd | head -10

# Parse .DS_Store to extract filenames
pip3 install ds_store
python3 -c "
from ds_store import DSStore
with DSStore.open('/tmp/ds_store_test', 'r') as d:
    for entry in d:
        print(entry.filename)
"

# Recursive .DS_Store enumeration
# Tool: https://github.com/lijiejie/ds_store_exp
python3 ds_store_exp.py "https://$TARGET/"
```

---

## Phase 7 — webpack Chunk Analysis

```bash
# Download and analyze webpack chunks for hardcoded values
# Find chunk files
curl -s https://$TARGET/ | grep -oP '"[^"]*\.chunk\.js"' | tr -d '"' | while read chunk; do
  echo "Analyzing: $chunk"
  curl -s "https://$TARGET$chunk" | \
    grep -oE '"(api_key|apiKey|secret|password|token|key)"\s*:\s*"[^"]+"' | head -5
done

# Also grep for internal hostnames
curl -s "https://$TARGET/static/js/main.*.js" | \
  grep -oE '"(https?://[^"]*internal[^"]*|http://[^"]*localhost[^"]*)"' | sort -u

# Check for Base64-encoded secrets
curl -s "https://$TARGET/static/js/main.*.js" | \
  grep -oP '"[A-Za-z0-9+/]{30,}={0,2}"' | while read b64; do
  DECODED=$(echo "$b64" | tr -d '"' | base64 -d 2>/dev/null)
  echo "$DECODED" | grep -iE "key|secret|password|token" && echo "  B64: $b64"
done
```

---

## Phase 7b — Bundle comprehension: AST, not grep (added 2026-10-21)

Phase 7's greps answer "does this string appear". They cannot answer the question that
decides a finding: **what does the code do with it.** Three of this workspace's recorded
misreads came from exactly that gap — a per-file `innerHTML` grep that missed the
framework's compiled raw-HTML helper, a `searchParams.get` grep that missed the prefix and
wholesale readers, and a hydration-list read that concluded a server-only route had no
client code. `jsluice` and `wakaru` are installed here; use them before writing any claim
about a bundle.

```bash
# jsluice — tree-sitter AST. Extracts by HOW a value is used, so it recovers the
# concatenated URL that grep sees only as three fragments, and it classifies secrets
# by provider instead of matching entropy.
curl -s "https://$TARGET/_next/static/chunks/main-*.js" -o /tmp/b.js
jsluice urls    /tmp/b.js | jq -c '{url,method,queryParams,bodyParams,headers}'
jsluice secrets /tmp/b.js | jq -c '{kind,severity,data}'
jsluice query -q '(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "postMessage")))' /tmp/b.js

# wakaru — decompiles the bundle back into per-module readable source. This is what
# makes a sink census possible: resolve the runtime's raw-HTML export, then find its
# importers, instead of grepping each minified file.
wakaru /tmp/b.js -o /tmp/unbundled/
grep -rn "dangerouslySetInnerHTML\|innerHTML\|\$\$render" /tmp/unbundled/

# wakaru extract — when a .map exists, pull the ORIGINALS out of sourcesContent
# (no reconstruction guesswork, no unwebpack-sourcemap needed)
wakaru extract /tmp/b.js.map -o /tmp/src/
```

**Rule:** a sink/reader census is only a census if it was taken over resolved modules.
A grep over minified chunks is a sample, and it must be reported as one.

---

## Chain Table

| Source leak finding | Chain to | Impact |
|--------------------|----------|--------|
| Source map with API key | Use key directly → API access | High/Critical |
| Source map with auth logic | Find auth bypass route | Critical |
| Swagger → internal endpoints | Test undocumented admin routes | High |
| .git exposed | Full source history → all past secrets | Critical |
| build-info with git hash | CVE targeting exact version | High |
| .env with DB_PASSWORD | Direct database access | Critical |

---

## Tools

```bash
# INSTALLED HERE (verified 2026-10-21)
jsluice urls|secrets|query <file.js>   # AST extraction, see Phase 7b
wakaru <bundle.js> -o out/             # decompile bundle -> modules
wakaru extract <bundle.js.map> -o src/ # originals from sourcesContent
gitleaks detect --no-git -s /tmp/repo/ # secret scan on a reconstructed tree
trivy fs /tmp/repo/                    # dependency CVEs once package files are recovered
katana -u https://$TARGET -jc -d 3     # crawl, including JS-derived endpoints

# NOT installed on this box — do not plan around these:
#   trufflehog  -> go install refuses it (replace directives); use gitleaks, then
#                  validate any hit by hand with ~/security-research/tools/data/keyhacks.md
#   git-dumper  -> no pip. Reconstruct .git by hand: fetch .git/HEAD, .git/config,
#                  .git/index, .git/refs/*, then walk .git/objects/<2>/<38> and
#                  `python3 -c "import zlib,sys;sys.stdout.buffer.write(zlib.decompress(open(sys.argv[1],'rb').read()))"`
#   source-map-explorer / unwebpack-sourcemap -> superseded by wakaru above
```

---

## Validation

✅ Source map: reconstructed TypeScript source contains API endpoints or hardcoded secrets
✅ Swagger: JSON contains internal endpoints not visible in UI
✅ .git exposed: git-dumper successfully clones repo, secrets in history
✅ .env exposed: DATABASE_URL, API_KEY, SECRET_KEY visible in plaintext

**Severity:**
- .env with credentials: Critical
- .git with secrets in history: Critical
- Source map with secrets: High
- Swagger with internal routes: Medium-High
- robots.txt only: Informational

## From leak to impact: validate and map (from the disclosed crit/high corpus, `docs/disclosed-reports/HIGH-CRIT-LESSONS-2026-11.md`)

The two largest payouts in the 51-report H1 set ($50,000 and $39,999.99) were a leaked
credential plus careful validation, with no exploitation. A secret left in `primitives/` as
"info" is the commonest way that money is lost. Vector `secret-exposure`:
1. Extract: `jsluice`, `gitleaks` over bundles, `.map` `sourcesContent`, app strings, env-like files.
   bbcurl flags `SIGNAL SECRET-IN-BODY` with a prefix only.
2. Validate with **one read-only identity call** per `~/security-research/tools/data/keyhacks.md`.
3. Map blast radius read-only: scopes/permissions, orgs, repos, buckets. Never write and never
   read customer data. Prove access with a SHA-256 of one private file or a count, not contents.
4. A signed cookie that carries its own key (itsdangerous) or a weak HS256 secret means forging
   a session for **your own second account** only.
5. Report with the scope map. Rotate-and-revoke is the vendor's job; say exactly which key (prefix).

### Namespace squatting (corpus gap pass 2026-11-02, `docs/disclosed-reports/corpus-2026-11/GAP.md`)
A predictable bucket, package or container name that the target's pipeline reads from or
writes to, but which is unregistered. Registering it (where policy allows, under your own
account) receives cross-tenant data or serves code. Prove it with the target's request arriving
at your object, never with their data contents.
