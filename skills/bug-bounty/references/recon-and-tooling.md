# Recon, tooling and source-code mining

> **Canonical sources:** `web2-recon` owns the recon pipeline, `bb-local-toolkit` owns
> where each tool actually lives on this machine, and `hunt-source-leak` owns
> sourcemap/`.env`/`.git` discovery. Check the tool stand in the workspace CLAUDE.md
> before running anything here: several tools named below are not installed, and a
> command that returns `command not found` is a step that gets silently skipped.

## Go Binaries
| Tool | Use |
|------|-----|
| subfinder | Passive subdomain enum |
| httpx | Probe live hosts |
| dnsx | DNS resolution |
| nuclei | Template scanner |
| katana | Crawl |
| waybackurls | Archive URLs |
| gau | Known URLs |
| dalfox | XSS scanner |
| ffuf | Fuzzer |
| anew | Dedup append |
| qsreplace | Replace param values |
| assetfinder | Subdomain enum |
| gf | Grep patterns (xss, sqli, ssrf, redirect) |
| interactsh-client | OOB callbacks |

## Tools to Install When Needed
| Tool | Use | Install |
|------|-----|---------|
| arjun | Hidden parameter discovery | `pip3 install arjun` |
| paramspider | URL parameter mining | `pip3 install paramspider` |
| kiterunner | API endpoint brute | `go install github.com/assetnote/kiterunner/cmd/kr@latest` |
| cloudenum | Cloud asset enumeration | `pip3 install cloud_enum` |
| trufflehog | Secret scanning | `brew install trufflehog` |
| gitleaks | Secret scanning | `brew install gitleaks` |
| XSStrike | Advanced XSS scanner | `pip3 install xsstrike` |
| SecretFinder | JS secret extraction | `pip3 install secretfinder` |
| sqlmap | SQL injection | `pip3 install sqlmap` |
| subzy | Subdomain takeover | `go install github.com/LukaSikic/subzy@latest` |

## Static Analysis (Semgrep Quick Audit)
```bash
# Install: pip3 install semgrep

# Broad security audit
semgrep --config=p/security-audit ./
semgrep --config=p/owasp-top-ten ./

# Language-specific rulesets
semgrep --config=p/javascript ./src/
semgrep --config=p/python ./
semgrep --config=p/golang ./
semgrep --config=p/php ./
semgrep --config=p/nodejs ./

# Targeted rules
semgrep --config=p/sql-injection ./
semgrep --config=p/jwt ./

# Custom pattern (example: find SQL concat in Python)
semgrep --pattern 'cursor.execute("..." + $X)' --lang python .

# Output to file for analysis
semgrep --config=p/security-audit ./ --json -o semgrep-results.json 2>/dev/null
cat semgrep-results.json | jq '.results[] | select(.extra.severity == "ERROR") | {path:.path, check:.check_id, msg:.extra.message}'
```

## FFUF Advanced Techniques
```bash
# THE ONE RULE: Always use -ac (auto-calibrate filters noise automatically)
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac

# Authenticated raw request file — IDOR testing (save Burp request to req.txt, replace ID with FUZZ)
seq 1 10000 | ffuf --request req.txt -w - -ac

# Authenticated API endpoint brute
ffuf -u https://TARGET/api/FUZZ -w wordlist.txt -H "Cookie: session=TOKEN" -ac

# Parameter discovery
ffuf -w ~/wordlists/burp-parameter-names.txt -u "https://target.com/api/endpoint?FUZZ=test" -ac -mc 200

# Hidden POST parameters
ffuf -w ~/wordlists/burp-parameter-names.txt -X POST -d "FUZZ=test" -u "https://target.com/api/endpoint" -ac

# Subdomain scan
ffuf -w subs.txt -u https://FUZZ.target.com -ac

# Filter strategies:
# -fc 404,403          Filter status codes
# -fs 1234             Filter by response size
# -fw 50               Filter by word count
# -fr "not found"      Filter regex in response body
# -rate 5 -t 10        Rate limit + fewer threads for stealth
# -e .php,.bak,.old    Add extensions
# -o results.json      Save output
```

## AI-Assisted Tools
- **strix** (usestrix.com) -- open-source AI scanner for automated initial sweep

---

# PHASE 1: RECON

## Standard Recon Pipeline
```bash
# Step 1: Subdomains
subfinder -d TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only TARGET | anew /tmp/subs.txt

# Step 2: Resolve + live hosts
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect -o /tmp/live.txt

# Step 3: URL collection
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -silent | anew /tmp/urls.txt
echo TARGET | waybackurls | anew /tmp/urls.txt
gau TARGET | anew /tmp/urls.txt

# Step 4: Nuclei scan
nuclei -l /tmp/live.txt -severity critical,high,medium -silent -o /tmp/nuclei.txt

# Step 5: JS secrets
cat /tmp/urls.txt | grep "\.js$" | sort -u > /tmp/jsfiles.txt
# Run SecretFinder on each JS file

# Step 6: GitHub dorking (if target has public repos)
# GitDorker -org TARGET_ORG -d dorks/alldorksv3
```

## Cloud Asset Enumeration
```bash
# Manual S3 brute
for suffix in dev staging test backup api data assets static cdn; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://${TARGET}-${suffix}.s3.amazonaws.com/")
  [ "$code" != "404" ] && echo "$code ${TARGET}-${suffix}.s3.amazonaws.com"
done
```

## API Endpoint Discovery
```bash
# ffuf API endpoint brute
ffuf -u https://TARGET/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302,403 -ac
```

## HackerOne Scope Retrieval
```bash
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { team(handle: \"PROGRAM_HANDLE\") { name url policy_scopes(archived: false) { edges { node { asset_type asset_identifier eligible_for_bounty instruction } } } } }"}' \
  | jq '.data.team.policy_scopes.edges[].node'
```

## Quick Wins Checklist
- [ ] Subdomain takeover (`subjack`, `subzy`)
- [ ] Exposed `.git` (`/.git/config`)
- [ ] Exposed env files (`/.env`, `/.env.local`)
- [ ] Default credentials on admin panels
- [ ] JS secrets (SecretFinder, jsluice)
- [ ] Open redirects (`?redirect=`, `?next=`, `?url=`)
- [ ] CORS misconfig (test `Origin: https://evil.com` + credentials)
- [ ] S3/cloud buckets
- [ ] GraphQL introspection enabled
- [ ] Spring actuators (`/actuator/env`, `/actuator/heapdump`)
- [ ] Firebase open read (`https://TARGET.firebaseio.com/.json`)

## Technology Fingerprinting

| Signal | Technology |
|---|---|
| Cookie: `XSRF-TOKEN` + `*_session` | Laravel |
| Cookie: `PHPSESSID` | PHP |
| Header: `X-Powered-By: Express` | Node.js/Express |
| Response: `wp-json`/`wp-content` | WordPress |
| Response: `{"errors":[{"message":` | GraphQL |
| Header: `X-Powered-By: Next.js` | Next.js |

## Framework Quick Wins

**Laravel**: `/horizon`, `/telescope`, `/.env`, `/storage/logs/laravel.log`
**WordPress**: `/wp-json/wp/v2/users`, `/xmlrpc.php`, `/?author=1`
**Node.js**: `/.env`, `/graphql` (introspection), `/_debug`
**AWS Cognito**: `/oauth2/userInfo` (leaks Pool ID), CORS reflects arbitrary origins

## Source Code Recon
```bash
# Security surface
cat SECURITY.md 2>/dev/null; cat CHANGELOG.md | head -100 | grep -i "security\|fix\|CVE"
git log --oneline --all --grep="security\|CVE\|fix\|vuln" | head -20

# Dev breadcrumbs
grep -rn "TODO\|FIXME\|HACK\|UNSAFE" --include="*.ts" --include="*.js" | grep -iv "test\|spec"

# Dangerous patterns (JS/TS)
grep -rn "eval(\|innerHTML\|dangerouslySetInner\|execSync" --include="*.ts" --include="*.js" | grep -v node_modules
grep -rn "===.*token\|===.*secret\|===.*hash" --include="*.ts" --include="*.js"
grep -rn "fetch(\|axios\." --include="*.ts" | grep "req\.\|params\.\|query\."

# Dangerous patterns (Solidity)
grep -rn "tx\.origin\|delegatecall\|selfdestruct\|block\.timestamp" --include="*.sol"
```

### Language-Specific Grep Patterns

```bash
# JavaScript/TypeScript -- prototype pollution, postMessage, RCE sinks
grep -rn "__proto__\|constructor\[" --include="*.js" --include="*.ts" | grep -v node_modules
grep -rn "postMessage\|addEventListener.*message" --include="*.js" | grep -v node_modules
grep -rn "child_process\|execSync\|spawn(" --include="*.js" | grep -v node_modules

# Python -- pickle, yaml.load, eval, shell injection
grep -rn "pickle\.loads\|yaml\.load\|eval(" --include="*.py" | grep -v test
grep -rn "subprocess\|os\.system\|os\.popen" --include="*.py" | grep -v test
grep -rn "__import__\|exec(" --include="*.py"

# PHP -- type juggling, unserialize, LFI
grep -rn "unserialize\|eval(\|preg_replace.*e" --include="*.php"
grep -rn "==.*password\|==.*token\|==.*hash" --include="*.php"
grep -rn "\$_GET\|\$_POST\|\$_REQUEST" --include="*.php" | grep "include\|require\|file_get"

# Go -- template.HTML, race conditions
grep -rn "template\.HTML\|template\.JS\|template\.URL" --include="*.go"
grep -rn "go func\|sync\.Mutex\|atomic\." --include="*.go"

# Ruby -- YAML.load, mass assignment
grep -rn "YAML\.load[^_]\|Marshal\.load\|eval(" --include="*.rb"
grep -rn "attr_accessible\|permit(" --include="*.rb"

# Rust -- panic on network input, unsafe blocks
grep -rn "\.unwrap()\|\.expect(" --include="*.rs" | grep -v "test\|encode\|to_bytes\|serialize"
grep -rn "unsafe {" --include="*.rs" -B5 | grep "read\|recv\|parse\|decode"
grep -rn "as u8\|as u16\|as u32\|as usize" --include="*.rs" | grep -v "checked\|saturating\|wrapping"
```

---

# PHASE 2: LEARN (Pre-Hunt Intelligence)

## Read Disclosed Reports
```bash
# By program on HackerOne
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ hacktivity_items(first:25, order_by:{field:popular, direction:DESC}, where:{team:{handle:{_eq:\"PROGRAM\"}}}) { nodes { ... on HacktivityDocument { report { title severity_rating } } } } }"}' \
  | jq '.data.hacktivity_items.nodes[].report'
```

## "What Changed" Method
1. Find disclosed report for similar tech
2. Get the fix commit
3. Read the diff -- identify the anti-pattern
4. Grep your target for that same anti-pattern

## Threat Model Template
```
TARGET: _______________
CROWN JEWELS: 1.___ 2.___ 3.___
ATTACK SURFACE:
  [ ] Unauthenticated: login, register, password reset, public APIs
  [ ] Authenticated: all user-facing endpoints, file uploads, API calls
  [ ] Cross-tenant: org/team/workspace ID parameters
  [ ] Admin: /admin, /internal, /debug
HIGHEST PRIORITY (crown jewel x easiest entry):
  1.___ 2.___ 3.___
```

## 6 Key Patterns from Top Reports
1. **Feature Complexity = Bug Surface** -- imports, integrations, multi-tenancy, multi-step workflows
2. **Developer Inconsistency = Strongest Evidence** -- `timingSafeEqual` in one place, `===` elsewhere
3. **"Else Branch" Bug** -- proxy/gateway passes raw token without validation in else path
4. **Import/Export = SSRF** -- every "import from URL" feature has historically had SSRF
5. **Secondary/Legacy Endpoints = No Auth** -- `/api/v1/` guarded but `/api/` isn't
6. **Race Windows in Financial Ops** -- check-then-deduct as two DB operations = double-spend

---

# PHASE 3: HUNT

## Note-Taking System (Never Hunt Without This)
```markdown
# TARGET: company.com -- SESSION 1

## Interesting Leads (not confirmed bugs yet)
- [14:22] /api/v2/invoices/{id} -- no auth check visible in source, testing...

## Dead Ends (don't revisit)
- /admin -> IP restricted, confirmed by trying 15+ bypass headers

## Anomalies
- GET /api/export returns 200 even when session cookie is missing
- Response time: POST /api/check-user -> 150ms (exists) vs 8ms (doesn't)

## Rabbit Holes (time-boxed, max 15 min each)
- [ ] 10 min: JWT kid injection on auth endpoint

## Confirmed Bugs
- [15:10] IDOR on /api/invoices/{id} -- read+write
```

## Subdomain Type -> Hunt Strategy
- **dev/staging/test**: Debug endpoints, disabled auth, verbose errors
- **admin/internal**: Default creds, IP bypass headers (`X-Forwarded-For: 127.0.0.1`)
- **api/api-v2**: Enumerate with kiterunner, check older unprotected versions
- **auth/sso**: OAuth misconfigs, open redirect in `redirect_uri`
- **upload/cdn**: CORS, path traversal, stored XSS

## CVE-Seeded Audit Approach
1. **Build a CVE eval set** -- collect 5-10 prior CVEs for the target codebase
2. **Reproduce old bugs** -- verify you can find the pattern in older code
3. **Pattern-match forward** -- search for the same anti-pattern in current code
4. **Focus on wide attack surfaces** -- JS engines, parsers, anything processing untrusted external input

## Rust/Blockchain Source Code (Hard-Won Lessons)

**Panic paths: encoding vs decoding** -- `.unwrap()` on an encoding path is NOT attacker-triggerable. Only panics on deserialization/decoding of network input are exploitable.

**"Known TODO" is not a mitigation** -- A comment like `// Votes are not signed for now` doesn't mean safe.

**Pattern-based hunting from confirmed findings** -- If `verify_signed_vote` is broken, check `verify_signed_proposal` and `verify_commit_signature`.

```bash
# Rust dangerous patterns (network-facing)
grep -rn "\.unwrap()\|\.expect(" --include="*.rs" | grep -v "test\|encode\|to_bytes\|serialize"
grep -rn "if let Ok\|let _ =" --include="*.rs" | grep -i "verify\|sign\|cert\|auth"
grep -rn "TODO\|FIXME\|not signed\|not verified\|for now" --include="*.rs" | grep -i "sign\|verify\|cert\|auth"
```

---

# VULNERABILITY HUNTING CHECKLISTS

