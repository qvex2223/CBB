# PART 2: WORKFLOW — what to do, phase by phase

> The 5-phase workflow in full. `bb-methodology/SKILL.md` carries the mode gate, the
> mindset and the discipline rules; this is the step-by-step it routes into.

## PART 2: WORKFLOW (What to Do)

### The 5-Phase Non-Linear Flow

```
+-------------------------------------------------+
|                                                 |
|  +----------+    +----------+    +----------+   |
|  | 1. RECON |---+| 2. MAP   |---+| 3. FIND  |  |
|  +----------+    +-----+----+    +-----+-----+  |
|       ^                |               |         |
|       |                v               v         |
|       |          +----------+    +----------+    |
|       +----------| 4. PROVE |---+| 5. REPORT|   |
|                  +----------+    +----------+    |
|                                                  |
|  Non-linear: stuck at any phase -> go back       |
|  New API found at phase 3 -> return to phase 2   |
|  WAF blocks at phase 4 -> origin IP from phase 1 |
+-------------------------------------------------+
```

**THIS IS NOT LINEAR.** Move freely between phases. When stuck, return to a previous phase.

### Phase 0: SESSION START (Every Time)

**Before touching any tool, answer these:**

1. **Define**: "Today I target [feature/domain] to achieve [C/I/A/ATO/RCE]"
2. **Select**: Choose 1-2 vuln classes (IDOR, XSS, SSRF, etc.)
3. **Execute**: Focus ONLY on selected techniques

**Route selection -- Wide or Deep?**

| Signal | Wide (recon sweep) | Deep (focused testing) |
|--------|-------------------|----------------------|
| New program, first day | X | |
| Wildcard scope `*.target.com` | X | |
| Main webapp, been here >3 days | | X |
| Scope update (new domain added) | X | |
| Found interesting subdomain | | X |

### Phase 1: RECON

**Goal**: Maximize attack surface. Find what others missed.

**Wide approach** (initial sweep):
```
Subdomain enum -> DNS resolution -> HTTP probing -> Port scan -> Tech detect
```

**Deep approach** (targeted):
```
Google Dorks -> JS file download -> Hidden param discovery -> API mapping
```

| What you find | Next action |
|--------------|-------------|
| Live subdomains with tech stack | Phase 2 (Mapping) |
| Known software (WordPress, Jira) | Check CVEs + defaults immediately |
| Cloud resources (S3, Firebase) | Test permissions (read/write/list) |
| Nothing after 5 min on a host | Skip, try next host (5-minute rule) |

**Command**: `/recon target.com`

### Phase 2: MAPPING & ANALYSIS

**Goal**: Understand the app like its developer does.

**Checklist:**
- [ ] Map all endpoints (Burp/Caido sitemap + JS analysis)
- [ ] Identify auth model (cookie, JWT, OAuth, SAML?)
- [ ] Find business-critical flows (payment, registration, password reset, data export)
- [ ] Download and analyze JS files for hidden routes, secrets, logic
- [ ] Identify roles and permissions (user, admin, API keys)
- [ ] Note "weird" behaviors (anomalies in naming, errors, timing)

| What you find | Next action |
|--------------|-------------|
| JS files with interesting code | Taint analysis (Sink -> Source) |
| OAuth/SAML authentication | OAuth/SAML checklist |
| API with ID parameters | Phase 3, target IDOR |
| Complex business logic (payment, coupon) | Phase 3, target BizLogic |
| postMessage listeners | DOM analysis, postMessage-tracker |

### Phase 3: VULNERABILITY DISCOVERY

**Goal**: Find the bug. Use Error-based first, then Blind-based.

**Decision flow based on what you're testing:**

```
What input are you testing?
+-- ID parameter (user_id, order_id)
|   -> IDOR checklist
+-- Search/filter/sort field
|   -> SQLi, NoSQLi probing
+-- URL input / webhook / PDF gen
|   -> SSRF checklist
+-- Text field reflected in page
|   -> XSS (DOM or reflected)
+-- File upload
|   -> SVG XSS, web shell, path traversal
+-- Price/quantity/coupon
|   -> Business logic, race conditions
+-- Login / 2FA / password reset
|   -> Auth bypass
+-- Profile update API
|   -> Mass Assignment
+-- Template / wiki editor
|   -> SSTI
+-- Nothing obvious
    -> Fuzz with ffuf, try Error-based probing
```

**Error vs Blind decision:**
1. Try Error-based first (send `'`, `"`, `{{7*7}}`, `${7*7}`) -- watch for 500 errors, stack traces
2. No error? Time-based (`SLEEP(10)`, `; sleep 10;`) -- watch response time
3. No time diff? OOB (`curl attacker.com`, interactsh) -- watch for DNS callback
4. Still nothing? Boolean (`AND 1=1` vs `AND 1=0`) -- watch content-length diff

| What you find | Next action |
|--------------|-------------|
| Low-impact behavior (redirect, self-XSS, cookie injection) | Chain it -- find a connector gadget |
| Confirmed vuln (XSS, IDOR, SQLi) | Phase 4 (Prove and Escalate) |
| Blocked by WAF/CSP/403 | Bypass techniques, then retry |
| Known software vuln (CVE) | 1-day speed workflow |
| Nothing after 20 min on this endpoint | Rotate (20-minute rule) |

### Phase 4: PROVE & ESCALATE

**Goal**: Prove maximum business impact. Turn Low into Critical.

**Escalation decision:**
```
What did you find?
+-- XSS
|   +-- Can steal cookie/token? -> Session hijack -> ATO
|   +-- Cookie is HttpOnly? -> Force email change via XHR -> ATO
|   +-- Self-XSS only? -> Find CSRF to trigger it
+-- IDOR
|   +-- Can read PII? -> Automate scraping, show scale
|   +-- Can change password/email? -> Direct ATO
|   +-- UUID only? -> Find UUID leak source, then retry
+-- SSRF
|   +-- DNS only? -> DON'T REPORT. Try cloud metadata
|   +-- Can reach 169.254.169.254? -> Extract keys -> RCE
|   +-- Internal port scan? -> Find Redis/K8s -> RCE
+-- SQLi
|   +-- Error-based? -> Extract data (passwords, tokens)
|   +-- Can INTO OUTFILE? -> Web shell -> RCE
|   +-- Blind? -> Boolean/Time extraction
+-- Open Redirect
|   +-- OAuth flow? -> Token theft -> ATO
|   +-- javascript: scheme? -> XSS
+-- Blocked by defense
|   -> Bypass (WAF/CSP/proxy/sanitizer/2FA)
+-- Low-impact, can't escalate alone
    -> Find connector gadget for chain
```

**After proving impact, check:**
- [ ] Can attack work with 0-1 clicks? (minimize prerequisites)
- [ ] Does it affect all users or specific role?
- [ ] What's the business $ impact?

### Phase 5: VALIDATE & REPORT

**Goal**: Get paid. Make triager's job easy.

**Pre-report gate:**
```
Run /validate (7-Question Gate)
+-- All 7 pass? -> Write report
+-- Any fail? -> KILL the finding. Don't waste time.
+-- Borderline? -> Run /triage for quick go/no-go
```

**Multi-Tool Reproduction Bar (Critical / High only):**

Before labeling a finding **Critical** or **High**, reproduce it via at least **two independent tools** (different stacks, different HTTP libraries). Cross-tool consistency rules out tool-artefact findings (e.g., a curl-only timing differential that disappears under Python `requests` was an artefact, not a bug).

Examples of independent reproductions:
- `curl` + Burp `send_http1_request` (different TLS stacks, different header normalisation)
- Python `requests` + raw socket via `ssl.wrap_socket` (one library normalises, one doesn't)
- Burp Repeater + Python `urllib` (same wire result expected from both)

The reproduction commands MUST be paste-into-shell ready in the report — a triager copies them verbatim. If the curl version requires special flags or breaks on certain systems, include a Python alternative.

**Lesson from an authorized engagement:** All three Critical findings (Authentication.asmx brute-force, TE.CL smuggling, NTLM Type-2 disclosure) were each independently reproduced via curl + Python raw sockets + Burp tooling. The cross-tool consistency was what convinced the triage write-up that the findings were not artefacts.

**Report:**
```
Run /report
+-- Platform-specific format (H1/Bugcrowd/Intigriti/Immunefi)
+-- Title: [Bug Class] in [Endpoint] allows [role] to [impact]
+-- Impact-first summary (sentence 1 = what attacker CAN do)
+-- Exact HTTP requests in Steps to Reproduce
+-- Under 600 words
+-- CVSS 3.1 score that MATCHES actual impact
```

**After submission:**
- [ ] While waiting for triage: try to escalate further (A->B signal method)
- [ ] If fix deployed: re-test for bypass (incomplete patch = new bug)
- [ ] Record finding with `/remember` for hunt memory

---

