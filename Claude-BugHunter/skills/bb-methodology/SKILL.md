---
name: bb-methodology
description: "TRIGGER — start of any hunting session; switching targets; feeling lost about what to do next; asking 'what should I do next' or 'where am I in the process'. Master orchestrator: 5-phase workflow plus critical-thinking framework, routes to hunt-* skills by phase. SKIP — once the vuln class is already identified (e.g. Host header reflects into a JS src URL) load the matching hunt-* skill directly instead of the orchestrator; don't keep this loaded once routing is done, it costs context with no further value."
---

# Bug Bounty Methodology: Workflow + Mindset

Master orchestrator for hunting sessions. Combines the 5-phase non-linear workflow with the critical thinking framework that separates top 1% hunters from the rest.

---

## PART 0: MODE CONFIRMATION (Before Anything Else)

**Confirm the engagement type before deciding what counts as a finding.** The same target produces a different report shape depending on which mode applies. Getting this wrong is the single biggest waste of time in this workflow — answer it explicitly before Phase 0.

| Engagement type | What counts as a finding | What gets rejected |
|---|---|---|
| **Bug bounty** (H1 / Bugcrowd / Intigriti / private VDP) | Impact-demonstrated bugs ONLY. Full chain to attacker-attainable harm. | Hygiene (EoL software alone, permissive CSP alone, stack traces, info disclosure without concrete impact, "best practice" violations) |
| **Red team** (external client engagement) | Hygiene findings + recon + IoCs + defensive-state observations are ALL deliverables | Nothing — even "no finding here" is reportable as a positive defensive observation |
| **Pentest** (signed SoW / WAPT) | Depends on SoW. Read scope explicitly. Usually accepts hygiene + impact + recon | Out-of-scope assets, unsigned testing |
| **Internal audit** | Compliance-mapped findings (PCI / ISO / NIST / DPDPA / GDPR) | Findings without a control-mapping |

**Hard rule:** Before Phase 0 runs, write the engagement type as the first line in your hunt notes. If you can't answer it from the user's instruction, ASK once. Don't assume — the mistake costs both you and the triager.

**Lesson from an authorized engagement:** First-pass on this target produced 5 hygiene findings (SP2013 EoL, permissive CSP, stack traces) shipped in red-team format. The engagement was bug-bounty. Findings would have been N/A'd as "informational, no impact demonstrated." After the corrected pass with hygiene-as-context-not-finding, the same target yielded 11 impact-demonstrated bugs including 3 Critical.

---

## PART 1: MINDSET (How to Think)

### Core Principle

Hunting is not "find a bug" -- it is "prove an attack scenario." Think like an attacker with a specific goal, not a scanner looking for patterns.

### Daily Discipline: Define, Select, Execute

Before touching any tool:

1. **Define**: "Today I target [feature/domain] to achieve [CIA impact]"
2. **Select**: Choose 1-2 vuln classes (IDOR, Race Condition, etc.)
3. **Execute**: Focus ONLY on selected techniques. No wandering.

### 5 Ultimate Goals (Pick One Per Session)

1. **Confidentiality** -- steal data the attacker shouldn't see
2. **Integrity** -- modify data the attacker shouldn't change
3. **Availability** -- disrupt service (app-level DoS only)
4. **Account Takeover** -- control another user's account
5. **RCE** -- execute commands on the server

### 4 Thinking Domains

#### 1. Critical Thinking (deep analysis)

**Question trust boundaries:**
- Frontend control disabled? Send request directly via proxy
- `user_role=user` cookie? Change to `admin`
- `price=1000` in POST? Change to `1`
- `<script>` blocked? Try `<img onerror=...>`

**Reverse-engineer developer psychology:**
- Feature A has auth checks -> Similar feature B (newly added) probably doesn't
- Complex flows (coupon + points + refund) -> Edge cases have bugs
- `/api/v2/user` exists -> Does `/api/v1/user` still work with weaker auth?

**What-If experiments:**
- Skip checkout -> hit `/checkout/success` directly
- Skip 2FA -> navigate to `/dashboard`
- Send coupon request 10x simultaneously -> Race condition?
- Replace `guid=f8a2...` with `id=100` on sibling endpoint -> IDOR?

#### 2. Multi-Perspective (multiple angles)

| Perspective | What to check |
|------------|---------------|
| Horizontal (same role) | User A's token + User B's ID -> IDOR |
| Vertical (different role) | Regular user -> `/admin/deleteUser` |
| Data flow (proxy view) | Hidden params in JSON: `debug=false`, `discount_rate` |
| Time/State | Race conditions, post-delete session reuse |
| Client environment | Mobile UA -> legacy API with weaker auth |
| Business impact | "What's the $ damage if this breaks?" |

#### 3. Tactical Thinking (pattern detection)

- **Naming anomaly**: `userId` everywhere but suddenly `user_id` -> different dev, weaker security
- **Error diff**: Same 403 but different JSON structure -> different backend systems
- **Environment diff**: Prod vs Dev/Staging -> debug headers, CSP disabled
- **Version diff**: JS file before/after update -> new endpoints, removed params
- **Supply chain**: Check framework/library versions for known CVEs
- **Third-party integration**: Stripe/Auth0/Intercom -> webhook signature missing?

#### 4. Strategic Thinking (big picture)

- **Asymmetry**: Defender must patch ALL holes. You only need ONE.
- **Intuition engineering**: Log why something "feels wrong." Verify later. Update mental DB.
- **Unknown management**: Can't understand something? Add to "investigate later" list. Just-in-Time Learning.

### Amateur vs Pro: 7-Phase Comparison

| Phase | Amateur | Pro |
|-------|---------|-----|
| Recon | Main domain only | Shadow IT, dev environments, all assets |
| Discovery | Look for errors | Look for design contradictions, business logic flaws |
| Exploit | Give up when blocked | Build filter-bypass payloads |
| Escalation | Report the phenomenon only | Chain to real harm (session steal, ATO) |
| Feasibility | Include unrealistic conditions | Minimize attack prerequisites |
| Reporting | State facts only | Quantify business risk |
| Retest | Check if old PoC fails | Analyze fix method, find incomplete patches |

### Two Approach Routes

- **Route A (Feature-based)**: "This feature is complex" -> deep-dive its input handling -> find vuln
- **Route B (Vuln-based)**: "I want IDOR" -> find endpoints with sequential IDs -> test access control

### Anti-Patterns (Stop Doing These)

- **Program hopping**: Stick with one target minimum 2 weeks / 30 hours
- **Tool-only hunting**: Automation finds duplicates. Manual testing finds unique bugs.
- **Rabbit hole**: Max 45 min per parameter. Set a timer. If stuck, sleep on it.
- **No goal**: "Just looking around" = wasted time. Always Define first.

---


## PART 2: WORKFLOW — see `references/workflow.md`

The five phases in full — recon, learn, hunt, validate, report — with what each phase
produces and the hand-off to the next. Read it when you are starting a phase, not while
you are inside one.

Deterministic backing for most of it:
`cbh scope --resolve` → `cbh recon` → `cbh surface` → `cbh api-manifest` → `cbh workflow`
→ `cbh vectors seed-from-manifest` → `cbh vectors next` → `cbh poc-run` → `cbh triage`
→ `cbh report`.

## PART 3: NAVIGATION & TIMING

### Non-Linear Navigation Quick Reference

| I'm stuck because... | Go to... |
|----------------------|----------|
| Can't find any subdomains | Phase 1: Try different recon sources, Google Dorks |
| Found subdomain but don't know what to test | Phase 2: Map the app, download JS, understand auth |
| Testing but nothing works | Phase 3: Switch vuln class (20-min rotation rule) |
| Found a bug but impact is low | Phase 4: Escalation paths or gadget chaining |
| WAF/CSP/403 blocking my payload | Bypass techniques, then return to current phase |
| Been stuck for 45 min on one param | STOP. Rabbit hole. Move to next endpoint. |
| New API endpoint discovered during testing | Return to Phase 2: map it before attacking |
| Found one bug | A->B signal: same dev made more mistakes. Hunt 20 min for siblings. |

### 20-Minute Rotation Clock

Every 20 minutes ask yourself: **"Am I making progress?"**
- Yes -> Continue
- No -> Rotate to next: endpoint -> subdomain -> vuln class -> target
- Been on same target 2+ weeks with no findings? -> Consider switching program

### Pushback Protocol (When the User Says "Find More")

When the user disagrees with your stopping point — e.g., "I've found 10+ bugs, you should find the same," or "look harder," or "you're missing things":

**Default assumption: they are correct. You stopped early.**

Before pushing back with "I think we're done because X," do this:
1. **Re-read 3 more `hunt-*` skills** beyond what you have loaded. Pick ones that match observed surface (e.g., custom login → `hunt-auth-bypass`; SOAP endpoints → look for protocol-specific skills; URL parameters → `hunt-ssrf`).
2. **Re-attack the same surface** with the new skill checklists. Walk every step in the new skills, even if it feels redundant.
3. **Document negatives** as you go — a confirmed "no bug here" is itself a finding for the user to see (it proves coverage).
4. **Only after exhausting 3 new skills' checklists** do you push back, and only with a concrete list of what was tested.

**Lesson from an authorized engagement:** After a first-pass of 5 weak findings the user said "I have 10+, find them." Loading `hunt-auth-bypass` (which had been loaded but not walked through end-to-end) immediately surfaced the `/_vti_bin/Authentication.asmx` legacy SOAP login — the highest-impact bug in the engagement. The user was right; pushback would have been wrong.

### Tool Routing by Phase

| Phase | Tools | Why this order |
|-------|-------|----------------|
| Recon: Subdomains | `subfinder` -> `amass` -> `puredns` -> `httpx` | Passive first (no detection) -> resolve DNS -> probe HTTP + tech stack |
| Recon: URLs | `gau` + `waymore` -> `katana` -> `uro` | Archive (forgotten endpoints) -> active crawl (JS-rendered) -> deduplicate |
| Recon: JS | `jsluice` + `mantra` + `trufflehog --only-verified` | Extract URLs/secrets -> find API keys -> verify keys actually work |
| Recon: Ports | `naabu` (wide) -> `rustscan` (deep) | Fast top-1000 sweep -> full 65535 on interesting targets |
| Recon: Scan | `nuclei -tags cve` -> `nuclei -tags takeover` | Known CVEs first -> then takeover (act immediately) |
| Mapping: Params | `arjun` + `paramspider` + ParamMiner | Brute-force hidden params + mine archives + cache headers |
| Mapping: JS code | Download -> `jsluice` -> VS Code/Cursor grep | Extract -> static analysis -> AI-assisted taint analysis |
| Mapping: Dorks | Manual Google Dorks | Custom per-target queries find what automation misses |
| Discovery: Fuzz | `ffuf -ac` + `cewl` custom wordlist | Auto-calibrate filtering + target-specific words beat generic lists |
| Discovery: XSS | `kxss` -> `dalfox` | Filter (which params reflect?) -> scan (only reflective params) |
| Discovery: SQLi | `ghauri` | Modern blind SQLi on ID-like parameters |
| Discovery: SSRF | `interactsh-client` | Self-hosted OOB listener for blind SSRF/XXE/RCE |
| Discovery: WAF | `wafw00f` -> `whatwaf` | Identify WAF vendor -> test bypass techniques |
| Exploit: 403 | `byp4xx` or `nomore403` | 20+ bypass techniques automated |
| Exploit: Takeover | `subzy` | Checks CNAME against 70+ vulnerable services |
| Exploit: Cloud | `s3scanner` + `aws` CLI | Scan bucket permissions -> extract metadata credentials |
| Exploit: Secrets | `trufflehog --only-verified` | Only verified working keys (no false positives) |

### Session End Checklist

- [ ] Save all Burp/Caido project files
- [ ] Record any "weird but not yet exploitable" behaviors (future gadgets)
- [ ] Update notes with failed attempts (don't re-test with same techniques)
- [ ] Log findings with `/remember`

---

## PART 4: METHODOLOGY DISCIPLINE (False-Positive Prevention)

Most retracted findings come from four recurring process bugs. Each has a hard rule.

> **Important framing:** These discipline rules are about *correctness of findings* — not throttling of effort. They tell you which signals are real findings and which aren't. They do **not** tell you to send fewer probes. If you find yourself using these rules to justify stopping early, you're misreading them — load `redteam-mindset` (DO NOT STOP primary directive) and continue. Coverage discipline and finding-correctness discipline are orthogonal axes; you need both on full.

### Marker Discipline

When testing for reflection, cache poisoning, parameter pollution, or OOB SSRF, the marker string you inject MUST be unique and unmistakable.

**Rules:**
- Markers are random alphanumeric strings, **8+ characters**, no English words, no protocol keywords.
- **NEVER** use `test`, `marker`, `evil`, `attacker`, `payload`, `javascript`, `script`, `AAAA`, `BBBB`, your domain name, or any string that could plausibly appear naturally in the target's HTML/JS/error messages.
- **Good markers:** `cpmark987abc`, `x4hd2k9pq`, a Collaborator subdomain prefix like `dlsrcurl.<collab>.oastify.com`, or `__ZZ_MARKER_<random>_ZZ__`.
- Before claiming reflection: search the **baseline** (no-marker) response for the marker string. If it appears naturally, change your marker. This single check catches 80% of false-positive reflection reports.
- For OOB testing, sub-tag each Collaborator payload (e.g., `dlsrcurl.<collab>`, `authsrc.<collab>`) so callbacks identify the specific sink that fired.

**Lesson from an authorized engagement:** Initial scan flagged `X-Forwarded-Proto: javascript` as reflecting into multiple SharePoint pages. The "reflection" was the literal word `javascript` appearing naturally in SP help-link hrefs (`href="javascript:HelpWindowKey(...)"`). False positive caused by a non-unique marker.

### Body-Diff Rule

A bypass claim requires response **body** differential, not just status code.

**Rules:**
- 200 OK with byte-identical body to the baseline is NOT a bypass.
- 200 OK with a 5-byte difference might be — verify what changed (correlation ID? timestamp? real content?).
- Always diff the body side-by-side before claiming bypass: `diff <(curl ... baseline) <(curl ... bypass)`.
- Status-code-only claims (e.g. "Host header X gave 200 instead of 403") are the most common rejected-as-N/A category on bug bounty platforms.

**Lesson from an authorized engagement:** `Host: target.example:80@evil.example.com` returned HTTP 200 instead of the baseline 403. Looked like a Host-header bypass. But the body was byte-identical (8341 bytes both) — the AWS ELB normalised the Host to `target.example:80`, dropping the `@evil` portion. Not a bypass.

### Statistical-Sample Rule (for timing-based claims)

Single outliers are NOT signal. Network jitter routinely produces 2× outliers.

**Rules for any user-enum / blind-SQLi / blind-NoSQLi / timing-side-channel claim:**
- Minimum sample size: **n ≥ 10 INTERLEAVED trials per group** (control + test, randomised order, not back-to-back).
- Compute mean, median, σ for each group.
- A signal requires the suspect group's mean to be **≥ 2σ above** the control group's mean.
- A single 2× outlier in n=1 testing is jitter, not signal.

**Lesson from an authorized engagement:** Single-shot probe showed `Administrator` taking 1527 ms vs ~700 ms control on Authentication.asmx Login — looked like clear user-enum signal. Reproduction with n=80 interleaved trials across 8 groups collapsed every group to mean=685-716 ms, σ=25-74 ms. The 1527 ms was network jitter. Finding retracted.

### Shell-Loop Ban (>5 iterations)

For any iteration that runs more than 5 times, **use Python (with try/except per iteration), not shell for-loops.**

**Why:** zsh array expansion fails silently on edge cases. A loop like `for x in "${arr[@]}"` can produce zero iterations with no error if the array wasn't populated by the previous command. The user sees output that looks complete but actually skipped the test entirely.

**Rules:**
- Loops of ≤5 hardcoded items in shell: OK.
- Anything that iterates a list, file, or computed range: Python.
- Always count results. If you expected 100 probes and got <50 lines of output, your loop ate something.

**Lesson from an authorized engagement:** A zsh array-iteration verb-tampering test silently produced no curl invocations across 20+ iterations (zsh ate the array). Output looked like "HIT [GET] /_api/web → " repeated for every probe but the actual response was missing. ~50 probes worth of testing lost. Switching the test to Python with explicit per-iteration logging surfaced the real results.

---

## Related Skills & Chains

- **`hunt-dispatch`** — When PART 0 mode is confirmed (redteam / wapt + blackbox|greybox). Workflow primitive: after the engagement-type answer is locked, hand off to `hunt-dispatch` to fingerprint the target and load the matching platform + hunt-* skill set; this skill stops being the active context once dispatch prints its taxonomy.
- **`bug-bounty`** — When the user asks a generic "what should I do" or starts a new target. Workflow primitive: `bug-bounty` is the orchestrator that names which `hunt-*` skills to load by topic; this skill (`bb-methodology`) provides the 5-phase workflow that orchestrator runs against.
- **`triage-validation`** — When a finding completes Phase 4 and is about to be written up. Workflow primitive: Phase 5 explicitly calls `/validate` (the 7-Question Gate); only findings that pass all 7 questions get handed off to `report-writing`.
- **`offensive-osint`** + **`web2-recon`** — When Phase 1 (Recon) is active. Workflow primitive: Phase 1's "Wide approach" delegates to `offensive-osint` for asset arsenal and `web2-recon` for the live-host + URL pipeline.

---

## Operator Notes (Claude-BugHunter)

> Engagement-derived additions to the vendored foundation. Wisdom from real
> authorized engagements + Phase 2 verification across this repo's 31+
> skill-area live tests. The upstream methodology covers the WHAT; this
> layer covers the WHEN-IT-ACTUALLY-WORKS and the FAILURE-MODES.

### What the methodology doesn't tell you

The vendored 5-phase workflow is a checklist; real engagements are improvisation. Sometimes you skip phases entirely — a client hands you a single URL and a JWT, recon was already done by their internal team, and Phase 1 collapses to a 10-minute fingerprint. Sometimes you spend 80% of the engagement in Phase 1 because the scope is a 200-asset financial-services parent org and asset discovery IS the work. The methodology is a map of terrain that exists in every engagement, not a sequence you traverse uniformly.

### Mode-confirmation, in practice

PART 0 (the bug-bounty vs WAPT vs red-team gate at the top of this file) is a hard rule, but the answer isn't always handed to you. Read the scope language:

- **"in-scope assets"** + **"out-of-scope assets"** + **"safe harbor"** → bug-bounty discipline. Validation-heavy, OOB-required, no exfil.
- **"kill chain"** + **"objectives"** + **"flag capture"** + **"adversary emulation"** → red-team. Stealth, persistence, lateral movement valid.
- **"compliance"** + **"PCI"** + **"HIPAA"** + **"executive report"** + **"remediation timeline"** → WAPT. Coverage-driven, deliverable-focused, all findings count regardless of exploitability.

When the language is mixed (common — clients often write WAPT-shaped SOWs and call them red-team engagements), default to bug-bounty discipline until proven otherwise. It's the most validation-strict mode; you can always relax later if the client confirms red-team. The reverse — assuming red-team latitude on what turns out to be a WAPT — gets findings retracted at delivery.

### Phase priority shifts by target type

The 5 phases are not equal-weight. Engagement type dictates the time allocation:

| Engagement | Recon | Hunt | Validate+Report |
|---|---|---|---|
| SaaS bug-bounty (defined scope) | 10% | 70% | 20% |
| External red-team (wide scope) | 40% | 30% | 30% |
| WAPT (asset list provided) | 0% | 60% | 40% |
| Enterprise on-prem (single product) | 5% | 50% | 45% |

If you find yourself spending 50% of a SaaS bug-bounty engagement in recon, you're procrastinating on the hunt. If you're spending 10% of an external red-team engagement on recon, you've already lost — the attack surface map IS the deliverable on those.

### When to break the methodology

If you find a Critical in the first 30 minutes of recon, **stop reconning, validate the Critical fully, report it, then return to recon.** The methodology says "complete the phase before moving on" — the value-per-hour curve disagrees. A confirmed Critical paying out within 24h of engagement start is worth more than a comprehensive asset list you'll never get to chain.

The same applies in reverse: if you've been hunting a candidate for 4+ hours and it won't reproduce on a second account, the candidate is dead. Don't sink another 4 hours into making a dead candidate reproduce. Drop it, document the retraction in your notes, move on.

### The discipline rules are non-negotiable

The discipline rules in this file — OOB Gate, Marker Discipline, Body-Diff Rule, Statistical-Sample Rule, Server-Policy-vs-State, Pre-Severity Gate, Shell-Loop Ban — are not methodology. They are quality gates. Methodology is the order of operations; these are the validation guarantees at each step.

Verified across Phase 2D's hardened-lab campaign: 8/8 discipline rules fired correctly against fake-bug-shaped behavior (URL echo dressed as XSS, word collision dressed as reflection, status-code-only "bypasses" with byte-identical bodies, 200-OK leak-claims with no actual leak data). Validation rates fall sharply when these rules get skipped. The friction is the feature — if a rule feels obstructive, that's it doing its job. The findings it kills are the half that would have come back N/A anyway.
- **`evidence-hygiene`** — When Phase 5 is collecting PoC screenshots / HARs. Workflow primitive: before any cookie / PII appears in a screenshot, hand off to `evidence-hygiene` for the redaction protocol.
