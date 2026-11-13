---
name: hunt-http-smuggling
description: "TRIGGER — target sits behind a CDN/reverse-proxy plus origin stack (load balancer, WAF) where front-end and back-end might disagree on Content-Length vs Transfer-Encoding; Burp HTTP Request Smuggler / smuggler.py is viable. SKIP — hunt-cache-poison once smuggling is confirmed and being chained specifically into cached-response poisoning — log that chain step there; hunt-host-header for Host-based routing/cache issues with no CL/TE desync involved."
---

## 17. HTTP REQUEST SMUGGLING
> Lowest dup rate. $5K–$30K. PortSwigger research by James Kettle.

### CL.TE (Content-Length front, Transfer-Encoding back)
```http
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### Detection
```
1. Burp extension: HTTP Request Smuggler
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. Manual timing: CL.TE probe + ~10s delay = backend waiting for rest of body
```

### Impact Chain
```
Poison next request → access admin as victim
Steal credentials → capture victim's session
Cache poisoning → stored XSS at scale
```

---

## Target-Suitability Matrix (2026 reality check)

The classic CL.TE / TE.CL payloads are NOT universally exploitable in 2026. Modern proxies are RFC 9112 strict by default. Fingerprint the front-end BEFORE investing time.

| Front-end | CL.TE | TE.CL | H2.CL | H2.TE | Notes |
|---|---|---|---|---|---|
| **Nginx ≥ 1.21** | NO | NO | partial (H2 ingress) | partial | RFC-strict; rejects CL+TE with HTTP 400. Verified locally on Nginx 1.27 — all 9 documented variants killed by front-end ([docs/verification/phase2h-smuggling-cachepoison.md](../../docs/verification/phase2h-smuggling-cachepoison.md)). |
| **Caddy 2.x** | NO | NO | — | — | Hardened by default |
| **Envoy ≥ 1.20** | NO | NO | partial | partial | Hardened in most paths |
| **HAProxy ≤ 2.4** | ✓ | ✓ | — | — | **Vulnerable**, see CVE-2021-40346 |
| **AWS ALB + specific upstream** | partial | partial | ✓ | ✓ | Several disclosed-paid reports 2022-2024 |
| **Cloudflare → S3 / Lambda chains** | — | — | ✓ | ✓ | H2-downgrade attacks remain viable |
| **Older F5 BIG-IP (TMM < 16)** | ✓ | — | — | — | Vendor advisories |
| **Citrix ADC / NetScaler (older firmware)** | ✓ | ✓ | — | — | Disclosed in 2020-2022 |
| **Squid 3.x** | ✓ | — | — | — | Older deployments |
| **Apache Traffic Server (older)** | ✓ | ✓ | ✓ | ✓ | PortSwigger research |
| **Custom Python / Go proxies** | ✓ | ✓ | — | — | Frequently miss RFC enforcement |

### Operator fingerprint quick-check

```bash
curl -sI https://target/ | grep -i "Server:"
```

- `nginx/1.21+`, `Caddy`, `envoy` → CL/TE classic is dead — pivot to H2.CL/H2.TE if the front-end speaks HTTP/2, or look for legacy proxies upstream
- `HAProxy`, header points to AWS/CDN → run the full payload matrix
- No Server header → assume hardened, but run a single quick `space-before-colon` probe; if it doesn't 400, dig deeper

### H2.CL / H2.TE (the modern dominant vector)

H2-downgrade smuggling attacks rely on the front-end speaking HTTP/2 to the client and HTTP/1.1 to origin. The downgrade introduces CL/TE confusion because HTTP/2's frame-length headers don't survive the conversion cleanly. Most CDN+origin chains in 2024-2026 use this exact topology.

Tools that send HTTP/2 raw frames (Burp Pro's HTTP Request Smuggler extension, `h2csmuggler`, `smuggler.py`) are the right starting point against CDN-fronted targets. Avoid HTTP/1.1-only test clients (curl, raw sockets) against H2-front-ended targets — you'll send the wrong protocol entirely.

---

## Related Skills & Chains

- **`hunt-cache-poison`** — Smuggling + cache is the canonical critical chain; one smuggled request becomes the cached response for every subsequent victim. Chain primitive: CL.TE smuggle a request whose response body contains attacker HTML/JS → front-end cache stores it under a popular URL (`/`, `/login`) → de-sync poisoning where the smuggled request becomes the cached response for the next N victims, persisting for the cache TTL.
- **`hunt-auth-bypass`** — Smuggling reaches internal-only routes that the front-end WAF/auth-proxy filters out. Chain primitive: smuggle `GET /admin/users HTTP/1.1` past the front-end ACL that blocks external `/admin/*` → backend processes the smuggled request as if from a trusted internal source → bypass front-end auth by smuggling internal-routed request → admin data in the response queue.
- **`hunt-idor`** — Smuggling attaches the NEXT user's session cookies to an attacker-controlled request path. Chain primitive: smuggle `GET /api/me HTTP/1.1` with no cookies → backend pairs it with the next legitimate user's incoming connection cookies → victim's session cookie attached to attacker's smuggled request → attacker reads the response containing victim's PII/tokens.
- **`hunt-xss`** — Smuggling injects XSS payloads into the response stream of the next victim without ever appearing in a URL parameter. Chain primitive: smuggled request body contains reflected payload that the backend renders into the next response in the queue → next visitor to `/` receives attacker HTML inline → reflected XSS at every visitor without any URL parameter visible to them or to logs.
- **`security-arsenal`** — Reach for the smuggling payload bank (CL.TE / TE.CL / TE.TE obfuscations, H2.CL downgrade probes, h2csmuggler one-liners, Burp HTTP Request Smuggler extension config) and the time-delay confirmation template before manual hex-editing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the smuggled-request effect MUST land on a request issued by a different client/session, not your own follow-up. A timing delta in your own browser alone is parser disagreement, not exploitable smuggling.

## Detection-only checklist from 2025 research (corpus gap pass 2026-11-02, `docs/disclosed-reports/corpus-2026-11/GAP.md`)
Kettle "HTTP/1.1 must die": desync now hides behind header *masking*. Detect, never weaponize:
- `Host` vs ` Host` vs `Host ` vs `Xost` vs `Host :`. A response different from BOTH the normal
  and the absent case means a V-H / H-V discrepancy candidate.
- `Expect: 100-continue` and the obfuscated `Expect: y 100-continue`: look for a second header
  block, front-end headers leaking back, or a 504/deadlock on HEAD.
- "Mystery 400" on a well-formed request, or 0.CL (an implicit Content-Length of 0 on the front)
  with an early-response gadget.
- Hand candidates to HTTP Request Smuggler / Turbo Intruder `0cl-find-offset` only with
  programme approval: desync affects other users' connections. `cbh diffprobe` covers the
  header axis safely.

### Shared-parser confusion / dangling byte (2026-11-13, operator's technique digest)
Detection-only, and the approval wording below is not optional — this one ends in reading
other users' responses.

The signal the earlier rows miss: a request that is **well-formed to both hops**. Where
two hops share a parser family but not its version, a body can be framed so that each
`Content-Length` it carries matches what that hop computes (hence "dual-matching"), and a
single byte is left dangling in the connection buffer. No 400, no deadlock, no header
masking — every detector above stays quiet, while the response queue is now off by one.

- Detect on **your own connection only**, and the oracle is an unasked-for response: send
  the candidate, then a distinctive clean request on the same connection, and check whether
  the second response answers the first request. `bbcurl` with two URLs reuses the
  connection; pin it with `--http1.1` and read the status line of each block.
- The offset persisting across a `Connection: close` boundary, or appearing on a connection
  you did not open, is the **shared pool** — stop at once: the next response in that queue
  belongs to a real user.
- Weaponisation (letting the queue serve you someone else's response) is forbidden here
  without the programme's written approval: it reads another user's data and desynchronises
  a pool other users are on. Write the offset capture to `blocked-tests/`, file the approval
  on `cbh queue`, and report the queue offset itself — a proven response-queue desync is a
  finding without stealing anything.

**Chain:** needs `dual-matching-content-length-accepted`, `response-queue-offset-own-connection`
· gives `response-queue-desync`, `cross-user-response-read-candidate`
