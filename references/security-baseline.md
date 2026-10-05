# Security baseline: what to look for, how to prove it, what to map it to

Read this file area by area while performing the static/manual review phase. Each area gives
(1) what to look for, (2) how to prove or disprove it, (3) the standards mapping to cite.
The mapping is for communication, not for checkbox auditing: a finding is real when you can
trace attacker-controlled input to an impact, not when a pattern matches.

Standards versions as of writing (confirm the current stable version with web tools when available,
never invent a version or a CVSS score): OWASP Top 10:2025, OWASP ASVS 5.0, OWASP API Security
Top 10 (2023), NIST SP 800-218 SSDF v1.1, CIS Benchmarks (Docker, Kubernetes, cloud provider
foundations), MITRE CWE.

## Table of contents

1. Authorization (BAC, IDOR/BOLA, BFLA, tenant isolation, mass assignment)
2. Authentication (login, registration, reset, MFA, lockout, credential stuffing)
3. Sessions, JWT, OAuth/OIDC/SSO
4. Injection (SQL, NoSQL, ORM, command, template, LDAP, XPath, EL, CRLF, log, eval)
5. XSS and unsafe rendering
6. CSRF
7. CORS
8. SSRF
9. File uploads, downloads, path traversal, archives
10. API security (inventory, exposure, pagination, debug, third-party consumption)
11. Rate limiting and resource/cost exhaustion
12. Business logic (race conditions, replay, idempotency, workflow bypass)
13. Cryptography
14. TLS and certificates
15. Secrets management and leakage
16. Databases
17. Redis and caches
18. Queues, workers and background jobs
19. Webhooks and external integrations
20. Frontend and browser security (storage, cookies, CSP, source maps, public env)
21. Security headers
22. Docker and containers
23. Kubernetes
24. Terraform and IaC
25. Cloud IAM, network and storage (AWS, Azure, GCP)
26. CI/CD and supply chain
27. Dependencies
28. Logging, monitoring and error handling
29. Backup and recovery
30. Reverse proxies, load balancers and network exposure

---

## 1. Authorization

Backend enforcement is the only control that counts. Frontend route guards, hidden buttons,
disabled inputs and "the UI never sends that" are not controls.

**Look for**
- Object access by client-supplied identifier without an ownership/tenant predicate
  (`/api/invoices/{id}`, `?user_id=`, GraphQL `node(id:)`, WebSocket room names, signed URLs).
- Queries scoped by nothing but the ID: `Invoice.objects.get(pk=id)`, `findUnique({where:{id}})`,
  `db.First(&inv, id)`, `_context.Invoices.Find(id)`, `Invoice.find(params[:id])`.
- Function-level gaps: admin/support/export/bulk endpoints whose only protection is a route prefix,
  a missing decorator/middleware/guard/attribute, or a role check done in the UI.
- Property-level gaps: serializers/DTOs/binders that accept `role`, `is_admin`, `tenant_id`,
  `owner_id`, `price`, `status`, `email_verified` from the request (mass assignment, over-posting).
- Horizontal escalation via sequential/guessable IDs; vertical escalation via role parameters,
  claim tampering, or self-service role change.
- Tenant/organization isolation: queries that filter by user but not by tenant, cross-tenant
  joins, shared caches keyed without tenant, background jobs that receive an ID and trust it.
- Support/impersonation features: who can impersonate whom, is it audited, can it be chained.
- Authorization in GraphQL resolvers (per field, not per query), in batch/bulk endpoints,
  in "list" endpoints that leak other users' rows through filters or sorting.

**Prove it**
- Build an authz matrix: for each sensitive route, test as unauthenticated, user A, user B
  (same role), tenant B, lower role, admin. Same request, only the identity changes.
- Change one identifier at a time. A 200 with another user's data, or a 204 on a modification,
  is Confirmed. A 403/404 is fine only if consistent across GET/PUT/PATCH/DELETE and bulk variants.
- For mass assignment: send an extra field the UI never sends and read it back.
- Read the ownership predicate in code and confirm it is applied on every path (list, detail,
  update, delete, export, nested resources, GraphQL mutations, WebSocket events, jobs).

**Map to**: OWASP Top 10 A01 Broken Access Control; API1 BOLA, API3 Broken Object Property Level
Authorization, API5 BFLA; ASVS V8 Authorization; CWE-639, CWE-862, CWE-863, CWE-284, CWE-915, CWE-269.

## 2. Authentication

**Look for**
- Login: user enumeration via differing messages/timings/status codes; missing lockout or
  progressive delay; no rate limit per account AND per IP; no credential-stuffing signal.
- Registration: weak password policy (check against breached lists where the framework supports
  it), unverified email used for authorization decisions, account pre-hijack (registering an email
  before the victim links SSO).
- Password reset/recovery: predictable or long-lived tokens, token not bound to user, token
  reusable, token in URL logged/leaked via Referer, host-header poisoning of the reset link,
  security questions, reset that does not invalidate sessions.
- MFA: enforced only in UI, bypassable by calling the post-MFA endpoint directly, OTP without
  rate limit (6 digits = 1M guesses), OTP reusable, backup codes weak, MFA state stored client-side.
- Logout that does not invalidate the server-side session or refresh token.
- Password storage: anything other than an adaptive one-way hash (bcrypt, scrypt, Argon2id,
  PBKDF2 with adequate work factor). Reversible encryption of passwords is Critical.
- Default/hardcoded credentials, debug logins, "test" accounts in fixtures deployed to prod.

**Prove it**
- Compare responses for valid vs invalid username (body, status, length, time).
- Send N failed logins and confirm what happens on N+1 (lockout, delay, captcha, nothing).
- Reset flow: request two tokens, use the older one; use a token after password change; alter
  the `Host` header when requesting a reset and inspect the generated link.
- MFA: after first factor, call an authenticated endpoint before completing the second factor.

**Map to**: A07 Authentication Failures; API2 Broken Authentication; ASVS V6 Authentication;
CWE-287, CWE-307, CWE-521, CWE-640, CWE-798, CWE-916, CWE-306.

## 3. Sessions, JWT, OAuth/OIDC/SSO

**Look for (sessions)**
- Cookies without `HttpOnly`, `Secure`, `SameSite`; session ID in URL; session fixation (ID not
  rotated on login/privilege change); absolute and idle timeouts absent; no server-side revocation.
- Session store shared across tenants without namespacing; session data trusted for authz.

**Look for (JWT)**
- Signature not verified (`decode` without verify, `verify_signature=False`, `jwt.decode(token, options={"verify_signature": False})`, `jwt.decode()` vs `jwt.verify()` in Node, `parse` vs `parseClaimsJws`).
- Algorithm not pinned (`alg: none`, HS256/RS256 confusion where the public key is used as the HMAC secret), key taken from the token (`jku`, `x5u`, `kid` path traversal / SQL injection).
- Missing `exp`, `nbf`, `iss`, `aud` validation; very long lifetimes; refresh tokens that never
  rotate or are not bound to the client/session; refresh token reuse not detected.
- No revocation strategy (logout, password change, role change should invalidate); role/claims
  read from the token and trusted for authorization without re-checking against the source of truth
  when the claim is security-critical and long-lived.
- Weak secrets (short, dictionary, committed, shared across environments), no key rotation.
- Token leakage: in URLs, logs, Referer, localStorage (XSS-readable), error responses.

**Look for (OAuth/OIDC/SSO)**
- Missing/unchecked `state` (CSRF on login), missing PKCE for public clients, open `redirect_uri`
  matching (prefix, subdomain, path traversal), implicit flow with tokens in fragments,
  ID token `aud`/`iss`/`nonce` not validated, access token used as ID proof, account linking
  by unverified email, IdP-initiated flows without replay protection.

**Prove it**
- Tamper the token payload (change `sub`/`role`), strip the signature, set `alg: none`, sign with
  the public key as HMAC secret, present an expired token, present a token from another
  environment (staging secret reuse). Any 200 is Confirmed.
- Log out, then replay the old cookie/token. Change password, replay old refresh token.
- OAuth: tamper `state`, alter `redirect_uri` to an attacker-controlled host/subpath.

**Map to**: A07; API2; ASVS V7 Session Management, V9 Self-contained Tokens, V10 OAuth and OIDC;
CWE-384, CWE-613, CWE-347, CWE-345, CWE-1004, CWE-614, CWE-1275, CWE-601.

## 4. Injection

Trace attacker-controlled data to the sink. Keyword matches ("raw SQL exists") are not findings;
a request parameter reaching string concatenation inside a query is.

**Look for**
- SQL: string formatting/concatenation into queries (`f"... {x}"`, `"..." + x`, `%` formatting,
  `String.format`, template literals), `raw()`/`extra()`/`RawSQL`/`FromSqlRaw`/`ExecuteSqlRaw` /
  `$queryRawUnsafe`/`sequelize.query`/`knex.raw`/`DB::raw`/`whereRaw`/`find_by_sql`/`db.Raw`,
  dynamic ORDER BY/column names, LIKE without escaping, stored procedures built dynamically.
- NoSQL: request objects passed straight into `find({...})` allowing `$ne`/`$gt`/`$where`/`$regex`;
  `$where` with user strings; aggregation pipelines built from input.
- ORM misuse: `.filter(**request.data)`, dynamic attribute names, `order_by(user_input)`,
  `.extra()`, HQL/JPQL string building, GORM `Where(fmt.Sprintf(...))`.
- OS command: `subprocess(..., shell=True)`, `os.system`, `exec`/`execSync`/`spawn` with `shell:true`,
  `Runtime.exec` with concatenated strings, `Process.Start` with user args, backticks/`system()`
  in Ruby/PHP, `os/exec` with `sh -c`.
- Template injection: user input in template *source* (`Template(user)`, `render_template_string`,
  `new Function`, `ejs.render(userString)`, Twig `createTemplate`, Thymeleaf expression
  preprocessing, Freemarker), not just in template variables.
- LDAP/XPath/EL/OGNL/SpEL injection in filters or expression evaluators.
- CRLF/header injection: user input into `Location`, `Set-Cookie`, custom headers, SMTP headers.
- Log injection: unescaped newlines/ANSI from input into logs; log-forging of audit trails.
- Code/eval: `eval`, `exec`, `pickle.loads`, `yaml.load` (non-safe), `unserialize`, `Marshal.load`,
  `ObjectInputStream`, `BinaryFormatter`, Jackson default typing, `TypeNameHandling.All`.
- XXE: XML parsers with external entities enabled (`resolve_entities=True`, `DocumentBuilderFactory`
  without secure processing, `XmlReaderSettings.DtdProcessing = Parse`, libxml external entities).

**Prove it**
- Static: locate the sink, walk backwards to the source (request, headers, cookies, file name,
  DB row previously written by a user, queue message, webhook payload).
- Dynamic (authorized, non-destructive): boolean/time-based probes on the exact parameter,
  `' OR '1'='1` style for enumeration only, `{"$ne": null}` on a login field, `{{7*7}}` / `${7*7}`
  in a rendered field. Stop at proof; never dump tables or run destructive payloads.

**Map to**: A05 Injection (A03 in the 2021 list), A08 Software or Data Integrity Failures (deserialization);
ASVS V1 Encoding and Sanitization, V2 Validation; CWE-89, CWE-943, CWE-78, CWE-94, CWE-95, CWE-1336,
CWE-90, CWE-643, CWE-917, CWE-113, CWE-117, CWE-502, CWE-611.

## 5. XSS and unsafe rendering

**Look for**
- Framework escape bypasses: `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `bypassSecurityTrust*`,
  `{@html}`, `{{{ }}}` (Handlebars), `|safe`, `mark_safe`, `format_html` with unsafe args,
  `autoescape off`, `{!! !!}` (Blade), `html_safe`/`raw` (Rails), `@Html.Raw`, `th:utext`, `<%- %>` (EJS).
- DOM XSS: `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `eval`, `setTimeout(string)`,
  `location.href = userInput` (javascript: URLs), jQuery `.html()`/`$(userString)`.
- Markdown renderers without sanitization (`marked` without DOMPurify, `react-markdown` with
  `rehype-raw`, Python `markdown` with `safe_mode` removed), rich text editors saving raw HTML.
- URL injection: `href`/`src`/`action` from user input without scheme allowlist (`javascript:`, `data:`).
- Iframes with user-controlled `src`, `srcdoc`; postMessage handlers without origin checks.
- Stored XSS via profile fields, comments, file names, SVG uploads, error pages echoing input,
  CSV/Excel exports (formula injection), PDF generators rendering HTML.
- Reflected XSS in search, error pages, 404 handlers, redirect parameters, JSONP callbacks.
- SPA server-side rendering that injects state into `<script>` without escaping `</script>`.

**Prove it**
- Find the render sink and the data path. If the same string can be set by an attacker and
  rendered for a victim without encoding, it is Confirmed even before a browser demo.
- Dynamic: benign canary `"><img src=x onerror=console.log(1)>` or `<svg onload>`; check reflection
  and context (HTML body, attribute, JS string, URL). Prefer `console.log` over `alert`.
- Check whether CSP would have blocked it (defense in depth, not a fix).

**Map to**: A05/A03 Injection; ASVS V1, V3 Web Frontend Security; CWE-79, CWE-80, CWE-116, CWE-1236 (CSV injection).

## 6. CSRF

**Look for**
- State-changing endpoints authenticated by cookies (session or JWT-in-cookie) without an
  anti-CSRF token, without `SameSite=Lax/Strict`, and accepting `application/x-www-form-urlencoded`,
  `multipart/form-data` or `text/plain`.
- CSRF middleware disabled globally or per view (`@csrf_exempt`, `csrf().disable()`,
  `[IgnoreAntiforgeryToken]`, `protect_from_forgery` removed, `$except` in `VerifyCsrfToken`).
- Token validation that only checks presence, or tokens shared across sessions.
- JSON APIs that also accept form encoding (content-type coercion), or that use a custom-header
  check that CORS misconfiguration nullifies.
- GET requests that change state. Login CSRF. Logout CSRF. WebSocket handshake without origin check.
- Bearer-token APIs are usually not CSRF-exposed; do not report CSRF there unless the token is
  also in a cookie that the server accepts.

**Prove it**
- Replay a state-changing request without the CSRF token / with a different session's token.
- Check the cookie attributes actually set in responses (not the config file).
- Cross-origin form POST from a local HTML page against a running instance.

**Map to**: A01 Broken Access Control; ASVS V3, V4; CWE-352, CWE-1275.

## 7. CORS

**Look for**
- `Access-Control-Allow-Origin: *` with credentials, or origin reflection
  (`Access-Control-Allow-Origin: <request Origin>` + `Allow-Credentials: true`) for any origin.
- Regex/prefix/suffix matching bugs: `origin.endswith("example.com")` (matches `evilexample.com`),
  `startswith("https://app.example")`, `null` origin allowed, `http` allowed for an `https` app.
- Wildcard sub-domain trust where any sub-domain can host user content (XSS on one = all).
- Over-broad `Access-Control-Allow-Headers`/`Methods`; long `Max-Age` hiding fixes.
- Framework defaults: `CORS_ALLOW_ALL_ORIGINS`, `cors()` with no options, `AllowAnyOrigin()` with
  `AllowCredentials()`, `@CrossOrigin("*")`, Laravel `paths => ['*']` + `supports_credentials`.

**Prove it**
- Send `Origin: https://evil.example` and `Origin: null` and a look-alike origin; inspect the
  response headers on an authenticated endpoint. Reflection + credentials = Confirmed High.

**Map to**: A02 Security Misconfiguration; ASVS V3; CWE-942, CWE-346.

## 8. SSRF

**Look for**
- Any server-side fetch of a user-influenced URL: webhooks, callbacks, "import from URL",
  avatar/image fetchers, link previews, PDF/HTML renderers (wkhtmltopdf, Puppeteer, WeasyPrint,
  dompdf, Chrome headless), RSS/OpenAPI importers, OAuth `jwks_uri`/discovery documents,
  package/plugin installers, proxy endpoints, health checks with target parameters.
- Validation done on the string before redirects/DNS (allowlist bypass via 302, DNS rebinding,
  `0x7f000001`, `127.1`, `[::1]`, `localhost.attacker.tld`, IPv6-mapped, decimal IPs, `@` in authority).
- Cloud metadata reachability: `169.254.169.254` (AWS/GCP/Azure), Azure `169.254.169.254/metadata`,
  GCP requires `Metadata-Flavor` header, AWS IMDSv1 vs IMDSv2, Kubernetes API from a pod.
- Internal services reachable from the app: Redis (gopher/CRLF), Elasticsearch, admin panels,
  Docker socket, Consul/Vault, internal APIs without auth because "they are internal".

**Prove it**
- Point the fetcher at a listener you control (or a local port on an owned host) and observe the
  request. Point it at `http://169.254.169.254/` on a cloud-hosted instance ONLY with authorization
  and read the response size/status, never persist credentials retrieved. Test redirect-following
  with an allowlisted URL that 302s to an internal one.

**Map to**: A10 SSRF (2021) / A02 Security Misconfiguration (2025 list folds SSRF into design/config);
API7 SSRF; ASVS V4; CWE-918.

## 9. File uploads, downloads, path traversal, archives

**Look for**
- Uploads: trust in client `Content-Type` or extension only; no magic-byte/content check;
  executable or server-parsed types (`.php`, `.phtml`, `.jsp`, `.aspx`, `.cshtml`, `.py`, `.sh`,
  `.svg` with scripts, `.html`, `.xml`); double extensions; null bytes; polyglots; uploads stored
  under the web root; user-controlled filename used in the path; image libraries with known RCEs
  (ImageMagick policy, old Pillow, exiftool); no size limit; no per-user quota; no virus scanning
  where required by policy.
- Path traversal: filename or path fragments from the request joined into filesystem paths
  (`os.path.join(base, user)`, `path.join`, `Path.Combine`, `File.join`) without canonicalization
  and prefix check; `../`, encoded variants, absolute paths, Windows drive letters/UNC.
- Archives: `zipfile.extractall`, `tar.extractall` (pre-3.12 default filter), `unzip` shell,
  `ZipInputStream`, `System.IO.Compression` without entry path validation (zip slip); no
  decompressed-size limit (zip bomb); symlinks in archives.
- Downloads: authorization by obscurity (unguessable URL that never expires), signed URLs with
  long expiry, `Content-Disposition` missing (HTML served inline), `Content-Type` sniffing,
  object-storage bucket public or "authenticated users" (any account) readable.
- Temporary files: predictable names in shared temp dirs, not deleted, world-readable.

**Prove it**
- Upload a benign `.svg` with `<script>` and open it in the browser from the app's origin.
- Upload `test.php.jpg`, `test.jpg` with PHP magic bytes, a 1 KB file that declares `image/png`
  but is HTML; check what is served and with which headers.
- Request `../../etc/hostname`-style paths on download endpoints (or the Windows equivalent).
- Fetch an uploaded private file's URL from a different user/tenant and unauthenticated.

**Map to**: A01, A04 (2021 A04 Insecure Design), A05; ASVS V5 File Handling; CWE-434, CWE-22,
CWE-23, CWE-409, CWE-73, CWE-377.

## 10. API security

**Look for**
- Inventory: undocumented, deprecated (`/v1` still live), debug, admin, GraphQL introspection and
  playground, Swagger UI, actuator/health/metrics/env endpoints, `.git`/`.env`/backup files
  served by the web server, WebSocket endpoints without auth.
- Excessive data exposure: serializers returning whole models (password hashes, tokens, PII,
  internal flags), GraphQL over-fetching, error responses with stack traces/SQL.
- Pagination: no max page size, offset pagination on large tables (DoS), pages that leak counts of
  other tenants' rows.
- Unsafe consumption of third-party APIs: trusting upstream responses without validation,
  following redirects, deserializing arbitrary types, TLS verification disabled on the client.
- Function-level and property-level authorization (see area 1), mass assignment.
- Batch/bulk endpoints and GraphQL aliases/batching that multiply cost or bypass per-request limits.

**Prove it**
- Enumerate routes from code (router files, decorators, controllers, OpenAPI) and from the
  running app; diff the two. Everything reachable but undocumented is in scope.
- Call GraphQL `__schema`; call `/actuator/env`, `/debug`, `/swagger`, `/graphql` GET; compare
  responses authenticated vs not.
- Read a resource and diff the fields returned vs the fields the UI uses.

**Map to**: API1-API10; A02 Security Misconfiguration; ASVS V4 API and Web Service; CWE-200,
CWE-213, CWE-1059, CWE-209.

## 11. Rate limiting and resource/cost exhaustion

**Look for**
- No limits on: login, register, password reset, OTP/MFA verify, email/SMS sending, search,
  exports/reports, expensive queries, file upload, AI/LLM or other paid third-party calls,
  bulk endpoints, webhook retries, public forms.
- Limits keyed only by IP (bypass via proxies/IPv6), only by user (bypass unauthenticated),
  trusting `X-Forwarded-For` from anyone, limits implemented in memory in a multi-instance deploy.
- Regex DoS, unbounded JSON depth/size, GraphQL query depth/complexity, XML expansion,
  image dimension bombs, unbounded concurrency on background jobs.
- Cost exhaustion: a single unauthenticated call triggering paid API usage, SMS sends, storage.

**Prove it**
- Send a modest burst (for example 20-50 requests in a few seconds) to the endpoint in a
  non-production environment and observe whether anything throttles. Never load-test production.
- Read the limiter config: key, window, storage backend, header trust.

**Map to**: API4 Unrestricted Resource Consumption, API6 Unrestricted Access to Sensitive Business
Flows; A07; ASVS V2, V6; CWE-770, CWE-799, CWE-400, CWE-1333 (ReDoS).

## 12. Business logic

Scanners do not find these. Read the flows.

**Look for**
- Double submission / double payment: no idempotency key, no unique constraint, no lock;
  race between "check balance" and "debit"; coupon applied twice by parallel requests.
- TOCTOU: permission checked, then object reloaded/used later without re-check; file validated
  then moved; price read from the client.
- Replay: signed requests without nonce/timestamp; webhook signatures without replay window;
  one-time tokens accepted more than once.
- Workflow bypass / step skipping: calling step 3 without step 2 (checkout without payment,
  activation without verification, KYC skipped), state transitions not validated server-side.
- Negative or absurd values: negative quantity/amount, zero-price, overflow, currency mismatch,
  discount > total, percentage > 100.
- Unauthorized state transitions: cancel/refund/approve endpoints not checking current state or
  actor role; privilege changes via profile update.
- Trust boundaries: client-computed totals, client-supplied prices, hidden fields, feature flags
  from the client, "isAdmin" in local state.

**Prove it**
- Fire two identical requests concurrently (thread pool or `xargs -P`) at a non-production instance
  and check for duplicate side effects.
- Call endpoints out of order with a valid session. Submit negative values. Replay a webhook.
- Read the transaction/lock strategy around every money or privilege change.

**Map to**: A06 Insecure Design; API6; ASVS V2 Validation and Business Logic; CWE-362, CWE-367,
CWE-294, CWE-841, CWE-840, CWE-20, CWE-682.

## 13. Cryptography

**Look for**
- Home-made crypto, custom "encryption" with XOR/base64/rot, custom token formats.
- AES-ECB; AES-CBC without MAC (padding oracle); static or reused IVs/nonces (AES-GCM nonce reuse
  is catastrophic); keys derived from passwords without a KDF; keys shorter than 128 bits.
- Deprecated algorithms: MD5/SHA-1 for security purposes, DES/3DES, RC4, RSA PKCS#1 v1.5
  encryption, RSA < 2048, DSA, ECB, TLS < 1.2.
- Password hashing with plain hashes or fast hashes (SHA-256 without salt/iterations, MD5),
  or reversible encryption; missing per-user salt; work factor too low.
- Insecure randomness for security values: `random`, `Math.random`, `rand()`, `Random` (Java/.NET),
  `mt_rand`, time-seeded generators for tokens, session IDs, reset codes, OTPs, IVs.
- Hardcoded keys/secrets in code, config, IaC, images, JS bundles; same key across environments;
  no rotation procedure; keys stored beside the data they protect.
- Signature verification that ignores the result, compares with `==` (timing), or accepts
  multiple algorithms.
- Certificate verification bypasses (see area 14).

**Prove it**
- Read the primitive, mode, key source, IV source and authentication. Cite file and line.
- For randomness: identify the generator used at the point of token generation.
- For password hashing: read the hasher config and, if data access is authorized, inspect the
  hash prefix format (`$2b$`, `$argon2id$`, `pbkdf2_sha256$`).

**Map to**: A04 Cryptographic Failures (A02 in 2021); ASVS V11 Cryptography; CWE-327, CWE-328,
CWE-329, CWE-323, CWE-338, CWE-330, CWE-321, CWE-798, CWE-916, CWE-347, CWE-208.

## 14. TLS and certificates

**Look for**
- HTTP endpoints without redirect to HTTPS; mixed content; HSTS missing (see headers).
- Backend-to-backend, app-to-DB, app-to-Redis, app-to-queue over plaintext across networks.
- Verification disabled: `verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `rejectUnauthorized:false`,
  `InsecureSkipVerify: true`, `ServerCertificateCustomValidationCallback = ... => true`,
  `CURLOPT_SSL_VERIFYPEER => false`, `OpenSSL::SSL::VERIFY_NONE`, custom `TrustManager` that trusts all,
  `sslmode=disable`/`require` without CA (Postgres `require` does not verify the CA; use
  `verify-full`), `tls=skip-verify`, `trustServerCertificate=true`, `ssl: { rejectUnauthorized: false }`.
- Hostname validation disabled separately from chain validation.
- Weak configuration on servers/proxies: TLS 1.0/1.1, RC4/3DES/export/NULL ciphers, no forward
  secrecy, weak DH, certificate expired/self-signed in prod, private key world-readable, wildcard
  certs shared broadly, mTLS missing where the architecture assumes it.
- Certificate pinning absent for mobile/high-value clients (informational).

**Prove it**
- `openssl s_client -connect host:443 -servername host` and read protocol, cipher, chain, expiry.
- `nmap --script ssl-enum-ciphers -p 443 host` (authorized targets only) or `testssl.sh`/`sslscan`.
- Grep the bypass flags above; confirm they are active in the production configuration path,
  not only in tests.

**Map to**: A04 Cryptographic Failures; ASVS V12 Secure Communication; CWE-295, CWE-297, CWE-319,
CWE-326, CWE-327; CIS Benchmarks for the relevant server.

## 15. Secrets management and leakage

**Look for**
- Secrets in source, config, `.env` committed, Dockerfiles (`ENV`/`ARG`, copied files, layer
  history), docker-compose `environment:`, Terraform (`default =`, tfvars, tfstate in repo or
  unencrypted backend), Helm values, K8s manifests (`stringData`), CI logs and workflow files,
  frontend bundles (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `NUXT_PUBLIC_*` used for private keys),
  source maps, mobile apps, git history (removed but still in history), issue trackers, logs.
- Secrets shared across environments; the same JWT secret in staging and prod.
- No secret manager; secrets baked into AMIs/images; long-lived static cloud keys instead of
  workload identity; service accounts with JSON keys committed.
- Application logs printing headers, tokens, full request bodies, DB URLs with passwords.

**Prove it**
- Run gitleaks/trufflehog on the working tree AND history (`git log -p` is in scope when the
  user owns the repo). Inspect the JS bundle for key-shaped strings. Inspect `docker history`.
- Confirm liveness carefully and only when authorized (for example a read-only `whoami` call);
  never use a found credential to access data. Report as Confirmed on the basis of format and
  location if liveness is not tested, and say so.
- NEVER paste the value in the report. Use `[REDACTED: type, length, location]`.

**Map to**: A02 Security Misconfiguration, A04; ASVS V13 Configuration, V14 Data Protection;
CWE-798, CWE-312, CWE-522, CWE-532, CWE-540.

## 16. Databases

**Look for**
- Public exposure (0.0.0.0 bind, security group open to the internet, compose `ports: 5432:5432`
  on a server), default ports with default credentials, no TLS in transit, no encryption at rest
  (cloud-managed disks usually encrypt; verify TDE/KMS on managed services), field-level encryption
  absent for regulated data where policy requires it.
- The application connects as a superuser/owner/`sa`/`root`; a single account for migrations and
  runtime; no separate read-only account for reporting; no row-level security where tenancy
  relies on it.
- Backups absent, unencrypted, in a public bucket, never restore-tested, retained forever with PII.
- Admin UIs (pgAdmin, phpMyAdmin, Adminer, mongo-express) reachable; SQL logging with parameters.
- Parameterization gaps (area 4); dynamic schema/tenant names concatenated.
- Mongo without auth (`--noauth`), Redis-like default no-password exposure, SQL Server with
  `xp_cmdshell` enabled, Postgres `trust` in `pg_hba.conf`.

**Prove it**
- Read the connection string source, user privileges (`\du`, `SHOW GRANTS`, `sp_helprolemember`,
  `db.getUsers()`), TLS settings, firewall/security group rules, backup config.
- `nmap -p 5432,3306,1433,27017,6379 host` on owned/authorized infrastructure.

**Map to**: A02, A04; ASVS V13, V14; CIS Benchmarks (PostgreSQL, MySQL, SQL Server, MongoDB);
CWE-284, CWE-306, CWE-311, CWE-732.

## 17. Redis and caches

**Look for**
- No `requirepass`/ACL, bound to all interfaces, exposed port, no TLS, `protected-mode no`,
  dangerous commands (`CONFIG`, `FLUSHALL`, `DEBUG`, `EVAL`, `MODULE`) available to the app user,
  shared instance across tenants/environments.
- Cache keys without user/tenant scoping (one user's cached response served to another),
  caching authenticated responses at the CDN/proxy (`Cache-Control: public` on private pages),
  sensitive data (tokens, PII, sessions) cached without TTL, pickle/serialized objects in cache
  (deserialization on read).
- Session stores and rate limiters in Redis with no auth = full account takeover if reachable.

**Prove it**
- Read the Redis config/compose/Helm values; `redis-cli -h host PING` against owned hosts only.
- Trace cache key construction for every authenticated cached response.

**Map to**: A02, A01; ASVS V13, V14; CIS; CWE-306, CWE-524, CWE-284.

## 18. Queues, workers and background jobs

**Look for**
- Workers trusting message contents (`user_id`, `tenant_id`, `is_admin`, file paths, URLs) without
  re-validating authorization against the source of truth; messages producible by less-trusted code
  or by users (public webhook -> queue).
- Serialized payloads: pickle (Celery `accept_content` with pickle), Java serialization, YAML,
  `Marshal` in Sidekiq args, JSON with type hints.
- Replay/duplicate delivery without idempotency (at-least-once delivery + non-idempotent handlers).
- Retry storms, poison messages that crash workers forever, unbounded queue growth by
  unauthenticated producers, dead-letter queues holding PII indefinitely.
- Broker exposed (RabbitMQ management UI default `guest/guest`, Kafka without SASL/TLS,
  SQS policies with `Principal: *`), Celery flower UI without auth, Sidekiq Web mounted without auth.
- Jobs that run shell commands with arguments from messages; jobs that write files by message-supplied path.

**Prove it**
- Read producer and consumer code for each queue; list who can enqueue.
- Enqueue a message with a forged ID in a non-production environment and observe the effect.

**Map to**: A01, A08 Software or Data Integrity Failures; ASVS V2, V4; CWE-502, CWE-862, CWE-294, CWE-400.

## 19. Webhooks and external integrations

**Look for**
- Inbound webhooks without signature verification (Stripe, GitHub, Twilio, payment providers),
  signature checked with non-constant-time compare, timestamp not checked (replay), raw body not
  used for HMAC (parsed then re-serialized), secrets shared across tenants, endpoints that process
  events for any account ID in the payload.
- Outbound webhooks/callbacks = SSRF surface (area 8); secrets sent to user-configured URLs;
  no retry limits; following redirects.
- Third-party credentials over-scoped (full-access API keys where read-only suffices); OAuth
  tokens stored unencrypted; TLS verification disabled on clients; trusting third-party data
  in HTML/SQL/commands.

**Prove it**
- Post an unsigned or re-signed payload to the webhook endpoint in a non-production environment.
- Replay a previously captured valid webhook.

**Map to**: A08, A10/API7, API10 Unsafe Consumption of APIs; ASVS V4; CWE-345, CWE-347, CWE-294, CWE-918.

## 20. Frontend and browser security

**Look for**
- Tokens/PII in `localStorage`/`sessionStorage`/IndexedDB (any XSS = account takeover); refresh
  tokens accessible to JS; secrets in public env variables (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`,
  `NUXT_PUBLIC_`, Angular `environment.ts`) or in the built bundle; source maps deployed to
  production exposing server-side code or keys; debug flags left on.
- Cookies missing `HttpOnly`/`Secure`/`SameSite`; overly broad `Domain`/`Path`.
- Missing or weak CSP (unsafe-inline/unsafe-eval, wildcard sources), missing frame-ancestors
  (clickjacking), postMessage without origin validation, `target=_blank` without `rel=noopener`
  (older browsers), open redirects via `?next=`/`returnUrl`, client-side authorization only.
- SSR-specific: injecting state into HTML without escaping, server-only code imported into
  client bundles, `getServerSideProps`/loaders returning more than the page needs.
- Third-party scripts without SRI, tag managers with unrestricted injection, prototype pollution
  via query parsing libraries.

**Prove it**
- Build the frontend and grep the output bundle for key-shaped strings, private hostnames,
  and known secret prefixes; check for `.map` files served in production.
- Inspect cookies and storage in the browser after login; inspect response headers.

**Map to**: A02, A04, A05; ASVS V3 Web Frontend Security, V14; CWE-922, CWE-1004, CWE-614,
CWE-1275, CWE-1021, CWE-601, CWE-540, CWE-829.

## 21. Security headers

Apply headers that fit the architecture. A strict CSP on an app that inlines scripts everywhere
will break it; propose a reportable rollout instead of a blind header.

**Evaluate**
- `Content-Security-Policy`: present; no `unsafe-inline` for scripts (use nonces/hashes) unless
  justified; no wildcard script sources; `object-src 'none'`; `base-uri 'self'`; `frame-ancestors`.
- `Strict-Transport-Security`: `max-age >= 31536000`, `includeSubDomains` where safe, preload only
  if all subdomains are HTTPS.
- Anti-clickjacking: `frame-ancestors` (preferred) or `X-Frame-Options: DENY/SAMEORIGIN`.
- `X-Content-Type-Options: nosniff`; `Referrer-Policy: strict-origin-when-cross-origin` or stricter;
  `Permissions-Policy` limiting camera/microphone/geolocation as appropriate.
- `Cache-Control: no-store` on authenticated/sensitive responses; `Set-Cookie` attributes.
- Cross-origin isolation headers (`Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`,
  `Cross-Origin-Embedder-Policy`) where the app benefits; `X-XSS-Protection` is obsolete, do not
  recommend it.
- Server/technology disclosure headers (`Server`, `X-Powered-By`) are Informational.

**Prove it**
- `curl -sI https://host/` and an authenticated page; read what is actually sent, per route
  (proxies often override the app).

**Map to**: A02 Security Misconfiguration; ASVS V3; CWE-1021, CWE-693, CWE-525.

## 22. Docker and containers

**Look for**
- Running as root (no `USER`), `privileged: true`, `--cap-add ALL`/`SYS_ADMIN`, Docker socket
  mounted, host paths mounted (`/`, `/etc`, `/var/run`), `network_mode: host`, `pid: host`,
  no read-only root filesystem, no `no-new-privileges`, no resource limits.
- Secrets in image layers (`COPY .env`, `ARG TOKEN` used in `RUN`, `docker history` shows them),
  `.dockerignore` missing so `.git`/`.env` end up in the image.
- Base images unpinned (`:latest`, tag without digest), EOL base images, large images with
  package managers and shells in production, no vulnerability scanning of images.
- Ports published to `0.0.0.0` on hosts (compose `ports:` vs `expose:`), databases published.
- `docker-compose` files with production credentials, shared default networks across unrelated
  services, no user namespaces, containers running SSH.

**Prove it**
- Read Dockerfiles/compose (the inventory script flags root, unpinned base, privileged, socket
  mounts, published ports). `trivy image`/`grype` for CVEs; `hadolint`/`dockle` for practices;
  `docker inspect` on running containers for caps/mounts (owned hosts only).

**Map to**: A02, A03 Software Supply Chain Failures (2025) / A06 Vulnerable and Outdated Components (2021);
CIS Docker Benchmark; CWE-250, CWE-269, CWE-1104, CWE-732.

## 23. Kubernetes

**Look for**
- RBAC: `cluster-admin` bound to service accounts/users broadly, wildcard verbs/resources,
  `default` service account auto-mounted with permissions, secrets `list`/`get` cluster-wide,
  `pods/exec` granted, escalate/bind/impersonate verbs.
- Pod security: `privileged`, `hostNetwork`/`hostPID`/`hostIPC`, `hostPath`, `runAsUser: 0`,
  `allowPrivilegeEscalation: true`, missing `securityContext`, no `readOnlyRootFilesystem`,
  capabilities added, no Pod Security Admission/Standards (`restricted`/`baseline`) enforced.
- Network: no `NetworkPolicy` (flat cluster), services `type: LoadBalancer`/`NodePort` exposing
  internal components, ingress without TLS, dashboard/kube-apiserver/etcd/kubelet reachable.
- Secrets: plain K8s Secrets (base64) without encryption at rest configured, secrets in
  ConfigMaps/env, no external secret manager, secrets in Helm values committed.
- Images: unpinned tags, `imagePullPolicy` issues, no admission control on registries, no
  signature verification, in-cluster registry credentials broadly readable.
- Resource limits missing (noisy neighbor/DoS), no namespaces separation between tenants/envs,
  `automountServiceAccountToken` default true.

**Prove it**
- Static: `kube-linter lint`, `kubescape scan`, `checkov -d`, `kubesec scan` on manifests/charts.
- Live (authorized, read-only): `kubectl auth can-i --list`, `kubectl get clusterrolebindings -o yaml`,
  `kubectl get pods -A -o json` and inspect securityContext; `kube-bench` on nodes.

**Map to**: A02; CIS Kubernetes Benchmark; Pod Security Standards; CWE-250, CWE-269, CWE-284, CWE-732.

## 24. Terraform and IaC

**Look for**
- State: local state committed, remote backend without encryption/locking/versioning, state
  readable by too many identities (state contains secrets in plaintext).
- Secrets: `default =` values for sensitive variables, tfvars committed, `sensitive = true` missing,
  outputs exposing secrets, provider credentials hardcoded.
- Resources: security groups/NSGs/firewall rules `0.0.0.0/0` on admin/DB ports, public S3/Blob/GCS
  buckets or ACLs, public IPs on databases, unencrypted disks/volumes/snapshots/queues, logging
  disabled, versioning disabled, deletion protection off, IAM policies with `*`, KMS keys with
  wide policies, VMs with IMDSv1 allowed, RDS/SQL `publicly_accessible`, storage without
  `https_only`, Key Vault without purge protection/soft delete, GCS uniform access off.
- Modules unpinned (`source = "git::..."` without ref, registry modules without version),
  providers unpinned, `terraform.lock.hcl` missing.
- Helm: values with secrets, `templates/` disabling security contexts, chart deps unpinned.
- CloudFormation/Bicep/ARM/Pulumi: equivalents of the above.

**Prove it**
- `checkov -d .`, `tfsec .`, `terrascan scan`, `kics scan`; then read each flagged resource and
  decide whether it is exploitable in this architecture (a public bucket serving a static website
  is intended; a public bucket holding uploads is not).

**Map to**: A02, A03; CIS Foundations Benchmarks (AWS/Azure/GCP); CWE-16, CWE-732, CWE-312, CWE-1188.

## 25. Cloud IAM, network and storage

Use read-only inventory first (see tooling-playbook.md). Never modify in Mode A/B.

**Look for**
- IAM: users with long-lived access keys (rotate/replace with roles/workload identity), keys
  unused for 90+ days, admin/`*` policies, no MFA on console/root/owner accounts, root/global
  admin used for daily work, cross-account trust policies with `Principal: *` or missing
  external ID, service principals with client secrets that never expire, over-broad managed
  identities, GCP default service accounts with Editor.
- Network: security groups/NSGs/firewall rules open to `0.0.0.0/0` on SSH/RDP/DB/Redis/Kafka,
  public IPs on data stores, no private endpoints/service endpoints for managed services, VPC
  flow logs off, bastion-less exposure, metadata service v1 allowed (AWS IMDSv1), Azure/GCP
  metadata reachable through SSRF (area 8).
- Storage: public buckets/containers, "authenticated users" grants, public snapshots/AMIs,
  SAS tokens with long expiry and broad permissions, signed URLs never expiring, no
  encryption with customer-managed keys where policy requires, versioning/soft delete off,
  no access logging.
- Secrets/keys: Key Vault/KMS/Secrets Manager not used, key policies broad, rotation off,
  secrets in Lambda/Function app settings without a vault, environment variables in
  container definitions.
- Logging/monitoring: CloudTrail/Activity Log/Audit Logs off or not retained, GuardDuty/Defender/SCC
  off, no alerts on root/global-admin usage, no alerts on IAM changes.
- Backup: no automated backups, no cross-region/cross-account copies, backups deletable by the
  same identity that could be compromised (no immutability/vault lock).
- Serverless: functions with `*` roles, public function URLs without auth, environment variables
  with secrets, unbounded concurrency (cost), VPC-less access to internal resources.

**Prove it**
- Read-only CLI inventory; cite resource IDs, never credentials. Cross-check with IaC to see
  whether drift exists (console changes not in code).

**Map to**: A02, A04, A07; CIS Foundations Benchmarks; NIST SSDF PO/PS practices; CWE-284,
CWE-306, CWE-732, CWE-798, CWE-311, CWE-778.

## 26. CI/CD and supply chain

**Look for**
- Secrets exposure: secrets echoed in logs, passed to untrusted steps, available to PR builds
  from forks, stored in repo variables instead of secrets, `.npmrc`/`.pypirc` with tokens.
- Overly privileged tokens: `permissions: write-all`, default `GITHUB_TOKEN` with write on PRs,
  PATs with `repo`/`admin`, deploy credentials in every job, cloud keys instead of OIDC federation.
- Unsafe PR workflows: `pull_request_target` with checkout of the PR head, `workflow_run` chains,
  running `npm install`/`pip install` from untrusted PRs on self-hosted runners, script injection
  via `${{ github.event.pull_request.title }}` in `run:`.
- Self-hosted runners shared across repos/trust levels, persistent runners, runners with cloud
  roles, no ephemeral isolation.
- Unpinned actions/plugins/orbs (tags instead of SHAs), unpinned base images, unpinned
  dependencies installed at build time, `curl | sh` installs, cache poisoning via PR-writable
  cache keys, artifacts from untrusted builds promoted to deploy, no provenance/signing (SLSA,
  Sigstore/cosign), no SBOM.
- Missing approvals: production environment without required reviewers, no branch protection,
  force-push allowed, no required status checks, CODEOWNERS absent, admins bypass.
- Deployment: credentials in `deploy.sh`, kubeconfig committed, `kubectl apply` from PR builds,
  Terraform apply on PR, secrets printed by `terraform plan`.

**Prove it**
- Read every workflow (the inventory script lists `uses:` pins, `pull_request_target`,
  `write-all`, self-hosted). Check branch protection via `gh api repos/{owner}/{repo}/branches/main/protection`
  (read-only) when access exists. Reproduce script injection with a benign PR title in a fork
  ONLY with authorization.

**Map to**: A03 Software Supply Chain Failures (2025), A08 Software or Data Integrity Failures;
NIST SSDF PO.3, PS.1-PS.3, PW.4; SLSA; CWE-829, CWE-494, CWE-506, CWE-1357, CWE-78 (script injection).

## 27. Dependencies

**Look for**
- Known-vulnerable versions (run the ecosystem audit + at least one cross-checker: OSV/Trivy/Grype).
- Unmaintained/EOL frameworks and runtimes (Django/Node/.NET/Spring/Rails/PHP versions past EOL),
  packages with no releases in years used in security-critical paths.
- Missing lockfiles; lockfile not used in CI (`npm install` instead of `npm ci`); `pip install` without hashes.
- Typosquat/dependency confusion risk: private package names without a scoped registry,
  `extra-index-url` mixing public and private, unscoped internal npm packages.
- Install scripts (`postinstall`) from untrusted packages; git/URL dependencies without commit pins.
- Vulnerable transitive deps that are actually reachable (triage reachability; report the rest as
  Low/Informational hygiene, not as exploitable).

**Prove it**
- Run the audit tools; for each High/Critical, confirm the vulnerable function/path is used
  (grep imports, read the advisory's affected API). Reachable = report at advisory severity;
  not reachable = downgrade with the reason.

**Map to**: A03 (2025) / A06 (2021); ASVS V15; NIST SSDF PW.4; CWE-1104, CWE-1395, CWE-937.

## 28. Logging, monitoring and error handling

**Look for**
- Missing audit logs for login, failed login, password/MFA changes, role changes, data export,
  admin actions, payment events, webhook receipts; logs without actor, target, timestamp, source.
- Sensitive data in logs (tokens, passwords, PII, full request bodies, DB URLs, card data).
- Log injection (newlines/ANSI/JSON-breaking from input); logs writable by the app user only
  (tamper), no central shipping, no retention policy, no alerting on security events.
- Error handling: stack traces/SQL/internal paths returned to clients, `DEBUG=True`,
  `app.debug`, `ASPNETCORE_ENVIRONMENT=Development` in prod, detailed errors in APIs, verbose
  404 pages, exceptions that fail open (catch-all that continues as authorized).
- Health/metrics endpoints leaking internals (`/metrics`, `/actuator`, `/debug/pprof`, `/_profiler`,
  `/telescope`, `/horizon`, `/__debug__`, `/elmah.axd`, `/hangfire`) without auth.

**Prove it**
- Trigger a handled and an unhandled error in non-production and read the response.
- Read logging config; grep log statements for secret-shaped variables.
- Perform a sensitive action and check whether it produced an audit record.

**Map to**: A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions (2025);
ASVS V16 Security Logging and Error Handling; CWE-778, CWE-532, CWE-117, CWE-209, CWE-215, CWE-636.

## 29. Backup and recovery

**Look for**
- No automated backups for databases, object storage, secrets, configuration; backups in the
  same account/region/blast radius as production; backups deletable with production credentials;
  no immutability/retention lock; unencrypted backups or backups encrypted with a key stored
  alongside; backups containing PII beyond retention policy; no restore test ever performed;
  no documented RPO/RTO; ransomware exposure (single identity can destroy prod and backups).

**Prove it**
- Read backup configuration (cloud backup policies, cron jobs, `pg_dump` scripts, snapshot
  schedules); look for a restore runbook and evidence of a test. Mark Blocked if not accessible.

**Map to**: A02, A09; NIST SSDF; CIS Controls 11; CWE-654 (reliance on a single factor), CWE-693.

## 30. Reverse proxies, load balancers and network exposure

**Look for**
- Proxy passing `X-Forwarded-For`/`X-Real-IP`/`X-Forwarded-Proto` without stripping client-supplied
  values (IP spoofing, rate-limit bypass, HTTPS-detection bypass); app trusting all proxies
  (`TrustedProxies = *`, `USE_X_FORWARDED_HOST` without ALLOWED_HOSTS, Express `trust proxy: true`).
- Host header injection (password reset links, cache poisoning) when the proxy forwards any Host.
- Path normalization mismatches between proxy and app (`/admin/../api`, `//admin`, `;` params,
  `%2e`), allowing bypass of proxy-level auth rules; nginx `alias` traversal (`location /static`
  with `alias /data/`); `proxy_pass` with user-influenced upstream (SSRF).
- Missing request size/timeout limits (slowloris, large body), HTTP/2 or request smuggling
  vectors (`Transfer-Encoding` vs `Content-Length` handling between proxy and backend), WebSocket
  upgrade without origin checks.
- TLS termination with plaintext to backend across untrusted networks; internal services
  reachable directly bypassing the proxy (auth enforced only at the edge).
- Directory listing, `.git`/`.env`/backup files served, default vhost serving the app for any Host,
  admin panels only "protected" by IP allowlists that trust forwarded headers.
- Exposed network services: `nmap` (authorized) on owned hosts for databases, message brokers,
  admin UIs, debug ports (`5005` JDWP, `9229` Node inspector, `2375` Docker API, `10250` kubelet).

**Prove it**
- Send `X-Forwarded-For: 127.0.0.1` and a spoofed `Host` to the running app and observe behavior
  (rate limit keys, generated links, admin allowlists).
- Request `/.git/HEAD`, `/.env`, `/backup.zip`, `/admin/` through the proxy.
- `nmap -sV -p- host` on authorized targets, then map every open port to an owner and an auth model.

**Map to**: A02, A01; ASVS V13, V4; CWE-444 (smuggling), CWE-290, CWE-346, CWE-548, CWE-441.
