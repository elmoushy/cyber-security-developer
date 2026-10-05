# Framework and platform playbooks

Open the sections that match the inventory (`scripts/security_inventory.py`). Each playbook
lists: how the technology is detected, its dangerous sinks and escape hatches, the auth/session
defaults and config keys that matter, the misconfigurations that keep coming back, and a
verification command that has to work in the target environment. The general checklists live in
`security-baseline.md`; this file only holds what is specific to the technology.

## Table of contents

Frontend: React | Next.js | Angular | Vue / Nuxt | Svelte / SvelteKit | Generic SPA / SSR
Backend: Django / DRF | FastAPI / Starlette | Flask | Node.js / Express | NestJS | ASP.NET Core |
Spring Boot | Laravel / PHP | Ruby on Rails | Go (net/http, Gin, Echo, Fiber, chi) | Serverless |
GraphQL | WebSockets
Data: PostgreSQL | MySQL / MariaDB | SQL Server | MongoDB | Redis | Queues (RabbitMQ, Kafka, SQS,
Celery, Sidekiq, BullMQ) | Object storage
Platform: Docker / Compose | Kubernetes / Helm | Terraform | nginx / Caddy / Traefik / HAProxy / IIS |
AWS | Azure | GCP | CI/CD (GitHub Actions, GitLab CI, Azure Pipelines, Jenkins)

---

## Frontend

### React
- Detect: `react`, `react-dom` in package.json; `.jsx/.tsx`.
- Sinks: `dangerouslySetInnerHTML`, `href={userInput}` (javascript: URLs; React blocks only
  some cases), `ref.current.innerHTML`, third-party components that accept raw HTML (`react-html-parser`,
  `html-react-parser`, `react-markdown` + `rehype-raw`), `eval`/`new Function` in helpers,
  server state serialized into `<script>` in custom SSR.
- Storage: tokens in `localStorage` (XSS-readable). Prefer HttpOnly cookies + CSRF protection, or
  in-memory access token + HttpOnly refresh cookie.
- Env: `REACT_APP_*`/`VITE_*` are public. Any private key there is a Confirmed leak.
- Misconfigs: source maps in prod (`GENERATE_SOURCEMAP=true`, `productionBrowserSourceMaps`), route
  guards treated as authorization, `process.env` secrets bundled by webpack `DefinePlugin`.
- Verify: build (`npm run build`), then search `dist/`/`build/` for key prefixes (`sk_live`, `AKIA`,
  `-----BEGIN`, `eyJhbGci`) and for internal hostnames.

### Next.js
- Detect: `next` dep, `next.config.*`, `app/` or `pages/`.
- Server/client boundary: only `NEXT_PUBLIC_*` reaches the browser by design, but importing a
  server module into a client component, returning secrets from `getServerSideProps`/`loaders`/
  server actions, or leaking via `props` serialization does. Check Server Actions for authorization
  (they are public POST endpoints), `revalidatePath`/`revalidateTag` handlers, Route Handlers
  (`app/api/**/route.ts`) for auth + method checks, middleware bypass (matcher gaps, `x-middleware-subrequest`
  header CVE-2025-29927 in affected versions: verify the version and patch).
- Sinks: `dangerouslySetInnerHTML`, `next/script` with user strings, `<Image src={userUrl}>` with
  open `remotePatterns` (SSRF via image optimizer), `redirect(userInput)` (open redirect),
  `rewrites`/`redirects` with user data, `next-auth` misconfig (missing `NEXTAUTH_SECRET`, `trustHost`).
- Headers: set in `next.config.js` `headers()` or middleware; CSP needs nonces for inline scripts.
- Misconfigs: `NEXT_PUBLIC_` misuse, API routes without auth, image optimizer open to any host,
  `output: 'standalone'` images running as root, `.env.local` committed.
- Verify: `npm run build` then grep `.next/static` for secrets; `curl -I` a protected route with and
  without the session cookie; check middleware version against advisories.

### Angular
- Detect: `@angular/core`, `angular.json`.
- Sinks: `[innerHTML]` (sanitized by default, but `DomSanitizer.bypassSecurityTrustHtml/Script/Style/Url/ResourceUrl`
  bypasses), `ElementRef.nativeElement.innerHTML`, `Renderer2.setProperty(el,'innerHTML')`, template
  injection when compiling templates at runtime (JIT with user strings), `window.location = userUrl`.
- Auth: `HttpInterceptor` attaching tokens to every host (token leakage to third parties), route
  `canActivate` is UX only, `HttpClient` XSRF support needs cookie `XSRF-TOKEN` + header `X-XSRF-TOKEN`.
- Env: `src/environments/*.ts` is shipped. Secrets there are public.
- Verify: `ng build --configuration production` then grep `dist/` for secrets and `bypassSecurityTrust`.

### Vue / Nuxt
- Detect: `vue`, `nuxt`, `nuxt.config.*`, `.vue` files.
- Sinks: `v-html`, `v-bind:href` with `javascript:`, `<component :is>` with user strings, runtime
  template compilation (`new Vue({template: userString})`, `compile()`), `innerHTML` in composables,
  Nuxt `useFetch`/server routes (`server/api/**`) without auth, `runtimeConfig.public` holding secrets,
  Nuxt `nuxt.config` `routeRules` proxying to user-controlled targets, `navigateTo(userInput, {external:true})`.
- Storage/env: `NUXT_PUBLIC_*` and `runtimeConfig.public` are public; private `runtimeConfig` keys
  must never be referenced in client components.
- Verify: `nuxi build`/`vite build` and grep the output; hit `server/api` routes unauthenticated.

### Svelte / SvelteKit
- Detect: `svelte`, `@sveltejs/kit`, `svelte.config.*`.
- Sinks: `{@html ...}`, `bind:innerHTML`, `goto(userInput)`, `redirect(303, userInput)`, form
  actions (`+page.server.ts` `actions`) without auth/CSRF (SvelteKit checks origin by default; verify
  `csrf.checkOrigin` not disabled), `+server.ts` endpoints without auth, `$env/static/public` vs
  `$env/static/private` misuse, `hooks.server.ts` handle that sets `locals.user` from an unverified cookie.
- Verify: build and grep; call `+server.ts` endpoints directly; check `csrf.checkOrigin` in config.

### Generic SPA / SSR checks (any framework)
- Bundle grep for secrets; source maps; `Cache-Control` on HTML with user data; CSP presence;
  cookie flags; open redirect params (`next`, `returnTo`, `redirect_uri`, `url`, `continue`);
  postMessage listeners; WebSocket origin checks; third-party script SRI; service worker caching
  authenticated responses.

---

## Backend

### Django / Django REST Framework
- Detect: `django`, `djangorestframework`, `manage.py`, `settings.py`.
- Settings that matter: `DEBUG`, `SECRET_KEY` (source and rotation), `ALLOWED_HOSTS` (`*` = host
  header attacks), `SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE/HTTPONLY/SAMESITE`, `CSRF_COOKIE_SECURE`,
  `CSRF_TRUSTED_ORIGINS`, `SECURE_HSTS_SECONDS`, `SECURE_PROXY_SSL_HEADER` (only behind a proxy that
  strips it), `USE_X_FORWARDED_HOST`, `PASSWORD_HASHERS` (Argon2/PBKDF2/bcrypt only), `AUTH_PASSWORD_VALIDATORS`,
  `X_FRAME_OPTIONS`, `DATA_UPLOAD_MAX_MEMORY_SIZE`, `FILE_UPLOAD_PERMISSIONS`, `MEDIA_ROOT` under web root,
  `CORS_ALLOW_ALL_ORIGINS`/`CORS_ALLOWED_ORIGIN_REGEXES` (django-cors-headers), `DEFAULT_PERMISSION_CLASSES`
  (DRF default is `AllowAny`), `DEFAULT_AUTHENTICATION_CLASSES`, `DEFAULT_THROTTLE_CLASSES/RATES`,
  SimpleJWT `SIGNING_KEY`/`ALGORITHM`/`ACCESS_TOKEN_LIFETIME`/`ROTATE_REFRESH_TOKENS`/`BLACKLIST_AFTER_ROTATION`.
- Sinks: `.raw()`, `.extra()`, `RawSQL`, `cursor.execute(f"...")`, `connection.cursor()` string
  formatting, `mark_safe`, `format_html` with unsafe args, `|safe`, `autoescape off`, `Template(user)`,
  `render_to_string` with user template names, `eval`/`exec`, `pickle` (cache backends with pickle,
  Celery `accept_content`), `yaml.load`, `subprocess(shell=True)`, `open(os.path.join(MEDIA_ROOT, user))`,
  `redirect(request.GET['next'])` without `url_has_allowed_host_and_scheme`, `HttpResponseRedirect` from input,
  `get_object_or_404(Model, pk=id)` without `owner=request.user` (IDOR), `serializer_class` with `fields='__all__'`
  or writable `owner`/`is_staff` (mass assignment), `ModelViewSet` `get_queryset` returning `Model.objects.all()`,
  `@csrf_exempt`, `permission_classes = []`, `AllowAny` on write views, `SessionAuthentication` mixed with
  token auth (CSRF only enforced for session), signals/tasks trusting IDs.
- Admin: `/admin/` exposed without 2FA or IP restriction; `django-debug-toolbar` in prod;
  `silk`, `django-extensions` `runserver_plus`.
- Verify: `python manage.py check --deploy`; `bandit -r .`; `semgrep --config p/django`; `pip-audit`;
  authz matrix with two users on every `ViewSet`.

### FastAPI / Starlette
- Detect: `fastapi`, `starlette`, `uvicorn`.
- Auth: dependencies (`Depends(get_current_user)`) must be on every router/route, including
  WebSocket routes and `include_router` groups; `OAuth2PasswordBearer` `auto_error=False` paths that
  continue anonymous; `python-jose`/`PyJWT` decode with `algorithms` unset or `verify_exp=False`;
  refresh tokens stored nowhere (no revocation); passlib config; `SECRET_KEY` from env.
- Sinks: f-string SQL in `text()`/`execute`, SQLAlchemy `text()` with format, `Jinja2Templates`
  rendering user strings, `RedirectResponse(user_url)`, `FileResponse(path_from_user)`, `StaticFiles`
  serving upload dirs, `BackgroundTasks` trusting IDs, `pickle`, `yaml.load`, `subprocess`.
- Misconfigs: `CORSMiddleware(allow_origins=["*"], allow_credentials=True)` (Starlette drops `*`
  with credentials but regex/lists can still be wrong), `/docs` `/redoc` `/openapi.json` exposed in
  prod (Informational unless they leak internals), no `TrustedHostMiddleware`, no rate limiting
  (slowapi absent), Pydantic models with `extra="allow"` and DB writes from `.model_dump()`
  (mass assignment), `debug=True`, uvicorn `--proxy-headers` without `--forwarded-allow-ips`.
- Verify: `semgrep --config p/python --config p/fastapi` (if available), `pip-audit`, hit every
  route unauthenticated, decode a tampered JWT.

### Flask
- Detect: `flask`, `app.py`/`wsgi.py`, `FLASK_APP`.
- Config: `SECRET_KEY` (sessions are client-side signed cookies: a leaked key = forge any session),
  `SESSION_COOKIE_SECURE/HTTPONLY/SAMESITE`, `PERMANENT_SESSION_LIFETIME`, `MAX_CONTENT_LENGTH`,
  `debug=True` (Werkzeug debugger = RCE), `flask-cors` `CORS(app)` defaults (`*`), `flask-wtf` CSRF
  enabled per form/globally, `flask-login` `login_required` on every view, `flask-jwt-extended`
  `JWT_SECRET_KEY`, blocklist for revocation, `flask-limiter` presence.
- Sinks: `render_template_string(user)` (SSTI -> RCE), `Markup(user)`, `|safe`, `send_file(user_path)`
  / `send_from_directory` with unvalidated names, `redirect(request.args.get('next'))`, `os.system`,
  `subprocess`, `eval`, raw SQL with format, `pickle`, `yaml.load`, `sqlalchemy.text`.
- Verify: check `app.run(debug=...)` and `FLASK_DEBUG` in deploy; `bandit`; `semgrep --config p/flask`;
  `pip-audit`.

### Node.js / Express
- Detect: `express`, `app.listen`, `server.js`.
- Auth/session: `express-session` `secret` source, `cookie: {secure, httpOnly, sameSite}`, store
  (MemoryStore in prod = leaks/DoS), `resave`/`saveUninitialized`; `jsonwebtoken` `verify` with
  `algorithms: [...]` pinned, `expiresIn`, `issuer`/`audience`; `passport` strategies and `session: false`
  for APIs; `bcrypt`/`argon2` for passwords; `cookie-parser` signed cookies with weak secrets.
- Sinks: string SQL (`pool.query("... " + x)`, `sequelize.query`, `knex.raw`, Prisma `$queryRawUnsafe`,
  `$executeRawUnsafe`), Mongo query objects from `req.body` (`User.find(req.body)`, `{ $where }`),
  `child_process.exec(userInput)`, `execSync`, `spawn(..., {shell:true})`, `eval`, `new Function`,
  `vm.runInNewContext` (not a sandbox), `vm2`, `res.send(userHtml)`, `ejs.render(userString)`,
  `res.redirect(req.query.url)`, `res.sendFile(path.join(base, req.params.file))` without
  `path.resolve` prefix check, `express.static` on upload dirs, `fs.*` with user paths,
  `serialize-javascript`/`node-serialize` `unserialize`, `xml2js`/`libxmljs` with entities,
  `JSON.parse` prototype pollution via `_.merge`/`deep-extend` on `req.body`, `qs` depth,
  `multer` without `fileFilter`/`limits`, `body-parser` without `limit`, `helmet` absent, `cors()`
  with `origin: true` reflecting any origin + `credentials: true`, `app.set('trust proxy', true)`
  behind an untrusted edge, missing `express-rate-limit`, error handler returning `err.stack`.
- Verify: `npm audit --audit-level=high`, `semgrep --config p/nodejs --config p/express`, `eslint-plugin-security`,
  `node --check`, authz matrix, `curl -H "Origin: https://evil.example"`.

### NestJS
- Detect: `@nestjs/core`, `main.ts` with `NestFactory`.
- Auth: `@UseGuards(AuthGuard(...))` per controller/handler or a global `APP_GUARD`; `@Public()`
  decorator logic (metadata reflection bugs make everything public); `RolesGuard` reading roles from
  the JWT without re-checking; `JwtModule.register({ secret })` source, `signOptions.expiresIn`,
  `JwtStrategy` `ignoreExpiration: true`, `secretOrKeyProvider` for rotation.
- Sinks: `TypeORM` `query()`/`createQueryBuilder().where(\`... ${x}\`)`, Prisma raw, Mongoose with
  body objects; `ValidationPipe` missing or without `whitelist: true`/`forbidNonWhitelisted: true`
  (mass assignment); DTOs with `@Allow()` on privileged fields; `@Res()` raw responses with HTML;
  `FileInterceptor` without `fileFilter`/`limits`; `HttpService` fetching user URLs; GraphQL
  resolvers without guards; WebSocket gateways without guards; microservice transports without auth.
- Misconfigs: `app.enableCors()` with no options, `helmet` absent, `ThrottlerModule` absent,
  Swagger (`/api`) exposed in prod, global exception filter leaking stack traces.
- Verify: `npm audit`, `semgrep --config p/nodejs`, check `APP_GUARD` and every `@Public()`.

### ASP.NET Core
- Detect: `<Project Sdk="Microsoft.NET.Sdk.Web">`, `Program.cs`, `appsettings*.json`.
- Auth: `AddAuthentication().AddJwtBearer` with `TokenValidationParameters` (`ValidateIssuer`,
  `ValidateAudience`, `ValidateLifetime`, `ValidateIssuerSigningKey`, `ClockSkew`, `ValidAlgorithms`),
  `RequireHttpsMetadata = false` in prod, `[Authorize]` per controller/endpoint or fallback policy
  (`FallbackPolicy = RequireAuthenticatedUser()`), `[AllowAnonymous]` sprawl, `MapGet` minimal APIs
  without `.RequireAuthorization()`, `AddAuthorization` policies vs role strings, Identity password
  options, lockout options, `DataProtection` keys persisted (shared across instances, not on ephemeral disk),
  cookie `Cookie.SecurePolicy/HttpOnly/SameSite`, `Antiforgery` for cookie-auth POSTs (`[ValidateAntiForgeryToken]`,
  `[AutoValidateAntiforgeryToken]`, minimal API antiforgery), `UseHsts`, `UseHttpsRedirection`.
- Sinks: `FromSqlRaw`/`ExecuteSqlRaw` with interpolation (use `FromSqlInterpolated`), Dapper with
  concatenated SQL, `SqlCommand` text building, `Html.Raw`, `HtmlString`, `Process.Start` with user
  args, `Newtonsoft` `TypeNameHandling != None`, `BinaryFormatter`, `XmlSerializer` with user types,
  `XmlDocument`/`XmlReader` with DTD processing, `Path.Combine(root, userInput)` without `GetFullPath`
  + `StartsWith(root)`, `Redirect(returnUrl)` without `Url.IsLocalUrl`, `HttpClient` with user URLs,
  model binding to entities with `[Bind]` missing / over-posting (use DTOs), `IFormFile` without
  content checks, `AddCors` with `AllowAnyOrigin().AllowCredentials()` (throws) or `SetIsOriginAllowed(_ => true)`,
  `ForwardedHeaders` without `KnownProxies`, `DeveloperExceptionPage` in prod, `Swagger` in prod,
  connection strings in `appsettings.json` committed, `Encrypt=False`/`TrustServerCertificate=True`.
- Verify: `dotnet list package --vulnerable --include-transitive`, `semgrep --config p/csharp`,
  `dotnet build -warnaserror` for analyzers (CA3xxx security rules), authz matrix.

### Spring Boot
- Detect: `spring-boot-starter-*`, `application.properties/yml`, `@SpringBootApplication`.
- Auth: `SecurityFilterChain` with `authorizeHttpRequests` ordering (`permitAll` before
  `anyRequest().authenticated()`; `/**` matchers; `requestMatchers` path variants), `csrf().disable()`
  on cookie-auth apps, method security `@PreAuthorize` reliance without class-level default,
  `oauth2ResourceServer().jwt()` issuer/audience validators, `spring-security-oauth2` legacy,
  `SecurityContextHolder` in async, `@Secured` role prefixes, `remember-me` keys, `session fixation`
  config, actuator exposure (`management.endpoints.web.exposure.include=*`, `/actuator/env`, `/heapdump`,
  `/gateway/routes`), `spring.h2.console.enabled`, `server.error.include-stacktrace`, `spring.devtools`.
- Sinks: JPQL/HQL/`JdbcTemplate` string building, `@Query` with concatenation, native queries,
  `Runtime.exec`/`ProcessBuilder`, SpEL evaluation of user input (`SpelExpressionParser`, `@Value`
  templates, Spring Cloud Function routing expressions), Thymeleaf `th:utext` and template names from
  input (view name manipulation), Freemarker/Velocity with user templates, `RestTemplate`/`WebClient`
  with user URLs, `ObjectInputStream`, Jackson `enableDefaultTyping`/`@JsonTypeInfo` on user input,
  XStream, `XMLDecoder`, `DocumentBuilderFactory` without `FEATURE_SECURE_PROCESSING`, `MultipartFile`
  `getOriginalFilename()` in paths, `ResponseEntity` redirects from input, `@CrossOrigin("*")`,
  `Spring Data REST` exposing repositories, `@RequestBody` entities (mass assignment), Log4j versions,
  `spring-cloud-gateway` actuator, Spring4Shell-era versions.
- Verify: `mvn org.owasp:dependency-check-maven:check` or Gradle plugin; `semgrep --config p/java
  --config p/spring`; `curl /actuator` unauthenticated; authz matrix.

### Laravel / PHP
- Detect: `laravel/framework`, `artisan`, `composer.json`; plain PHP by `.php` without a framework.
- Config: `APP_DEBUG` (Ignition/Whoops leak env + RCE history), `APP_KEY` (encryption/session
  signing; rotation), `APP_URL`, `SESSION_SECURE_COOKIE`, `SESSION_SAME_SITE`, `SANCTUM_STATEFUL_DOMAINS`,
  `cors.php` (`supports_credentials` with `allowed_origins => ['*']`), `filesystems.php` public disks,
  `TrustProxies` middleware `$proxies = '*'`, `ThrottleRequests` on auth routes, `password` hashing
  (bcrypt/argon default; `Hash::make` vs `md5`), `VerifyCsrfToken` `$except`, `.env` in web root
  (server must deny), `storage/` and `.git` exposure, `php artisan` routes without `auth` middleware,
  `telescope`/`horizon`/`debugbar` in prod, `APP_ENV=local`.
- Sinks: `DB::raw`, `whereRaw`, `selectRaw`, `orderByRaw` with interpolation, `DB::statement`,
  `{!! !!}` in Blade, `Blade::compileString`/`Blade::render` with user strings, `eval`, `unserialize`
  (POP chains), `include`/`require` with user paths, `exec`/`shell_exec`/`system`/`passthru`/`proc_open`/
  backticks, `preg_replace` with `/e` (removed in PHP 7), `file_get_contents($url)`/`curl` with user URLs
  and `CURLOPT_SSL_VERIFYPEER => false`, `move_uploaded_file` with original names / `$request->file()->store()`
  into public disks with `.php`/`.phtml`/`.phar`/`.svg`, `Storage::url` on private files, `redirect($request->input('url'))`
  / `redirect()->intended` with tampered session, mass assignment (`$guarded = []`, `$fillable` with
  `role`/`is_admin`, `Model::create($request->all())`), `$request->all()` to `update`, `Route::resource`
  without policies (`authorize()` missing), `Gate`/`Policy` not applied in API controllers, `firstOrFail($id)`
  without ownership, `SimpleXMLElement`/`DOMDocument` with `LIBXML_NOENT`, `extract($_REQUEST)`,
  `register_globals` (legacy), `$_SERVER['HTTP_HOST']` in links, `header("Location: ".$_GET[...])`,
  `mail()` header injection, `session.use_strict_mode=0`, `display_errors=On`, `allow_url_include=On`.
- Verify: `composer audit`, `semgrep --config p/php`, `psalm --taint-analysis` or `phpstan` security
  extensions where present, `php -i | grep -E "display_errors|allow_url"`, request `/.env` and `/storage/logs/laravel.log`.

### Ruby on Rails
- Detect: `rails` gem, `config/routes.rb`, `bin/rails`.
- Config: `config.force_ssl`, `secret_key_base` source (credentials.yml.enc + master.key not
  committed), cookie store sessions (signed, encrypted; key rotation), `config.action_dispatch.cookies_same_site_protection`,
  `config.hosts` (host authorization), `protect_from_forgery` default in `ApplicationController`
  (API mode disables it: verify token/cookie usage), `config.filter_parameters` (logs), Devise
  lockable/timeoutable/confirmable modules, `rack-attack` throttles, `ActiveStorage` public vs private
  services, `config.action_controller.raise_on_open_redirects` (7.0+), `rails_admin`/`sidekiq/web`
  mounted without auth constraints, `config.consider_all_requests_local`, `web-console` in prod.
- Sinks: `where("name = '#{x}'")`, `find_by_sql`, `order(params[:sort])`, `pluck(params[...])`,
  `select`, `execute`, `html_safe`, `raw`, `<%== %>`, `render inline:`, `render params[:template]`
  (template injection / file read), `render file:`, `send_file(params[:path])`, `redirect_to params[:url]`,
  `Kernel#open` with `|` (command injection, use `File.open`/`URI.open`), backticks/`system` with
  interpolation, `eval`, `instance_eval`, `constantize`/`safe_constantize` on input, `send(params[...])`,
  `YAML.load` (use `safe_load`), `Marshal.load`, `Oj`/`JSON.load` with create_additions, mass assignment
  (`params.permit!`, `permit(:role)`, `update(params[:user])`), missing `current_user.scope.find` (IDOR),
  `Net::HTTP.get(URI(params[:url]))`, `CarrierWave`/`Shrine` without extension/content allowlists,
  `content_tag`/`link_to` with user URLs (`javascript:`), `ActionMailer` header injection.
- Verify: `bundle exec brakeman -A`, `bundle exec bundler-audit check --update`, `rails routes`
  diffed against auth filters, authz matrix.

### Go (net/http, Gin, Echo, Fiber, chi, gorilla)
- Detect: `go.mod`; router by dependency.
- Auth: middleware ordering (`r.Use` before route registration; groups), JWT libs
  (`dgrijalva/jwt-go` deprecated with `aud` bypass CVE-2020-26160: migrate to `golang-jwt/jwt/v5`),
  `jwt.Parse` with `keyFunc` that does not check `token.Method` (alg confusion), `ParseUnverified`
  used for decisions, `WithValidMethods`, `exp` validation, sessions via `gorilla/sessions` keys,
  `crypto/rand` vs `math/rand` for tokens, `bcrypt`/`argon2` usage, constant-time compare
  (`subtle.ConstantTimeCompare`).
- Sinks: `fmt.Sprintf` SQL into `db.Query`/`Exec`/GORM `Where(fmt.Sprintf)`/`Raw`, `sqlx` string
  building, `exec.Command("sh","-c", user)`, `template.HTML(user)`/`template.JS`/`template.URL`
  (html/template bypass), `text/template` for HTML, `http.Redirect(w, r, userURL)`, `http.ServeFile`
  / `http.FileServer` / `os.Open(filepath.Join(base, user))` without `filepath.Clean` + prefix,
  `http.Get(userURL)` (SSRF; also `net/http` follows redirects by default), `archive/zip`/`tar`
  extraction without path checks, `encoding/gob`/`xml` with untrusted data, `unsafe`, `reflect`
  on input, `InsecureSkipVerify: true`, `gorilla/websocket` `CheckOrigin: func() bool {return true}`,
  `cors.AllowAll()`/`AllowOriginFunc` returning true, missing `http.Server` `ReadHeaderTimeout`
  (slowloris), `MaxBytesReader` absent, `pprof` handlers (`net/http/pprof` import) exposed, panics
  recovered without logging, `log.Printf` of tokens, `strconv` overflow in amounts.
- Verify: `govulncheck ./...`, `gosec ./...`, `semgrep --config p/golang`, `staticcheck`,
  `go vet`, authz matrix.

### Serverless (AWS Lambda, Azure Functions, GCP Cloud Functions, Vercel/Netlify functions)
- Detect: `serverless.yml`, `template.yaml` (SAM), `host.json`/`function.json`, `api/` on
  Vercel, `netlify/functions`.
- Look for: function roles with `*`/broad policies, secrets in environment variables (use a vault +
  KMS), public function URLs/HTTP triggers without auth (`authLevel: anonymous`, `AuthorizationType: NONE`),
  API Gateway without authorizer/WAF/throttling, event-source injection (S3 key names, SQS bodies,
  DynamoDB streams used in commands/paths/queries), temp dir reuse across invocations (`/tmp` leaking
  data between tenants), dependency bloat and unpinned layers, unbounded concurrency (cost), VPC
  configuration giving DB access from public functions, logs with payloads, cold-start init code
  that caches credentials, IAM authorizers vs custom authorizers with permissive policies caching.
- Verify: read IaC/roles; `aws lambda get-function-url-config`; `aws apigateway get-authorizers`;
  invoke unauthenticated in non-prod.

### GraphQL (any server)
- Introspection and playground in prod (Informational to Medium depending on exposure), missing
  per-resolver/per-field authorization, batching/aliases bypassing rate limits and enabling
  brute force, depth/complexity limits absent, `__typename`-based IDOR via `node(id:)`, mutations
  with mass assignment inputs, error messages leaking resolvers/SQL, subscriptions without auth,
  file upload scalars without validation, CSRF via GET queries or `text/plain` mutations when
  cookie-authenticated, persisted queries not enforced.
- Verify: `{"query":"{__schema{types{name}}}"}` unauthenticated; batched login attempts; deep
  nested query in non-prod.

### WebSockets (Socket.IO, ws, Channels, SignalR, gorilla, Spring)
- Handshake authentication (cookie-based handshake = CSWSH if origin not checked; token in query
  string logged), `CheckOrigin`/`allowedOrigins` disabled, per-message authorization (room/channel
  join by client-supplied IDs), message size limits, rate limits, broadcasting other users' data,
  reconnection replay, JSON deserialization of messages into commands.
- Verify: connect from a different origin with the victim cookie; join a room with another
  tenant's ID; send oversize frames in non-prod.

---

## Data stores and queues

### PostgreSQL
- Checks: `pg_hba.conf` `trust`/`md5` over network (prefer `scram-sha-256` + TLS), `listen_addresses='*'`
  with open firewall, app user is superuser/owner, `CREATEROLE`, no RLS for tenancy where relied on,
  `sslmode` `disable`/`allow`/`prefer`/`require` (none verify CA; use `verify-full`), extensions
  like `dblink`/`file_fdw` granted to app user, `log_statement=all` with parameters, backups (`pg_dump`
  to unencrypted storage), default `postgres` password, pgAdmin exposed.
- Verify (authorized): `psql -c "\du"`, `SHOW ssl;`, `SELECT rolsuper FROM pg_roles WHERE rolname=current_user;`,
  `nmap -p 5432`.

### MySQL / MariaDB
- Checks: `root` used by app, users with `%` host and `ALL PRIVILEGES`, `FILE` privilege (read/write
  files), `LOAD DATA LOCAL INFILE` enabled, `secure_file_priv` empty, no `require_secure_transport`,
  `skip-grant-tables`, `general_log` with credentials, old auth plugin (`mysql_native_password`),
  `bind-address=0.0.0.0` exposed, phpMyAdmin exposed, `sql_mode` allowing silent truncation of
  security fields.
- Verify: `SHOW GRANTS;`, `SHOW VARIABLES LIKE 'require_secure_transport';`, `nmap -p 3306`.

### SQL Server
- Checks: `sa` used by app, `sysadmin`/`db_owner` for runtime, `xp_cmdshell` enabled, `TrustServerCertificate=True`
  / `Encrypt=False`, mixed auth with weak passwords, no TDE/Always Encrypted where required,
  linked servers with saved credentials, SQL Agent jobs running scripts from user tables, CLR enabled,
  port 1433 public, no auditing.
- Verify: `sqlcmd -Q "SELECT IS_SRVROLEMEMBER('sysadmin')"`, `EXEC sp_configure 'xp_cmdshell'`,
  `SELECT encrypt_option FROM sys.dm_exec_connections`.

### MongoDB
- Checks: no auth (`security.authorization` disabled), bound to `0.0.0.0`, no TLS, app user with
  `root`/`dbOwner`, `$where`/JS enabled (`javascriptEnabled`), operator injection from JSON bodies
  (`{"$ne": null}`), `mongo-express` exposed, no field-level encryption for regulated data,
  backups unencrypted, Atlas IP allowlist `0.0.0.0/0`.
- Verify: `mongosh --eval "db.runCommand({connectionStatus:1})"`, login endpoint with `{"username":{"$ne":null}}`
  in non-prod.

### Redis
- Checks: no password/ACL, `protected-mode no`, `bind 0.0.0.0`, no TLS, `rename-command` absent for
  `CONFIG`/`FLUSHALL`/`DEBUG`, used for sessions/rate limits/queues (impact scaling), keys without
  tenant prefix, serialized objects (pickle/Marshal) stored and loaded, `redis-commander` exposed,
  Lua scripts with user input.
- Verify: `redis-cli -h host PING` (owned only), `CONFIG GET requirepass` (authorized), read the
  key-building code.

### Queues: RabbitMQ, Kafka, SQS/Service Bus/PubSub, Celery, Sidekiq, BullMQ, Hangfire
- RabbitMQ: `guest/guest` reachable, management UI public, no TLS, vhost permissions `.*`.
- Kafka: `PLAINTEXT` listeners, no SASL/ACLs, topics with PII unencrypted, consumer groups shared.
- Cloud queues: resource policies with `Principal: *`, encryption off, DLQ retention with PII.
- Celery: `accept_content=['pickle']`, broker URL with credentials in code, Flower without auth,
  tasks trusting `user_id`, `task_always_eager` in prod, result backend exposing results.
- Sidekiq: `Sidekiq::Web` unauthenticated, jobs with `Marshal`, args containing PII in Redis.
- BullMQ/Bull: `bull-board`/`arena` exposed, job data trusted, Redis without auth.
- Hangfire: `/hangfire` dashboard without `IDashboardAuthorizationFilter` (default allows local only:
  verify behind proxies), jobs invoking arbitrary methods from stored type names.
- Verify: locate every producer, list every consumer's trust assumptions, check dashboards over HTTP.

### Object storage (S3, Azure Blob, GCS, MinIO)
- Checks: public buckets/containers/ACLs, "authenticated users" grants, block-public-access off,
  bucket policy with `Principal: *` on `s3:GetObject` for private data, presigned/SAS URLs with
  long expiry or write permissions, missing `Content-Disposition`/`Content-Type` enforcement (stored
  XSS via HTML/SVG served from the app origin or a custom domain), uploads with user-controlled keys
  (overwrite others' objects), no versioning/soft delete, no encryption with CMK where required,
  MinIO default credentials, CORS on buckets allowing any origin with credentials, logs off.
- Verify: `aws s3api get-bucket-policy-status`, `get-public-access-block`, `get-bucket-acl`;
  `az storage container show-permission`; `gsutil iam get gs://bucket`; fetch a private object URL
  unauthenticated.

---

## Platform

### Docker / Compose
- Read every `Dockerfile` (`USER`, `FROM` pin, `COPY . .` with `.dockerignore`, `ARG`/`ENV` secrets,
  `curl | sh`, `chmod 777`, `EXPOSE`), every compose file (`privileged`, `cap_add`, `network_mode: host`,
  `pid: host`, `/var/run/docker.sock`, host mounts, `ports` on `0.0.0.0`, `environment` secrets,
  `restart: always` on debug tools, default networks), and image scan results.
- Verify: `hadolint Dockerfile`, `trivy config .`, `trivy image name:tag`, `docker history name:tag`
  (look for secrets in layer commands), `docker inspect <container>` (owned host) for `Privileged`,
  `CapAdd`, `Mounts`, `NetworkMode`, `User`.

### Kubernetes / Helm
- Read manifests/charts for the items in security-baseline.md area 23. For Helm, render first:
  `helm template release ./chart -f values.yaml > rendered.yaml`, then lint the rendered output.
- Verify: `kube-linter lint ./k8s`, `kubescape scan .`, `checkov -d ./k8s`, `kubectl auth can-i --list
  --as=system:serviceaccount:ns:sa` (authorized, read-only), `kubectl get netpol -A`, `kubectl get psa`
  / namespace labels `pod-security.kubernetes.io/enforce`.

### Terraform (and Terragrunt, Pulumi, CloudFormation, Bicep)
- Read `backend`, `provider`, variables with defaults, every resource in security-baseline.md area 24.
- Verify: `terraform init -backend=false && terraform validate`, `checkov -d .`, `tfsec .`,
  `terrascan scan -i terraform`, `kics scan -p .`; never run `terraform apply` in Mode A/B; in Mode C
  produce a `terraform plan` and require approval for production-affecting changes.

### nginx / Caddy / Traefik / HAProxy / IIS
- nginx: `alias` traversal (`location /static { alias /var/www/static/; }` vs `location /static/`),
  `proxy_pass` with `$uri`/`$request_uri` from user input, missing `proxy_set_header X-Forwarded-For`
  handling (append vs overwrite), `real_ip_header` with `set_real_ip_from 0.0.0.0/0`, `server_tokens on`,
  `autoindex on`, `client_max_body_size` unset, `ssl_protocols` including TLSv1/1.1, weak `ssl_ciphers`,
  `add_header` inheritance pitfalls (headers vanish in nested `location`s), `if` misuse, `merge_slashes off`,
  `location ~ \.php$` passing any path to PHP-FPM (`try_files` missing), default server catching all hosts.
- Caddy: automatic HTTPS good; check `reverse_proxy` header trust (`trusted_proxies`), `file_server browse`,
  `basicauth` hashes, admin API (`:2019`) exposure.
- Traefik: dashboard `api.insecure=true` / `--api.dashboard` exposed, `insecureSkipVerify`, entrypoints
  without TLS, `forwardedHeaders.insecure`, Docker provider with socket mounted (container escape),
  middlewares (rate limit, headers) not attached.
- HAProxy: `option forwardfor` trust, missing `http-request deny` for admin paths, stats page
  (`stats uri`) without auth, `ssl-default-bind-options` weak.
- IIS/web.config: `customErrors mode="Off"`, `debug="true"`, request filtering (`requestLimits`,
  hidden segments for `.git`/`.env`), `httpProtocol` headers, directory browsing, `machineKey`
  committed, `trace.axd`/`elmah.axd` exposed, `requestValidation` disabled.
- Verify: `nginx -T` (owned host) to see the effective config; request path-normalization variants
  through the proxy; `curl -sI` for headers per path.

### AWS (read-only inventory)
- `aws sts get-caller-identity`; `aws iam get-account-summary`; `aws iam list-users` +
  `list-access-keys` + `get-access-key-last-used`; `aws iam get-account-password-policy`;
  `aws iam list-policies --scope Local` and `get-policy-version` for `*`; `aws ec2 describe-security-groups`
  (filter `0.0.0.0/0`); `aws ec2 describe-instances` (public IPs, `HttpTokens` optional = IMDSv1);
  `aws rds describe-db-instances` (`PubliclyAccessible`, `StorageEncrypted`); `aws s3api list-buckets`,
  `get-public-access-block`, `get-bucket-policy-status`, `get-bucket-encryption`, `get-bucket-versioning`;
  `aws cloudtrail describe-trails`; `aws guardduty list-detectors`; `aws kms list-keys` + `get-key-policy`;
  `aws lambda list-functions` (+ `get-function-url-config`, `get-policy`); `aws secretsmanager list-secrets`;
  `aws elasticache describe-cache-clusters` (`TransitEncryptionEnabled`, `AuthTokenEnabled`);
  `aws sqs get-queue-attributes` (Policy, KmsMasterKeyId); `aws backup list-backup-plans`;
  `aws ecr describe-repositories` (scanOnPush); `aws eks describe-cluster` (endpoint public access, logging).
- Never run `put-*`, `create-*`, `delete-*`, `update-*` in Mode A/B.

### Azure (read-only inventory)
- `az account show`; `az ad signed-in-user show`; `az role assignment list --all` (Owner/Contributor
  at subscription scope, service principals); `az ad app list` / `az ad sp list --all` + credentials
  expiry (`az ad app credential list`); `az network nsg list` + `az network nsg rule list` (`*`/`Internet`
  on 22/3389/1433/5432/6379); `az vm list -d` (public IPs, `--query` identity); `az sql server list` +
  `az sql server firewall-rule list` (0.0.0.0-255.255.255.255 = public), `az sql db tde show`;
  `az postgres flexible-server list` (`publicNetworkAccess`, `sslEnforcement`); `az storage account list`
  (`allowBlobPublicAccess`, `minimumTlsVersion`, `supportsHttpsTrafficOnly`, `networkRuleSet.defaultAction`,
  `allowSharedKeyAccess`), `az storage container list --auth-mode login --account-name X` (public access level);
  `az keyvault list` + `az keyvault show` (`enablePurgeProtection`, `enableSoftDelete`, `enableRbacAuthorization`,
  network ACLs), `az keyvault secret list` (names only, never values); `az webapp list` + `az webapp config show`
  (`httpsOnly`, `minTlsVersion`, `ftpsState`, `remoteDebuggingEnabled`), `az webapp config appsettings list`
  (names only: redact values); `az functionapp list`; `az aks list` (`apiServerAccessProfile`, `enableRBAC`,
  `networkProfile`, `azurePolicy`); `az acr list` (`adminUserEnabled`); `az monitor activity-log list`
  (retention), `az monitor diagnostic-settings list`; `az security` (Defender) `pricing list`;
  `az backup vault list`; `az redis list` (`enableNonSslPort`, `publicNetworkAccess`, `minimumTlsVersion`);
  `az servicebus namespace list`; `az cosmosdb list` (`publicNetworkAccess`, `ipRules`).
- Never run `az ... create|update|delete|set` in Mode A/B.

### GCP (read-only inventory)
- `gcloud auth list`; `gcloud config list`; `gcloud projects get-iam-policy PROJECT` (roles/owner,
  roles/editor on users/SAs, `allUsers`/`allAuthenticatedUsers`); `gcloud iam service-accounts list` +
  `keys list --managed-by=user` (user-managed keys); `gcloud compute firewall-rules list` (`0.0.0.0/0`);
  `gcloud compute instances list` (external IPs, default SA with cloud-platform scope);
  `gcloud sql instances list` (`ipAddresses`, `settings.ipConfiguration.requireSsl`, authorized networks `0.0.0.0/0`);
  `gsutil iam get gs://BUCKET` / `gcloud storage buckets describe` (`allUsers`, uniform access, public
  access prevention); `gcloud kms keys list`; `gcloud secrets list` (names only); `gcloud logging sinks list`;
  `gcloud container clusters list` (private endpoint, network policy, workload identity, legacy ABAC);
  `gcloud functions list` (`ingressSettings`, `allUsers` invoker); `gcloud run services list` +
  `get-iam-policy` (`allUsers`); `gcloud redis instances list` (`authEnabled`, `transitEncryptionMode`);
  `gcloud scc findings list` where Security Command Center is enabled.
- Never run `gcloud ... create|update|delete|add-iam-policy-binding` in Mode A/B.

### CI/CD: GitHub Actions, GitLab CI, Azure Pipelines, Jenkins, others
- GitHub Actions: `pull_request_target` + checkout of `github.event.pull_request.head.sha`,
  `${{ github.event.* }}` interpolated in `run:` (script injection; use env vars), `permissions`
  missing (defaults may be write) or `write-all`, actions pinned to tags not SHAs, secrets in
  `env:` at workflow level (exposed to all steps), `actions/cache` keys derived from PR input,
  self-hosted runners on `pull_request`, `workflow_dispatch` inputs in commands, artifacts from
  untrusted jobs deployed, OIDC `id-token: write` with broad trust policies in the cloud,
  `GITHUB_TOKEN` used to push, no environment protection rules, Dependabot/Renovate PRs auto-merged
  without checks. Check with `gh api repos/{o}/{r}/branches/{b}/protection` (read-only).
- GitLab CI: `only`/`rules` allowing fork MRs to use protected variables, `CI_JOB_TOKEN` scope,
  unprotected variables, `image:` unpinned, `script:` with `$CI_MERGE_REQUEST_TITLE`, shared runners
  with privileged Docker-in-Docker (`privileged = true`), deploy tokens in variables, `allow_failure`
  on security jobs.
- Azure Pipelines: service connections with broad Azure RBAC and no approvals, `checkout` of forks
  with secrets (`Make secrets available to builds of forks` on), unpinned tasks/extensions,
  variable groups linked to Key Vault without RBAC, self-hosted agents with persistent credentials,
  `System.AccessToken` scope.
- Jenkins: script security bypass (`Script Console` open), `Jenkinsfile` from PRs with `sh` of
  branch names, credentials bound to all jobs, plugins outdated, anonymous read/build, agents with
  Docker socket, no CSRF protection, `Build with Parameters` used in shell without quoting.
- Others (CircleCI, Bitbucket, Drone, Buildkite, CodeBuild, Cloud Build, Tekton): contexts/secrets
  available to forks, orbs/plugins unpinned, privileged executors, deploy keys with write.
- Verify: read every pipeline file (the inventory script pre-lists GitHub Actions risks), diff
  secrets usage per job, confirm branch protections through read-only APIs when accessible.
