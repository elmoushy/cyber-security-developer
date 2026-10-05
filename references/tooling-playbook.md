# Tooling playbook

Run the inventory first (`python scripts/security_inventory.py <root>`), then pick tools that match
what it found and what is on PATH (the inventory's "tools on PATH" section). Combine layers: never
rely on a single scanner. Every scanner result is a hypothesis until you validate it (see the
false-positive triage at the end).

Defense-in-depth layers to cover when possible:
manual review + SAST + SCA/dependency + secret scanning + IaC/config + dynamic testing.

Read-only in Mode A and Mode B. In Mode C you may run fixes and re-scans, but production-affecting
operations still require explicit approval (see SKILL.md).

## Table of contents

1. Dependency / SCA (per ecosystem)
2. SAST / static analysis
3. Secret scanning
4. Container and image scanning
5. IaC / config scanning
6. Kubernetes scanning
7. Cloud read-only inventory (pointers)
8. Dynamic testing recipes (curl authz matrix, JWT, headers, TLS, CORS, SSRF, rate limit)
9. Nmap / network (authorized only)
10. Installing a missing tool
11. False-positive triage

---

## 1. Dependency / SCA (run the native tool, then one cross-checker)

| Ecosystem | Native command | Notes |
| :-- | :-- | :-- |
| npm | `npm audit --audit-level=high --json` | use `npm ci` first for an accurate tree; `--omit=dev` for prod-only |
| pnpm | `pnpm audit --audit-level high` | |
| yarn | `yarn npm audit` (berry) or `yarn audit` (classic) | |
| Python | `pip-audit -r requirements.txt` or `pip-audit` (env) | add `safety check` as a second source |
| Poetry | `pip-audit` against exported reqs, or `poetry export | pip-audit -r /dev/stdin` | |
| .NET | `dotnet list package --vulnerable --include-transitive` | needs restore; `--include-transitive` matters |
| Go | `govulncheck ./...` | reachability-aware, low false positives |
| Rust | `cargo audit` | needs `Cargo.lock` |
| PHP | `composer audit` | |
| Ruby | `bundle exec bundler-audit check --update` | |
| Java (Maven) | `mvn org.owasp:dependency-check-maven:check` | slow first run (NVD download); or `dependency-check --scan .` |
| Java (Gradle) | `./gradlew dependencyCheckAnalyze` | needs the plugin; else run `dependency-check` CLI |

Cross-ecosystem cross-checkers (use at least one in addition to the native tool):
- `osv-scanner -r .` (Google OSV; understands most lockfiles)
- `trivy fs --scanners vuln,secret,misconfig .` (deps + secrets + IaC in one pass)
- `grype dir:.` (SBOM/vuln; pairs with `syft` for SBOM)
- `snyk test` / `snyk iac test` (if licensed and authenticated)

For each High/Critical: confirm the vulnerable API is actually reachable (grep the imports/usage
against the advisory's affected functions). Reachable -> report at advisory severity. Not reachable
-> downgrade to Low/Informational with the reason.

## 2. SAST / static analysis

- `semgrep --config auto` (or targeted: `p/owasp-top-ten`, `p/security-audit`, `p/secrets`,
  `p/django`, `p/flask`, `p/nodejs`, `p/react`, `p/java`, `p/csharp`, `p/golang`, `p/php`, `p/ruby`).
  Fast, multi-language, low setup. Start here.
- `codeql` when the project already has a database or CI setup; deepest dataflow, slowest.
  `codeql database create db --language=<lang>` then `codeql database analyze db <suite> --format=sarif-latest`.
- Language-native: `bandit -r .` (Python), `gosec ./...` + `staticcheck` (Go), `brakeman -A` (Rails),
  `eslint` with `eslint-plugin-security` (JS/TS), .NET Roslyn security analyzers (`dotnet build`
  with `-warnaserror` and the `CAxxxx` rules), `psalm --taint-analysis`/`phpstan` (PHP),
  `spotbugs` + `find-sec-bugs` (Java).
- Always pair SAST with manual dataflow tracing for the high-value sinks (injection, deserialization,
  authz). SAST finds candidates; you confirm the source-to-sink path.

## 3. Secret scanning (working tree AND history when the repo is owned)

- `gitleaks detect --source . --redact` (working tree) and `gitleaks detect --source . --log-opts="--all" --redact`
  (full history). `--redact` keeps values out of output.
- `trufflehog filesystem .` or `trufflehog git file://.` (verifies some secrets against live APIs;
  in Mode A only do read-only verification, never use a found secret to access data).
- `detect-secrets scan` (Yelp) as a baseline tool.
- Also inspect: built frontend bundles (`dist/`, `.next/static`, `build/`), `docker history <image>`,
  source maps (`*.map`), and CI logs.
- NEVER paste a discovered value anywhere in the report. Redact per reporting.md.

## 4. Container and image scanning

- `hadolint Dockerfile` (Dockerfile best practices).
- `trivy image <name:tag>` (OS + language package CVEs, secrets, misconfig) and/or `grype <name:tag>`.
- `docker scout cves <name:tag>` (Docker Scout CVE analysis) and `docker scout recommendations <name:tag>`
  when the Docker CLI with Scout is available.
- `trivy config .` (Dockerfile + compose + K8s + Terraform misconfig in one pass).
- `dockle <name:tag>` (CIS-aligned image checks).
- `docker history --no-trunc <name:tag>` to spot secrets baked into layers.
- Running containers (owned host): `docker inspect <c>` for `Privileged`, `CapAdd`, `Mounts`,
  `NetworkMode`, `User`, `SecurityOpt` (`no-new-privileges`).

## 5. IaC / config scanning

- `checkov -d .` (Terraform, CloudFormation, K8s, Helm, ARM, Bicep, Dockerfile, serverless).
- `tfsec .` and/or `trivy config .` for Terraform.
- `terrascan scan -i terraform` / `kics scan -p .` as additional Terraform/CloudFormation sources.
- For Terraform, `terraform init -backend=false && terraform validate` first so the files parse.
- Read every flagged resource; decide exploitability in this architecture (a public bucket for a
  static site is intended; a public bucket of uploads is not).

## 6. Kubernetes scanning

- `kube-linter lint ./k8s` (or the chart dir).
- `kubescape scan .` (framework-based, NSA/CIS).
- `checkov -d ./k8s`.
- `kubesec scan deploy.yaml` (per-manifest risk score).
- For Helm, render first: `helm template rel ./chart -f values.yaml > rendered.yaml`, then lint
  `rendered.yaml`.
- Live cluster (authorized, read-only): `kube-bench` (node CIS), `kubectl auth can-i --list`,
  `kubectl get clusterrolebindings,rolebindings -A -o yaml`, `kubectl get netpol -A`,
  namespace PSA labels.

## 7. Cloud read-only inventory

Use the read-only command lists in `framework-playbooks.md` (AWS, Azure, GCP sections). Confirm the
active identity first (`aws sts get-caller-identity`, `az account show`, `gcloud auth list`), scope
to the intended account/subscription/project, and never run a mutating verb in Mode A/B. Cite
resource IDs; never cite credentials.

## 8. Dynamic testing recipes (authorized targets only, prefer non-production)

Set a base URL and reuse it. Never run destructive payloads; stop at proof.

### Authorization matrix (the highest-value test)
Capture two real sessions (user A, user B, ideally different tenants) and replay the same request
with each identity, changing only the object ID.

```bash
BASE=https://staging.example.test
A='Authorization: Bearer <token_A>'    # obtain via the app's own login, in a non-prod env
B='Authorization: Bearer <token_B>'
# A's own object: expect 200
curl -s -o /dev/null -w "A->A %{http_code}\n" -H "$A" "$BASE/api/invoices/1001"
# B reading A's object: expect 403/404, a 200 is Confirmed BOLA/IDOR
curl -s -o /dev/null -w "B->A %{http_code}\n" -H "$B" "$BASE/api/invoices/1001"
# unauthenticated: expect 401
curl -s -o /dev/null -w "anon %{http_code}\n" "$BASE/api/invoices/1001"
# same for write + delete + bulk + nested + GraphQL node()
curl -s -o /dev/null -w "B->A PATCH %{http_code}\n" -X PATCH -H "$B" -H 'Content-Type: application/json' -d '{"note":"x"}' "$BASE/api/invoices/1001"
```
Function-level (BFLA): call admin/support/export endpoints as a normal user. Property-level:
send an extra field (`"role":"admin"`, `"is_admin":true`, `"tenant_id":"other"`) and read it back.

### JWT probes
```bash
TOKEN=<a valid token from the app>
# decode header/payload (no verification) to read alg/exp/aud/iss
echo "$TOKEN" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
# expired token -> expect 401
curl -s -o /dev/null -w "expired %{http_code}\n" -H "Authorization: Bearer <expired>" "$BASE/api/me"
# tampered payload without re-signing -> expect 401
# alg:none and HS/RS confusion: only with a tool you control (jwt_tool) in a non-prod env
```
If `jwt_tool` is available: `jwt_tool "$TOKEN" -X a` (alg:none), `-X k` (key confusion),
`-X i` (inject claims). Authorized, non-prod only.

### Security headers and cookies
```bash
curl -sSI "$BASE/" | grep -iE 'content-security-policy|strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|set-cookie|cache-control'
# authenticated page (headers often differ and proxies override the app)
curl -sSI -H "$A" "$BASE/dashboard"
```
Check `Set-Cookie` for `HttpOnly; Secure; SameSite`. Check `Cache-Control: no-store` on sensitive pages.

### CORS
```bash
for O in "https://evil.example" "null" "https://staging.example.test.evil.com"; do
  echo "== Origin: $O"
  curl -sSI -H "Origin: $O" -H "$A" "$BASE/api/me" | grep -i 'access-control-allow'
done
```
Reflected origin + `Access-Control-Allow-Credentials: true` = Confirmed.

### TLS
```bash
echo | openssl s_client -connect example.test:443 -servername example.test 2>/dev/null | openssl x509 -noout -subject -issuer -dates
# protocols/ciphers (authorized):
nmap --script ssl-enum-ciphers -p 443 example.test   # or: testssl.sh example.test ; sslscan example.test
```
Client-side verification bypass: grep for the flags in security-baseline.md area 14 and confirm
they are on the production path.

### SSRF (authorized, controlled listener)
Point the fetcher/webhook/import at a listener you control and confirm the server connects; test
redirect-following with an allowlisted URL that 302s internally. On cloud hosts, only probe the
metadata endpoint with authorization and never persist retrieved credentials.

### Rate limiting (non-production burst)
```bash
seq 1 40 | xargs -P 10 -I{} curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST -H 'Content-Type: application/json' -d '{"email":"a@b.c","password":"x"}' \
  "$BASE/api/login" | sort | uniq -c
```
All `200/401` and no `429`/lockout after many attempts = missing throttling. Keep bursts modest;
never run against production.

### Injection (authorized, non-destructive)
Boolean/time probes on the exact parameter (`sleep`/`pg_sleep` only in non-prod), `{"$ne":null}`
on a login field for NoSQL, `{{7*7}}`/`${7*7}` in a rendered field for SSTI, a benign
`"><svg onload=console.log(1)>` for XSS reflection. `sqlmap` only on authorized non-prod targets
with `--batch --level=1 --risk=1` and never `--dump` of real data.

## 9. Nmap / network (owned or explicitly authorized targets only)

```bash
nmap -sV -p- --open target        # full service/version sweep
nmap -p 5432,3306,1433,27017,6379,9200,5672,9092,2375,10250,9229,5005 target  # data stores, brokers, debug ports
```
Map every open port to an owner and an auth model. Debug/admin ports (2375 Docker API, 10250 kubelet,
9229 Node inspector, 5005 JDWP) exposed = High/Critical.

## 10. Installing a missing tool

Prefer tools already on PATH. If a scanner is missing and installing is acceptable in the
environment, use the least-invasive method and pin a version:
- Python tools: `pipx install pip-audit` (or `pip install --user`), `pipx install semgrep`, `pipx install checkov`.
- Node tools: `npx` one-shot where possible (`npx --yes @cyclonedx/cdxgen`).
- Go tools: `go install golang.org/x/vuln/cmd/govulncheck@latest`.
- Single-binary tools (trivy, grype, gitleaks, tfsec, kube-linter): download the pinned release
  binary for the OS/arch. On Windows without a package manager, download the release zip and run the
  `.exe`. Do not `curl | sh` from unverified sources; verify checksums.
- If installation is not possible, record the gap in "Unassessed/Blocked Areas" and rely on manual
  review plus whatever is available.

## 11. False-positive triage

For every scanner finding, before it enters the report:
1. Read the flagged code/config. Does attacker-controlled input actually reach the sink?
2. Is the vulnerable dependency function actually called (reachability)?
3. Is there a compensating control (WAF is not one; a parameterized query, an allowlist, framework
   auto-escaping, a guard applied globally, are)?
4. Is the environment relevant (a `DEBUG=True` in a test settings file that never ships is not prod)?
5. Can you reproduce it, statically (a clear path) or dynamically (a safe probe)?

Assign confidence: Confirmed (reproduced), High (clear path, not yet reproduced), Medium (plausible,
needs conditions), Low (theoretical/hygiene). Dismissed scanner output goes in the "False Positives /
Dismissed Findings" section with a one-line reason. Do not inflate counts with unreachable CVEs or
style-only lints.
