# Reporting reference

The report is the deliverable in every mode. It must be honest about coverage, precise about
evidence, and free of live secret values. Use the structure below verbatim as section headings;
omit a section only when it is genuinely empty and say so ("None found in the assessed scope").

## Redaction rule (applies everywhere)

Never place a live password, token, private key, cookie, connection string with credentials, or
customer-sensitive datum in the report or in any evidence. Redact as:

`[REDACTED: <type>, len=<N>, location=<file:line or resource>]`

Examples:
- `[REDACTED: AWS access key, len=20, location=infra/main.tf:42]`
- `[REDACTED: JWT signing secret, len=64, location=.env]`
- `[REDACTED: DB password in connection string, location=docker-compose.yml:11]`

For proof of a live/valid secret, describe the non-sensitive confirmation (e.g. "a read-only
identity call returned HTTP 200 for the account associated with this key"), never the value.

## Severity scale

Critical | High | Medium | Low | Informational.

Do not exaggerate. Anchor to real impact and exploitability in this system, not to the scariest
theoretical case. Use CVSS only when there is enough information and it adds clarity; state the
vector string and version. Never invent a CVSS score or a base metric you did not derive.

Rough anchors (adjust to context):
- Critical: unauthenticated RCE, full auth bypass, mass PII/secret exposure, cross-tenant data
  access at scale, keys granting production infrastructure control.
- High: authenticated RCE with common privileges, IDOR/BOLA on sensitive objects, stored XSS in a
  privileged context, SQLi behind auth, secret leak with real blast radius, privilege escalation.
- Medium: reflected XSS requiring interaction, CSRF on meaningful actions, SSRF to limited targets,
  missing rate limiting on sensitive flows, weak crypto not yet exploitable, misconfig with
  conditional impact.
- Low: security-hardening gaps, verbose errors, missing defense-in-depth headers with low real risk.
- Informational: hygiene, version disclosure, best-practice deviations without a concrete attack.

## Confidence scale

Confirmed (reproduced statically with a clear path or dynamically with a safe probe) | High (clear
path, not yet reproduced) | Medium (plausible, needs conditions to confirm) | Low (theoretical or
scanner-only, not validated). Every High/Critical severity finding should aim for Confirmed or High
confidence; if it is only Low confidence, say why and what would confirm it.

## Status values

Open | Fixed | Mitigated | Accepted (risk accepted by owner) | Blocked (cannot proceed, external
blocker) | False Positive (dismissed).

## Finding record template

Use one block per finding. Give each a stable Security ID (`SEC-001`, `SEC-002`, ...).

```
### SEC-001  <short title>
- Severity:     <Critical|High|Medium|Low|Informational>
- Confidence:   <Confirmed|High|Medium|Low>
- Status:       <Open|Fixed|Mitigated|Accepted|Blocked|False Positive>
- Category:     <e.g. Broken Access Control / IDOR>
- Standards:    <OWASP A0x; API0x; ASVS Vx.y; CWE-nnn; CVE-yyyy-nnnnn if applicable>
- Affected:     <file:line | endpoint | resource id | image | pipeline>
- Prerequisites:<what the attacker needs: a low-priv account, network position, a victim click...>
- Attack path:  <numbered steps from entry to impact>
- Evidence:     <request/response excerpt, code excerpt, config excerpt, scanner ref - REDACTED>
- Impact:       <what an attacker achieves; data/systems affected; scale>
- Root cause:   <the underlying defect, not the symptom>
- Remediation:  <the exact fix; the correct pattern; not just "sanitize input">
- Verification: <how to prove it is fixed: the test, the request, the scan to re-run>
```

Mode B additionally requires, per finding: files/components affected, recommended implementation
(concrete code/config direction, not a platitude), priority (relative order to fix), expected
impact of the fix, the security test(s) that should be added, and the verification procedure. Do
not modify code in Mode B.

Mode C additionally records, per finding that was fixed:
```
- Files modified:   <paths>
- Tests added:      <path::test name>
- Tests run:        <command + pass/fail summary>
- Scan before:      <tool + result/finding present>
- Scan after:       <tool + result/finding absent>
- Dynamic verify:   <the probe re-run + new result, e.g. B->A now 403>
- Bypass attempts:  <neighboring variants tried and their results>
- Remaining limits: <anything the fix does not cover>
```

## Report structure (the 15 sections)

1. **Executive Summary** - plain-language risk picture for a decision-maker: how many findings by
   severity, the top few risks in one sentence each, overall posture, and (Mode C) what was fixed.
   No jargon dumps.
2. **Scope** - what was assessed, what was explicitly out of scope, the environments touched
   (repo/local/staging/prod), the time, and the authorization basis for any dynamic testing.
3. **Architecture / Attack Surface** - the system as understood from the inventory: components,
   trust boundaries, data flows, entry points, external integrations, exposed services. A short
   diagram in text is fine.
4. **Threat Model** - the relevant actors (anonymous, authenticated user, other tenant, insider,
   compromised dependency, supply chain), their goals, and the assets at risk. Tie findings to it.
5. **Findings** - all findings, most severe first, using the record template. Group by area if long.
6. **Fixes** - Mode B: the remediation plan (ordered, with implementation guidance). Mode C: what
   was actually changed, cross-referenced to findings, with the per-finding Mode C block.
7. **False Positives / Dismissed Findings** - scanner output or suspicions that analysis ruled out,
   each with a one-line reason. This section builds trust; do not skip it.
8. **Defense-in-Depth Improvements** - hardening beyond the confirmed findings: headers, least
   privilege, monitoring, secret management, dependency hygiene. Marked as improvements, not
   as exploited vulnerabilities.
9. **Security Verification Matrix** - the table below.
10. **Tests Performed** - every static and dynamic test run, with enough detail to reproduce.
11. **Scanners / Tools Used** - each tool, version if known, and what it covered; note gaps.
12. **Changes Performed for Mode C** - the consolidated change log: branch used, commits/diffs,
    files touched, tests added, scans re-run. Empty (say so) in Modes A and B.
13. **Remaining Risks** - what is still open or accepted, why, and the recommended next step; any
    external blockers that stopped a fix.
14. **Unassessed / Blocked Areas** - what could not be reached (no cloud creds, no running app, no
    prod access, a tool unavailable) and what it would take to cover it. Be explicit; silence here
    is dishonest.
15. **Final Conclusion** - the honest closing statement. See the rule below.

## Security Verification Matrix

One row per area; fill Status and a short note. Status values: **Verified** (actively tested and
evidence gathered), **Inspected** (reviewed statically, not dynamically tested), **Blocked** (could
not assess, say why), **N/A** (not present in this system).

| # | Area | Status | Notes |
|---|------|--------|-------|
| 1 | Authentication | | |
| 2 | Authorization (BAC/BFLA) | | |
| 3 | IDOR / BOLA (object-level) | | |
| 4 | Property-level authz / mass assignment | | |
| 5 | Tenant / organization isolation | | |
| 6 | Sessions | | |
| 7 | JWT | | |
| 8 | OAuth / OIDC / SSO | | |
| 9 | MFA / account recovery | | |
| 10 | SQL / NoSQL / ORM injection | | |
| 11 | Command / code / template injection | | |
| 12 | Deserialization / XXE | | |
| 13 | XSS (stored/reflected/DOM) | | |
| 14 | CSRF | | |
| 15 | CORS | | |
| 16 | Security headers / CSP | | |
| 17 | SSRF | | |
| 18 | File upload / download / path traversal | | |
| 19 | API security (inventory/exposure) | | |
| 20 | Rate limiting / resource & cost abuse | | |
| 21 | Business logic / race / replay | | |
| 22 | Cryptography | | |
| 23 | TLS / certificates | | |
| 24 | Secrets (source/config/bundles/history) | | |
| 25 | Database (privileges/exposure/TLS) | | |
| 26 | Redis / cache | | |
| 27 | Queues / workers / background jobs | | |
| 28 | Webhooks / external integrations | | |
| 29 | Frontend / browser storage | | |
| 30 | Docker / containers | | |
| 31 | Kubernetes | | |
| 32 | Terraform / IaC | | |
| 33 | Cloud IAM / network / storage | | |
| 34 | CI/CD / supply chain | | |
| 35 | Dependencies (SCA) | | |
| 36 | Logging / monitoring / error handling | | |
| 37 | Backup / recovery | | |
| 38 | Reverse proxy / LB / network exposure | | |
| 39 | Dynamic application testing | | |

Add or drop rows to match the actual system, but never quietly omit an area that exists: if it is
present and you did not assess it, mark it Blocked with the reason.

## Final Conclusion rule (mandatory)

Never claim "100% secure", "guaranteed secure", "fully secure", or that no vulnerability can ever
exist. Security cannot be proven absolutely.

If a strong, broad assessment completed and confirmed in-scope issues are fixed or accepted, use
wording such as:

> "No known exploitable issues remain within the assessed scope after the completed security checks
> and remediations. This does not guarantee that undiscovered vulnerabilities do not exist."

If coverage was incomplete, say so plainly and point to the Unassessed / Blocked Areas section.
State what was and was not assessed, and what would raise confidence further.
