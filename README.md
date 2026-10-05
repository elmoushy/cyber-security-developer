# cyber-security-developer

A framework-independent security engineering skill for Claude Code. It turns the agent into a senior
application, cloud and DevSecOps security engineer and authorized penetration tester: it inspects a
complete software system, finds and explains weaknesses with evidence, and on request fixes, tests and
rescans them. It is deliberately not a wrapper around a single scanner.

## Features

- **Whole system, not just source:** frontend, backend, REST/GraphQL/WebSockets, auth, sessions, JWT,
  OAuth/OIDC/SSO, databases, Redis, queues and workers, webhooks, file upload/download, cryptography,
  secrets, TLS, Docker, Kubernetes, Terraform/IaC, reverse proxies, cloud IAM and storage, CI/CD,
  dependencies, logging and backups.
- **Stack auto-detection** via `scripts/security_inventory.py`: React, Next.js, Angular, Vue, Nuxt,
  Svelte, Django/DRF, FastAPI, Flask, Node/Express/NestJS, ASP.NET Core, Spring Boot, Laravel, Rails,
  Go, PHP, Java, .NET; PostgreSQL, MySQL, SQL Server, MongoDB, Redis; message queues; Docker, K8s, Helm,
  Terraform; nginx, Caddy, Traefik, HAProxy, IIS; AWS, Azure, GCP; common CI/CD systems.
- **Standards-backed:** OWASP Top 10, ASVS, API Security Top 10, NIST SSDF, CIS Benchmarks, CWE and CVE,
  used as engineering analysis rather than checkboxes.
- **Verified fixes:** in fix mode a change is never reported as done until it is tested and rescanned.

## Installation

Requirements: [Claude Code](https://docs.claude.com/en/docs/claude-code) and Python 3.8+ (for the
inventory script; standard library only).

**macOS / Linux / WSL**

```bash
git clone https://github.com/elmoushy/cyber-security-developer.git ~/.claude/skills/cyber-security-developer
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/elmoushy/cyber-security-developer.git "$env:USERPROFILE\.claude\skills\cyber-security-developer"
```

`SKILL.md` must end up at `~/.claude/skills/cyber-security-developer/SKILL.md`. Skills are discovered
live, so no restart is needed. To install it for a single project only, clone it into that project's
`.claude/skills/` folder instead.

To update later:

```bash
cd ~/.claude/skills/cyber-security-developer && git pull
```

## Usage

Open Claude Code in the project you want to assess, then either:

- **Ask naturally** and the skill triggers on its own:
  - "scan this project for security issues"
  - "audit the auth and JWT handling"
  - "check for IDOR and tenant isolation problems in the API"
  - "give me a remediation plan for the Docker and Kubernetes config"
  - "find and fix the vulnerabilities, then verify"
- **Call it directly:**

  ```
  /cyber-security-developer audit the payments service and give me a remediation plan
  ```

### Modes

The mode is picked from your wording; when it is unclear, Mode B is used.

| Mode | What it does | Changes code? |
|------|--------------|---------------|
| **A - Security Audit** | Inspects the system and reports findings with evidence | No |
| **B - Audit + Remediation Plan** | Everything in A, plus exact fixes, affected files, priority, impact, tests to add and how to verify | No |
| **C - Audit + Fix + Verify** | Fixes behind a reversible checkpoint, adds security regression tests, runs tests, rescans and attempts bypasses until no known exploitable in-scope issue remains or a blocker is documented | Yes |

To force a mode, say so: "Mode A only, don't change anything" or "fix them and verify (Mode C)".

### Report output

Each finding includes severity, exploitability, the affected files and lines, evidence, the standard it
maps to (OWASP/CWE), and a fix. Secrets are redacted in reports. The full report template is in
`references/reporting.md`.

## The inventory script

A read-only Python script that maps the technologies and attack surface of a project. It reports
secret-like and certificate files **by name only** and never prints their contents. It writes nothing
into the assessed project. You can also run it on its own:

```bash
python scripts/security_inventory.py /path/to/project                 # human summary + tools found on PATH
python scripts/security_inventory.py /path/to/project --json          # machine-readable output
python scripts/security_inventory.py /path/to/project --output inv.json --quiet
python scripts/security_inventory.py /path/to/project --no-tools --exclude node_modules --max-files 50000
```

Exit codes: `0` on success (even if nothing is found), `2` for bad arguments or an unreadable root.

## Repository layout

```
cyber-security-developer/
  SKILL.md                     agent instructions: modes, workflow, rules
  agents/openai.yaml           OpenAI-compatible agent definition mirroring SKILL.md
  references/
    security-baseline.md       30 area checklists: what to look for, how to prove it, standards mapping
    framework-playbooks.md     per-technology sinks, config keys, misconfigurations, verify commands
    tooling-playbook.md        scanner and dynamic-test commands, false-positive triage
    reporting.md               finding template, severity scales, redaction, report structure
  scripts/
    security_inventory.py      safe read-only technology and attack-surface inventory
  evals/evals.json             test prompts and assertions for each mode
  LICENSE.txt
  README.md
```

## Authorized use only

Static review of code and configuration you own is always fine. For dynamic testing, cloud access or
network scanning, only assess systems you own or are explicitly authorized to test, and prefer
non-production environments. You are responsible for having that authorization.

## License

MIT - see [LICENSE.txt](LICENSE.txt).
