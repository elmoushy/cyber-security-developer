#!/usr/bin/env python3
"""
security_inventory.py - read-only technology and attack-surface inventory.

Walks a project tree and reports, WITHOUT printing the contents of any
secret-like file:

  * programming languages (by file extension counts)
  * frontend / backend frameworks and notable libraries (from manifests)
  * dependency manifests and lockfiles
  * Docker / Compose, Kubernetes, Helm, Terraform and other IaC
  * CI/CD pipeline definitions (GitHub Actions `uses:` refs are checked
    for SHA pinning; `pull_request_target` triggers are flagged)
  * reverse-proxy / server configuration files
  * data stores, caches and queues inferred from dependencies and images
  * `.env` / secret-like files by FILENAME ONLY (never opened)
  * certificate / private-key files by FILENAME ONLY (never opened)
  * security scanners and cloud CLIs available on PATH

Two file classes exist and the distinction is deliberate:

  NAME-ONLY   secret-like files, keys, certs, tfstate, tfvars, kubeconfig,
              credential stores. Reported by path and size only. Never opened.
  PEEKED      an explicit allowlist of dependency manifests, Dockerfiles,
              compose files, K8s/Helm/CI YAML and Terraform *.tf files.
              Only structural tokens are extracted (dependency names, image
              names, kind/name, `uses:` refs, provider/resource types).
              Values of environment variables, `data:`/`stringData:` blocks
              and anything that looks like an assignment are never echoed.

Standard library only. Works on Windows, macOS and Linux.

Usage:
    python security_inventory.py [ROOT] [--json] [--output FILE]
                                 [--exclude DIR ...] [--max-files N]
                                 [--no-tools] [--quiet]

Exit codes: 0 success (even if nothing found), 2 bad arguments / unreadable root.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path

VERSION = "1.0.0"

# --------------------------------------------------------------------------- #
# Console safety: cp1252 consoles on Windows choke on non-ASCII. Keep output
# ASCII-only and force UTF-8 where the stream supports it.
# --------------------------------------------------------------------------- #
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover - very old interpreters
        pass

# --------------------------------------------------------------------------- #
# Static tables
# --------------------------------------------------------------------------- #

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", ".env.d",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
    "dist", "build", "out", "target", "vendor", "bin", "obj", ".terraform",
    ".next", ".nuxt", ".angular", ".svelte-kit", ".output", ".cache",
    "coverage", ".idea", ".vs", ".vscode", ".gradle", ".m2", "Pods",
    ".serverless", ".aws-sam", "cdk.out", "site-packages", ".dart_tool",
}

LANG_BY_EXT = {
    ".py": "Python", ".pyi": "Python",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript (JSX)",
    ".ts": "TypeScript", ".tsx": "TypeScript (TSX)", ".mts": "TypeScript", ".cts": "TypeScript",
    ".vue": "Vue SFC", ".svelte": "Svelte",
    ".go": "Go", ".rs": "Rust",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala", ".groovy": "Groovy",
    ".cs": "C#", ".fs": "F#", ".vb": "VB.NET", ".cshtml": "Razor", ".razor": "Razor",
    ".php": "PHP", ".rb": "Ruby", ".erb": "ERB template",
    ".swift": "Swift", ".m": "Objective-C", ".dart": "Dart",
    ".c": "C", ".h": "C/C++ header", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".lua": "Lua", ".pl": "Perl",
    ".r": "R", ".jl": "Julia",
    ".sql": "SQL", ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell", ".ps1": "PowerShell", ".bat": "Batch", ".cmd": "Batch",
    ".tf": "Terraform HCL", ".hcl": "HCL", ".bicep": "Bicep",
    ".yaml": "YAML", ".yml": "YAML", ".json": "JSON", ".toml": "TOML", ".xml": "XML",
    ".html": "HTML", ".htm": "HTML", ".css": "CSS", ".scss": "SCSS", ".less": "LESS",
    ".twig": "Twig template", ".jinja": "Jinja template", ".j2": "Jinja template",
    ".hbs": "Handlebars template", ".ejs": "EJS template", ".pug": "Pug template", ".mustache": "Mustache template",
    ".proto": "Protobuf", ".graphql": "GraphQL schema", ".gql": "GraphQL schema",
}

# Files that are NEVER opened. Matched against the basename (fnmatch, case-insensitive)
# or against the tail of the relative path for directory-qualified entries.
SECRET_NAME_PATTERNS = [
    ".env", ".env.*", "*.env", ".envrc", ".flaskenv",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.ppk", "*.asc", "*.gpg", "*.pgp",
    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*",
    "*.tfstate", "*.tfstate.*", "*.tfvars", "*.tfvars.json", "*.auto.tfvars",
    "kubeconfig", "kubeconfig.*", "*.kubeconfig",
    "credentials", "credentials.json", "credentials.yaml", "credentials.yml",
    "service-account*.json", "service_account*.json", "client_secret*.json",
    "secrets.yaml", "secrets.yml", "secrets.json", "secrets.toml", "secret.yaml", "secret.yml",
    "*.secrets.yaml", "*.secrets.yml", "secrets.properties", "application-secrets.*",
    ".npmrc", ".pypirc", ".netrc", "_netrc", ".htpasswd", ".git-credentials", ".pgpass", ".my.cnf",
    "*.keytab", "*.ovpn", "*.jwk", "*.jwks", "master.key", "credentials.yml.enc",
    "appsettings.*.json", "secrets.dev.yaml", "local.settings.json", ".dev.vars",
    "*.sqlite", "*.sqlite3", "*.db", "*.mdb", "*.bak", "*.dump", "*.sql.gz",
]
# Directory-qualified secret paths (matched against forward-slash relative path tail)
SECRET_PATH_SUFFIXES = [
    ".aws/credentials", ".aws/config", ".docker/config.json", ".kube/config",
    ".azure/accessTokens.json", ".azure/azureProfile.json", ".config/gcloud/credentials.db",
    ".ssh/config", ".gnupg/", "config/master.key", "config/credentials.yml.enc",
]
TEMPLATE_MARKERS = (".example", ".sample", ".template", ".dist", ".tpl", ".default")

CERT_NAME_PATTERNS = [
    "*.pem", "*.crt", "*.cer", "*.der", "*.csr", "*.key", "*.p12", "*.pfx",
    "*.jks", "*.keystore", "*.truststore", "*.ppk", "*.pub", "*.p7b", "*.p7c", "*.spc",
    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*", "ca-bundle*", "cacert*", "fullchain*", "privkey*",
]

# Content-peeked allowlist (basename patterns). Only structural tokens are extracted.
MANIFEST_PATTERNS = {
    "package.json": "npm", "requirements*.txt": "pip", "requirements/*.txt": "pip",
    "pyproject.toml": "python", "Pipfile": "pipenv", "setup.cfg": "python", "environment.yml": "conda",
    "go.mod": "go", "*.csproj": "dotnet", "*.fsproj": "dotnet", "*.vbproj": "dotnet",
    "Directory.Packages.props": "dotnet", "packages.config": "dotnet",
    "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle",
    "composer.json": "composer", "Gemfile": "bundler", "Cargo.toml": "cargo",
    "mix.exs": "hex", "pubspec.yaml": "pub", "Package.swift": "swiftpm",
}
LOCKFILE_NAMES = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm", "bun.lockb": "bun", "bun.lock": "bun",
    "poetry.lock": "poetry", "Pipfile.lock": "pipenv", "uv.lock": "uv", "pdm.lock": "pdm",
    "requirements.lock": "pip", "go.sum": "go", "packages.lock.json": "dotnet",
    "composer.lock": "composer", "Gemfile.lock": "bundler", "Cargo.lock": "cargo",
    "gradle.lockfile": "gradle", "mix.lock": "hex", "pubspec.lock": "pub", "Package.resolved": "swiftpm",
    ".terraform.lock.hcl": "terraform",
}

CI_PATTERNS = {
    ".github/workflows/*.yml": "GitHub Actions", ".github/workflows/*.yaml": "GitHub Actions",
    ".gitlab-ci.yml": "GitLab CI", "azure-pipelines.yml": "Azure Pipelines", "azure-pipelines.yaml": "Azure Pipelines",
    ".azure-pipelines/*.yml": "Azure Pipelines", "Jenkinsfile": "Jenkins", "Jenkinsfile.*": "Jenkins",
    "bitbucket-pipelines.yml": "Bitbucket Pipelines", ".circleci/config.yml": "CircleCI",
    ".travis.yml": "Travis CI", ".drone.yml": "Drone", "buildspec.yml": "AWS CodeBuild", "buildspec.yaml": "AWS CodeBuild",
    "cloudbuild.yaml": "Google Cloud Build", "cloudbuild.yml": "Google Cloud Build",
    ".buildkite/*.yml": "Buildkite", ".tekton/*.yaml": "Tekton", "appveyor.yml": "AppVeyor",
    ".woodpecker.yml": "Woodpecker", "codemagic.yaml": "Codemagic", ".semaphore/*.yml": "Semaphore",
    "Dockerfile.ci": "CI Dockerfile",
}

PROXY_PATTERNS = {
    "nginx.conf": "nginx", "*.nginx": "nginx", "nginx/*.conf": "nginx", "conf.d/*.conf": "nginx/apache",
    "sites-available/*": "nginx/apache", "sites-enabled/*": "nginx/apache",
    "Caddyfile": "Caddy", "haproxy.cfg": "HAProxy", "traefik.yml": "Traefik", "traefik.yaml": "Traefik",
    "traefik.toml": "Traefik", "httpd.conf": "Apache", "apache2.conf": "Apache", ".htaccess": "Apache",
    "web.config": "IIS / ASP.NET", "envoy.yaml": "Envoy", "kong.yml": "Kong", "kong.yaml": "Kong",
}

# Marker files that identify frameworks / platforms without reading dependencies.
MARKER_FILES = {
    "manage.py": "Django", "next.config.js": "Next.js", "next.config.mjs": "Next.js", "next.config.ts": "Next.js",
    "nuxt.config.js": "Nuxt", "nuxt.config.ts": "Nuxt", "angular.json": "Angular",
    "svelte.config.js": "SvelteKit / Svelte", "svelte.config.ts": "SvelteKit / Svelte",
    "vite.config.js": "Vite", "vite.config.ts": "Vite", "vite.config.mjs": "Vite",
    "remix.config.js": "Remix", "astro.config.mjs": "Astro", "gatsby-config.js": "Gatsby",
    "artisan": "Laravel", "config/routes.rb": "Ruby on Rails", "config.ru": "Rack (Ruby)",
    "Program.cs": ".NET", "Startup.cs": "ASP.NET Core", "global.asax": "ASP.NET (Framework)",
    "application.properties": "Spring Boot", "application.yml": "Spring Boot", "application.yaml": "Spring Boot",
    "wp-config.php": "WordPress", "wp-config-sample.php": "WordPress",
    "serverless.yml": "Serverless Framework", "serverless.yaml": "Serverless Framework", "serverless.ts": "Serverless Framework",
    "template.yaml": "AWS SAM (verify Transform)", "samconfig.toml": "AWS SAM",
    "host.json": "Azure Functions", "function.json": "Azure Functions", "function.app.json": "Azure Functions",
    "vercel.json": "Vercel", "netlify.toml": "Netlify", "fly.toml": "Fly.io", "Procfile": "Heroku-style Procfile",
    "app.yaml": "Google App Engine", "firebase.json": "Firebase", "amplify.yml": "AWS Amplify",
    "cdk.json": "AWS CDK", "Pulumi.yaml": "Pulumi", "Pulumi.yml": "Pulumi", "main.bicep": "Azure Bicep",
    "azuredeploy.json": "Azure ARM template", "ansible.cfg": "Ansible", "Vagrantfile": "Vagrant",
    "skaffold.yaml": "Skaffold", "kustomization.yaml": "Kustomize", "kustomization.yml": "Kustomize",
    "Chart.yaml": "Helm chart", "Tiltfile": "Tilt", "devspace.yaml": "DevSpace",
    "schema.graphql": "GraphQL", "schema.prisma": "Prisma ORM", "drizzle.config.ts": "Drizzle ORM",
    "alembic.ini": "Alembic migrations", "knexfile.js": "Knex", "ormconfig.json": "TypeORM",
    "openapi.yaml": "OpenAPI spec", "openapi.json": "OpenAPI spec", "swagger.yaml": "OpenAPI spec", "swagger.json": "OpenAPI spec",
    "tsconfig.json": "TypeScript", "jsconfig.json": "JavaScript project",
    "SECURITY.md": "Security policy present", ".pre-commit-config.yaml": "pre-commit hooks",
    ".gitleaks.toml": "gitleaks config", ".semgrep.yml": "Semgrep config", ".semgrep.yaml": "Semgrep config",
    "sonar-project.properties": "SonarQube", ".snyk": "Snyk policy", "renovate.json": "Renovate",
    ".github/dependabot.yml": "Dependabot", "CODEOWNERS": "CODEOWNERS", ".github/CODEOWNERS": "CODEOWNERS",
    "codeql-config.yml": "CodeQL config", ".trivyignore": "Trivy config", "checkov.yml": "Checkov config", ".checkov.yaml": "Checkov config",
    "electron-builder.yml": "Electron", "capacitor.config.ts": "Capacitor", "app.json": "Expo / React Native (verify)",
}

# Dependency name -> (category, label). Categories drive the summary sections.
DEP_SIGNALS = {
    # --- JavaScript / TypeScript frontend ---
    "react": ("frontend", "React"), "react-dom": ("frontend", "React"), "next": ("frontend", "Next.js"),
    "@angular/core": ("frontend", "Angular"), "vue": ("frontend", "Vue"), "nuxt": ("frontend", "Nuxt"),
    "svelte": ("frontend", "Svelte"), "@sveltejs/kit": ("frontend", "SvelteKit"), "solid-js": ("frontend", "SolidJS"),
    "@remix-run/react": ("frontend", "Remix"), "astro": ("frontend", "Astro"), "gatsby": ("frontend", "Gatsby"),
    "@builder.io/qwik": ("frontend", "Qwik"), "preact": ("frontend", "Preact"), "ember-source": ("frontend", "Ember"),
    "jquery": ("frontend", "jQuery"), "electron": ("frontend", "Electron"), "react-native": ("frontend", "React Native"),
    "dompurify": ("security-lib", "DOMPurify sanitizer"), "sanitize-html": ("security-lib", "sanitize-html"),
    "marked": ("frontend", "marked (markdown - check sanitization)"), "react-markdown": ("frontend", "react-markdown"),
    "vite": ("frontend", "Vite"), "webpack": ("frontend", "webpack"),
    # --- JavaScript / TypeScript backend ---
    "express": ("backend", "Express"), "@nestjs/core": ("backend", "NestJS"), "fastify": ("backend", "Fastify"),
    "koa": ("backend", "Koa"), "@hapi/hapi": ("backend", "hapi"), "hono": ("backend", "Hono"), "elysia": ("backend", "Elysia"),
    "@adonisjs/core": ("backend", "AdonisJS"), "sails": ("backend", "Sails"), "meteor": ("backend", "Meteor"),
    "@trpc/server": ("backend", "tRPC"), "graphql": ("api", "GraphQL"), "apollo-server": ("api", "Apollo Server"),
    "@apollo/server": ("api", "Apollo Server"), "graphql-yoga": ("api", "GraphQL Yoga"), "type-graphql": ("api", "TypeGraphQL"),
    "socket.io": ("api", "Socket.IO (WebSockets)"), "ws": ("api", "ws (WebSockets)"), "@grpc/grpc-js": ("api", "gRPC"),
    "jsonwebtoken": ("auth", "jsonwebtoken (JWT)"), "jose": ("auth", "jose (JWT/JWE)"), "passport": ("auth", "Passport"),
    "next-auth": ("auth", "NextAuth / Auth.js"), "@auth/core": ("auth", "Auth.js"), "express-session": ("auth", "express-session"),
    "cookie-session": ("auth", "cookie-session"), "bcrypt": ("auth", "bcrypt password hashing"), "bcryptjs": ("auth", "bcryptjs"),
    "argon2": ("auth", "argon2 password hashing"), "@node-rs/argon2": ("auth", "argon2"), "oidc-provider": ("auth", "oidc-provider"),
    "openid-client": ("auth", "openid-client"), "@clerk/nextjs": ("auth", "Clerk"), "@supabase/supabase-js": ("auth", "Supabase client"),
    "firebase-admin": ("cloud", "Firebase Admin"), "helmet": ("security-lib", "helmet headers"), "cors": ("security-lib", "cors middleware"),
    "csurf": ("security-lib", "csurf (deprecated)"), "csrf-csrf": ("security-lib", "csrf-csrf"), "express-rate-limit": ("security-lib", "express-rate-limit"),
    "rate-limiter-flexible": ("security-lib", "rate-limiter-flexible"), "@nestjs/throttler": ("security-lib", "NestJS throttler"),
    "zod": ("validation", "zod"), "joi": ("validation", "joi"), "yup": ("validation", "yup"), "class-validator": ("validation", "class-validator"),
    "ajv": ("validation", "ajv"), "express-validator": ("validation", "express-validator"),
    "multer": ("files", "multer uploads"), "formidable": ("files", "formidable uploads"), "busboy": ("files", "busboy uploads"),
    "sharp": ("files", "sharp image processing"), "puppeteer": ("ssrf-risk", "puppeteer (SSRF/PDF risk)"), "playwright": ("ssrf-risk", "playwright"),
    "axios": ("http-client", "axios"), "node-fetch": ("http-client", "node-fetch"), "got": ("http-client", "got"), "undici": ("http-client", "undici"),
    "prisma": ("orm", "Prisma"), "@prisma/client": ("orm", "Prisma"), "sequelize": ("orm", "Sequelize"), "typeorm": ("orm", "TypeORM"),
    "knex": ("orm", "Knex"), "drizzle-orm": ("orm", "Drizzle"), "mongoose": ("datastore", "MongoDB (mongoose)"), "mongodb": ("datastore", "MongoDB"),
    "pg": ("datastore", "PostgreSQL"), "postgres": ("datastore", "PostgreSQL"), "mysql": ("datastore", "MySQL"), "mysql2": ("datastore", "MySQL"),
    "mssql": ("datastore", "SQL Server"), "tedious": ("datastore", "SQL Server"), "sqlite3": ("datastore", "SQLite"), "better-sqlite3": ("datastore", "SQLite"),
    "redis": ("datastore", "Redis"), "ioredis": ("datastore", "Redis"), "@upstash/redis": ("datastore", "Redis (Upstash)"),
    "amqplib": ("queue", "RabbitMQ / AMQP"), "kafkajs": ("queue", "Kafka"), "bullmq": ("queue", "BullMQ (Redis)"), "bull": ("queue", "Bull (Redis)"),
    "bee-queue": ("queue", "bee-queue"), "nats": ("queue", "NATS"), "@aws-sdk/client-sqs": ("queue", "AWS SQS"), "@azure/service-bus": ("queue", "Azure Service Bus"),
    "aws-sdk": ("cloud", "AWS SDK v2"), "@aws-sdk/client-s3": ("cloud", "AWS S3"), "@azure/identity": ("cloud", "Azure Identity"),
    "@azure/storage-blob": ("cloud", "Azure Blob Storage"), "@azure/keyvault-secrets": ("cloud", "Azure Key Vault"),
    "@google-cloud/storage": ("cloud", "GCP Storage"), "minio": ("cloud", "MinIO / S3-compatible"), "serverless": ("cloud", "Serverless Framework"),
    "@vercel/node": ("cloud", "Vercel functions"), "stripe": ("payments", "Stripe"), "@paypal/checkout-server-sdk": ("payments", "PayPal"),
    "nodemailer": ("integration", "nodemailer (email)"), "twilio": ("integration", "Twilio (SMS)"), "openai": ("integration", "OpenAI API (paid)"),
    "@anthropic-ai/sdk": ("integration", "Anthropic API (paid)"), "lodash": ("supply-chain", "lodash (check prototype pollution CVEs)"),
    "serialize-javascript": ("supply-chain", "serialize-javascript"), "vm2": ("supply-chain", "vm2 (known sandbox escapes)"),
    "xml2js": ("parser", "xml2js"), "fast-xml-parser": ("parser", "fast-xml-parser"), "libxmljs": ("parser", "libxmljs (XXE risk)"),
    "handlebars": ("template", "Handlebars"), "ejs": ("template", "EJS (SSTI risk)"), "pug": ("template", "Pug"), "nunjucks": ("template", "Nunjucks"),
    # --- Python ---
    "django": ("backend", "Django"), "djangorestframework": ("backend", "Django REST Framework"), "fastapi": ("backend", "FastAPI"),
    "flask": ("backend", "Flask"), "starlette": ("backend", "Starlette"), "tornado": ("backend", "Tornado"), "aiohttp": ("backend", "aiohttp"),
    "sanic": ("backend", "Sanic"), "litestar": ("backend", "Litestar"), "pyramid": ("backend", "Pyramid"), "bottle": ("backend", "Bottle"),
    "graphene": ("api", "Graphene (GraphQL)"), "strawberry-graphql": ("api", "Strawberry (GraphQL)"), "ariadne": ("api", "Ariadne (GraphQL)"),
    "channels": ("api", "Django Channels (WebSockets)"), "websockets": ("api", "websockets"), "grpcio": ("api", "gRPC"),
    "celery": ("queue", "Celery"), "rq": ("queue", "RQ (Redis)"), "dramatiq": ("queue", "Dramatiq"), "huey": ("queue", "Huey"), "kombu": ("queue", "Kombu/AMQP"),
    "pika": ("queue", "RabbitMQ (pika)"), "confluent-kafka": ("queue", "Kafka"), "kafka-python": ("queue", "Kafka"), "boto3": ("cloud", "AWS SDK (boto3)"),
    "azure-identity": ("cloud", "Azure Identity"), "azure-storage-blob": ("cloud", "Azure Blob Storage"), "azure-keyvault-secrets": ("cloud", "Azure Key Vault"),
    "google-cloud-storage": ("cloud", "GCP Storage"), "pyjwt": ("auth", "PyJWT"), "jwt": ("auth", "jwt (verify which package)"),
    "python-jose": ("auth", "python-jose (JWT)"), "authlib": ("auth", "Authlib (OAuth/OIDC)"), "django-allauth": ("auth", "django-allauth"),
    "djangorestframework-simplejwt": ("auth", "SimpleJWT"), "dj-rest-auth": ("auth", "dj-rest-auth"), "flask-login": ("auth", "Flask-Login"),
    "flask-jwt-extended": ("auth", "Flask-JWT-Extended"), "passlib": ("auth", "passlib"), "bcrypt": ("auth", "bcrypt"), "argon2-cffi": ("auth", "argon2-cffi"),
    "cryptography": ("crypto", "cryptography"), "pycryptodome": ("crypto", "PyCryptodome"), "pycrypto": ("crypto", "pycrypto (unmaintained)"),
    "sqlalchemy": ("orm", "SQLAlchemy"), "peewee": ("orm", "Peewee"), "tortoise-orm": ("orm", "Tortoise ORM"), "sqlmodel": ("orm", "SQLModel"),
    "psycopg2": ("datastore", "PostgreSQL"), "psycopg2-binary": ("datastore", "PostgreSQL"), "psycopg": ("datastore", "PostgreSQL"), "asyncpg": ("datastore", "PostgreSQL"),
    "mysqlclient": ("datastore", "MySQL"), "pymysql": ("datastore", "MySQL"), "pyodbc": ("datastore", "SQL Server / ODBC"), "pymssql": ("datastore", "SQL Server"),
    "pymongo": ("datastore", "MongoDB"), "motor": ("datastore", "MongoDB (motor)"), "redis": ("datastore", "Redis"), "django-redis": ("datastore", "Redis"),
    "elasticsearch": ("datastore", "Elasticsearch"), "requests": ("http-client", "requests"), "httpx": ("http-client", "httpx"), "urllib3": ("http-client", "urllib3"),
    "pillow": ("files", "Pillow image processing"), "python-magic": ("files", "python-magic (MIME sniffing)"), "weasyprint": ("ssrf-risk", "WeasyPrint (PDF/SSRF risk)"),
    "pdfkit": ("ssrf-risk", "pdfkit/wkhtmltopdf (SSRF risk)"), "lxml": ("parser", "lxml (XXE if resolve_entities)"), "xmltodict": ("parser", "xmltodict"),
    "pyyaml": ("parser", "PyYAML (use safe_load)"), "jinja2": ("template", "Jinja2 (SSTI risk)"), "mako": ("template", "Mako (SSTI risk)"),
    "django-cors-headers": ("security-lib", "django-cors-headers"), "django-ratelimit": ("security-lib", "django-ratelimit"), "slowapi": ("security-lib", "slowapi rate limiting"),
    "django-axes": ("security-lib", "django-axes lockout"), "bleach": ("security-lib", "bleach sanitizer"), "nh3": ("security-lib", "nh3 sanitizer"),
    "gunicorn": ("server", "gunicorn"), "uvicorn": ("server", "uvicorn"), "hypercorn": ("server", "hypercorn"), "waitress": ("server", "waitress"),
    "stripe": ("payments", "Stripe"), "openai": ("integration", "OpenAI API (paid)"), "anthropic": ("integration", "Anthropic API (paid)"),
    "sentry-sdk": ("observability", "Sentry"), "pickle5": ("supply-chain", "pickle (deserialization)"),
    # --- .NET (PackageReference / SDK) ---
    "microsoft.net.sdk.web": ("backend", "ASP.NET Core"), "microsoft.aspnetcore.app": ("backend", "ASP.NET Core"),
    "microsoft.aspnetcore.authentication.jwtbearer": ("auth", "ASP.NET JWT Bearer"), "microsoft.aspnetcore.identity.entityframeworkcore": ("auth", "ASP.NET Identity"),
    "microsoft.identity.web": ("auth", "Microsoft.Identity.Web (Entra ID)"), "duende.identityserver": ("auth", "Duende IdentityServer"),
    "identityserver4": ("auth", "IdentityServer4 (EOL)"), "microsoft.entityframeworkcore": ("orm", "Entity Framework Core"), "dapper": ("orm", "Dapper (raw SQL)"),
    "npgsql": ("datastore", "PostgreSQL"), "mysql.data": ("datastore", "MySQL"), "microsoft.data.sqlclient": ("datastore", "SQL Server"),
    "mongodb.driver": ("datastore", "MongoDB"), "stackexchange.redis": ("datastore", "Redis"), "masstransit": ("queue", "MassTransit"),
    "rabbitmq.client": ("queue", "RabbitMQ"), "confluent.kafka": ("queue", "Kafka"), "azure.messaging.servicebus": ("queue", "Azure Service Bus"),
    "azure.identity": ("cloud", "Azure Identity"), "azure.storage.blobs": ("cloud", "Azure Blob Storage"), "azure.security.keyvault.secrets": ("cloud", "Azure Key Vault"),
    "awssdk.s3": ("cloud", "AWS S3"), "microsoft.aspnetcore.signalr": ("api", "SignalR (WebSockets)"), "hotchocolate.aspnetcore": ("api", "Hot Chocolate (GraphQL)"),
    "graphql.server.all": ("api", "GraphQL.NET"), "grpc.aspnetcore": ("api", "gRPC"), "swashbuckle.aspnetcore": ("api", "Swagger/OpenAPI"),
    "aspnetcoreratelimit": ("security-lib", "AspNetCoreRateLimit"), "microsoft.aspnetcore.ratelimiting": ("security-lib", "ASP.NET rate limiting"),
    "bcrypt.net-next": ("auth", "BCrypt.Net"), "system.identitymodel.tokens.jwt": ("auth", "JWT handler"), "microsoft.aspnetcore.dataprotection": ("crypto", "Data Protection"),
    "newtonsoft.json": ("parser", "Newtonsoft.Json (TypeNameHandling risk)"), "fluentvalidation": ("validation", "FluentValidation"),
    # --- Java / Kotlin ---
    "spring-boot-starter-web": ("backend", "Spring Boot (MVC)"), "spring-boot-starter-webflux": ("backend", "Spring Boot (WebFlux)"),
    "spring-boot-starter": ("backend", "Spring Boot"), "spring-boot-starter-security": ("auth", "Spring Security"),
    "spring-boot-starter-oauth2-resource-server": ("auth", "Spring OAuth2 Resource Server"), "spring-boot-starter-oauth2-client": ("auth", "Spring OAuth2 Client"),
    "spring-boot-starter-data-jpa": ("orm", "Spring Data JPA"), "spring-boot-starter-data-redis": ("datastore", "Redis"), "spring-boot-starter-data-mongodb": ("datastore", "MongoDB"),
    "spring-boot-starter-actuator": ("api", "Spring Actuator (check exposure)"), "spring-kafka": ("queue", "Kafka"), "spring-boot-starter-amqp": ("queue", "RabbitMQ"),
    "spring-boot-starter-websocket": ("api", "Spring WebSocket"), "spring-boot-starter-graphql": ("api", "Spring GraphQL"), "spring-boot-starter-thymeleaf": ("template", "Thymeleaf"),
    "quarkus-resteasy": ("backend", "Quarkus"), "quarkus-core": ("backend", "Quarkus"), "micronaut-core": ("backend", "Micronaut"), "micronaut-http-server-netty": ("backend", "Micronaut"),
    "jakarta.jakartaee-api": ("backend", "Jakarta EE"), "javax.servlet-api": ("backend", "Servlet"), "dropwizard-core": ("backend", "Dropwizard"), "vertx-web": ("backend", "Vert.x"),
    "jjwt": ("auth", "jjwt (JWT)"), "jjwt-api": ("auth", "jjwt (JWT)"), "java-jwt": ("auth", "auth0 java-jwt"), "nimbus-jose-jwt": ("auth", "Nimbus JOSE+JWT"),
    "keycloak-spring-boot-starter": ("auth", "Keycloak adapter"), "hibernate-core": ("orm", "Hibernate"), "mybatis": ("orm", "MyBatis (raw SQL)"), "jooq": ("orm", "jOOQ"),
    "postgresql": ("datastore", "PostgreSQL"), "mysql-connector-java": ("datastore", "MySQL"), "mysql-connector-j": ("datastore", "MySQL"), "mssql-jdbc": ("datastore", "SQL Server"),
    "mongodb-driver-sync": ("datastore", "MongoDB"), "jedis": ("datastore", "Redis"), "lettuce-core": ("datastore", "Redis"), "kafka-clients": ("queue", "Kafka"),
    "amqp-client": ("queue", "RabbitMQ"), "aws-java-sdk": ("cloud", "AWS SDK"), "software.amazon.awssdk": ("cloud", "AWS SDK v2"), "azure-identity": ("cloud", "Azure Identity"),
    "log4j-core": ("supply-chain", "log4j-core (verify >= 2.17.1)"), "jackson-databind": ("parser", "Jackson (polymorphic typing risk)"), "xstream": ("parser", "XStream (deserialization risk)"),
    "commons-collections": ("supply-chain", "commons-collections (gadget chains)"), "bouncycastle": ("crypto", "Bouncy Castle"), "bcprov-jdk18on": ("crypto", "Bouncy Castle"),
    "springdoc-openapi": ("api", "springdoc OpenAPI"), "bucket4j": ("security-lib", "Bucket4j rate limiting"), "owasp-java-html-sanitizer": ("security-lib", "OWASP HTML sanitizer"),
    # --- PHP ---
    "laravel/framework": ("backend", "Laravel"), "laravel/sanctum": ("auth", "Laravel Sanctum"), "laravel/passport": ("auth", "Laravel Passport (OAuth2)"),
    "laravel/fortify": ("auth", "Laravel Fortify"), "laravel/breeze": ("auth", "Laravel Breeze"), "laravel/jetstream": ("auth", "Laravel Jetstream"),
    "symfony/framework-bundle": ("backend", "Symfony"), "symfony/security-bundle": ("auth", "Symfony Security"), "slim/slim": ("backend", "Slim"),
    "cakephp/cakephp": ("backend", "CakePHP"), "codeigniter4/framework": ("backend", "CodeIgniter"), "yiisoft/yii2": ("backend", "Yii"),
    "firebase/php-jwt": ("auth", "php-jwt"), "lcobucci/jwt": ("auth", "lcobucci/jwt"), "league/oauth2-server": ("auth", "league/oauth2-server"),
    "guzzlehttp/guzzle": ("http-client", "Guzzle"), "doctrine/orm": ("orm", "Doctrine ORM"), "predis/predis": ("datastore", "Redis"),
    "mongodb/mongodb": ("datastore", "MongoDB"), "php-amqplib/php-amqplib": ("queue", "RabbitMQ"), "aws/aws-sdk-php": ("cloud", "AWS SDK"),
    "intervention/image": ("files", "Intervention Image"), "dompdf/dompdf": ("ssrf-risk", "dompdf (SSRF/RCE history)"), "phpoffice/phpspreadsheet": ("files", "PhpSpreadsheet"),
    "twig/twig": ("template", "Twig"), "league/flysystem": ("files", "Flysystem"), "spatie/laravel-permission": ("auth", "spatie permissions"),
    # --- Ruby ---
    "rails": ("backend", "Ruby on Rails"), "sinatra": ("backend", "Sinatra"), "hanami": ("backend", "Hanami"), "grape": ("api", "Grape API"),
    "devise": ("auth", "Devise"), "omniauth": ("auth", "OmniAuth"), "doorkeeper": ("auth", "Doorkeeper (OAuth2)"), "jwt": ("auth", "jwt (JWT library - verify which package)"),
    "bcrypt": ("auth", "bcrypt"), "pundit": ("auth", "Pundit authorization"), "cancancan": ("auth", "CanCanCan authorization"),
    "sidekiq": ("queue", "Sidekiq (Redis)"), "resque": ("queue", "Resque"), "delayed_job": ("queue", "Delayed Job"), "bunny": ("queue", "RabbitMQ"),
    "pg": ("datastore", "PostgreSQL"), "mysql2": ("datastore", "MySQL"), "mongoid": ("datastore", "MongoDB"), "redis": ("datastore", "Redis"),
    "puma": ("server", "Puma"), "unicorn": ("server", "Unicorn"), "rack-attack": ("security-lib", "rack-attack rate limiting"), "brakeman": ("security-lib", "Brakeman SAST"),
    "carrierwave": ("files", "CarrierWave uploads"), "shrine": ("files", "Shrine uploads"), "aws-sdk-s3": ("cloud", "AWS S3"), "graphql": ("api", "GraphQL library"),
    "nokogiri": ("parser", "Nokogiri"), "rails_admin": ("api", "RailsAdmin (check exposure)"),
    # --- Go ---
    "github.com/gin-gonic/gin": ("backend", "Gin"), "github.com/labstack/echo": ("backend", "Echo"), "github.com/gofiber/fiber": ("backend", "Fiber"),
    "github.com/go-chi/chi": ("backend", "chi"), "github.com/gorilla/mux": ("backend", "gorilla/mux"), "github.com/beego/beego": ("backend", "Beego"),
    "github.com/golang-jwt/jwt": ("auth", "golang-jwt"), "github.com/dgrijalva/jwt-go": ("auth", "jwt-go (deprecated, CVE-2020-26160)"),
    "github.com/lestrrat-go/jwx": ("auth", "jwx"), "github.com/coreos/go-oidc": ("auth", "go-oidc"), "golang.org/x/oauth2": ("auth", "x/oauth2"),
    "golang.org/x/crypto": ("crypto", "x/crypto"), "gorm.io/gorm": ("orm", "GORM"), "github.com/jmoiron/sqlx": ("orm", "sqlx"), "entgo.io/ent": ("orm", "ent"),
    "github.com/jackc/pgx": ("datastore", "PostgreSQL (pgx)"), "github.com/lib/pq": ("datastore", "PostgreSQL"), "github.com/go-sql-driver/mysql": ("datastore", "MySQL"),
    "github.com/microsoft/go-mssqldb": ("datastore", "SQL Server"), "go.mongodb.org/mongo-driver": ("datastore", "MongoDB"), "github.com/redis/go-redis": ("datastore", "Redis"),
    "github.com/go-redis/redis": ("datastore", "Redis"), "github.com/segmentio/kafka-go": ("queue", "Kafka"), "github.com/rabbitmq/amqp091-go": ("queue", "RabbitMQ"),
    "github.com/nats-io/nats.go": ("queue", "NATS"), "github.com/aws/aws-sdk-go": ("cloud", "AWS SDK"), "github.com/aws/aws-sdk-go-v2": ("cloud", "AWS SDK v2"),
    "github.com/Azure/azure-sdk-for-go": ("cloud", "Azure SDK"), "cloud.google.com/go": ("cloud", "GCP SDK"), "google.golang.org/grpc": ("api", "gRPC"),
    "github.com/gorilla/websocket": ("api", "gorilla/websocket"), "github.com/99designs/gqlgen": ("api", "gqlgen (GraphQL)"), "github.com/graphql-go/graphql": ("api", "graphql-go"),
    "github.com/rs/cors": ("security-lib", "rs/cors"), "github.com/ulule/limiter": ("security-lib", "ulule/limiter"), "golang.org/x/time": ("security-lib", "x/time rate"),
    "github.com/spf13/viper": ("config", "viper config"), "github.com/gorilla/csrf": ("security-lib", "gorilla/csrf"), "github.com/microcosm-cc/bluemonday": ("security-lib", "bluemonday sanitizer"),
    # --- Rust ---
    "actix-web": ("backend", "Actix Web"), "axum": ("backend", "Axum"), "rocket": ("backend", "Rocket"), "warp": ("backend", "warp"), "tide": ("backend", "Tide"),
    "jsonwebtoken": ("auth", "jsonwebtoken (JWT)"), "sqlx": ("orm", "sqlx"), "diesel": ("orm", "Diesel"), "sea-orm": ("orm", "SeaORM"),
    "tokio-postgres": ("datastore", "PostgreSQL"), "mongodb": ("datastore", "MongoDB"), "redis": ("datastore", "Redis"), "lapin": ("queue", "RabbitMQ"),
    "rdkafka": ("queue", "Kafka"), "aws-sdk-s3": ("cloud", "AWS S3"), "reqwest": ("http-client", "reqwest"), "ring": ("crypto", "ring"), "rustls": ("crypto", "rustls"),
    "openssl": ("crypto", "openssl"), "argon2": ("auth", "argon2"), "bcrypt": ("auth", "bcrypt"), "tonic": ("api", "gRPC (tonic)"), "async-graphql": ("api", "async-graphql"),
}

# Compose / K8s image name fragments -> service label
IMAGE_SIGNALS = [
    ("postgres", "PostgreSQL"), ("pgvector", "PostgreSQL (pgvector)"), ("timescale", "PostgreSQL (Timescale)"), ("mysql", "MySQL"), ("mariadb", "MariaDB"),
    ("mssql", "SQL Server"), ("mongo", "MongoDB"), ("redis", "Redis"), ("valkey", "Valkey (Redis-compatible)"), ("memcached", "Memcached"),
    ("rabbitmq", "RabbitMQ"), ("kafka", "Kafka"), ("redpanda", "Redpanda (Kafka API)"), ("nats", "NATS"), ("zookeeper", "ZooKeeper"), ("activemq", "ActiveMQ"),
    ("elasticsearch", "Elasticsearch"), ("opensearch", "OpenSearch"), ("kibana", "Kibana"), ("minio", "MinIO (S3-compatible)"), ("localstack", "LocalStack"),
    ("nginx", "nginx"), ("traefik", "Traefik"), ("caddy", "Caddy"), ("haproxy", "HAProxy"), ("envoy", "Envoy"), ("keycloak", "Keycloak (IdP)"),
    ("vault", "HashiCorp Vault"), ("consul", "Consul"), ("grafana", "Grafana"), ("prometheus", "Prometheus"), ("jaeger", "Jaeger"), ("otel", "OpenTelemetry collector"),
    ("clickhouse", "ClickHouse"), ("cassandra", "Cassandra"), ("neo4j", "Neo4j"), ("influxdb", "InfluxDB"), ("mailhog", "MailHog"), ("mailpit", "Mailpit"),
    ("pgadmin", "pgAdmin (admin UI - check exposure)"), ("phpmyadmin", "phpMyAdmin (admin UI - check exposure)"), ("adminer", "Adminer (admin UI - check exposure)"),
    ("mongo-express", "mongo-express (admin UI - check exposure)"), ("redis-commander", "redis-commander (admin UI - check exposure)"),
]

TOOLS_ON_PATH = [
    # SAST / SCA / secrets / IaC / container
    "semgrep", "codeql", "bandit", "brakeman", "gosec", "trivy", "grype", "syft", "gitleaks", "trufflehog", "detect-secrets",
    "checkov", "tfsec", "terrascan", "kics", "kube-linter", "kube-bench", "kubesec", "kubescape", "hadolint", "dockle", "osv-scanner", "snyk",
    "pip-audit", "safety", "npm", "pnpm", "yarn", "bun", "dotnet", "govulncheck", "cargo", "cargo-audit", "composer", "bundle", "bundler-audit",
    "mvn", "gradle", "dependency-check", "sonar-scanner",
    # dynamic / network / TLS
    "curl", "wget", "httpie", "http", "nmap", "openssl", "sslscan", "testssl.sh", "nikto", "zap.sh", "zap-cli", "ffuf", "sqlmap", "nuclei", "jwt_tool", "jwt-cracker",
    # runtimes / platform / cloud
    "python", "python3", "node", "java", "go", "php", "ruby", "git", "gh", "glab", "docker", "docker-compose", "docker-scout", "podman", "kubectl", "helm", "kustomize", "minikube", "kind",
    "terraform", "tofu", "terragrunt", "pulumi", "ansible", "az", "aws", "gcloud", "gsutil", "doctl", "flyctl", "vercel", "netlify", "sam", "cdk", "func",
    "psql", "mysql", "sqlcmd", "mongosh", "redis-cli",
]

TEXT_PEEK_BYTES = 64 * 1024     # bytes read from an allowlisted manifest
YAML_PEEK_BYTES = 8 * 1024      # bytes read from a YAML file to classify it
DEFAULT_MAX_FILES = 250_000

K8S_API_RE = re.compile(r"^\s*apiVersion:\s*['\"]?([\w./-]+)", re.MULTILINE)
K8S_KIND_RE = re.compile(r"^\s*kind:\s*['\"]?([A-Za-z0-9]+)", re.MULTILINE)
K8S_NAME_RE = re.compile(r"^\s*name:\s*['\"]?([\w.-]+)", re.MULTILINE)
COMPOSE_SERVICES_RE = re.compile(r"^\s*services:\s*$", re.MULTILINE)
IMAGE_RE = re.compile(r"^\s*(?:-\s*)?image:\s*['\"]?([^\s'\"#]+)", re.MULTILINE)
HOST_PORT_RE = re.compile(r"^\s*-\s*['\"]?(?:(\d{1,3}(?:\.\d{1,3}){3}):)?(\d{2,5}):(\d{2,5})(?:/\w+)?['\"]?\s*$", re.MULTILINE)
PRIVILEGED_RE = re.compile(r"^\s*privileged:\s*true", re.MULTILINE | re.IGNORECASE)
DOCKER_SOCK_RE = re.compile(r"/var/run/docker\.sock")
HOSTNET_RE = re.compile(r"^\s*(hostNetwork|hostPID|hostIPC):\s*true", re.MULTILINE)
HOSTPATH_RE = re.compile(r"^\s*hostPath:", re.MULTILINE)
RUNASROOT_RE = re.compile(r"^\s*runAsUser:\s*0\b", re.MULTILINE)
ALLOW_PRIV_ESC_RE = re.compile(r"^\s*allowPrivilegeEscalation:\s*true", re.MULTILINE)
GHA_USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^\s'\"#]+)", re.MULTILINE)
GHA_PR_TARGET_RE = re.compile(r"pull_request_target", re.MULTILINE)
GHA_PERMS_RE = re.compile(r"^\s*permissions:\s*write-all", re.MULTILINE)
GHA_SELF_HOSTED_RE = re.compile(r"runs-on:.*self-hosted", re.MULTILINE)
SHA40_RE = re.compile(r"@[0-9a-f]{40}$")
CFN_RE = re.compile(r"^\s*AWSTemplateFormatVersion:", re.MULTILINE)
SAM_RE = re.compile(r"^\s*Transform:\s*['\"]?AWS::Serverless", re.MULTILINE)
DOCKER_FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.MULTILINE | re.IGNORECASE)
DOCKER_USER_RE = re.compile(r"^\s*USER\s+(\S+)", re.MULTILINE | re.IGNORECASE)
DOCKER_EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+(.+)$", re.MULTILINE | re.IGNORECASE)
TF_PROVIDER_RE = re.compile(r'^\s*provider\s+"([\w-]+)"', re.MULTILINE)
TF_RESOURCE_RE = re.compile(r'^\s*resource\s+"([\w-]+)"', re.MULTILINE)
TF_BACKEND_RE = re.compile(r'^\s*backend\s+"([\w-]+)"', re.MULTILINE)
HELM_CHART_RE = re.compile(r"^\s*apiVersion:\s*v[12]\s*$", re.MULTILINE)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _match_any(name: str, patterns) -> bool:
    lname = name.lower()
    return any(fnmatch.fnmatchcase(lname, p.lower()) for p in patterns)


def _match_pathpat(rel: str, patterns: dict) -> str | None:
    """Match a forward-slash relative path against basename or tail patterns."""
    base = rel.rsplit("/", 1)[-1]
    for pat, label in patterns.items():
        if "/" in pat:
            if fnmatch.fnmatchcase(rel.lower(), ("*/" + pat).lower()) or fnmatch.fnmatchcase(rel.lower(), pat.lower()):
                return label
        elif fnmatch.fnmatchcase(base.lower(), pat.lower()):
            return label
    return None


def _is_template(name: str) -> bool:
    lname = name.lower()
    return any(m in lname for m in TEMPLATE_MARKERS)


def _is_secret_like(rel: str, base: str) -> bool:
    if _match_any(base, SECRET_NAME_PATTERNS):
        return True
    lrel = rel.lower()
    return any(lrel.endswith(s.lower()) or ("/" + s.lower()) in lrel for s in SECRET_PATH_SUFFIXES)


def _peek_text(path: Path, limit: int) -> str:
    """Read at most `limit` bytes from an ALLOWLISTED file. Never used on name-only files."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(limit)
    except (OSError, PermissionError):
        return ""


def _safe_size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def _dep_lookup(names, found: dict, source: str) -> None:
    for raw in names:
        n = raw.strip().lower()
        if not n:
            continue
        hit = DEP_SIGNALS.get(n)
        if hit is None:
            # go modules and maven coords: match on prefix
            for key, val in DEP_SIGNALS.items():
                if "/" in key and n.startswith(key):
                    hit = val
                    break
        if hit:
            cat, label = hit
            found[cat].setdefault(label, set()).add(source)


# --------------------------------------------------------------------------- #
# Manifest parsers (structural tokens only)
# --------------------------------------------------------------------------- #

def parse_package_json(text: str):
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return [], {}
    deps = []
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = data.get(key)
        if isinstance(block, dict):
            deps.extend(block.keys())
    meta = {
        "has_scripts": bool(data.get("scripts")),
        "workspaces": bool(data.get("workspaces")),
        "private": bool(data.get("private", False)),
        "type_module": data.get("type") == "module",
    }
    return deps, meta


PY_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[|==|>=|<=|~=|!=|>|<|;|$|@|\s)")


def parse_requirements(text: str):
    deps = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = PY_REQ_RE.match(line)
        if m:
            deps.append(m.group(1))
    return deps


PYPROJECT_DEP_RE = re.compile(r'^\s*"?([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[=<>!~;@"\s]|$)')


def parse_pyproject(text: str):
    deps, in_block = [], False
    for line in text.splitlines():
        s = line.strip()
        if re.match(r"^\[(tool\.poetry\.(group\.\w+\.)?dependencies|project\.optional-dependencies\.\w+)\]", s) or s == "[tool.poetry.dependencies]":
            in_block, is_table = True, True
            continue
        if s.startswith("dependencies") and "[" in s:
            in_block, is_table = True, False
            continue
        if s.startswith("[") and s.endswith("]"):
            in_block = False
            continue
        if in_block:
            if s.startswith("]"):
                in_block = False
                continue
            if s.startswith(("#", "python ")) or not s:
                continue
            m = PYPROJECT_DEP_RE.match(s)
            if m:
                deps.append(m.group(1))
    return deps


def parse_pipfile(text: str):
    deps, in_block = [], False
    for line in text.splitlines():
        s = line.strip()
        if s in ("[packages]", "[dev-packages]"):
            in_block = True
            continue
        if s.startswith("["):
            in_block = False
            continue
        if in_block and "=" in s and not s.startswith("#"):
            deps.append(s.split("=", 1)[0].strip().strip('"'))
    return deps


GOMOD_RE = re.compile(r"^\s*([\w./~-]+)\s+v[\w.+-]+", re.MULTILINE)


def parse_gomod(text: str):
    return [m.group(1) for m in GOMOD_RE.finditer(text) if "/" in m.group(1)]


CSPROJ_PKG_RE = re.compile(r'<PackageReference\s+[^>]*Include\s*=\s*"([^"]+)"', re.IGNORECASE)
CSPROJ_SDK_RE = re.compile(r'<Project\s+Sdk\s*=\s*"([^"]+)"', re.IGNORECASE)
CSPROJ_FRAMEWORK_RE = re.compile(r"<FrameworkReference\s+[^>]*Include\s*=\s*\"([^\"]+)\"", re.IGNORECASE)
CSPROJ_TFM_RE = re.compile(r"<TargetFrameworks?>([^<]+)</TargetFrameworks?>", re.IGNORECASE)


def parse_csproj(text: str):
    deps = [m.group(1) for m in CSPROJ_PKG_RE.finditer(text)]
    deps += [m.group(1) for m in CSPROJ_FRAMEWORK_RE.finditer(text)]
    sdk = CSPROJ_SDK_RE.search(text)
    if sdk:
        deps.append(sdk.group(1))
    tfm = CSPROJ_TFM_RE.search(text)
    return deps, {"sdk": sdk.group(1) if sdk else None, "target_framework": tfm.group(1).strip() if tfm else None}


POM_ARTIFACT_RE = re.compile(r"<artifactId>\s*([^<\s]+)\s*</artifactId>")
POM_GROUP_RE = re.compile(r"<groupId>\s*([^<\s]+)\s*</groupId>")


def parse_pom(text: str):
    return [m.group(1) for m in POM_ARTIFACT_RE.finditer(text)] + [m.group(1) for m in POM_GROUP_RE.finditer(text)]


GRADLE_DEP_RE = re.compile(r"""(?:implementation|api|compile|runtimeOnly|compileOnly|testImplementation|kapt|annotationProcessor)\s*\(?\s*['"]([^:'"]+):([^:'"]+)""")


def parse_gradle(text: str):
    out = []
    for m in GRADLE_DEP_RE.finditer(text):
        out.append(m.group(2))
        out.append(m.group(1))
    return out


def parse_composer(text: str):
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    deps = []
    for key in ("require", "require-dev"):
        block = data.get(key)
        if isinstance(block, dict):
            deps.extend(block.keys())
    return deps


GEM_RE = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"]""", re.MULTILINE)


def parse_gemfile(text: str):
    return [m.group(1) for m in GEM_RE.finditer(text)]


def parse_cargo(text: str):
    deps, in_block = [], False
    for line in text.splitlines():
        s = line.strip()
        if re.match(r"^\[(dependencies|dev-dependencies|build-dependencies|workspace\.dependencies)\]", s):
            in_block = True
            continue
        if s.startswith("["):
            in_block = False
            continue
        if in_block and "=" in s and not s.startswith("#"):
            deps.append(s.split("=", 1)[0].strip().strip('"'))
    return deps


# --------------------------------------------------------------------------- #
# Inventory
# --------------------------------------------------------------------------- #

class Inventory:
    def __init__(self, root: Path, extra_excludes, max_files: int, check_tools: bool):
        self.root = root
        self.skip = SKIP_DIRS | set(extra_excludes)
        self.max_files = max_files
        self.check_tools = check_tools
        self.languages = Counter()
        self.frameworks = defaultdict(dict)   # category -> label -> set(sources)
        self.markers = defaultdict(list)      # label -> [paths]
        self.manifests = []                   # {path, ecosystem}
        self.lockfiles = []
        self.docker = {"dockerfiles": [], "compose": [], "dockerignore": []}
        self.kubernetes = {"manifests": [], "kinds": Counter(), "secret_manifests": [], "risky": []}
        self.helm = {"charts": [], "values": []}
        self.terraform = {"files": [], "providers": Counter(), "resource_types": Counter(), "backends": Counter(), "modules_dirs": set()}
        self.other_iac = defaultdict(list)    # label -> paths
        self.cicd = defaultdict(list)         # system -> paths
        self.gha = {"uses": Counter(), "unpinned": [], "pull_request_target": [], "write_all": [], "self_hosted": []}
        self.proxies = defaultdict(list)
        self.services = defaultdict(set)      # label -> set(sources)
        self.host_ports = []                  # (source, host_ip, host_port, container_port)
        self.secret_like = []                 # {path, size, reason}
        self.templates = []
        self.certs = []
        self.git = {"repos": []}
        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors = []
        self.truncated = False

    # ------------------------------------------------------------------ walk
    def run(self):
        for dirpath, dirnames, filenames in os.walk(self.root, topdown=True, followlinks=False, onerror=self._walk_error):
            self.dirs_scanned += 1
            rel_dir = self._rel(Path(dirpath))
            if ".git" in dirnames or ".git" in filenames:
                self.git["repos"].append(rel_dir or ".")
            dirnames[:] = sorted(d for d in dirnames if d not in self.skip and not self._is_secret_dir(d))
            for fname in sorted(filenames):
                if self.files_scanned >= self.max_files:
                    self.truncated = True
                    return
                self.files_scanned += 1
                path = Path(dirpath) / fname
                rel = (rel_dir + "/" + fname) if rel_dir else fname
                try:
                    self._classify(path, rel, fname)
                except (OSError, PermissionError) as exc:
                    self.errors.append(f"{rel}: {exc.__class__.__name__}")
                except Exception as exc:  # never let one odd file abort the inventory
                    self.errors.append(f"{rel}: {exc.__class__.__name__}: {exc}")

    def _walk_error(self, exc):
        self.errors.append(f"{getattr(exc, 'filename', '?')}: {exc.__class__.__name__}")

    def _rel(self, p: Path) -> str:
        try:
            s = p.relative_to(self.root).as_posix()
        except ValueError:
            return p.as_posix()
        return "" if s == "." else s

    @staticmethod
    def _is_secret_dir(d: str) -> bool:
        return d.lower() in {".ssh", ".gnupg", ".aws", ".kube", ".azure", ".docker", ".gcloud"}

    # -------------------------------------------------------------- classify
    def _classify(self, path: Path, rel: str, fname: str):
        lower = fname.lower()
        ext = path.suffix.lower()

        # 1. Languages by extension (count only)
        if ext in LANG_BY_EXT:
            self.languages[LANG_BY_EXT[ext]] += 1
        elif lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile"):
            self.languages["Dockerfile"] += 1

        # 2. NAME-ONLY classes first. Return immediately: these files are never opened.
        if _is_secret_like(rel, fname):
            entry = {"path": rel, "size": _safe_size(path)}
            if _is_template(fname):
                self.templates.append(entry)
            else:
                entry["reason"] = "secret-like filename (contents NOT read)"
                self.secret_like.append(entry)
            if _match_any(fname, CERT_NAME_PATTERNS):
                self.certs.append({"path": rel, "size": entry["size"], "kind": "private-key/cert (contents NOT read)"})
            return
        if _match_any(fname, CERT_NAME_PATTERNS):
            kind = "public key" if lower.endswith(".pub") else "certificate/key material (contents NOT read)"
            self.certs.append({"path": rel, "size": _safe_size(path), "kind": kind})
            return

        # 3. Lockfiles (name only)
        if fname in LOCKFILE_NAMES:
            self.lockfiles.append({"path": rel, "ecosystem": LOCKFILE_NAMES[fname]})
            return

        # 4. Marker files (name only)
        for marker, label in MARKER_FILES.items():
            if "/" in marker:
                if rel.lower().endswith(marker.lower()):
                    self.markers[label].append(rel)
            elif lower == marker.lower():
                self.markers[label].append(rel)

        # 5. CI/CD (peek: GitHub Actions `uses:` refs and risky triggers only)
        ci = _match_pathpat(rel, CI_PATTERNS)
        if ci:
            self.cicd[ci].append(rel)
            if ci == "GitHub Actions":
                self._peek_gha(path, rel)
            return

        # 6. Reverse proxy / server config (name only)
        proxy = _match_pathpat(rel, PROXY_PATTERNS)
        if proxy:
            self.proxies[proxy].append(rel)
            return

        # 7. Docker
        if lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile") or lower == "containerfile":
            self._peek_dockerfile(path, rel)
            return
        if lower == ".dockerignore":
            self.docker["dockerignore"].append(rel)
            return
        if re.match(r"^(docker-)?compose[\w.-]*\.ya?ml$", lower):
            self._peek_compose(path, rel)
            return

        # 8. Terraform (peek *.tf for provider/resource/backend names only)
        if ext == ".tf":
            self._peek_tf(path, rel)
            return
        if ext == ".hcl" and lower in ("terragrunt.hcl",):
            self.other_iac["Terragrunt"].append(rel)
            return
        if ext == ".bicep":
            self.other_iac["Azure Bicep"].append(rel)
            return

        # 9. Dependency manifests (peek: dependency names only)
        eco = _match_pathpat(rel, MANIFEST_PATTERNS)
        if eco:
            self._peek_manifest(path, rel, fname, eco)
            return

        # 10. YAML: Kubernetes / Helm / CloudFormation / SAM classification
        if ext in (".yaml", ".yml"):
            self._peek_yaml(path, rel, fname)
            return

    # ------------------------------------------------------------------ peeks
    def _peek_manifest(self, path: Path, rel: str, fname: str, eco: str):
        text = _peek_text(path, TEXT_PEEK_BYTES)
        self.manifests.append({"path": rel, "ecosystem": eco})
        lower = fname.lower()
        deps, meta = [], {}
        if lower == "package.json":
            deps, meta = parse_package_json(text)
        elif lower.startswith("requirements") and lower.endswith(".txt"):
            deps = parse_requirements(text)
        elif lower == "pyproject.toml":
            deps = parse_pyproject(text)
        elif lower == "pipfile":
            deps = parse_pipfile(text)
        elif lower == "go.mod":
            deps = parse_gomod(text)
        elif lower.endswith((".csproj", ".fsproj", ".vbproj")) or lower == "directory.packages.props":
            deps, meta = parse_csproj(text)
        elif lower == "pom.xml":
            deps = parse_pom(text)
        elif lower.startswith("build.gradle"):
            deps = parse_gradle(text)
        elif lower == "composer.json":
            deps = parse_composer(text)
        elif lower == "gemfile":
            deps = parse_gemfile(text)
        elif lower == "cargo.toml":
            deps = parse_cargo(text)
        _dep_lookup(deps, self.frameworks, rel)
        if meta:
            self.manifests[-1]["meta"] = meta

    def _peek_dockerfile(self, path: Path, rel: str):
        text = _peek_text(path, TEXT_PEEK_BYTES)
        froms = [m.group(1) for m in DOCKER_FROM_RE.finditer(text)]
        users = [m.group(1) for m in DOCKER_USER_RE.finditer(text)]
        exposes = [m.group(1).strip() for m in DOCKER_EXPOSE_RE.finditer(text)]
        entry = {
            "path": rel,
            "base_images": froms,
            "unpinned_base": [f for f in froms if "@sha256:" not in f and not f.lower().startswith(("scratch", "$"))],
            "user_instruction": users[-1] if users else None,
            "runs_as_root": (not users) or users[-1].strip().lower() in ("root", "0"),
            "expose": exposes,
        }
        self.docker["dockerfiles"].append(entry)
        for img in froms:
            self._image_signal(img, rel)

    def _peek_compose(self, path: Path, rel: str):
        text = _peek_text(path, TEXT_PEEK_BYTES)
        images = IMAGE_RE.findall(text)
        entry = {
            "path": rel,
            "images": images,
            "privileged": bool(PRIVILEGED_RE.search(text)),
            "docker_socket_mount": bool(DOCKER_SOCK_RE.search(text)),
            "host_ports": [],
        }
        for m in HOST_PORT_RE.finditer(text):
            host_ip, host_port, cport = m.group(1) or "0.0.0.0", m.group(2), m.group(3)
            entry["host_ports"].append({"host_ip": host_ip, "host_port": host_port, "container_port": cport})
            self.host_ports.append((rel, host_ip, host_port, cport))
        self.docker["compose"].append(entry)
        for img in images:
            self._image_signal(img, rel)

    def _image_signal(self, image: str, source: str):
        low = image.lower()
        for frag, label in IMAGE_SIGNALS:
            if frag in low:
                self.services[label].add(source)

    def _peek_tf(self, path: Path, rel: str):
        text = _peek_text(path, TEXT_PEEK_BYTES)
        self.terraform["files"].append(rel)
        self.terraform["modules_dirs"].add(rel.rsplit("/", 1)[0] if "/" in rel else ".")
        for m in TF_PROVIDER_RE.finditer(text):
            self.terraform["providers"][m.group(1)] += 1
        for m in TF_RESOURCE_RE.finditer(text):
            self.terraform["resource_types"][m.group(1)] += 1
        for m in TF_BACKEND_RE.finditer(text):
            self.terraform["backends"][m.group(1)] += 1

    def _peek_gha(self, path: Path, rel: str):
        text = _peek_text(path, TEXT_PEEK_BYTES)
        for m in GHA_USES_RE.finditer(text):
            ref = m.group(1)
            self.gha["uses"][ref] += 1
            if ref.startswith(("./", "docker://")):
                continue
            if not SHA40_RE.search(ref):
                self.gha["unpinned"].append({"workflow": rel, "uses": ref})
        if GHA_PR_TARGET_RE.search(text):
            self.gha["pull_request_target"].append(rel)
        if GHA_PERMS_RE.search(text):
            self.gha["write_all"].append(rel)
        if GHA_SELF_HOSTED_RE.search(text):
            self.gha["self_hosted"].append(rel)

    def _peek_yaml(self, path: Path, rel: str, fname: str):
        lower = fname.lower()
        text = _peek_text(path, YAML_PEEK_BYTES)
        if not text:
            return
        # Helm
        if lower == "chart.yaml" and HELM_CHART_RE.search(text):
            self.helm["charts"].append(rel)
            return
        if lower.startswith("values") and lower.endswith((".yaml", ".yml")) and "/templates/" not in rel.lower():
            # values files can hold secrets: record path only, never parsed further
            self.helm["values"].append(rel)
            return
        if CFN_RE.search(text):
            label = "AWS SAM" if SAM_RE.search(text) else "AWS CloudFormation"
            self.other_iac[label].append(rel)
            return
        # Kubernetes: apiVersion + kind present
        api = K8S_API_RE.search(text)
        kind = K8S_KIND_RE.search(text)
        if api and kind:
            k = kind.group(1)
            name_m = K8S_NAME_RE.search(text)
            entry = {"path": rel, "apiVersion": api.group(1), "kind": k, "name": name_m.group(1) if name_m else None}
            if k.lower() in ("secret", "sealedsecret", "externalsecret", "secretproviderclass"):
                entry["note"] = "secret manifest detected - data/stringData NOT read"
                self.kubernetes["secret_manifests"].append(entry)
            self.kubernetes["manifests"].append(entry)
            self.kubernetes["kinds"][k] += 1
            risks = []
            if PRIVILEGED_RE.search(text):
                risks.append("privileged: true")
            if HOSTNET_RE.search(text):
                risks.append("hostNetwork/hostPID/hostIPC: true")
            if HOSTPATH_RE.search(text):
                risks.append("hostPath volume")
            if RUNASROOT_RE.search(text):
                risks.append("runAsUser: 0")
            if ALLOW_PRIV_ESC_RE.search(text):
                risks.append("allowPrivilegeEscalation: true")
            if DOCKER_SOCK_RE.search(text):
                risks.append("docker.sock mount")
            if risks:
                self.kubernetes["risky"].append({"path": rel, "kind": k, "flags": risks})
            for img in IMAGE_RE.findall(text):
                self._image_signal(img, rel)

    # ---------------------------------------------------------------- tools
    def tools(self) -> dict:
        if not self.check_tools:
            return {}
        return {t: (shutil.which(t) is not None) for t in TOOLS_ON_PATH}

    # ---------------------------------------------------------------- output
    def to_dict(self) -> dict:
        fw = {cat: {label: sorted(src) for label, src in sorted(labels.items())} for cat, labels in sorted(self.frameworks.items())}
        for cat in ("frontend", "backend"):
            fw.setdefault(cat, {})
        # Marker-based frameworks fold into the same view
        for label, paths in self.markers.items():
            cat = "backend" if label in ("Django", "Laravel", "Ruby on Rails", "Rack (Ruby)", ".NET", "ASP.NET Core", "ASP.NET (Framework)", "Spring Boot", "WordPress") \
                else "frontend" if label in ("Next.js", "Nuxt", "Angular", "SvelteKit / Svelte", "Vite", "Remix", "Astro", "Gatsby", "Electron", "Capacitor") \
                else "platform"
            fw.setdefault(cat, {}).setdefault(label, [])
            fw[cat][label] = sorted(set(fw[cat][label]) | set(paths))
        return {
            "inventory_version": VERSION,
            "root": str(self.root),
            "summary": {
                "files_scanned": self.files_scanned,
                "dirs_scanned": self.dirs_scanned,
                "truncated_at_max_files": self.truncated,
                "errors": len(self.errors),
            },
            "git": self.git,
            "languages": dict(self.languages.most_common()),
            "frameworks": fw,
            "manifests": self.manifests,
            "lockfiles": self.lockfiles,
            "services_inferred": {label: sorted(src) for label, src in sorted(self.services.items())},
            "docker": self.docker,
            "kubernetes": {
                "manifests": self.kubernetes["manifests"],
                "kinds": dict(self.kubernetes["kinds"]),
                "secret_manifests": self.kubernetes["secret_manifests"],
                "risky_settings": self.kubernetes["risky"],
            },
            "helm": self.helm,
            "terraform": {
                "files": self.terraform["files"],
                "module_dirs": sorted(self.terraform["modules_dirs"]),
                "providers": dict(self.terraform["providers"]),
                "resource_types": dict(self.terraform["resource_types"].most_common()),
                "backends": dict(self.terraform["backends"]),
            },
            "other_iac": dict(self.other_iac),
            "cicd": dict(self.cicd),
            "github_actions": {
                "uses_refs": dict(self.gha["uses"]),
                "unpinned_actions": self.gha["unpinned"],
                "pull_request_target_workflows": self.gha["pull_request_target"],
                "permissions_write_all": self.gha["write_all"],
                "self_hosted_runners": self.gha["self_hosted"],
            },
            "reverse_proxies": dict(self.proxies),
            "host_published_ports": [
                {"source": s, "host_ip": ip, "host_port": hp, "container_port": cp} for (s, ip, hp, cp) in self.host_ports
            ],
            "secret_like_files": self.secret_like,
            "secret_templates": self.templates,
            "certificate_key_files": self.certs,
            "tools_on_path": self.tools(),
            "errors": self.errors[:50],
            "notes": [
                "Secret-like files, keys, certificates, tfstate/tfvars and kubeconfigs were reported by NAME ONLY and never opened.",
                "Manifest peeks extracted dependency names, image names, kind/name, uses: refs and provider/resource types only.",
                "This is a static inventory; it is a starting point for review, not a vulnerability scan.",
            ],
        }


# --------------------------------------------------------------------------- #
# Human-readable rendering (ASCII only)
# --------------------------------------------------------------------------- #

def _section(title: str) -> str:
    return f"\n== {title} " + "=" * max(4, 70 - len(title))


def render_text(d: dict) -> str:
    out = []
    s = d["summary"]
    out.append(f"security_inventory v{d['inventory_version']}  root={d['root']}")
    out.append(f"files={s['files_scanned']} dirs={s['dirs_scanned']} errors={s['errors']}" + ("  [TRUNCATED at --max-files]" if s["truncated_at_max_files"] else ""))
    if d["git"]["repos"]:
        out.append("git repos: " + ", ".join(d["git"]["repos"][:10]))

    out.append(_section("Languages (file counts)"))
    langs = d["languages"]
    out.append("  " + (", ".join(f"{k}={v}" for k, v in list(langs.items())[:25]) if langs else "(none detected)"))

    out.append(_section("Frameworks and notable libraries"))
    order = ["frontend", "backend", "api", "auth", "orm", "datastore", "queue", "cloud", "files", "ssrf-risk", "template", "parser",
             "crypto", "security-lib", "validation", "http-client", "server", "payments", "integration", "supply-chain", "observability", "config", "platform"]
    any_fw = False
    for cat in order + [c for c in d["frameworks"] if c not in order]:
        labels = d["frameworks"].get(cat) or {}
        if not labels:
            continue
        any_fw = True
        out.append(f"  [{cat}]")
        for label, sources in labels.items():
            src = f"  <- {', '.join(sources[:3])}" + (" ..." if len(sources) > 3 else "") if sources else ""
            out.append(f"    - {label}{src}")
    if not any_fw:
        out.append("  (none detected)")

    out.append(_section("Dependency manifests / lockfiles"))
    for m in d["manifests"][:60]:
        out.append(f"  manifest  {m['ecosystem']:10s} {m['path']}")
    for l in d["lockfiles"][:60]:
        out.append(f"  lockfile  {l['ecosystem']:10s} {l['path']}")
    if not d["manifests"] and not d["lockfiles"]:
        out.append("  (none)")
    missing_lock = {m["ecosystem"] for m in d["manifests"]} - {l["ecosystem"] for l in d["lockfiles"]} - {"python", "dotnet", "maven", "gradle"}
    if missing_lock:
        out.append(f"  NOTE: manifests without a matching lockfile: {', '.join(sorted(missing_lock))}")

    out.append(_section("Inferred services (databases, caches, queues, proxies)"))
    if d["services_inferred"]:
        for label, src in d["services_inferred"].items():
            out.append(f"  - {label}  <- {', '.join(src[:3])}")
    else:
        out.append("  (none inferred from images)")

    out.append(_section("Docker"))
    dk = d["docker"]
    for f in dk["dockerfiles"]:
        flags = []
        if f["runs_as_root"]:
            flags.append("RUNS-AS-ROOT(no USER)" if f["user_instruction"] is None else "USER root")
        if f["unpinned_base"]:
            flags.append("base-not-digest-pinned")
        out.append(f"  Dockerfile {f['path']}  FROM {', '.join(f['base_images']) or '?'}  EXPOSE {', '.join(f['expose']) or '-'}  {' '.join(flags)}")
    for c in dk["compose"]:
        flags = []
        if c["privileged"]:
            flags.append("PRIVILEGED")
        if c["docker_socket_mount"]:
            flags.append("DOCKER-SOCKET-MOUNT")
        out.append(f"  compose    {c['path']}  images={len(c['images'])} host_ports={len(c['host_ports'])} {' '.join(flags)}")
    if not dk["dockerfiles"] and not dk["compose"]:
        out.append("  (none)")
    if d["host_published_ports"]:
        out.append("  host-published ports:")
        for p in d["host_published_ports"][:40]:
            bind = "ALL-INTERFACES" if p["host_ip"] == "0.0.0.0" else p["host_ip"]
            out.append(f"    {p['source']}: {bind}:{p['host_port']} -> {p['container_port']}")

    out.append(_section("Kubernetes / Helm"))
    k8 = d["kubernetes"]
    if k8["manifests"]:
        out.append("  kinds: " + ", ".join(f"{k}={v}" for k, v in k8["kinds"].items()))
        for sm in k8["secret_manifests"]:
            out.append(f"  SECRET manifest: {sm['path']} (kind={sm['kind']}, name={sm['name']}) - contents NOT read")
        for r in k8["risky_settings"]:
            out.append(f"  RISKY: {r['path']} ({r['kind']}): {', '.join(r['flags'])}")
    else:
        out.append("  (no Kubernetes manifests)")
    if d["helm"]["charts"]:
        out.append("  helm charts: " + ", ".join(d["helm"]["charts"]))
    if d["helm"]["values"]:
        out.append("  helm values files (may hold secrets, not parsed): " + ", ".join(d["helm"]["values"][:10]))

    out.append(_section("Terraform / IaC"))
    tf = d["terraform"]
    if tf["files"]:
        out.append(f"  terraform files={len(tf['files'])} module_dirs={', '.join(tf['module_dirs'][:8])}")
        out.append("  providers: " + (", ".join(f"{k}={v}" for k, v in tf["providers"].items()) or "(none declared in scanned files)"))
        out.append("  backends: " + (", ".join(tf["backends"]) or "(none/local state!)"))
        out.append("  top resource types: " + ", ".join(f"{k}={v}" for k, v in list(tf["resource_types"].items())[:15]))
    for label, paths in d["other_iac"].items():
        out.append(f"  {label}: {', '.join(paths[:8])}")
    if not tf["files"] and not d["other_iac"]:
        out.append("  (none)")

    out.append(_section("CI/CD"))
    if d["cicd"]:
        for system, paths in d["cicd"].items():
            out.append(f"  {system}: {', '.join(paths[:8])}" + (" ..." if len(paths) > 8 else ""))
        g = d["github_actions"]
        if g["uses_refs"]:
            out.append(f"  GitHub Actions: {len(g['uses_refs'])} distinct action refs, {len(g['unpinned_actions'])} not SHA-pinned")
            for u in g["unpinned_actions"][:15]:
                out.append(f"    unpinned: {u['uses']}  ({u['workflow']})")
        for w in g["pull_request_target_workflows"]:
            out.append(f"  WARNING pull_request_target trigger: {w}")
        for w in g["permissions_write_all"]:
            out.append(f"  WARNING permissions: write-all: {w}")
        for w in g["self_hosted_runners"]:
            out.append(f"  NOTE self-hosted runner: {w}")
    else:
        out.append("  (none)")

    out.append(_section("Reverse proxy / server config"))
    if d["reverse_proxies"]:
        for label, paths in d["reverse_proxies"].items():
            out.append(f"  {label}: {', '.join(paths[:8])}")
    else:
        out.append("  (none)")

    out.append(_section("Secret-like files (NAME ONLY - contents never read)"))
    if d["secret_like_files"]:
        for f in d["secret_like_files"][:80]:
            out.append(f"  {f['path']}  ({f['size']} bytes)")
        if len(d["secret_like_files"]) > 80:
            out.append(f"  ... {len(d['secret_like_files']) - 80} more")
    else:
        out.append("  (none)")
    if d["secret_templates"]:
        out.append("  templates/examples (not live secrets): " + ", ".join(t["path"] for t in d["secret_templates"][:20]))

    out.append(_section("Certificate / key files (NAME ONLY)"))
    if d["certificate_key_files"]:
        for c in d["certificate_key_files"][:60]:
            out.append(f"  {c['path']}  [{c['kind']}]")
    else:
        out.append("  (none)")

    if d["tools_on_path"]:
        out.append(_section("Security tools / CLIs on PATH"))
        present = [t for t, ok in d["tools_on_path"].items() if ok]
        absent = [t for t, ok in d["tools_on_path"].items() if not ok]
        out.append("  present: " + (", ".join(present) or "(none)"))
        out.append("  absent:  " + (", ".join(absent) or "(none)"))

    if d["errors"]:
        out.append(_section("Errors (first 50)"))
        out.extend("  " + e for e in d["errors"])

    out.append(_section("Notes"))
    out.extend("  - " + n for n in d["notes"])
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Read-only security technology inventory (never prints secret file contents).")
    ap.add_argument("root", nargs="?", default=".", help="project root to inventory (default: .)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of the text summary")
    ap.add_argument("--output", "-o", help="write JSON to this file (text summary still printed unless --quiet)")
    ap.add_argument("--exclude", nargs="*", default=[], help="additional directory names to skip")
    ap.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, help=f"stop after N files (default {DEFAULT_MAX_FILES})")
    ap.add_argument("--no-tools", action="store_true", help="do not probe PATH for security tools")
    ap.add_argument("--quiet", "-q", action="store_true", help="print nothing to stdout (use with --output)")
    ap.add_argument("--version", action="version", version=f"security_inventory {VERSION}")
    args = ap.parse_args(argv)

    root = Path(args.root).expanduser()
    try:
        root = root.resolve()
    except OSError:
        pass
    if not root.exists() or not root.is_dir():
        print(f"error: root is not a readable directory: {root}", file=sys.stderr)
        return 2
    if args.max_files <= 0:
        print("error: --max-files must be positive", file=sys.stderr)
        return 2

    inv = Inventory(root, args.exclude, args.max_files, check_tools=not args.no_tools)
    inv.run()
    data = inv.to_dict()

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, sort_keys=False)
        except OSError as exc:
            print(f"error: cannot write {args.output}: {exc}", file=sys.stderr)
            return 2
    if not args.quiet:
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print(render_text(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
