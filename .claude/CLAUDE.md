# AI Code Assistant Security & Code-Generation Instructions

- Revision checklist (high-level)
  - Remove hardcoded secrets; require env/secret-manager usage and detect-secrets in pre-commit/CI.
  - Enforce network timeouts and TLS verification on all HTTP clients.
  - Forbid unsafe deserialization, insecure hashing (MD5/SHA1), eval/exec, and subprocess shell=True; provide secure alternatives.
  - Ensure SQL parameterization/ORM usage only; forbid f-string/concatenated SQL.
  - Default Flask debug OFF, secure session settings, and hide stack traces.
  - Add CI + pre-commit enforcement (bandit, semgrep, detect-secrets, pip-audit) and fail builds on findings.

## Purpose
These instructions are mandatory for the AI Code Assistant tool. They ensure generated code will not reproduce the vulnerabilities detected by recent scans (hardcoded secrets, missing timeouts, unsafe deserialization, insecure hashing, SQL injection, Flask debug enabled, shell injection risks, etc.). All generated code must adhere to these rules and the CI/pre-commit checks described below.

## Principles (short)
- Fail-safe defaults: deny dangerous actions by default (no shell execution, no unsafe deserialization, debug OFF).
- Use well-maintained libraries and explicit secure primitives.
- Always prefer parameterization, explicit validation/whitelisting, and secret management.
- Avoid logging secrets/PII; redact before logging.
- Provide a concise inline comment when an alternate, less secure approach is intentionally requested (must include documented approval and risk acceptance).

## Secrets and Configuration
- NEVER hardcode secrets, credentials, API keys, or passwords in source, tests, examples, or CI.
- Read secrets from environment variables or a secret manager. Use explicit TODO comments for wiring:
```python
# Do NOT hardcode. Fetch from env or a secret manager (Vault, AWS Secrets Manager, etc.).
DB_PASSWORD = os.environ.get("MY_SERVICE_DB_PASSWORD")  # TODO: wire to secret manager
```
- Tests must use mocks, fixtures, or CI-injected secrets (do not commit plaintext test secrets).
- Add detect-secrets to pre-commit and CI.

## HTTP Clients and Network Calls
- ALWAYS include explicit timeouts and TLS verification; provide a configurable default:
```python
import requests
DEFAULT_TIMEOUT = 5  # seconds

def get_json(url: str, timeout: float = DEFAULT_TIMEOUT):
    # explicit timeout prevents hung requests; do not set verify=False in production.
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.json()
```
- For aiohttp:
```python
import aiohttp
from aiohttp import ClientTimeout

DEFAULT_TIMEOUT = ClientTimeout(total=10)
async def fetch(session: aiohttp.ClientSession, url: str, timeout: ClientTimeout = DEFAULT_TIMEOUT):
    async with session.get(url, timeout=timeout) as resp:
        resp.raise_for_status()
        return await resp.text()
```
- DO NOT use verify=False. Document how to use a custom CA bundle via env var (e.g., REQUESTS_CA_BUNDLE).

## Cryptography and Hashing
- DO NOT use MD5 or SHA1 for security-sensitive purposes (passwords, signatures, tokens).
- Use passlib / argon2 / bcrypt for password hashing:
```python
from passlib.context import CryptContext
pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str) -> str:
    # Argon2 provides memory-hard password hashing.
    return pwd_ctx.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_ctx.verify(password, hashed)
```
- For HMAC and non-password crypto use stdlib with SHA-256 or better:
```python
import hmac, hashlib
def compute_hmac(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
```
- If non-security sha256-based digests are used for caching, document rationale.

## SQL and Database Access
- NEVER construct SQL via string concatenation, f-strings, or .format() with user input.
- Use parameterized queries or ORM:
```python
# psycopg2 example
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
# SQLAlchemy example
session.query(User).filter(User.id == user_id).one()
```
- For dynamic SQL fragments, use query builders, explicit validation, and whitelisting. Always validate/whitelist column names and other identifiers before interpolation.
- Do not commit DB credentials; read from env/secret manager.

## YAML and Deserialization
- DO NOT use yaml.load() on untrusted input. Use yaml.safe_load() or json.loads():
```python
import yaml
with open("config.yaml") as f:
    cfg = yaml.safe_load(f)
```
- DO NOT use pickle, marshal, eval, exec, or any unsafe deserialization on untrusted input.
- If structured deserialization is required, require schema validation (e.g., jsonschema, pydantic) and whitelist allowed types. Document supported types.

## Command Execution and Shell Safety
- Avoid generating code that executes arbitrary shell commands. When necessary:
  - Use subprocess.run with a list and shell=False:
```python
import subprocess
subprocess.run(["/usr/bin/convert", input_file, output_file], check=True)
```
  - Validate and whitelist user-provided command arguments.
  - Disallow shell=True in generated code unless an approved, logged security exception is recorded in the PR with mitigation steps.

## Flask and Web Application Settings
- Default to debug OFF and enable only via explicit environment configuration:
```python
import os
from flask import Flask
app = Flask(__name__)
app.debug = os.environ.get("FLASK_DEBUG", "False").lower() in ("1","true")
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY"),  # must be set in production
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
```
- Do not include app.run(debug=True) in production examples.
- Do not return stack traces to clients; register error handlers and log detailed traces in server logs after redaction.
- Ensure secret keys come from env/secret manager.

## Logging and Telemetry
- Never log secrets or PII in plaintext. Provide a small redact utility in generated code:
```python
def redact_secret(value: str, visible: int = 4) -> str:
    if not value:
        return value
    if len(value) <= visible:
        return "***"
    return value[:visible] + "***"
```
- Prefer structured logging and configurable scrubbing filters.

## Prohibited / Blacklisted Patterns
The AI must never generate code containing these patterns. If a requested snippet would require such behavior, the AI must (1) refuse or (2) generate a secure alternative and require an explicit, documented exception with owner and mitigation.

Forbidden patterns (automatic rewrite required):
- Hardcoded secrets (e.g., password = "secret"). Replacement: env var or secret manager.
- yaml.load(...) without safe loader. Replacement: yaml.safe_load().
- pickle.load(s)/pickle.loads() on untrusted input. Replacement: json/protobuf/pydantic with validation.
- eval(...)/exec(...)/compile(..., 'eval') on untrusted input. Replacement: safe parsers or limited DSL with whitelist.
- hashlib.md5(...) or hashlib.sha1(...) for authentication or password hashing. Replacement: passlib/argon2 or hashlib.sha256 for non-sensitive use.
- subprocess.run(..., shell=True), os.system(), or popen with shell-concatenation of untrusted input. Replacement: subprocess.run(list, shell=False) + validation.
- SQL constructed by f-strings or string concatenation. Replacement: parameterized queries/ORM.
- requests.* calls without timeout or with verify=False. Replacement: include timeout and respect TLS.
- app.run(debug=True) in production examples.
- Programmatic disabling of TLS validation.

Every generated file must include a short inline comment when a prohibition was explicitly applied and why.

## CI / Automation Checks (required)
CI must run these security checks and FAIL the build on any findings related to prohibited patterns:
- bandit
- semgrep (with project rules below)
- detect-secrets (pre-commit + CI)
- pip-audit or safety

Minimal GitHub Actions job (fail on findings):
```yaml
name: Security Checks
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"
      - name: Install tools
        run: pip install bandit semgrep detect-secrets pip-audit
      - name: Detect secrets
        run: detect-secrets scan || true
      - name: Bandit scan
        run: bandit -r .
      - name: Semgrep scan
        run: semgrep --config p/ci .
      - name: Dependency audit
        run: pip-audit
```
- The CI must be configured to return a non-zero exit code on semgrep/bandit findings relevant to prohibited patterns.

Semgrep rules (examples) — include these in repo at .github/semgrep/p/ci or as referenced config:
- Disallow yaml.load without loader.
- Disallow pickle.load(s)/pickle.loads().
- Disallow hashlib.md5 and hashlib.sha1.
- Detect requests.get/post without timeout argument.
- Detect subprocess.run(..., shell=True).
- Detect app.run(debug=True).
- Detect SQL with f-strings or string concatenation patterns.
- Detect obvious hardcoded secrets via regex (API_KEY|PASSWORD|SECRET) with low-FP tuning.

Provide baseline suppression only for carefully reviewed, documented exceptions.

## Pre-commit and Repo Hygiene
- Enforce pre-commit with detect-secrets, black, flake8, and semgrep:
```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.0.1
    hooks:
      - id: check-added-large-files
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.1.0
    hooks:
      - id: detect-secrets
  - repo: https://github.com/psf/black
    rev: stable
    hooks:
      - id: black
  - repo: https://github.com/pre-commit/mirrors-semgrep
    rev: v1.29.0
    hooks:
      - id: semgrep
        args: ["--config", ".github/semgrep/p/ci"]
```
- Maintain a detect-secrets baseline in the repo (reviewed and rotated when new secrets are added via approved process).

## Safe Code-Generation Rules for the AI Tool
When producing code, the AI must:
1. Never output literal secrets. Use env variables or placeholders and include a TODO comment linking to secret manager instructions.
2. Enforce secure defaults: include timeouts, TLS verification, safe deserialization, parameterized DB access, Argon2 for passwords, debug OFF.
3. Automatically replace prohibited patterns with secure alternatives. If a user explicitly requests legacy/insecure behavior, require a documented security exception (owner, risk, mitigation) and present the secure alternative first.
4. Add concise inline comments explaining security choices.
5. Provide short usage examples showing correct error handling, timeouts, and parameterized queries for any helper utilities generated.
6. For generated CI/automation, include semgrep rules and detect-secrets baseline to prevent regressions.

## Developer and Reviewer Checklist (must be completed before merge)
- No hardcoded secrets or passwords in code, tests, examples, or CI.
- All HTTP calls include timeouts and enforce TLS.
- No unsafe deserialization (yaml.load without loader, pickle, eval).
- No MD5/SHA1 usage for authentication or password hashing.
- All SQL statements are parameterized or use an ORM safely.
- Flask apps do not enable debug in production and do not return stack traces to clients.
- No eval/exec or subprocess shell=True usage without a reviewed exception.
- CI contains bandit, semgrep, detect-secrets, and pip-audit and is configured to fail on banned patterns.
- Pre-commit hooks installed and passing (detect-secrets, semgrep, black/flake8).

## Enforcement & Exceptions
- Violations discovered in generated code must be auto-rewritten or rejected by the AI. Human exceptions require a documented security rationale in the PR, an owner, and compensating controls; the CI must still flag the exception.
- Monthly rule-review to update semgrep rules, SCA tooling, and the instruction set.

## Quick Reference Examples
- Safe HTTP:
```python
import requests
resp = requests.get("https://api.example.com/data", timeout=5)
resp.raise_for_status()
```
- Safe YAML:
```python
import yaml
cfg = yaml.safe_load(open("config.yaml"))
```
- Safe password hashing:
```python
from passlib.context import CryptContext
pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")
pw_hash = pwd_ctx.hash("s3cr3t")
```
- Safe subprocess:
```python
import subprocess
subprocess.run(["/usr/bin/ls", "-la"], check=True)
```
- Safe SQL:
```python
# psycopg2 parameterized query
cursor.execute("INSERT INTO users (name, email) VALUES (%s, %s)", (name, email))
```

## Required Repository Files (minimum)
- .pre-commit-config.yaml (detect-secrets, semgrep, black)
- .github/workflows/security.yml (CI with bandit, semgrep, detect-secrets, pip-audit)
- .github/semgrep/p/ci/ (semgrep rule set detecting banned patterns)
- detect-secrets baseline (.secrets.baseline) — reviewed and committed per policy

By following these rules, the AI Code Assistant will prevent reintroduction of vulnerabilities flagged by the scan (hardcoded passwords, request without timeout, insecure deserialization, unsafe hashing, SQL injection, Flask debug enabled, shell execution risks, etc.). These instructions are mandatory and enforced via pre-commit and CI.