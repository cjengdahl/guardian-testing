# AI Code Assistant — Security & Secure Code-Generation Instructions

High-level revision checklist (apply before generating or committing code)
- Remove any hardcoded secrets and require environment variables or secret manager usage; enforce detect-secrets baseline in pre-commit/CI.
- Ensure all network calls include explicit timeouts and TLS verification; provide configurable defaults.
- Forbid unsafe deserialization (pickle, yaml.load), eval/exec, insecure hashing (MD5/SHA1), and subprocess shell=True; provide secure alternatives and require documented exception for any override.
- Enforce parameterized SQL/ORM use and explicit validation/whitelisting for any dynamic SQL fragments.
- Default Flask debug OFF, secure session settings, and ensure CI/pre-commit (bandit, semgrep, detect-secrets, pip-audit) fail builds on disallowed patterns.

## Purpose
These instructions are mandatory for the AI Code Assistant tool. They ensure generated code will not reintroduce vulnerabilities discovered in prior scans (hardcoded secrets, missing HTTP timeouts, unsafe deserialization, insecure hashing, SQL injection, Flask debug enabled, shell injection, etc.). All generated code and repository configuration must adhere to these rules and the CI/pre-commit checks described herein.

## Principles (concise)
- Fail-safe defaults: deny dangerous actions by default (no shell execution, no unsafe deserialization, debug OFF).
- Prefer well-maintained libraries and explicit secure primitives.
- Use parameterization, explicit validation/whitelisting, and secret management.
- Never log secrets/PII; redact before logging.
- If an explicit insecure/legacy behavior is requested, present a secure alternative first and require a documented, reviewed exception in the PR (owner, risk, and mitigations).

## Secrets and Configuration
- NEVER commit secrets, credentials, API keys, or passwords to source, tests, examples, or CI.
- Read secrets from environment variables or a secure secret manager. Use explicit TODO comments to indicate wiring:
```python
# Do NOT hardcode. Fetch from env or a secret manager (e.g., Vault, AWS Secrets Manager).
DB_PASSWORD = os.environ.get("MY_SERVICE_DB_PASSWORD")  # TODO: wire to secret manager
```
- Tests must use mocks, fixtures, or CI-injected secrets; do not commit plaintext test secrets.
- Add detect-secrets to pre-commit and CI and maintain a reviewed .secrets.baseline in the repo. CI must fail if new secrets are detected:
```bash
detect-secrets scan --baseline .secrets.baseline || exit 1
```

## HTTP Clients and Network Calls
- ALWAYS include explicit timeouts and TLS verification. Provide configurable defaults:
```python
import os
import requests

DEFAULT_TIMEOUT = float(os.environ.get("DEFAULT_HTTP_TIMEOUT", "5"))  # seconds
REQUESTS_CA_BUNDLE = os.environ.get("REQUESTS_CA_BUNDLE")  # optional custom CA bundle

def get_json(url: str, timeout: float = DEFAULT_TIMEOUT):
    # Ensure verify defaults to True. Do NOT set verify=False in production.
    resp = requests.get(url, timeout=timeout, verify=REQUESTS_CA_BUNDLE or True)
    resp.raise_for_status()
    return resp.json()
```
- For async HTTP (aiohttp) use ClientTimeout with explicit settings:
```python
import aiohttp
from aiohttp import ClientTimeout

DEFAULT_TIMEOUT = ClientTimeout(total=int(os.environ.get("DEFAULT_HTTP_TIMEOUT", "10")))

async def fetch(session: aiohttp.ClientSession, url: str, timeout: ClientTimeout = DEFAULT_TIMEOUT):
    async with session.get(url, timeout=timeout) as resp:
        resp.raise_for_status()
        return await resp.text()
```
- Document how to use a custom CA bundle via REQUESTS_CA_BUNDLE environment variable; do not programmatically disable TLS verification.

## Cryptography and Hashing
- NEVER use MD5 or SHA1 for authentication, password hashing, or signatures.
- Use passlib/argon2, bcrypt, or scrypt for password hashing:
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
import hmac
import hashlib

def compute_hmac(key: bytes, msg: bytes) -> str:
    # Use SHA-256 for message authentication.
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
```
- If a non-security sha256 digest is used for caching or fingerprinting, document rationale inline and avoid misusing it for authentication.

## SQL and Database Access
- NEVER construct SQL using string concatenation, f-strings, or .format() with user input.
- Use parameterized queries or an ORM. Examples:
```python
# psycopg2 parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
# SQLAlchemy example
session.query(User).filter(User.id == user_id).one()
```
- For dynamic SQL fragments (e.g., dynamic ORDER BY or column names), use explicit whitelists and query builders:
```python
ALLOWED_SORT_COLUMNS = {"created_at", "name", "id"}

def build_order_by(column: str):
    if column not in ALLOWED_SORT_COLUMNS:
        raise ValueError("invalid sort column")
    # safe to interpolate validated identifier
    return f"ORDER BY {column}"
```
- Do not commit DB credentials; read from env/secret manager. All DB access code must include connection timeouts where supported.

## YAML and Deserialization
- DO NOT use yaml.load() on untrusted input. Use yaml.safe_load() or json.loads().
```python
import yaml
with open("config.yaml") as f:
    cfg = yaml.safe_load(f)
```
- DO NOT use pickle, marshal, eval, exec, or compile on untrusted input. When structured deserialization is required, use schema validation (pydantic, jsonschema) and whitelist allowed object types/fields.
- If deserializing files uploaded by users, strictly validate structure, types, and allowed fields; log and reject otherwise.

## Command Execution and Shell Safety
- Avoid generating code that executes arbitrary shell commands. Use subprocess.run with a list and shell=False:
```python
import subprocess

subprocess.run(["/usr/bin/convert", input_file, output_file], check=True)
```
- Validate and whitelist user-provided command arguments. Disallow shell=True in generated code unless an approved, logged security exception is recorded in the PR with mitigation steps. Any file containing an exception MUST include a concise inline comment describing the approval (owner, date, risk, mitigation).
- Disallow os.system(), popen with shell concatenation patterns, and other constructs that allow shell injection.

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
- Do not return stack traces to clients. Register error handlers and log detailed traces to server logs after redaction.
- Ensure secret keys come from env/secret manager and are not hardcoded.

## Logging and Telemetry
- Never log secrets or PII in plaintext. Provide a redact utility and encourage structured logging:
```python
def redact_secret(value: str, visible: int = 4) -> str:
    if not value:
        return value
    if len(value) <= visible:
        return "***"
    return value[:visible] + "***"
```
- Use logging filters or middleware to scrub sensitive fields before emitting logs.

## Prohibited / Blacklisted Patterns (must never be generated)
The AI must never generate code containing these patterns. Any requested snippet that would require such behavior must either be refused or replaced with a secure alternative plus a documented PR exception.

- Hardcoded secrets (e.g., password = "secret"). Replacement: env var or secret manager.
- yaml.load(...) without a safe loader. Replacement: yaml.safe_load().
- pickle.load(s)/pickle.loads() on untrusted input. Replacement: json/protobuf/pydantic with validation.
- eval(...)/exec(...)/compile(..., 'eval') on untrusted input. Replacement: safe parsers or limited DSL with whitelist.
- hashlib.md5(...) or hashlib.sha1(...) for authentication or password hashing. Replacement: passlib/argon2 or hashlib.sha256 for non-security uses with documented rationale.
- subprocess.run(..., shell=True), os.system(), or popen with shell-concatenation of untrusted input. Replacement: subprocess.run(list, shell=False) + validation.
- SQL constructed by f-strings or string concatenation. Replacement: parameterized queries/ORM.
- requests.* calls without timeout or with verify=False. Replacement: include timeout and respect TLS.
- app.run(debug=True) in production examples.
- Programmatic disabling of TLS validation (verify=False or SSLContext that disables cert verification).

Every generated file must include a short inline comment when a prohibition was intentionally bypassed stating why and referencing the PR exception (owner, date, mitigation). Example:
```python
# SECURITY-EXCEPTION: shell=True allowed for legacy tool integration (owner: alice@example.com, date: 2026-01-01).
# Mitigation: inputs are validated and run in an isolated container; see PR #123 for details.
subprocess.run("legacy-cmd", shell=True, check=True)
```

## CI / Automation Checks (required)
CI must run these security checks and FAIL the build on any findings related to prohibited patterns. Minimal GitHub Actions job (fail on findings):
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
      - name: Detect secrets (baseline enforced)
        run: |
          detect-secrets scan --baseline .secrets.baseline || (echo "detect-secrets found new secrets" && exit 1)
      - name: Bandit scan (fail on findings)
        run: |
          bandit -r . -f json -o bandit_report.json || (echo "bandit found issues" && exit 1)
      - name: Semgrep scan (fail on findings)
        run: |
          semgrep --config .github/semgrep/p/ci --json --output semgrep_report.json || (echo "semgrep found issues" && exit 1)
      - name: Dependency audit
        run: pip-audit --exit-zero && echo "pip-audit completed"
```
- The CI must be configured to return non-zero when bandit or semgrep finds issues relevant to prohibited patterns. Review and tune rules to reduce false positives while ensuring coverage of the disallowed constructs.

## Semgrep Rules (required)
- Place project semgrep rules under .github/semgrep/p/ci and enforce in CI and pre-commit.
- Required detections include (examples):
  - yaml.load without loader
  - pickle.load(s)/pickle.loads()
  - hashlib.md5 and hashlib.sha1
  - requests.get/post without timeout argument or with verify=False
  - subprocess.run(..., shell=True)
  - app.run(debug=True)
  - SQL constructed via f-strings or string concatenation
  - eval/exec/compile uses
  - hardcoded secrets via regex (API_KEY|PASSWORD|SECRET)
- Example semgrep rule (yaml_load) saved to .github/semgrep/p/ci/yaml_load.yml:
```yaml
rules:
  - id: yaml-load-unsafe
    patterns:
      - pattern-either:
          - pattern: "yaml.load($X)"
    message: "Use yaml.safe_load() instead of yaml.load() on untrusted input"
    severity: ERROR
```
- Provide equivalent rules for other prohibited patterns. Keep rules minimal and high-fidelity to reduce noise; require review and a documented suppression for any permitted exceptions.

## Pre-commit and Repo Hygiene
- Enforce pre-commit with detect-secrets, black, flake8, and semgrep:
```yaml
# .pre-commit-config.yaml
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
- Maintain a reviewed .secrets.baseline at repository root and update only via an approved process.

## Safe Code-Generation Rules for the AI Tool (must be enforced on every output)
1. Never output literal secrets. Use environment variables or placeholders and include a TODO comment linking to secret manager instructions.
2. Enforce secure defaults: include timeouts, TLS verification, safe deserialization, parameterized DB access, Argon2 (or equivalent) for passwords, debug OFF.
3. Replace prohibited patterns with secure alternatives automatically. If the user explicitly requests insecure behavior, require a documented security exception (owner, risk, mitigation) and present the secure alternative first.
4. Add concise inline comments explaining security choices and why a given secure primitive was chosen.
5. Provide short usage examples showing correct error handling, timeouts, and parameterized queries for any helper utilities generated.
6. For generated CI/automation, include semgrep rules and detect-secrets baseline to prevent regressions.
7. Any file that intentionally contains a prohibited pattern must include a SECURITY-EXCEPTION comment block linking to a PR entry where the exception is authorized.

## Required Repository Files (minimum)
- .pre-commit-config.yaml (detect-secrets, semgrep, black)
- .github/workflows/security.yml (CI with bandit, semgrep, detect-secrets, pip-audit)
- .github/semgrep/p/ci/ (semgrep rule set detecting banned patterns)
- .secrets.baseline (detect-secrets baseline — reviewed and committed per policy)

## Enforcement & Exceptions
- Violations discovered in generated code must be auto-rewritten or rejected by the AI. Human exceptions require:
  - A documented security rationale in the PR,
  - Named owner and review date,
  - Compensating controls and test coverage,
  - An inline SECURITY-EXCEPTION comment in the file.
- CI must still flag the exception; suppression in semgrep must reference the PR and justification.

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
pw_hash = pwd_ctx.hash("s3cr3t")  # DO NOT hardcode; example only
```
- Safe subprocess:
```python
import subprocess
subprocess.run(["/usr/bin/ls", "-la"], check=True)
```
- Safe SQL:
```python
cursor.execute("INSERT INTO users (name, email) VALUES (%s, %s)", (name, email))
```

## Change Control and Rule Review
- Perform a monthly rule-review for semgrep, bandit baseline updates, and SCA tooling.
- Maintain an audit trail for any security exceptions and rotate secrets referenced in .secrets.baseline on a regular schedule.

By following these condensed, mandatory rules, the AI Code Assistant will prevent reintroduction of the vulnerabilities flagged by prior scans (hardcoded passwords, missing timeouts, unsafe deserialization, insecure hashing, SQL injection, Flask debug enabled, shell execution risks, etc.). These instructions are enforceable via pre-commit and CI and must be treated as required constraints for all generated code.