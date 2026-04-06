# AI Code Assistant Security & Coding Guidelines (Revised)

Revision checklist (high-level)
- Eliminate hardcoded secrets and enforce secret-management patterns (env vars, secret managers, detect-secrets).
- Enforce explicit network timeouts and TLS verification for all HTTP clients.
- Prohibit insecure deserialization, insecure hashing (MD5/SHA1), eval/exec, shell=True, and SQL via string interpolation; provide secure alternatives.
- Ensure Flask defaults to debug OFF and safe error handling/session settings.
- Add CI + pre-commit enforcement to detect banned patterns (bandit, semgrep, detect-secrets, pip-audit/safety) and fail builds on findings.
- Require monthly rule-review and automated checks to prevent future regressions.

## Purpose
These concise, mandatory instructions govern code produced by the AI Code Assistant tool to prevent the class of vulnerabilities identified by recent scans (hardcoded secrets, request without timeout, insecure hashing/deserialization, SQL injection, enabling Flask debug, shell injection, etc.). All rules are binding for generated code and must be enforced in CI and pre-commit tooling.

## Principles (applies to generated code)
- Fail-safe defaults: deny dangerous actions by default (no shell execution, no unsafe deserialization, no debug-on).
- Prefer secure, well-maintained libraries and primitives (requests/aiohttp with timeouts, passlib/argon2, SQLAlchemy/parameterized DB APIs).
- Always use explicit parameterization for external-facing operations (SQL, shell, HTTP).
- Avoid logging secrets or PII in plaintext; mask/redact if necessary.
- Provide concise comments where a security decision is intentionally made.

## Secrets and Configuration
- NEVER hardcode secrets, credentials, API keys, or passwords in source code, tests, examples or CI files.
- Always read secrets from environment variables or a secrets manager. Use explicit comments and placeholders in generated code:
```python
# Do NOT hardcode. Fetch from environment or secret manager (Vault, AWS Secrets Manager, etc.).
# Example: DB_PASSWORD = os.environ["MY_SERVICE_DB_PASSWORD"]
DB_PASSWORD = os.environ.get("MY_SERVICE_DB_PASSWORD")  # TODO: wire to secret manager
```
- Tests: use secure test-config fixtures, mocks, or secrets injected by CI; never commit plaintext test secrets.
- Add detect-secrets to pre-commit and CI. Example .pre-commit-config.yaml snippet:
```yaml
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.1.0
    hooks:
      - id: detect-secrets
```

## HTTP Clients and Network Calls
- ALWAYS include explicit timeouts and enforce TLS verification on network calls. Provide a configurable default and allow overrides:
```python
import requests
DEFAULT_TIMEOUT = 5  # seconds

def get_json(url: str, timeout: float = DEFAULT_TIMEOUT):
    resp = requests.get(url, timeout=timeout)  # timeout enforced
    resp.raise_for_status()
    return resp.json()
```
- DO NOT set verify=False. If connecting to internal certs, document how to provide CA bundles via env vars or config.
- For async clients (aiohttp) include both connect and read timeouts:
```python
import aiohttp
from aiohttp import ClientTimeout

DEFAULT_TIMEOUT = ClientTimeout(total=10)

async def fetch(session: aiohttp.ClientSession, url: str, timeout: ClientTimeout = DEFAULT_TIMEOUT):
    async with session.get(url, timeout=timeout) as resp:
        resp.raise_for_status()
        return await resp.text()
```
- For streaming/long-polling add cancellation logic and smaller read/conn timeouts.

## Cryptography and Hashing
- DO NOT use MD5 or SHA1 for security-sensitive purposes (passwords, signatures, token generation). For non-security hashing (cache keys, deduplication) prefer SHA-256 and document the use.
- For password storage and verification use dedicated libraries (passlib, bcrypt, argon2). Example:
```python
from passlib.context import CryptContext

pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str) -> str:
    # Argon2 is chosen for strong password hashing with memory hardness.
    return pwd_ctx.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_ctx.verify(password, hashed)
```
- For HMAC use the stdlib hmac with SHA-256 or better:
```python
import hmac
import hashlib

def compute_hmac(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
```
- Prohibit use of hashlib.md5() or hashlib.sha1() for authentication; if present in scans flag for manual review and replacement with hashlib.sha256 or Argon2 depending on use-case.

## SQL and Database Access
- NEVER construct SQL queries via string concatenation, f-strings, or .format() with user input.
- Use parameterized queries or ORM APIs. Examples:
```python
# psycopg2
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# sqlite3
cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))

# SQLAlchemy (ORM)
session.query(User).filter(User.id == user_id).one()
```
- Do not commit database credentials. Read DB connection strings via env vars or secret managers.
- For dynamic queries use libraries' parameter binding APIs; never inject user input into SQL fragments without strict validation and whitelisting.

## YAML and Deserialization
- DO NOT use yaml.load() on untrusted input. Use yaml.safe_load() or json.loads():
```python
import yaml

with open("config.yaml") as f:
    cfg = yaml.safe_load(f)  # safe_load avoids arbitrary object instantiation
```
- DO NOT use pickle, marshal, or eval on untrusted input. If object deserialization is required, implement whitelist-based deserializers and document supported types explicitly.
- For complex formats (protobufs, JSON schema) prefer schema validation libraries and explicit parsing.

## Prohibited / Blacklisted Patterns (do not generate)
The AI must not generate code containing these patterns. When flagged, the AI must automatically replace with secure alternatives or require explicit developer-approved exceptions with a documented security rationale.

- Hardcoded secrets (passwords, API keys, tokens)
  - Forbidden pattern example: password = "secret"
  - Alternative: read from env or secret manager (see "Secrets and Configuration").
- yaml.load(...) without loader or safe_load
  - Forbidden; replace with yaml.safe_load or explicit loader.
- pickle.loads(), pickle.load(), or any unsafe deserialization on untrusted input
  - Forbidden; replace with safe alternatives or whitelist-based deserializers.
- eval(...), exec(...), compile(..., 'eval') on untrusted input
  - Forbidden; prefer safe parsers or restricted sandboxes.
- hashlib.md5(...) or hashlib.sha1(...) used for authentication/passwords
  - Forbidden for security uses; replace with passlib/argon2 or hashlib.sha256 for non-sensitive purposes.
- subprocess.run(..., shell=True), os.system(...), popen with shell construction using untrusted input
  - Forbidden unless there is a vetted, logged justification. Use subprocess.run(list_of_args, shell=False) instead and sanitize inputs.
- SQL via f-strings or concatenation
  - Forbidden; use parameterized queries or ORM APIs.
- requests.* calls without timeout or with verify=False
  - Forbidden; always include timeouts and verify by default.
- app.run(debug=True) or FLASK_DEBUG enabled by default in generated code
  - Forbidden in examples intended for production; always default to OFF and read from env in development.
- Any code that programmatically disables TLS certificate validation
  - Forbidden.
- Logging secrets/PII in plaintext (including returning stack traces to clients)
  - Forbidden; redact/mask sensitive fields.

For every prohibited pattern above, the AI must generate the secure alternative inline (see examples elsewhere in this file).

## Flask and Web Application Settings
- Default to debug OFF and enable only via explicit environment configuration for development:
```python
import os
from flask import Flask

app = Flask(__name__)
app.debug = os.environ.get("FLASK_DEBUG", "False").lower() in ("1", "true")
# Secure session and cookie defaults for production:
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
# Never include app.run(debug=True) in production examples.
```
- Do not return stack traces or internal errors to clients. Use error handlers and log detailed traces server-side with masking of sensitive fields.
- Use strong secret keys from env/secret manager:
```python
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")  # must be set in production
```

## Command Execution and Shell
- Avoid generating code that executes arbitrary shell commands. When required:
  - Use subprocess with argument lists and shell=False:
  ```python
  import subprocess
  subprocess.run(["ls", "-la", "/tmp"], check=True)
  ```
  - Validate and whitelist any user-provided portions of commands.
  - Log command execution (not secrets) and handle errors.

## Logging, Telemetry, and Error Messages
- Never log secrets, credentials, or PII in plaintext. Implement a redact utility:
```python
def redact_secret(value: str) -> str:
    if not value:
        return value
    return value[:4] + "***"  # simple example; prefer structured filters in real projects
```
- Use structured logging and configurable scrubbing of sensitive fields before emission.
- Limit error messages returned to clients; keep detailed traces in server logs only.

## Dependency and Version Guidance
- Prefer well-maintained libraries, current stable versions and avoid deprecated algorithms.
- Pin critical dependencies in lockfiles (pip-tools/poetry/Pipfile.lock).
- Recommend periodic SCA and vulnerability scanning (Dependabot, OSV, pip-audit/safety).

## CI / Automation Checks (required)
- CI must run static and dynamic security checks and fail on findings of banned patterns:
  - bandit (Python security checks)
  - semgrep (detect banned patterns like yaml.load, pickle, hashlib.md5/sha1, requests without timeout, app.run(debug=True), subprocess shell=True, SQL f-strings)
  - detect-secrets (pre-commit + CI)
  - pip-audit or safety for dependency vulnerabilities
- Example GitHub Actions workflow (minimal):
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
      - name: Bandit scan
        run: bandit -r .
      - name: Semgrep scan
        run: semgrep --config p/ci .
      - name: Detect secrets
        run: detect-secrets scan > .secrets.baseline || true
      - name: Dependency audit
        run: pip-audit || true
```
- Add semgrep rules to catch these banned patterns (examples):
  - yaml.load(
  - pickle.load(
  - hashlib.md5(
  - hashlib.sha1(
  - requests.get(    # without timeout param
  - app.run(debug=True)
  - subprocess.run(..., shell=True)
  - f"SELECT .*{user_input}.*"  (pattern to catch SQL string formatting)
- CI must be configured to FAIL the build on any findings related to the prohibited patterns above.

## Pre-commit and Repo Hygiene
- Enforce pre-commit with detect-secrets, black/flake8, and a dedicated semgrep hook:
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
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.29.0
    hooks:
      - id: semgrep
        args: ["--config", "p/ci"]
```

## Safe Code-Generation Rules for the AI Tool
When producing code, the AI must:
1. Never output literal secrets. Use environment variables or placeholders with explicit instructions on secret source.
2. Enforce secure defaults: include timeouts for network calls, verify TLS, safe deserialization, parameterized DB access, strong password hashing (Argon2), and debug OFF for web apps.
3. Replace prohibited patterns automatically with secure alternatives. If a user requests legacy/insecure behavior, require an explicit warning, documented acceptance of risk, and generate a secure alternative first.
4. Add concise inline comments explaining security decisions (e.g., why argon2 chosen).
5. Provide short usage examples showing correct error handling, timeouts, and parameterized queries for any generated helper utilities.
6. For any generated CI or automation, include semgrep rules and detect-secrets baseline to prevent regressions.

## Developer and Reviewer Checklist (must be completed before merge)
- No hardcoded secrets or passwords present anywhere in code or tests.
- All HTTP calls include timeouts and TLS verification.
- No use of unsafe deserialization (yaml.load without loader, pickle on untrusted input).
- No MD5/SHA1 usage for authentication or password hashing.
- All SQL statements are parameterized or use an ORM safely; no f-string SQL.
- Flask apps do not enable debug in production and do not return stack traces to clients.
- No eval/exec or subprocess with shell=True usage without documented, reviewed justification.
- CI contains the required security checks (bandit, semgrep, detect-secrets, pip-audit/safety) and is configured to fail on findings for banned patterns.
- Pre-commit hooks configured (detect-secrets, semgrep, flake8/black).

## Enforcement & Iteration
- These rules are mandatory for the AI Code Assistant tool. Any generated code violating them must be rejected or automatically rewritten.
- Maintain a monthly review process to update rulesets and semgrep patterns based on new findings or SCA reports.
- Maintain a documented exemptions process: exceptions require a recorded security rationale, an owner, mitigation steps, and approval by a security reviewer.

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
pwd = CryptContext(schemes=["argon2"], deprecated="auto")
pw_hash = pwd.hash("s3cr3t")
```
- Safe subprocess:
```python
import subprocess
subprocess.run(["/usr/bin/convert", input_file, output_file], check=True)
```

By following these rules, the AI Code Assistant will not re-introduce the vulnerabilities found by the scan (hardcoded passwords, request without timeout, insecure hashing/deserialization, SQL injection, Flask debug enabled, shell execution risks, etc.). These guidelines are concise, actionable, and must be enforced in both generation and CI/pre-commit automation.