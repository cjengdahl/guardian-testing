# AI Code Assistant Security & Coding Guidelines

This instruction file defines mandatory security and coding rules for the AI Code Assistant tool. Its purpose is to prevent the generation of insecure code, secrets leakage, and unsafe patterns identified by recent vulnerability scans. These guidelines are concise, actionable, and intended to be enforced during code generation and in CI.

## Principles (applies to generated code)
- Never hardcode secrets, credentials, API keys, or passwords in source code or tests.
- Prefer secure libraries and current best-practice primitives for cryptography, serialization, and remote calls.
- Fail safe: deny dangerous actions by default (e.g., shell execution, insecure deserialization, debug mode).
- Always prefer explicit, parameterized APIs over string interpolation for external-facing operations (SQL, shell, HTTP).
- Generate code that includes defensive defaults (timeouts, input validation, no debug=True in production).

## Secrets and Configuration
- Never generate or commit plaintext secrets. Always read secrets from environment variables or a secret manager (Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault).
- Use placeholders in generated code with a clear comment indicating the secret source. Example:
```python
# Do NOT hardcode. Fetch from environment or secret manager.
# Example: API_TOKEN = os.environ["MY_SERVICE_API_TOKEN"]
API_TOKEN = os.environ.get("MY_SERVICE_API_TOKEN")  # TODO: configure secret manager
```
- For tests, use fixtures that load secrets from a secure test-config file excluded from source control, or use test doubles/mocks.

## HTTP Clients and Network Calls
- Always include explicit timeouts and proper TLS verification when making HTTP requests. Do not set verify=False.
- Use a configurable default timeout value and allow callers to override it.
```python
import requests

DEFAULT_TIMEOUT = 5  # seconds

def get_json(url, timeout=DEFAULT_TIMEOUT):
    resp = requests.get(url, timeout=timeout)  # enforce timeout
    resp.raise_for_status()
    return resp.json()
```
- For long-polling or streaming, include appropriate connection/read timeouts and cancellation logic.

## Cryptography and Hashing
- Do not use MD5 or SHA1 for security-sensitive purposes (passwords, signatures, tokens).
- For password storage and verification, use a dedicated password hashing library such as bcrypt, scrypt, or Argon2 (e.g., passlib or bcrypt). Example with werkzeug or passlib:
```python
# Recommended: passlib or bcrypt / argon2
from passlib.context import CryptContext

pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_ctx.verify(password, hashed)
```
- For non-security checks (e.g., cache keys, deduplication), prefer SHA-256 instead of MD5/SHA1 and document uses clearly.

## SQL and Database Access
- Never build SQL queries using string concatenation, f-strings, or format(). Always use parameterized queries or an ORM's parameter API.
```python
# psycopg2 / psycopg2-binary example
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
# sqlite3 example
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```
- For ORMs (SQLAlchemy, Django ORM), use the ORM's parameterization and query builders.
- Do not generate code that contains hardcoded SQL credentials or SQL fragments with embedded user input.

## YAML and Deserialization
- Do not use yaml.load() or other insecure deserialization that can instantiate arbitrary objects.
- Use safe deserialization APIs such as yaml.safe_load() or json.loads(). Avoid pickle, marshal, or eval for untrusted data.
```python
import yaml

with open("config.yaml") as f:
    cfg = yaml.safe_load(f)  # safe_load instead of load
```
- If deserialization of complex objects is required, require a whitelist-based deserializer and document the exact safe types.

## Prohibited / Blacklisted Patterns (do not generate)
- Hardcoded secrets, e.g., passwords, API keys, tokens: "password = 'secret'"
- yaml.load(...) without loader or safe_load
- hashlib.md5(...) or hashlib.sha1(...) for authentication or password hashing
- Use of pickle.loads(), pickle.load() on untrusted input
- eval(...), exec(...), compile(..., 'eval') on untrusted input
- subprocess.run(..., shell=True) or os.system(...) with dynamic/unvalidated input
- SQL constructed via f-strings or string concatenation (cursor.execute(f"...{user_input}..."))
- requests.* calls without timeout or with verify=False
- app.run(debug=True) or FLASK_DEBUG enabled by default in generated code
- Any patterns that programmatically disable TLS certificate validation
- Any code that logs secrets or PII in plaintext (avoid logging of full tokens, passwords, SSNs)

For each prohibited pattern, the AI must propose and generate a secure alternative (examples above).

## Flask and Web Application Settings
- Generated Flask applications must default to debug OFF and read debug flag from environment only when explicitly set for development:
```python
import os
from flask import Flask

app = Flask(__name__)
app.debug = os.environ.get("FLASK_DEBUG", "False").lower() in ("1", "true")
# Ensure we never produce app.run(debug=True) for production examples.
```
- Never print or return stack traces or internal errors in production. Use proper error handlers and safe logging.
- Enforce secure session handling: use strong secret keys stored in environment and set secure cookie flags in production.

## Command Execution and Shell
- Avoid generating code that executes arbitrary shell commands. When necessary, use subprocess with argument lists and shell=False:
```python
import subprocess

# Safe: pass args as a list, avoid shell=True
subprocess.run(["ls", "-la", "/tmp"], check=True)
```
- Sanitize and validate any inputs used to build commands; prefer Python standard library APIs over shell utilities.

## Logging, Telemetry, and Error Messages
- Do not include secrets in logs, error messages, or telemetry. Mask or redact tokens and PII.
- Use structured logging and allow sensitive fields to be filtered before emission.

## Dependency and Version Guidance
- Prefer well-maintained libraries. Avoid recommending deprecated or insecure algorithms.
- Generated project configs should include a security-focused CI job (examples below) and pinned dependency constraints where appropriate.
- Recommend periodic SCA (software composition analysis) scans and automated dependency checks (e.g., GitHub Dependabot, OSV/Safety).

## CI / Automation Checks (recommended to include in generated projects)
- Add automated checks to prevent insecure code from being merged:
  - bandit or semgrep for Python security rules
  - detect-secrets (pre-commit) for secret scanning
  - safety or pip-audit for dependency vulnerabilities
  - unit tests covering security-critical flows (password hashing, auth, input validation)
- Example GitHub Actions snippet (minimal):
```yaml
name: Security Checks
on: [push, pull_request]
jobs:
  bandit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"
      - name: Install deps
        run: pip install bandit detect-secrets safety
      - name: Bandit scan
        run: bandit -r .
      - name: Detect secrets
        run: detect-secrets scan > .secrets.baseline || true
      - name: Safety check
        run: safety check
```
- CI must fail the build on findings for banned patterns defined in this file.

## Safe Code-Generation Rules for the AI Tool
When producing code, the AI must:
1. Never output literal secrets. Use environment variables or placeholders with instructions.
2. Prefer secure defaults: timeouts, TLS verification, parameterized DB access, safe deserialization, and secure password hashing.
3. Avoid using deprecated/insecure algorithms such as MD5/SHA1 for security, SHA-1-based HMACs, or custom cryptographic constructions. Recommend vetted libraries.
4. Replace prohibited patterns automatically with secure alternatives. If the user requests legacy/insecure behavior, require an explicit warning and alternative secure implementation first.
5. Provide concise comments where security decisions are made (e.g., why Argon2 chosen, why safe_load used).
6. Always include examples that demonstrate correct usage (error handling, timeouts, parameterized queries).

## Examples (quick reference)

- HTTP request with timeout and verification:
```python
import requests

def fetch(url):
    resp = requests.get(url, timeout=10)  # timeout enforced
    resp.raise_for_status()
    return resp.text
```

- Safe YAML:
```python
import yaml

with open("config.yaml") as f:
    config = yaml.safe_load(f)
```

- Parameterized SQL (psycopg2):
```python
cursor.execute("INSERT INTO users (name, email) VALUES (%s, %s)", (name, email))
```

- Password hashing (passlib / argon2):
```python
from passlib.context import CryptContext
pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

pw_hash = pwd_ctx.hash("plain_password")
assert pwd_ctx.verify("plain_password", pw_hash)
```

## Developer and Reviewer Checklist (must be followed before merging generated code)
- No secrets or passwords hardcoded.
- All HTTP calls include timeouts and verify TLS by default.
- No use of unsafe deserialization (yaml.load, pickle on untrusted input).
- No MD5/SHA1 for authentication or password hashing.
- SQL statements are parameterized or use an ORM safely.
- Flask apps do not enable debug in production example code.
- No eval/exec or shell=True usage without explicit justification and safeguards.
- CI contains security checks (bandit/semgrep/detect-secrets/safety or equivalent).

## Enforcement & Iteration
- These rules are binding for the AI Code Assistant tool. The tool must be updated to reject or rewrite generated code that violates these rules.
- Periodically (at least monthly) review generated patterns and update this instruction file to cover new insecure idioms discovered by scans or audit findings.

--- 

These guidelines address insecure defaults and the following classes of findings: hardcoded passwords, requests without timeouts, insecure hashing (MD5/SHA1), insecure deserialization (yaml.load/pickle), hardcoded SQL / injection risk, enabling Flask debug in production, use of eval/exec/shell execution, and other blacklisted patterns. Follow them strictly when generating code.