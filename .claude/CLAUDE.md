# AI Code Assistant — Secure Code-Generation & Repository Security Instructions

These instructions are mandatory for the AI Code Assistant tool. They ensure generated code and repository configuration do not reintroduce vulnerabilities (hardcoded secrets, missing HTTP timeouts, unsafe deserialization, insecure hashing, SQL injection, Flask debug enabled, shell execution, etc.). Follow fail-safe defaults, prefer secure libraries, and require documented exceptions for any deviation.

## High-level revision policy
- Never commit secrets: require environment variables or secret manager usage for any credentials or keys.
- Default secure primitives: timeouts + TLS verification for network calls; safe deserialization; Argon2/bcrypt/scrypt for passwords; parameterized DB queries/ORM; debug OFF for web frameworks.
- Forbid unsafe constructs by default: eval/exec/compile, pickle/marshal, yaml.load without explicit safe loader, subprocess with shell=True, hashlib.md5/sha1 for security purposes, string-based SQL construction.
- Enforce tooling: pre-commit (detect-secrets, semgrep, black), CI (bandit, semgrep, detect-secrets, pip-audit). CI must fail on prohibited patterns.

## Required repository files
- .pre-commit-config.yaml — include detect-secrets, semgrep, black, flake8 (example below).
- .github/workflows/security.yml — CI job running bandit, semgrep, detect-secrets, pip-audit and exiting non-zero on findings.
- .github/semgrep/p/ci/ — semgrep rules detecting all prohibited patterns (examples below).
- .secrets.baseline — reviewed detect-secrets baseline committed to repo.

## Secrets & configuration rules
- NEVER hardcode secrets in code, tests, examples, or CI. Read from environment variables or secret manager.
- Use clear TODO comments to indicate wiring to a secret manager:
```python
# DO NOT hardcode. Fetch from env or secret manager (e.g., Vault, AWS Secrets Manager).
DB_PASSWORD = os.environ.get("MY_SERVICE_DB_PASSWORD")  # TODO: wire to secret manager
```
- Tests must use mocks/fixtures or CI-injected secrets; do not commit plaintext test secrets.
- Add detect-secrets to pre-commit and CI and enforce baseline:
```bash
detect-secrets scan --baseline .secrets.baseline || (echo "detect-secrets found new secrets" && exit 1)
```

## HTTP / Network calls
- Always include explicit timeouts and TLS verification. Provide configurable defaults and document a REQUESTS_CA_BUNDLE option:
```python
import os
import requests

DEFAULT_HTTP_TIMEOUT = float(os.environ.get("DEFAULT_HTTP_TIMEOUT", "5"))  # seconds
REQUESTS_CA_BUNDLE = os.environ.get("REQUESTS_CA_BUNDLE")  # optional custom CA bundle

def get_json(url: str, timeout: float = DEFAULT_HTTP_TIMEOUT):
    # verify defaults to True unless a custom CA bundle is provided via env.
    resp = requests.get(url, timeout=timeout, verify=REQUESTS_CA_BUNDLE or True)
    resp.raise_for_status()
    return resp.json()
```
- For async HTTP use aiohttp ClientTimeout:
```python
import aiohttp
from aiohttp import ClientTimeout

DEFAULT_AIO_TIMEOUT = ClientTimeout(total=int(os.environ.get("DEFAULT_HTTP_TIMEOUT", "10")))

async def fetch(session: aiohttp.ClientSession, url: str, timeout: ClientTimeout = DEFAULT_AIO_TIMEOUT):
    async with session.get(url, timeout=timeout) as resp:
        resp.raise_for_status()
        return await resp.text()
```
- Do NOT set verify=False programmatically. Document how to use REQUESTS_CA_BUNDLE for custom CAs.

## Cryptography & hashing
- Prohibit hashlib.md5 and hashlib.sha1 for authentication or password hashing. Disallow generated use for secrets/signatures.
- Use Argon2, bcrypt, or scrypt (via passlib) for password hashing:
```python
from passlib.context import CryptContext

pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str) -> str:
    # Argon2 provides memory-hard password hashing.
    return pwd_ctx.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_ctx.verify(password, hashed)
```
- For HMAC or non-password crypto use stdlib with SHA-256+:
```python
import hmac
import hashlib

def compute_hmac(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
```
- If using SHA-256 for non-security purposes (cache/fingerprint) document rationale inline.

## SQL & database access
- NEVER construct SQL from untrusted input using f-strings, .format(), or concatenation. Use parameterized queries or an ORM.
```python
# psycopg2 example
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# SQLAlchemy example
session.query(User).filter(User.id == user_id).one()
```
- For dynamic SQL fragments (ORDER BY, column names) use explicit whitelists:
```python
ALLOWED_SORT_COLUMNS = {"created_at", "name", "id"}

def build_order_by(column: str):
    if column not in ALLOWED_SORT_COLUMNS:
        raise ValueError("invalid sort column")
    return f"ORDER BY {column}"
```
- Do not commit DB credentials; read from env/secret manager and use connection timeouts when supported.

## Deserialization & YAML
- DO NOT use yaml.load() on untrusted input. Use yaml.safe_load() or structured parsing with pydantic/jsonschema.
```python
import yaml
with open("config.yaml") as f:
    cfg = yaml.safe_load(f)
```
- DO NOT use pickle, marshal, eval, exec, or compile on untrusted input. For structured uploads validate with pydantic or jsonschema.
- If a legacy format requires unsafe deserialization, require a documented SECURITY-EXCEPTION comment in the file with owner/date/mitigations and a PR-level rationale.

## Command execution & shell safety
- Avoid executing arbitrary shell commands. Use subprocess.run with list args and shell=False:
```python
import subprocess

subprocess.run(["/usr/bin/convert", input_file, output_file], check=True)
```
- Validate/whitelist user-supplied command arguments. Disallow shell=True unless a documented SECURITY-EXCEPTION comment is present (owner/date/mitigation + PR reference).
- Disallow os.system(), popen with concatenated strings from untrusted input.

## Flask & web frameworks
- Default to debug OFF. Enable only via explicit env var:
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
- Never include app.run(debug=True) in production examples.
- Do not return stack traces to clients; register error handlers and log redacted traces server-side.

## Logging & telemetry
- Never log secrets or PII directly. Provide a simple redact utility and encourage structured logging:
```python
def redact_secret(value: str, visible: int = 4) -> str:
    if not value:
        return value
    if len(value) <= visible:
        return "***"
    return value[:visible] + "***"
```
- Use logging filters/middleware to scrub sensitive fields before emitting logs.

## Prohibited patterns (must not be generated)
The AI must never generate code containing these patterns. Replace with secure alternatives or require an explicit documented SECURITY-EXCEPTION in the file (owner, date, mitigation, and PR link).
- Hardcoded secrets (e.g., password = "secret"). Use env vars/secret manager.
- yaml.load(...) without a safe loader. Use yaml.safe_load().
- pickle.load(s)/pickle.loads() on untrusted input. Use json/protobuf/pydantic with validation.
- eval(...)/exec(...)/compile(..., 'eval'). Use safe parsers/whitelist DSLs.
- hashlib.md5(...) or hashlib.sha1(...) for authentication/passwords. Use passlib/argon2 or SHA-256+ for non-security uses with documented rationale.
- subprocess.run(..., shell=True), os.system(), or popen with shell concatenation. Use subprocess.run(list, shell=False) + validation.
- SQL built via f-strings or string concatenation (user input). Use parameterized queries/ORM.
- requests.* calls without timeout or with verify=False.
- app.run(debug=True) in examples.

Files containing an intentional prohibition bypass must include this inline:
```python
# SECURITY-EXCEPTION: <brief reason> (owner: alice@example.com, date: 2026-01-01).
# Mitigation: <compensating controls>. See PR #123 for details.
```

## AI-safe code-generation rules (enforced on every output)
1. Never output literal secrets—use placeholders/env vars + TODO to wire secrets into secret manager.
2. Default to secure primitives: timeouts, TLS verification, safe deserialization, parameterized DB access, Argon2 for passwords, debug OFF.
3. Replace prohibited patterns automatically with secure alternatives. If the user insists on insecure behavior require a documented SECURITY-EXCEPTION and show the secure alternative first.
4. Add concise inline comments explaining security choices and why a primitive was chosen.
5. Provide short usage examples showing error handling, timeouts, and parameterized queries for helper utilities.
6. For generated CI/automation include semgrep rules and detect-secrets baseline checks to prevent regressions.
7. Any file intentionally containing a prohibited pattern must include a SECURITY-EXCEPTION comment block referencing the PR where the exception is authorized.

## CI / Automation (required)
- CI must run these checks and FAIL on findings relevant to prohibited patterns:
  - detect-secrets (baseline enforced)
  - bandit (fail on findings)
  - semgrep (project rules in .github/semgrep/p/ci)
  - pip-audit (SCA; surface issues)
- Minimal GitHub Actions job:
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
        run: |
          pip-audit --exit-code 0 || echo "pip-audit completed"
```
- Configure CI to return non-zero when bandit or semgrep finds relevant issues. Tune rules to minimize false positives while covering prohibited constructs.

## Pre-commit configuration
- Enforce pre-commit with detect-secrets, black, flake8, semgrep:
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
- Maintain and review .secrets.baseline at repo root; update only via approved process.

## Semgrep rules (required set)
- Place semgrep rules under .github/semgrep/p/ci. Required detections:
  - yaml.load without loader
  - pickle.load(s)/pickle.loads()
  - hashlib.md5 and hashlib.sha1
  - requests.get/post without timeout argument or with verify=False
  - subprocess.run(..., shell=True)
  - app.run(debug=True)
  - SQL constructed via f-strings or concatenation (detect user inputs in string joins)
  - eval/exec/compile usage
  - hardcoded secrets via regex (API_KEY|PASSWORD|SECRET|token)
- Example rules (saved as separate .yml files in .github/semgrep/p/ci):
```yaml
# yaml_load.yml
rules:
  - id: yaml-load-unsafe
    patterns:
      - pattern: "yaml.load($X)"
    message: "Use yaml.safe_load() instead of yaml.load() on untrusted input"
    severity: ERROR

# pickle.yml
rules:
  - id: pickle-load-unsafe
    patterns:
      - pattern-either:
          - pattern: "pickle.load($X)"
          - pattern: "pickle.loads($X)"
    message: "Do not use pickle on untrusted input. Use json/pydantic with validation."
    severity: ERROR

# hashlib_weak.yml
rules:
  - id: hashlib-md5-sha1
    patterns:
      - pattern-either:
          - pattern: "hashlib.md5($X)"
          - pattern: "hashlib.sha1($X)"
    message: "Do not use MD5/SHA1 for authentication or password hashing. Use passlib/argon2 or HMAC-SHA256."
    severity: ERROR

# requests_timeout.yml
rules:
  - id: requests-without-timeout
    patterns:
      - pattern-either:
          - pattern: "requests.get($URL)"
          - pattern: "requests.post($URL)"
    message: "Include timeout and verify parameters in requests (e.g., timeout=5, verify=True or REQUESTS_CA_BUNDLE)."
    severity: ERROR

# subprocess_shell.yml
rules:
  - id: subprocess-shell-true
    patterns:
      - pattern: "subprocess.run(..., shell=True, ...)"
    message: "Do not use shell=True; use a list of args and shell=False."
    severity: ERROR

# flask_debug.yml
rules:
  - id: flask-debug-true
    patterns:
      - pattern: "app.run(debug=True)"
    message: "Do not enable Flask debug mode in production examples."
    severity: ERROR

# sql_string.yml
rules:
  - id: sql-string-format
    patterns:
      - pattern-regex: "execute\\(.*\\%s.*\\)" # humble check; tune for project
    message: "Use parameterized queries or an ORM; do not interpolate user input into SQL."
    severity: ERROR

# hardcoded_secret.yml
rules:
  - id: hardcoded-secret
    patterns:
      - pattern-regex: "(API_KEY|PASSWORD|SECRET|TOKEN)\\s*[:=]\\s*['\\\"]\\w+['\\\"]"
    message: "Do not commit hardcoded secrets; use environment variables or a secret manager."
    severity: ERROR
```
- Keep rules high-fidelity; review and tune periodically. Any allowed suppression must reference a PR with justification.

## Enforcement & exceptions
- Violations in generated code must be rewritten or rejected by the AI. Human exceptions require:
  - A documented security rationale in the PR,
  - Named owner and review date,
  - Compensating controls and test coverage,
  - An inline SECURITY-EXCEPTION comment in the file linking to the PR.
- CI must still flag the exception; semgrep suppression must reference the PR and justification.

## Quick reference examples (safe patterns)
- Safe HTTP:
```python
resp = requests.get("https://api.example.com/data", timeout=5, verify=True)
resp.raise_for_status()
```
- Safe YAML:
```python
cfg = yaml.safe_load(open("config.yaml"))
```
- Safe password hashing:
```python
pw_hash = pwd_ctx.hash("s3cr3t")  # Example only — DO NOT hardcode
```
- Safe subprocess:
```python
subprocess.run(["/usr/bin/ls", "-la"], check=True)
```
- Safe SQL:
```python
cursor.execute("INSERT INTO users (name, email) VALUES (%s, %s)", (name, email))
```

## Change control & maintenance
- Monthly review of semgrep rules, bandit baselines, and SCA tooling.
- Maintain an audit trail for security exceptions and rotate secrets referenced in .secrets.baseline regularly.

By following these concise, enforceable rules, the AI Code Assistant will prevent reintroduction of the vulnerabilities found in prior scans (hardcoded credentials, missing HTTP timeouts, unsafe deserialization, insecure hashing, SQL injection, Flask debug enabled, shell execution risks, etc.).