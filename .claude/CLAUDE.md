# AI Code Assistant — Secure Code-Generation & Repository Security Instructions

## Purpose
These mandatory instructions govern code and repository configuration produced by the AI Code Assistant tool. They prevent reintroduction of known vulnerabilities (hardcoded secrets, missing HTTP timeouts, unsafe deserialization, insecure hashing, SQL injection, Flask debug enabled, shell execution, etc.) and ensure generated code is safe-by-default. Any deviation must follow the documented SECURITY-EXCEPTION process.

## High-level revision policy
- Default to safe primitives and deny insecure constructs. Never generate code that hardcodes secrets, uses weak hashing for authentication, omits HTTP timeouts, or performs unsafe deserialization.
- Prefer secure libraries and idioms:
  - Passwords: Argon2/bcrypt/scrypt via passlib (Argon2 preferred).
  - HTTP: requests with explicit timeout and TLS verification; aiohttp with ClientTimeout.
  - DB: parameterized queries / ORM only; whitelist dynamic SQL fragments.
  - Deserialization: yaml.safe_load, json, pydantic/jsonschema — never pickle/marshal on untrusted input.
  - Shell: subprocess.run([...], check=True) with shell=False; never shell=True for user-supplied data.
- Forbid the following constructs in generated code by default (see "Prohibited patterns"):
  - eval/exec/compile on untrusted input, pickle/marshal, yaml.load without safe loader, hashlib.md5/sha1 for security, requests without timeout or with verify=False, app.run(debug=True), SQL built by string interpolation, subprocess.run(..., shell=True), os.system/popopen with concatenated strings.

## Required repository files (must exist and be enforced)
- .pre-commit-config.yaml — include detect-secrets, semgrep, black, flake8, etc. (example below).
- .github/workflows/security.yml — CI job that runs detect-secrets (baseline enforced), bandit, semgrep, pip-audit and fails on findings.
- .github/semgrep/p/ci/ — semgrep rules detecting prohibited patterns (examples below).
- .secrets.baseline — reviewed detect-secrets baseline committed to repo root.

## Secrets & configuration rules
- Never hardcode credentials, API keys, tokens, or passwords in code, tests, examples, or CI. Always read secrets from environment variables or a secret manager, and annotate TODOs for wiring.
  ```python
  # DO NOT hardcode. Fetch from env or secret manager (e.g., Vault, AWS Secrets Manager).
  DB_PASSWORD = os.environ.get("MY_SERVICE_DB_PASSWORD")  # TODO: wire to secret manager
  ```
- Tests must use mocks, fixtures, or CI-injected secrets; do not commit plaintext test secrets.
- Detect-secrets must be added to pre-commit and CI and the baseline enforced:
  ```bash
  detect-secrets scan --baseline .secrets.baseline || (echo "detect-secrets found new secrets" && exit 1)
  ```

## HTTP / Network calls
- Always include explicit timeouts and TLS verification. Use configurable defaults and support custom CA bundles via REQUESTS_CA_BUNDLE.
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
- For aiohttp:
  ```python
  import aiohttp
  from aiohttp import ClientTimeout

  DEFAULT_AIO_TIMEOUT = ClientTimeout(total=int(os.environ.get("DEFAULT_HTTP_TIMEOUT", "10")))

  async def fetch(session: aiohttp.ClientSession, url: str, timeout: ClientTimeout = DEFAULT_AIO_TIMEOUT):
      async with session.get(url, timeout=timeout) as resp:
          resp.raise_for_status()
          return await resp.text()
  ```
- Do NOT set verify=False. Document how to use REQUESTS_CA_BUNDLE for valid custom CAs.

## Cryptography & hashing
- Disallow hashlib.md5 and hashlib.sha1 for authentication or password hashing. Use Argon2 via passlib as default:
  ```python
  from passlib.context import CryptContext

  pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

  def hash_password(password: str) -> str:
      # Argon2 provides memory-hard password hashing.
      return pwd_ctx.hash(password)

  def verify_password(password: str, hashed: str) -> bool:
      return pwd_ctx.verify(password, hashed)
  ```
- For HMAC/non-password use:
  ```python
  import hmac
  import hashlib

  def compute_hmac(key: bytes, msg: bytes) -> str:
      # HMAC with SHA-256 for message authentication
      return hmac.new(key, msg, hashlib.sha256).hexdigest()
  ```
- If using SHA-256 for non-security fingerprints document rationale inline.

## SQL & database access
- Never construct SQL from untrusted input using f-strings, .format(), or string concatenation. Use parameterized queries or an ORM.
  ```python
  # psycopg2 example
  cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
  ```
- For dynamic query components (ORDER BY, column names) use explicit whitelists:
  ```python
  ALLOWED_SORT_COLUMNS = {"created_at", "name", "id"}

  def build_order_by(column: str):
      if column not in ALLOWED_SORT_COLUMNS:
          raise ValueError("invalid sort column")
      return f"ORDER BY {column}"
  ```
- Do not commit DB credentials; read from env/secret manager and use connection timeouts when supported.

## Deserialization & YAML
- Do NOT use yaml.load() on untrusted input. Use yaml.safe_load() or structured parsing with pydantic/jsonschema.
  ```python
  import yaml
  with open("config.yaml") as f:
      cfg = yaml.safe_load(f)
  ```
- Do NOT use pickle, marshal, eval, exec, or compile on untrusted input. Use json/protobuf/pydantic with validation.
- If a legacy flow requires unsafe deserialization, require an inline SECURITY-EXCEPTION comment in the file (owner/date/mitigation + PR link) and document compensating controls and review steps.

## Command execution & shell safety
- Avoid executing arbitrary shell commands. Use subprocess.run with list args and shell=False and validate/whitelist user-supplied arguments:
  ```python
  import subprocess
  subprocess.run(["/usr/bin/convert", input_file, output_file], check=True)
  ```
- Disallow os.system(), popen with concatenated strings, and subprocess.run(..., shell=True). Any intentional use of shell=True must include a SECURITY-EXCEPTION block in-file linking to an approved PR.

## Flask & web frameworks
- Default to debug OFF. Enable only via an explicit env var and ensure SECRET_KEY is read from env:
  ```python
  import os
  from flask import Flask

  app = Flask(__name__)
  app.debug = os.environ.get("FLASK_DEBUG", "False").lower() in ("1", "true")
  app.config.update(
      SECRET_KEY=os.environ.get("FLASK_SECRET_KEY"),  # required in production
      SESSION_COOKIE_SECURE=True,
      SESSION_COOKIE_HTTPONLY=True,
      SESSION_COOKIE_SAMESITE="Lax",
  )
  ```
- Never include app.run(debug=True) in production examples.
- Do not return raw stack traces to clients; register error handlers and log redacted traces server-side.

## Logging & telemetry
- Never log secrets or sensitive PII. Provide a redact utility and encourage structured logging:
  ```python
  def redact_secret(value: str, visible: int = 4) -> str:
      if not value:
          return value
      if len(value) <= visible:
          return "***"
      return value[:visible] + "***"
  ```
- Use logging filters/middleware to scrub sensitive fields before emitting logs. Ensure logs do not contain whole secrets, tokens, or raw DB connection strings.

## Prohibited patterns (must not be generated)
The AI must never generate code containing these patterns. Replace with secure alternatives or include a documented SECURITY-EXCEPTION comment in the file (owner, date, mitigation, PR link) if absolutely necessary.
- Hardcoded secrets (e.g., password = "secret") — use env vars/secret manager.
- yaml.load(...) without a safe loader — use yaml.safe_load().
- pickle.load(s)/pickle.loads() or marshal on untrusted input — use json/pydantic/protobuf.
- eval(...)/exec(...)/compile(..., 'eval') — use safe parsers or whitelist DSLs.
- hashlib.md5(...) or hashlib.sha1(...) for authentication/password hashing — use passlib/argon2 or HMAC-SHA256.
- subprocess.run(..., shell=True), os.system(), popen with concatenated strings — use subprocess.run(list, shell=False).
- SQL built by f-strings/.format() or concatenation from user input — use parameterized queries/ORM.
- requests.* calls without timeout or with verify=False.
- app.run(debug=True) in examples.
- Logging secrets or PII without redaction.

Files intentionally containing a prohibited pattern must include the explicit inline block:
```python
# SECURITY-EXCEPTION: <brief reason> (owner: alice@example.com, date: 2026-01-01).
# Mitigation: <compensating controls>. See PR #123 for details.
```

## Semgrep rules (required set)
Place semgrep rules under .github/semgrep/p/ci. These rules must detect the prohibited patterns and the vulnerabilities reported by scans. Example required rules (tune for project to reduce false positives):

- yaml_load.yml — detect yaml.load usage
- pickle.yml — detect pickle.load(s)/pickle.loads()
- hashlib_weak.yml — detect hashlib.md5 and hashlib.sha1
- requests_timeout.yml — detect requests.get/post without timeout or with verify=False
- subprocess_shell.yml — detect subprocess.run(..., shell=True), os.system(), popen with concatenation
- flask_debug.yml — detect app.run(debug=True) and Flask debug env misuse
- sql_string.yml — detect SQL built via f-strings/.format/concatenation with user input
- hardcoded_secret.yml — detect hardcoded secrets via regex
- eval_exec.yml — detect eval/exec/compile usage
- marshal.yml — detect marshal usage
- os_system.yml — detect os.system and dangerous popen usage
- logging_secrets.yml — detect logging of env variables or secret-like names directly

Example YAML rule for requests without timeout (simplified):
```yaml
rules:
  - id: requests-without-timeout-or-verify-false
    patterns:
      - pattern-either:
          - pattern: requests.get($URL)
          - pattern: requests.post($URL)
          - pattern: requests.request($METHOD, $URL)
      - pattern-not:
          - pattern: timeout=$TIMEOUT
      - pattern-not:
          - pattern: verify=True
    message: "Include timeout and verify parameters in requests (e.g., timeout=5, verify=True or REQUESTS_CA_BUNDLE)."
    severity: ERROR
```
Ensure rules detect verify=False and timeout omission and treat findings as ERROR.

## CI / Automation (required)
CI must run security checks and fail on relevant findings:
- detect-secrets (baseline enforced)
- bandit (fail on findings)
- semgrep using .github/semgrep/p/ci (fail on findings)
- pip-audit (SCA; surface issues)
- unit tests

Minimal GitHub Actions security job (example):
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
- CI must return non-zero when bandit or semgrep finds relevant issues. Tune semgrep rules to minimize false positives while covering prohibited constructs.

## Pre-commit configuration
- Enforce pre-commit with detect-secrets, black, flake8, semgrep. Example:
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
  - repo: https://github.com/pre-commit/mirrors-flake8
    rev: 6.0.0
    hooks:
      - id: flake8
```
- Maintain and review .secrets.baseline at repo root; update only via approved process.

## Enforcement & exceptions
- The AI must automatically rewrite or refuse to emit code with prohibited patterns. Human exceptions require:
  - A documented security rationale in the PR,
  - Named owner and review date,
  - Compensating controls and test coverage,
  - An inline SECURITY-EXCEPTION comment in the file referencing the PR.
- Semgrep suppressions are only allowed when the PR includes the SECURITY-EXCEPTION and reviewer acknowledgement.

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

## Auditing for reported vulnerabilities
These instructions explicitly mitigate vulnerabilities reported by automated scans:
- Hardcoded passwords (B105): prohibited; detect-secrets baseline enforced; examples show env/secret manager usage.
- Requests without timeout (B113): semgrep rules require timeout and verify; examples show explicit timeout + verify.
- Unsafe hashing (B324, B413, B304): hashlib.md5/sha1 banned for auth; passlib/argon2 mandated; HMAC-SHA256 recommended for message auth.
- Unsafe deserialization and yaml.load (B506): yaml.safe_load required; pickle/marshal banned; semgrep rules detect usage.
- Shell/exec risks and eval/exec (B403/B405/B301/B314 etc.): forbidden; subprocess.run with list required; semgrep rules detect shell=True, os.system, eval.
- Hardcoded SQL expressions / SQL injection (B608): parameterized queries/ORM required; semgrep rules detect string interpolation into SQL.
- Flask debug enabled (B201): debug OFF by default; app.run(debug=True) banned in examples; env-controlled debug only.
- Other "blacklist" findings: covered by explicit prohibitions and semgrep rules for marshal, eval, subprocess, insecure crypto, and logging secrets.

By following these concise, enforceable rules the AI Code Assistant will prevent reintroduction of the vulnerabilities found in prior scans.