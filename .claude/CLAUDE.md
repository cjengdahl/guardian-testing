# AI Code Assistant — Secure Code Generation Instructions

- Review and apply these rules before generating or committing code.
- Replace any direct subprocess shell calls with safe, parameterized invocations.
- Always use parameterized queries or ORM APIs for database access; never compose SQL with untrusted input.
- Use modern, secure hash functions (bcrypt/argon2 for secrets; SHA-2+ or HMAC for digests). Only permit MD5 for non-security checks with explicit justification and annotation.
- Configure CI to run static analysis (e.g., Bandit) and fail on HIGH findings; require security-review label for any exception.

## Purpose & Scope
These instructions guide the AI Code Assistant to avoid generating code patterns that introduce the vulnerabilities identified by the security scan (subprocess misuse, SQL injection, use of weak hashes). They apply to all generated Python code and to code templates used by the assistant.

## General Policies
- Default to secure libraries and safe APIs. Prefer high-level abstractions (ORMs, library wrappers) over manual string-building.
- Treat all external input (user input, environment, network, files) as untrusted. Validate, sanitize, and/or whitelist before use.
- For any API or pattern that can cause high-severity security issues, require:
  - a brief comment in-code explaining why the pattern is necessary, and
  - an explicit code review and security approval step in the PR workflow.

## Subprocess Usage (Addresses B404, B602)
Policy:
- Never generate code that calls subprocess with shell=True.
- Use list/sequence argument forms (shell=False) and avoid string interpolation of commands.
- When user-provided values are used in commands, validate against a whitelist of allowed values or map user choices to safe predefined commands.
- Prefer library alternatives (e.g., shutil, os, platform-specific APIs) over launching external processes where possible.
- When invoking external commands, use absolute paths (or verify via shutil.which), set environment explicitly, and use timeouts.

Disallowed (unsafe) example:
```python
# Unsafe — DO NOT generate
import subprocess
cmd = f"tar -czf {archive_name} {path}"   # archive_name/path may be attacker-controlled
subprocess.Popen(cmd, shell=True)
```

Preferred (safe) examples:
```python
# Safe — use list args and avoid shell=True
import subprocess, shutil

cmd = ["tar", "-czf", archive_name, path]  # archive_name and path must be validated/whitelisted
# Verify the executable exists
if shutil.which(cmd[0]) is None:
    raise RuntimeError("Required binary not found")
subprocess.run(cmd, check=True, timeout=60)
```

When dynamic user input must select a command, map values:
```python
# Map user choice to safe commands
COMMAND_MAP = {
    "backup": ["/usr/bin/rsync", "-a", "/src", "/dest"],
    "list": ["/bin/ls", "-la", "/some/folder"],
}
choice = get_user_choice()
cmd = COMMAND_MAP.get(choice)
if cmd is None:
    raise ValueError("Invalid action")
subprocess.run(cmd, check=True, timeout=30)
```

Exception process:
- If shell=True is absolutely required (rare), include in-code justification, require a security PR label, and add unit tests that assert the non-exposures (e.g., no unescaped user input). Prefer sandboxing or privileged-review.

## SQL & Database Access (Addresses B608)
Policy:
- Never generate SQL by concatenating or interpolating user-supplied strings.
- Use parameterized queries, prepared statements, or an ORM query builder.
- Validate and/or whitelist any identifiers (table/column names) if they must be dynamic — do not pass them as SQL string fragments without validation.

Unsafe (do not generate):
```python
# Unsafe — DO NOT generate
query = f"SELECT * FROM users WHERE name = '{user_name}'"
cursor.execute(query)
```

Safe examples (parameterized):
```python
# sqlite3 / DB-API parameterized
cursor.execute("SELECT * FROM users WHERE name = ?", (user_name,))

# psycopg2 (Postgres)
cursor.execute("SELECT * FROM users WHERE email = %s", (user_email,))
```

Safe example (SQLAlchemy ORM):
```python
# SQLAlchemy — prefer ORM or SQL expression language
from sqlalchemy import select
stmt = select(User).where(User.email == user_email)
result = session.execute(stmt)
```

Dynamic identifiers:
- If dynamic table or column names are required, validate against a strict whitelist and never interpolate raw user input.
```python
# Example whitelist for dynamic columns
ALLOWED_COLUMNS = {"id", "username", "email"}
if column_name not in ALLOWED_COLUMNS:
    raise ValueError("Invalid column")
query = f"SELECT {column_name} FROM users WHERE id = %s"
cursor.execute(query, (user_id,))
```

Testing & CI:
- Add unit tests that assert no SQL is built via string concatenation (e.g., scan committed code for patterns).
- Run static analyzers that detect SQL injection patterns. Fail CI on MEDIUM/HIGH severity findings.

## Hashing & Cryptography (Addresses B324)
Policy:
- Do not use MD5 (or other broken algorithms) for password hashing or any security-sensitive hashing (integrity/authentication). Use bcrypt or Argon2 for passwords; use SHA-256+ or HMAC for non-secret digests and signatures.
- If MD5 is required strictly for non-security purposes (e.g., legacy non-auth checksum), document the reason inline and, where supported, call hashlib.md5(..., usedforsecurity=False) to make intent explicit. Prefer stronger checksum algorithms (SHA-256) where feasible.

Password hashing (recommended):
```python
# Use passlib / bcrypt or argon2 for passwords
from passlib.hash import bcrypt

hashed = bcrypt.hash(password)
if not bcrypt.verify(candidate_password, hashed):
    raise ValueError("Invalid credentials")
```

Non-secret digests or checksums:
```python
# Prefer SHA-256 for general-purpose digests
import hashlib
digest = hashlib.sha256(data).hexdigest()
```

MD5 exception (non-security only):
```python
# Only for non-security checksums and with justification in-code
import hashlib
# Python 3.9+: explicitly mark usedforsecurity=False
md5_checksum = hashlib.md5(data, usedforsecurity=False).hexdigest()
# Document why MD5 is acceptable here (e.g., legacy compatibility, checksum only).
```

Secrets and keys:
- Use HMAC (hashlib/hmac) or authenticated encryption for message integrity.
- Never store raw secrets; use appropriate key management or environment-based secret storage. Do not commit secrets to source.

## CI / Static Analysis & Tooling
- Integrate Bandit (or equivalent) into CI and fail builds for HIGH severity findings and for specified MEDIUM severity classes (e.g., SQL injection, subprocess shell=True).
- Example Bandit configuration snippet for CI:
```yaml
# .github/workflows/security.yml (example)
name: security-scan
on: [push, pull_request]
jobs:
  bandit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run bandit
        run: |
          pip install bandit
          bandit -r . -ll -iii -f json -o bandit-results.json
      - name: Fail on high severity
        run: |
          python - <<'PY'
import json
r=json.load(open("bandit-results.json"))
if any(i['issue_severity']=='HIGH' for i in r['results']):
    raise SystemExit("High severity findings detected")
print("No HIGH severity findings")
PY
```
- Configure static analyzers to flag:
  - subprocess.run/ Popen with shell=True,
  - MD5 usage for security-sensitive contexts,
  - string-based SQL command construction.

## Review, Exceptions & Documentation
- All PRs that include:
  - new subprocess usage, or
  - any hashing change from recommended algorithms, or
  - dynamic SQL or raw SQL strings
  must include:
  - a short security rationale in the PR description, and
  - the label "security-review" before merging.
- Keep a central, versioned "approved commands" mapping for any subprocess actions that are allowed. Store it under a documented config file in the repo.
- Document any accepted MD5 usage with a comment and link to the PR that approved it.

## Example Snippets Summary
Safe subprocess:
```python
import subprocess, shutil
cmd = ["/usr/bin/rsync", "-a", "/src", "/dest"]
if shutil.which(cmd[0]) is None:
    raise RuntimeError("Executable not found")
subprocess.run(cmd, check=True, timeout=60)
```

Safe SQL (psycopg2):
```python
cursor.execute("INSERT INTO logs (event, created_at) VALUES (%s, now())", (event_name,))
```

Secure password hash:
```python
from passlib.hash import argon2
hash = argon2.hash("s3cret")
assert argon2.verify("s3cret", hash)
```

## Enforcement Checklist for Generated Code
When the assistant generates code, ensure:
- No subprocess calls use shell=True.
- All subprocess invocations use list args and/or whitelist mappings.
- No SQL strings are built by concatenating untrusted input.
- Passwords/secrets use bcrypt/argon2; MD5 is not used for security.
- Static analysis passes (no HIGH findings) and PR includes security justification for any exceptions.

---