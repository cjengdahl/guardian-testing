# AI Code Assistant — Secure Coding & Generation Instructions

## Purpose
Provide concise, enforceable guidance for the AI Code Assistant so generated code for this repository avoids recurring security problems. These instructions target known vulnerability categories discovered by automated scans (subprocess misuse, shell=True, string-built SQL, and use of MD5 for security) and define required safe patterns, CI checks, and explicit prohibitions.

## High-level policies
- Do not generate code that executes shell commands with shell=True or that concatenates untrusted input into shell strings.
- Do not generate string-based SQL queries constructed with f-strings, %-formatting, or concatenation; always use parameterized queries or an ORM.
- Do not use MD5 (or other weak hashes such as SHA1) for security-sensitive purposes (passwords, tokens, HMAC keys). Use modern password hashing (Argon2/Bcrypt/Scrypt) or secure hashes (SHA-256+) only for non-security checksums.
- Always prefer standard library/third-party APIs over spawning shell commands when functionality can be achieved in-process.
- If a user requests an insecure pattern, refuse and provide a secure alternative and clear rationale.

## Subprocess and shell execution (addresses B404, B602)
- Forbidden: subprocess.Popen(..., shell=True), subprocess.run(..., shell=True), os.system(), and any pattern that shells untrusted input.
- Required: use subprocess.run / subprocess.Popen with a sequence (list) of arguments and shell=False. Validate or strictly whitelist all external input used to build command arguments. When possible, use higher-level APIs or libraries instead of subprocess.
- Always check command existence with shutil.which() before invoking.
- Use subprocess.run(..., check=True, capture_output=True, text=True) for robust behavior and explicit error handling.

Example — safe subprocess usage:
```python
import shutil
import subprocess

def run_tool(args):
    # args is a list e.g. ["git", "status"]
    if not isinstance(args, (list, tuple)) or not args:
        raise ValueError("args must be a non-empty list of command and arguments")
    if shutil.which(args[0]) is None:
        raise FileNotFoundError(f"Command not found: {args[0]}")
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    return result.stdout
```

If you must accept a single string from untrusted sources, never pass it to subprocess with shell=True. Parse or tokenize it safely (prefer whitelist parsing) and convert to a list.

Bad pattern (prohibited):
```python
# DO NOT GENERATE
subprocess.run(f"tar -xzf {user_input}", shell=True)
```

Safer alternative (generate instead):
```python
# Parse/validate then pass as list
user_file = sanitize_filename(user_input)  # implement strict validation/whitelist
subprocess.run(["tar", "-xzf", user_file], check=True)
```

## SQL query construction (addresses B608)
- Forbidden: building SQL using string concatenation, f-strings, or %-formatting with untrusted input.
- Required: use parameterized statements supported by DB-API (cursor.execute(query, params)) or use a proven ORM (SQLAlchemy, Django ORM) with built-in parameterization and query builders.
- Validate and/or whitelist identifiers (table/column names) separately: DB parameterization does not substitute identifiers — if identifiers must be dynamic, compare them against a server-side whitelist and refuse unknown values.

Example — parameterized queries (sqlite3 / DB-API):
```python
import sqlite3

def get_user_by_email(conn, email):
    # NEVER: f"SELECT * FROM users WHERE email = '{email}'"
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE email = ?", (email,))
    return cur.fetchone()
```

Example — validating dynamic column (whitelisting):
```python
ALLOWED_COLUMNS = {"id", "email", "created_at"}

def fetch_sorted(conn, column):
    if column not in ALLOWED_COLUMNS:
        raise ValueError("Invalid sort column")
    query = f"SELECT id, email FROM users ORDER BY {column} DESC"
    # column is from whitelist, values are not concatenated into params
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()
```

If the user requests dynamic SQL generation, the assistant must:
- Recommend an ORM or query builder first.
- If raw SQL is required, generate code that uses parameterized queries and shows explicit identifier whitelisting.

## Hashing and password storage (addresses B324)
- Forbidden: MD5 or SHA1 for password hashing, token signing, or any security-sensitive operation.
- Required for passwords: use a specialized password hashing algorithm (Argon2 recommended; Bcrypt/Scrypt acceptable). Use well-maintained libraries (argon2-cffi, passlib).
- For non-security checksums (e.g., deduplication, non-adversarial integrity checks), prefer SHA-256. If MD5 MUST be used for a non-security purpose, annotate the code and use the Python 3.9+ parameter usedforsecurity=False.

Examples — password hashing (argon2):
```python
from argon2 import PasswordHasher

ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(hash: str, password: str) -> bool:
    try:
        return ph.verify(hash, password)
    except Exception:
        return False
```

Example — secure checksum (non-auth) with SHA-256:
```python
import hashlib

def file_sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
```

Example — MD5 only for non-security uses (explicit, documented):
```python
import hashlib

# MD5 used only for non-security checksum; not for authentication or integrity protection.
def md5_checksum(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()
```

The assistant must refuse to generate MD5 for password hashing, token HMACs, or cryptographic signing; always recommend a secure alternative.

## AI Generation rules for the assistant (explicit)
- Never output code that:
  - Uses subprocess with shell=True.
  - Constructs SQL with string concatenation/f-strings/unescaped interpolation.
  - Uses MD5 or SHA1 for security-sensitive functionality.
- Always prefer:
  - subprocess.run/list arguments with validation and shutil.which checks.
  - DB parameterization or ORM usage; if identifiers must be dynamic, validate against a server-side whitelist.
  - Argon2 (argon2-cffi / passlib), bcrypt, or other modern password hashing libraries for credentials.
  - Clear comments explaining why a given pattern is secure.
- If asked to produce an insecure pattern (e.g., "show me how to run user input with shell=True"), refuse and instead provide a secure alternative plus a short explanation.
- When providing examples, include error handling and explicit input validation.

## CI and automated enforcement (scanning + blocking)
- Add Bandit / pip-audit / safety checks to CI to detect regressions. Example GitHub Action snippet:
```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  bandit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"
      - name: Install deps
        run: |
          python -m pip install --upgrade pip
          pip install bandit
      - name: Run bandit
        run: bandit -r . -ll -f json -o bandit-output.json
```
- Configure CI to fail on high/medium findings that match these categories (subprocess shell usage, SQL injection patterns, weak hash use). Include Bandit config or custom grep checks for patterns like "shell=True", "f\"SELECT", "md5(".

## Examples — quick forbidden vs allowed
Forbidden (do not generate):
```python
# insecure: shell=True and untrusted input
subprocess.run(f"tar -xzf {user_input}", shell=True)

# insecure: SQL via f-string
cur.execute(f"SELECT * FROM users WHERE username = '{username}'")

# insecure: md5 for password
pwd_hash = hashlib.md5(password.encode()).hexdigest()
```

Allowed (generate this instead):
```python
# safe subprocess
subprocess.run(["tar", "-xzf", user_file], check=True)

# parameterized SQL
cur.execute("SELECT * FROM users WHERE username = ?", (username,))

# secure password hashing (argon2)
from argon2 import PasswordHasher
hash = PasswordHasher().hash(password)
```

## Minimal code-review checklist for PRs produced by AI
- No use of shell=True or raw os.system calls.
- All SQL statements use parameterization or ORM and any dynamic identifiers are whitelisted.
- No MD5/SHA1 used for auth or secrets; Argon2/Bcrypt used for passwords.
- Any subprocess invocation validates command and arguments (shutil.which / explicit whitelist).
- Unit tests or integration tests added when behavior changes relate to security-sensitive code paths.

## Maintenance notes
- Keep this instruction file near the AI tooling config; update if new scan patterns emerge.
- Ensure the assistant has a machine-readable policy enforcement layer (linting/CI) that blocks generation of the prohibited patterns above.