# AI Code Assistant — Secure Coding & Generation Instructions

## Revision plan
- Prevent subprocess/shell misuse by forbidding shell=True and enforcing list-argument subprocess usage with validation.
- Eliminate string-built SQL generation by requiring parameterized queries or ORM and explicit identifier whitelisting.
- Remove use of MD5/SHA1 for security; require Argon2/Bcrypt/Scrypt for passwords and SHA-256+ for non-security checksums.
- Add CI enforcement (Bandit + grep/pipeline checks) that fails on regressions for these patterns.
- Require assistant to refuse insecure requests and provide secure alternatives with rationale.

## Purpose
Provide concise, enforceable guidance so the AI Code Assistant will not generate code that recreates recurring security problems found during automated scans (subprocess misuse, shell=True, string-built SQL injection, and MD5 for security). These rules are mandatory for any code produced by the assistant for this repository.

## High-level policies
- Do not generate code that:
  - Executes shell commands with shell=True.
  - Concatenates or interpolates untrusted input into shell command strings.
  - Constructs SQL via f-strings, %-formatting, or string concatenation with untrusted input.
  - Uses MD5 or SHA1 for passwords, token signing, HMAC, or other security-sensitive purposes.
- Always prefer:
  - subprocess.run/list-argument usage with validation and shutil.which checks.
  - Parameterized DB-API queries or a proven ORM (SQLAlchemy, Django ORM) for database access.
  - Argon2 (argon2-cffi), bcrypt, or scrypt for password hashing; SHA-256+ for non-security checksums.
- If a user requests an insecure pattern, refuse and present a secure alternative and short explanation.

## Subprocess & shell execution rules
- Forbidden:
  - subprocess.run(..., shell=True), subprocess.Popen(..., shell=True), os.system(), or patterns that build shell strings from untrusted input.
- Required:
  - Always call subprocess with a sequence of arguments (list or tuple) and shell=False.
  - Validate command availability with shutil.which() before executing.
  - Validate or whitelist any user-provided arguments (filenames, flags, etc.).
  - Use subprocess.run(..., check=True, capture_output=True, text=True) and handle CalledProcessError.
- If accepting a single string from an untrusted source, refuse to pass it to subprocess with shell=True. Parse and validate into a safe list or reject.

Example — safe subprocess usage:
```python
import shutil
import subprocess
from typing import Sequence

def run_tool(args: Sequence[str]) -> str:
    if not isinstance(args, (list, tuple)) or not args:
        raise ValueError("args must be a non-empty list/tuple of command and arguments")
    if shutil.which(args[0]) is None:
        raise FileNotFoundError(f"Command not found: {args[0]}")
    try:
        res = subprocess.run(args, check=True, capture_output=True, text=True)
        return res.stdout
    except subprocess.CalledProcessError as e:
        # handle or re-raise with sanitized message
        raise RuntimeError(f"command failed: {e}") from e
```

Bad (prohibited) pattern:
```python
# DO NOT GENERATE
subprocess.run(f"tar -xzf {user_input}", shell=True)
```

Safer alternative (generate instead):
```python
# validate filename strictly and pass list
user_file = sanitize_filename(user_input)  # implement strict validation/whitelist
subprocess.run(["tar", "-xzf", user_file], check=True, capture_output=True, text=True)
```

## SQL query construction rules
- Forbidden:
  - Building SQL statements with string concatenation, f-strings, or %-formatting that include untrusted values.
- Required:
  - Use DB-API parameterized queries (cursor.execute(query, params)) or ORM query builders to pass data parameters.
  - Dynamic identifiers (table/column names) must be validated against a server-side whitelist. Never substitute unvalidated identifiers directly into SQL.
  - Show explicit validation and error handling for inputs used in queries.
- Prefer recommending an ORM for dynamic query generation; if raw SQL is necessary, include parameterization + identifier whitelisting.

Example — parameterized DB-API:
```python
import sqlite3

def get_user_by_email(conn: sqlite3.Connection, email: str):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE email = ?", (email,))
    return cur.fetchone()
```

Example — whitelisting dynamic identifiers:
```python
ALLOWED_SORT_COLS = {"id", "email", "created_at"}

def fetch_sorted(conn, sort_col: str):
    if sort_col not in ALLOWED_SORT_COLS:
        raise ValueError("Invalid sort column")
    query = f"SELECT id, email FROM users ORDER BY {sort_col} DESC"
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()
```

## Hashing and password storage rules
- Forbidden:
  - Using MD5 or SHA1 for password hashing, token signing, HMAC keys, or any security-sensitive functionality.
- Required:
  - Use Argon2 (argon2-cffi) or passlib wrappers for password hashing. Bcrypt or scrypt are acceptable alternatives.
  - Use SHA-256+ for non-security checksums/integrity where appropriate.
  - If MD5 is used only for non-security purposes (e.g., legacy non-adversarial checksums), annotate the code and call hashlib.md5(..., usedforsecurity=False) on Python 3.9+ and document why it's safe and non-security-critical.
- Assistant must refuse to generate MD5 for authentication/token purposes and instead provide a secure alternative with clear rationale.

Example — Argon2 password hashing:
```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
```

Example — non-security checksum with SHA-256:
```python
import hashlib

def sha256_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
```

Example — MD5 only for non-security use (explicitly documented):
```python
import hashlib

# MD5 used only for non-security deduplication; not for authentication or signing.
def md5_checksum(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()
```

## AI generation rules (enforced)
- The assistant must never output code that:
  - Uses subprocess with shell=True or os.system().
  - Constructs SQL via f-strings/string concatenation using untrusted input.
  - Uses MD5 or SHA1 for security-sensitive functions (passwords, tokens, HMAC).
- When asked for insecure examples, the assistant must:
  - Refuse to provide the insecure pattern.
  - Provide a secure alternative and explain concisely why it's safer.
- All generated examples must include input validation and error handling.

## CI & automated enforcement
- Add security scanning to CI and fail builds on flagged patterns (shell=True, unparameterized SQL, md5 usage).
- Recommended GitHub Action (Bandit + pattern checks):
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"
      - name: Install tools
        run: |
          python -m pip install --upgrade pip
          pip install bandit
      - name: Run bandit
        run: bandit -r . -ll -f json -o bandit-output.json || true
      - name: Fail on policy patterns
        run: |
          # fail if forbidden patterns appear in diff or codebase
          if git grep -n --line-number -E "shell=True|os\\.system\\(|subprocess\\..*shell=|f\"SELECT|%\\s*\\(|\\bmd5\\(" -- ':!*venv/*' ; then
            echo "Forbidden security patterns detected"; exit 1
          fi
```
- Configure Bandit and/or custom scripts to fail the pipeline on high/medium severity findings relevant to:
  - subprocess shell usage (shell=True, os.system)
  - hardcoded/unparameterized SQL patterns (f"SELECT", concatenated queries)
  - weak hash usage (md5(), sha1())
- Add tests/lint rules to the repo (pre-commit hooks or CI) to detect regressions for these exact patterns.

## Examples — forbidden vs allowed (short)
Forbidden:
```python
# DO NOT GENERATE
subprocess.run(f"tar -xzf {user_input}", shell=True)
cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
pwd_hash = hashlib.md5(password.encode()).hexdigest()
```

Allowed:
```python
# safe subprocess
subprocess.run(["tar", "-xzf", user_file], check=True, capture_output=True, text=True)

# parameterized SQL
cur.execute("SELECT * FROM users WHERE username = ?", (username,))

# secure password hashing
from argon2 import PasswordHasher
hash = PasswordHasher().hash(password)
```

## Minimal PR code-review checklist (apply to AI-generated PRs)
- No use of shell=True, os.system(), or unvalidated shell strings.
- All subprocess invocations use list arguments, shutil.which checks, and proper error handling.
- No SQL constructed via f-strings/concatenation; parameters or ORM used. Dynamic identifiers validated by whitelist.
- No MD5/SHA1 used for authentication or signing; Argon2/Bcrypt used for passwords.
- CI passes Bandit and custom pattern checks; any security findings addressed before merge.

## Maintenance & updates
- Keep this file adjacent to AI tooling config and update when new scan patterns appear.
- Ensure CI rules and pre-commit hooks reflect these constraints so generation and merges are blocked on regressions.